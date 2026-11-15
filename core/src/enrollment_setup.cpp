#include "rwn/core/enrollment_setup.hpp"
#include <algorithm>
#include <cstring>

namespace rwn::core::enrollment {
namespace {
using Clock=PairingConsent::Clock;
void require(bool b){if(!b)throw std::runtime_error("pairing did not complete; existing settings were preserved");}
struct Exchange {
    EnrollmentChannel& channel;const EnrollmentSetupCallbacks& cb;const std::atomic_bool& cancelled;
    Clock::time_point deadline;std::size_t received{},sent{};
    void live(){require(!cancelled && Clock::now()<deadline);}
    void progress(std::string_view s){if(cb.progress)cb.progress(s);}
    bool read(Bytes& bytes,std::size_t target,bool wait){
        require(target<=131104 && bytes.size()<=target);
        do {live();const auto before=bytes.size();const auto chunk=std::min<std::size_t>(target-before,4096);if(chunk==0)return true;
            bytes.resize(before+chunk);const auto r=channel.read(std::span(bytes).subspan(before),std::chrono::milliseconds{20});require(r.bytes<=chunk && !r.eof);
            bytes.resize(before+r.bytes);received+=r.bytes;require(received<=262144);
            if(bytes.size()==target)return true;
        }while(wait);return false;
    }
    void send(std::span<const std::byte> b){live();require(b.size()<=131104 && sent+b.size()<=262144);channel.write(b,deadline,cancelled);sent+=b.size();}
    Bytes lpp(){Bytes b;read(b,16,true);require(std::memcmp(b.data(),"LPP1",4)==0);std::size_t n{};for(auto x:std::span(b).subspan(8,4))n=(n<<8)|std::to_integer<unsigned>(x);
        require(n>=8 && n<=199);read(b,16+n,true);return b;}
    Bytes lpc(){Bytes b;read(b,135,true);require(std::memcmp(b.data(),"LPC1",4)==0);const auto n=(std::to_integer<unsigned>(b[133])<<8)|std::to_integer<unsigned>(b[134]);
        require(n>=8 && n<=72);read(b,135+n,true);return b;}
};
void number(Bytes& b,std::size_t n){for(int shift=24;shift>=0;shift-=8)b.push_back(static_cast<std::byte>(n>>shift));}
Bytes bundle_wire(const PublicIdentityBundle& b){Bytes out{std::byte{'L'},std::byte{'P'},std::byte{'B'},std::byte{'1'}};std::size_t total{};
    for(const auto* o:{&b.root,&b.server,&b.client,&b.crl,&b.server_ocsp,&b.client_ocsp}){require(!o->empty() && o->size()<=65536);total+=o->size();}require(total<=131072);
    number(out,total+24);for(const auto* o:{&b.root,&b.server,&b.client,&b.crl,&b.server_ocsp,&b.client_ocsp}){number(out,o->size());out.insert(out.end(),o->begin(),o->end());}return out;
}
PublicIdentityBundle bundle_read(Exchange& io){Bytes b;io.read(b,8,true);require(std::memcmp(b.data(),"LPB1",4)==0);std::size_t size{};
    for(auto x:std::span(b).subspan(4,4))size=(size<<8)|std::to_integer<unsigned>(x);
    require(size>24 && size<=131096);io.read(b,8+size,true);
    PublicIdentityBundle out;std::size_t at=8,total{};for(auto* o:{&out.root,&out.server,&out.client,&out.crl,&out.server_ocsp,&out.client_ocsp}){
        require(b.size()-at>=4);std::size_t n{};for(unsigned i=0;i<4;++i)n=(n<<8)|std::to_integer<unsigned>(b[at++]);
        require(n>0 && n<=65536 && n<=b.size()-at);total+=n;require(total<=131072);o->assign(b.begin()+static_cast<std::ptrdiff_t>(at),b.begin()+static_cast<std::ptrdiff_t>(at+n));at+=n;
    }require(at==b.size());return out;
}
std::unique_ptr<ApprovedPairing> compare(PairingSession& session,Exchange& io){
    io.progress("Exchanging public pairing identities…");
    io.send(session.send_hello(Clock::now()));
    io.progress("Waiting for the other computer's public identity…");
    session.receive(io.lpp(),Clock::now());
    io.send(session.send_proof(Clock::now()));session.receive(io.lpp(),Clock::now());
    auto model=session.shared_consent_for_local_ui(Clock::now());require(static_cast<bool>(io.cb.show_comparison));
    struct Cancel{std::shared_ptr<PairingConsent> m;~Cancel(){if(m)m->cancel(Clock::now());}} guard{model};
    io.progress("Compare the pairing information on both computers.");io.cb.show_comparison(model);
    bool sent{},received{};Bytes input;std::size_t target=16;
    while(!sent || !received){io.live();const auto state=model->state(Clock::now());
        require(state==PairingConsent::State::awaiting_both || state==PairingConsent::State::awaiting_local || state==PairingConsent::State::awaiting_peer || state==PairingConsent::State::ready_to_persist);
        if(!sent && (state==PairingConsent::State::awaiting_peer || state==PairingConsent::State::ready_to_persist)){
            io.send(session.send_local_approval(Clock::now()));sent=true;
        }
        if(!received && io.read(input,target,false)){
            if(target==16){require(std::memcmp(input.data(),"LPP1",4)==0);std::size_t n{};for(auto x:std::span(input).subspan(8,4))n=(n<<8)|std::to_integer<unsigned>(x);
                require(n>=8 && n<=72);target=16+n;
            }else{session.receive(input,Clock::now());received=true;}
        }
        if(received && !sent){std::array<std::byte,1> extra{};const auto r=io.channel.read(extra,std::chrono::milliseconds{20});require(!r.eof && r.bytes==0);}
    }
    // Both local click and the peer's verified signed approval have arrived.
    guard.m.reset();return session.take_approved(Clock::now());
}
Serial serial(const EnrollmentSetupCallbacks& cb){Serial s{};cb.random(s);require(std::any_of(s.begin(),s.end(),[](auto b){return b!=std::byte{};}));return s;}
struct LocalKeys {std::unique_ptr<Signer> authority,identity;std::vector<KeyReference> refs;};
LocalKeys local(EnrollmentStager& stage,KeyStore& keys,PairRole role,const EnrollmentSetupCallbacks& cb,bool& started){
    require(static_cast<bool>(cb.random));std::array<std::byte,32> id{};cb.random(id);LocalKeys out;
    if(role==PairRole::host){KeyReference ref{KeyPurpose::authority,{}};cb.random(ref.id);out.refs.push_back(ref);}
    KeyReference ref{role==PairRole::host?KeyPurpose::server:KeyPurpose::client,{}};cb.random(ref.id);out.refs.push_back(ref);
    stage.begin(id,role,out.refs);started=true;stage.ensure_keys();out.identity=keys.open(out.refs.back());require(out.identity!=nullptr);
    if(role==PairRole::host){out.authority=keys.open(out.refs.front());require(out.authority!=nullptr);}return out;
}
struct Attempt {
    EnrollmentChannel& channel;EnrollmentStager& stage;bool started{},prepared{},success{};
    ~Attempt(){channel.close();if(started && !prepared && !success)try{stage.rollback();}catch(...){}}
};
Bytes recovery_header(unsigned kind,PairRole role){
    return {std::byte{'L'},std::byte{'P'},std::byte{'R'},std::byte{'1'},
        static_cast<std::byte>(kind),static_cast<std::byte>(role),std::byte{},std::byte{}};
}
bool nonzero(std::span<const std::byte> bytes){return std::any_of(bytes.begin(),bytes.end(),[](auto b){return b!=std::byte{};});}
void append(Bytes& out,std::span<const std::byte> b){out.insert(out.end(),b.begin(),b.end());}
Bytes recovery_message(const Bytes& host,const Bytes& client,PairRole signer){
    constexpr std::string_view domain="LanPilot pairing recovery v1";
    Bytes result;append(result,std::as_bytes(std::span{domain}));result.push_back(std::byte{});
    append(result,host);append(result,client);result.push_back(static_cast<std::byte>(signer));return result;
}
Bytes abort_reply(const EnrollmentCommitRecord& r){
    auto reply=recovery_header(4,PairRole::host);reply[2]=std::byte{'A'};append(reply,r.round);append(reply,std::as_bytes(std::span{r.transcript.binding}));
    const auto& receipt=r.receipts[5];require(receipt.size()>=143 && receipt.size()<=commit_receipt_cap);
    reply.push_back(static_cast<std::byte>(receipt.size()>>8));reply.push_back(static_cast<std::byte>(receipt.size()));append(reply,receipt);return reply;
}
struct RecoveryHandshake{std::optional<Bytes> received_abort;bool served_history{};};
RecoveryHandshake authenticate_recovery(Exchange& io,FileEnrollmentJournal& file,const EnrollmentCommitRecord& r,Signer* signer,const PairProofVerifier& verifier){
    require(static_cast<bool>(io.cb.random));const auto role=r.staged.role;
    const auto peer=role==PairRole::host?PairRole::client:PairRole::host;
    auto hello=recovery_header(1,role);append(hello,r.round);append(hello,std::as_bytes(std::span{r.transcript.binding}));
    std::array<std::byte,32> nonce{};io.cb.random(nonce);require(nonzero(nonce));append(hello,nonce);
    if(role==PairRole::client)io.send(hello);
    Bytes other;io.read(other,104,true);
    if(role==PairRole::host){
        const auto prefix=recovery_header(1,PairRole::client);require(std::equal(prefix.begin(),prefix.end(),other.begin()) && nonzero(std::span(other).subspan(72,32)));
        std::array<std::byte,32> requested{};std::copy_n(other.begin()+8,32,requested.begin());
        if(requested!=r.round){
            const auto old=DurablePairing::archived_abort(file,requested,verifier);
            require(old && old->staged.role==PairRole::host && std::ranges::equal(std::as_bytes(std::span{old->transcript.binding}),std::span(other).subspan(40,32)));
            io.send(abort_reply(*old));return {{},true};
        }
        io.send(hello);
    }
    if(std::memcmp(other.data(),"LPA1",4)==0){
        require(role==PairRole::client);auto prefix=recovery_header(4,PairRole::host);prefix[2]=std::byte{'A'};
        require(std::equal(prefix.begin(),prefix.end(),other.begin()) && std::equal(r.round.begin(),r.round.end(),other.begin()+8) &&
            std::ranges::equal(std::as_bytes(std::span{r.transcript.binding}),std::span(other).subspan(40,32)));
        const auto n=(std::to_integer<unsigned>(other[72])<<8)|std::to_integer<unsigned>(other[73]);require(n>=143 && n<=commit_receipt_cap);
        io.read(other,74+n,true);return {Bytes(other.begin()+74,other.end()),false};
    }
    const auto expected=recovery_header(1,peer);
    require(std::equal(expected.begin(),expected.end(),other.begin()) &&
        std::equal(r.round.begin(),r.round.end(),other.begin()+8) &&
        std::ranges::equal(std::as_bytes(std::span{r.transcript.binding}),std::span(other).subspan(40,32)) &&
        nonzero(std::span(other).subspan(72,32)) && !std::ranges::equal(nonce,std::span(other).subspan(72,32)));
    const auto& host=role==PairRole::host?hello:other;const auto& client=role==PairRole::client?hello:other;
    require(signer!=nullptr);const auto signature=signer->sign_sha256(recovery_message(host,client,role));(void)pairing_signature_raw(signature);
    auto proof=recovery_header(2,role);proof.push_back(static_cast<std::byte>(signature.size()>>8));proof.push_back(static_cast<std::byte>(signature.size()));append(proof,signature);io.send(proof);
    Bytes received;io.read(received,10,true);const auto prefix=recovery_header(2,peer);
    require(std::equal(prefix.begin(),prefix.end(),received.begin()));
    const auto size=(std::to_integer<unsigned>(received[8])<<8)|std::to_integer<unsigned>(received[9]);require(size>=8 && size<=72);io.read(received,10+size,true);
    const auto peer_signature=std::span(received).subspan(10);(void)pairing_signature_raw(peer_signature);
    require(verifier.verify(peer==PairRole::host?r.transcript.host.identity_key:r.transcript.client.identity_key,
        recovery_message(host,client,peer),peer_signature));
    return {};
}
void exchange_receipts(Exchange& io,DurablePairing& pairing){
    const auto role=pairing.record().staged.role;const auto peer=role==PairRole::host?PairRole::client:PairRole::host;
    const auto outgoing=pairing.outgoing();require(!outgoing.empty() && outgoing.size()<=3);
    auto batch=recovery_header(3,role);batch.push_back(static_cast<std::byte>(outgoing.size()));
    for(const auto& receipt:outgoing){require(receipt.size()<=commit_receipt_cap);
        batch.push_back(static_cast<std::byte>(receipt.size()>>8));batch.push_back(static_cast<std::byte>(receipt.size()));append(batch,receipt);}
    io.send(batch);Bytes header;io.read(header,9,true);const auto expected=recovery_header(3,peer);
    require(std::equal(expected.begin(),expected.end(),header.begin()));const auto count=std::to_integer<unsigned>(header[8]);
    require(count>=1 && count<=(peer==PairRole::host?3U:2U));unsigned previous{};
    for(unsigned i=0;i<count;++i){Bytes receipt;io.read(receipt,2,true);const auto n=(std::to_integer<unsigned>(receipt[0])<<8)|std::to_integer<unsigned>(receipt[1]);
        require(n>=143 && n<=commit_receipt_cap);receipt.clear();io.read(receipt,n,true);
        const auto kind=std::to_integer<unsigned>(receipt[4]);require(kind>previous);previous=kind;
        pairing.receive(receipt);
    }
}
void repair_staging(FileEnrollmentJournal& file,EnrollmentStager& stage,const PairProofVerifier& verifier){
    // LPJ1 has not exposed PREPARED. LPJ2 must use authenticated replay instead;
    // it can never be cleared merely to make a fresh pairing succeed.
    require(!DurablePairing::inspect(file,verifier));if(file.load())require(stage.rollback());
}
}
EnrollmentConfigurationReceipt enroll_fresh_host(EnrollmentChannel& channel,FileEnrollmentJournal& file,KeyStore& keys,IdentityStore& identities,
    const PairProofVerifier& verifier,EnrollmentEndpoint endpoint,const EnrollmentSetupCallbacks& cb,const std::atomic_bool& cancelled,EnrollmentCertificateLifetimes lifetimes){
    using namespace std::chrono;
    Exchange io{channel,cb,cancelled,Clock::now()+seconds{120}};EnrollmentStager stage(file,keys,identities);Attempt attempt{channel,stage};
    repair_staging(file,stage,verifier);
    io.progress("Preparing this Mac's protected identity…");auto own=local(stage,keys,PairRole::host,cb,attempt.started);
    const auto wall=floor<seconds>(system_clock::now());const Validity issuer{wall-minutes{5},wall+lifetimes.root},leaf{wall-minutes{5},wall+lifetimes.leaf},status{wall-minutes{5},wall+hours{23}};
    PublicIdentityBundle bundle;bundle.root=root_certificate(*own.authority,serial(cb),issuer);
    PairHello h{};h.role=PairRole::host;cb.random(h.nonce);h.identity_key=own.identity->public_key();h.authority_key=own.authority->public_key();h.root_sha256=sha256(bundle.root);h.desktop_ipv4=endpoint.address;h.desktop_port=endpoint.port;
    PairingSession session(h,*own.identity,verifier,Clock::now());auto approval=compare(session,io);const auto& t=approval->transcript();
    const AlternativeName ip{Bytes(endpoint.address.begin(),endpoint.address.end()),{}};const auto server_id=serial(cb),client_id=serial(cb);
    bundle.server=leaf_certificate(*own.authority,server_id,h.identity_key,Role::server,leaf,issuer,std::span{&ip,1});
    bundle.client=leaf_certificate(*own.authority,client_id,t.client.identity_key,Role::client,leaf,issuer);
    bundle.crl=revocation_list(*own.authority,1,status,issuer,{});bundle.server_ocsp=ocsp_response(*own.authority,server_id,Status::good,wall,status,issuer);
    bundle.client_ocsp=ocsp_response(*own.authority,client_id,Status::good,wall,status,issuer);
    io.progress("Saving the approved identities…");stage.associate(*approval,bundle,Clock::now());
    io.send(bundle_wire(bundle));auto completion=DurablePairing::prepare(file,std::move(approval),*own.identity,identities,verifier,Clock::now());attempt.prepared=true;
    io.send(completion->outgoing().front());completion->receive(io.lpc());completion->decide_commit(Clock::now());io.send(completion->outgoing().back());
    completion->receive(io.lpc());io.send(completion->outgoing().back());auto proof=completion->persistable();require(proof.has_value());
    const auto result=EnrollmentConfigurationHandoff::persist(file,*proof,identities,verifier);attempt.success=true;
    io.progress("Paired settings saved. Desktop permissions and service activation remain separate.");return result;
}
EnrollmentConfigurationReceipt enroll_client(EnrollmentChannel& channel,FileEnrollmentJournal& file,KeyStore& keys,IdentityStore& identities,
    const PairProofVerifier& verifier,std::array<std::byte,4> expected_host,const EnrollmentSetupCallbacks& cb,const std::atomic_bool& cancelled){
    using namespace std::chrono;
    Exchange io{channel,cb,cancelled,Clock::now()+seconds{120}};EnrollmentStager stage(file,keys,identities);Attempt attempt{channel,stage};
    repair_staging(file,stage,verifier);
    io.progress("Preparing your protected Windows identity…");auto own=local(stage,keys,PairRole::client,cb,attempt.started);
    PairHello h{};h.role=PairRole::client;cb.random(h.nonce);h.identity_key=own.identity->public_key();PairingSession session(h,*own.identity,verifier,Clock::now());
    auto approval=compare(session,io);require(approval->transcript().host.desktop_ipv4==expected_host);
    auto bundle=bundle_read(io);stage.associate(*approval,bundle,Clock::now());
    const auto host_prepared=io.lpc();auto completion=DurablePairing::prepare(file,std::move(approval),*own.identity,identities,verifier,Clock::now(),host_prepared);attempt.prepared=true;
    io.send(completion->outgoing().front());completion->receive(io.lpc());io.send(completion->outgoing().back());completion->receive(io.lpc());
    auto proof=completion->persistable();require(proof.has_value());const auto result=EnrollmentConfigurationHandoff::persist(file,*proof,identities,verifier);attempt.success=true;
    io.progress("Paired connection saved. You can now connect using the saved profile.");return result;
}
std::optional<PersistablePairing> recover_enrollment(EnrollmentChannel& channel,FileEnrollmentJournal& file,KeyStore& keys,
    IdentityStore& identities,const PairProofVerifier& verifier,std::array<std::byte,4> expected_host,
    const EnrollmentSetupCallbacks& cb,const std::atomic_bool& cancelled,bool keep_after_abort){
    struct Close{EnrollmentChannel& c;bool keep{};~Close(){if(!keep)c.close();}} close{channel};
    Exchange io{channel,cb,cancelled,Clock::now()+std::chrono::seconds{30}};
    const auto saved=DurablePairing::inspect(file,verifier);require(saved && saved->transcript.host.desktop_ipv4==expected_host);
    auto signer=keys.open(saved->staged.keys.back().reference);if(signer)require(signer->public_key()==saved->staged.keys.back().point);
    io.progress("Verifying the exact saved pairing identities…");const auto handshake=authenticate_recovery(io,file,*saved,signer.get(),verifier);
    if(handshake.served_history)return {};
    if(handshake.received_abort){const auto& archived=*handshake.received_abort;
        // Only an irrevocable, exactly scoped HOST abort may arrive without a
        // fresh possession proof. It cannot publish config or resume a commit.
        require(archived.size()>4 && archived[4]==std::byte{6} && saved->receipts[2].empty());
        auto aborted=DurablePairing::resume(file,nullptr,identities,verifier);aborted->receive(archived);
        require(!aborted->record().receipts[5].empty() && !aborted->persistable());close.keep=keep_after_abort;return {};
    }
    auto pairing=DurablePairing::resume(file,signer.get(),identities,verifier);
    if(pairing->record().staged.role==PairRole::host && pairing->record().receipts[2].empty())pairing->decide_abort();
    // At most three dependent receipts need to propagate. A fixed fourth round
    // replays the final durable outcome; no timer, fresh consent or new commit.
    for(unsigned round=0;round<4;++round)exchange_receipts(io,*pairing);
    if(!pairing->record().receipts[5].empty()){
        io.progress("The interrupted pairing was safely cancelled. Existing settings were preserved.");close.keep=keep_after_abort;return {};
    }
    auto proof=pairing->persistable();require(proof.has_value());
    io.progress("The saved pairing decision has been recovered without changing identity.");return proof;
}
void prepare_enrollment_retry(FileEnrollmentJournal& file,KeyStore& keys,IdentityStore& identities,const PairProofVerifier& verifier,PairRole role){
    auto pending=DurablePairing::inspect(file,verifier);if(!pending)return;require(pending->staged.role==role);
    if(role==PairRole::host && pending->receipts[2].empty() && pending->receipts[5].empty()){
        auto key=keys.open(pending->staged.keys.back().reference);require(key && key->public_key()==pending->staged.keys.back().point);
        auto pairing=DurablePairing::resume(file,key.get(),identities,verifier);pairing->decide_abort();pending=pairing->record();
    }
    if(!pending->receipts[5].empty())DurablePairing::retire_abort(file,keys,identities,verifier);
}
EnrollmentConfigurationReceipt enroll_host(EnrollmentChannel& channel,FileEnrollmentJournal& file,KeyStore& keys,IdentityStore& identities,
    const PairProofVerifier& verifier,EnrollmentEndpoint endpoint,const EnrollmentSetupCallbacks& cb,const std::atomic_bool& cancelled,EnrollmentCertificateLifetimes lifetimes){
    require(lifetimes.root>=std::chrono::days{1} && lifetimes.root<=std::chrono::days{3650} && lifetimes.leaf>=std::chrono::days{1} && lifetimes.leaf<=std::chrono::days{180} && lifetimes.leaf<=lifetimes.root);
    // A late peer may still own PREPARED for a retired abort. Replay the public
    // negative proof, then require an entirely new LPP1/dual-consent attempt.
    // At most one historical outcome is served per explicit pairing window.
    struct Buffered final:EnrollmentChannel{
        EnrollmentChannel& c;Bytes prefix;std::size_t used{};
        Buffered(EnrollmentChannel& x,Bytes b):c(x),prefix(std::move(b)){}
        Read read(std::span<std::byte> out,std::chrono::milliseconds t)override{if(used<prefix.size()){const auto n=std::min(out.size(),prefix.size()-used);std::copy_n(prefix.begin()+static_cast<std::ptrdiff_t>(used),n,out.begin());used+=n;return {n,false};}return c.read(out,t);}
        void write(std::span<const std::byte> b,Clock::time_point t,const std::atomic_bool& stop)override{c.write(b,t,stop);}
        void close()noexcept override{c.close();}
    };
    Exchange io{channel,cb,cancelled,Clock::now()+std::chrono::seconds{120}};Bytes first;io.read(first,4,true);
    if(std::memcmp(first.data(),"LPR1",4)==0){
        io.read(first,104,true);const auto expected=recovery_header(1,PairRole::client);
        require(std::equal(expected.begin(),expected.end(),first.begin()) && nonzero(std::span(first).subspan(72,32)));
        std::array<std::byte,32> round{};std::copy_n(first.begin()+8,32,round.begin());
        const auto old=DurablePairing::archived_abort(file,round,verifier);
        require(old && old->staged.role==PairRole::host && old->transcript.host.desktop_ipv4==endpoint.address &&
            std::ranges::equal(std::as_bytes(std::span{old->transcript.binding}),std::span(first).subspan(40,32)));
        io.send(abort_reply(*old));
        first.clear();io.read(first,4,true);
    }
    require(std::memcmp(first.data(),"LPP1",4)==0);Buffered buffered(channel,std::move(first));
    return enroll_fresh_host(buffered,file,keys,identities,verifier,endpoint,cb,cancelled,lifetimes);
}
} // namespace rwn::core::enrollment
