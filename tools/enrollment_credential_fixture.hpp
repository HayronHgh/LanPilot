#pragma once
#include "rwn/core/enrollment_credentials.hpp"
#include "enrollment_status_fixture.hpp"

namespace rwn::fixture {
inline std::string credential_hex(const core::Sha256Digest& bytes){std::string out;for(auto b:bytes){const auto n=std::to_integer<unsigned>(b);out+="0123456789abcdef"[n>>4];out+="0123456789abcdef"[n&15];}return out;}
inline core::enrollment::Bytes credential_wire(const core::enrollment::EnrollmentCommitRecord& origin,
    core::enrollment::PublicIdentityBundle b,core::enrollment::Signer& issuer,core::enrollment::Time issued,core::enrollment::Time expires){
    namespace e=core::enrollment;
    auto add=[](e::Bytes& out,std::span<const std::byte> data){out.insert(out.end(),data.begin(),data.end());};
    auto number=[](e::Bytes& out,std::uint64_t n,unsigned width){for(unsigned i=width;i>0;--i)out.push_back(static_cast<std::byte>(n>>((i-1)*8)));};
    e::Bytes body{std::byte{2},std::byte{},std::byte{},std::byte{}};const auto request=e::status_request(origin);add(body,std::span(request).subspan(4));
    number(body,static_cast<std::uint64_t>(issued.time_since_epoch().count()),8);number(body,static_cast<std::uint64_t>(expires.time_since_epoch().count()),8);
    const std::array parts{&b.root,&b.server,&b.client,&b.crl,&b.server_ocsp,&b.client_ocsp};for(const auto* p:parts)add(body,core::sha256(*p));for(const auto* p:parts)number(body,p->size(),4);
    constexpr std::string_view domain="LanPilot native revocation refresh v2";e::Bytes message;add(message,std::as_bytes(std::span{domain}));message.push_back(std::byte{});add(message,body);
    const auto signature=issuer.sign_sha256(message);number(body,signature.size(),2);add(body,signature);for(const auto* p:parts)add(body,*p);
    e::Bytes wire{std::byte{'L'},std::byte{'P'},std::byte{'S'},std::byte{'2'}};number(wire,body.size(),4);add(wire,body);return wire;
}
struct NoNewCredentialKeys final:core::enrollment::KeyStore {
    core::enrollment::KeyStore& native;unsigned creates{};
    explicit NoNewCredentialKeys(core::enrollment::KeyStore& n):native(n){}
    std::unique_ptr<core::enrollment::Signer> create_new(const core::enrollment::KeyReference&)override{++creates;throw std::runtime_error("renewal attempted to replace a key");}
    std::unique_ptr<core::enrollment::Signer> open(const core::enrollment::KeyReference& r)override{return native.open(r);}
    bool remove_if_matches(const core::enrollment::KeyReference&,const core::enrollment::PublicKey&)override{throw std::runtime_error("renewal attempted to delete a key");}
};
struct InterruptedCredentialStore final:core::enrollment::IdentityStore {
    core::enrollment::IdentityStore& native;bool after;
    InterruptedCredentialStore(core::enrollment::IdentityStore& n,bool a):native(n),after(a){}
    core::enrollment::AssociatedIdentity associate(const core::enrollment::ApprovedPairing& a,const core::enrollment::KeyReference& r,core::enrollment::PublicIdentityBundle b,core::PairingConsent::Clock::time_point t)override{return native.associate(a,r,std::move(b),t);}
    core::enrollment::AssociatedIdentity associate_renewed(const core::enrollment::RenewedIdentity& p,const core::enrollment::KeyReference& r)override{
        if(after)(void)native.associate_renewed(p,r);
        throw std::runtime_error("fixture interrupted native certificate association");}
    bool ready(const core::enrollment::AssociatedIdentity& r)override{return native.ready(r);}
    auto describe(const core::enrollment::KeyReference& r,core::enrollment::Bytes b,std::array<std::byte,4> ip)->core::enrollment::Bytes override{return native.describe(r,std::move(b),ip);}
    auto locate(const core::enrollment::KeyReference& r,core::enrollment::Bytes b,std::array<std::byte,4> ip)->std::optional<core::enrollment::AssociatedIdentity> override{return native.locate(r,std::move(b),ip);}
    bool certificate_absent(std::span<const std::byte> b)override{return native.certificate_absent(b);}
    bool remove_created(const core::enrollment::AssociatedIdentity& r)override{return native.remove_created(r);}
    bool verify_revocation(const core::enrollment::PublicIdentityBundle& b,std::array<std::byte,4> ip,core::enrollment::Time t={})override{return native.verify_revocation(b,ip,t);}
};
template<class Count,class Random>
void credential_fixture(core::enrollment::FileEnrollmentJournal& host,core::enrollment::FileEnrollmentJournal& client,
    core::enrollment::KeyStore& native_keys,core::enrollment::IdentityStore& ids,const core::enrollment::PairProofVerifier& verifier,
    const std::filesystem::path& host_root,const std::filesystem::path& client_root,
    const core::enrollment::AssociatedIdentity& original_host,const core::enrollment::AssociatedIdentity& original_client,Count count,Random random){
    namespace e=core::enrollment;using namespace std::chrono;
    auto check=[](bool good,const std::source_location at=std::source_location::current()){if(!good)throw std::runtime_error("credential fixture check "+std::to_string(at.line()));};
    auto reject=[](auto f,const std::source_location at=std::source_location::current()){bool no=false;try{f();}catch(...){no=true;}if(!no)throw std::runtime_error("credential fixture unexpected acceptance "+std::to_string(at.line()));};
    NoNewCredentialKeys keys(native_keys);const auto now=floor<seconds>(system_clock::now());
    const auto h=*e::DurablePairing::inspect(host,verifier),c=*e::DurablePairing::inspect(client,verifier);
    const auto hbytes=e::encode_enrollment_commit(h),cbytes=e::encode_enrollment_commit(c);
    const auto first=e::EnrollmentStatus::issue(host,keys,ids,verifier,now);(void)e::EnrollmentStatus::accept(client,ids,verifier,first.wire,now);
    check(!e::CredentialInstaller::install(host,keys,ids,verifier,now).created && !e::CredentialInstaller::install(client,keys,ids,verifier,now).created && count()==2);
    // Correctly signed short-lived credentials exercise TWO native certificate
    // generations at actual time,without changing clocks or trust policy.
    auto issuer=keys.open(h.staged.keys.front().reference);auto short_bundle=h.staged.bundle;
    const e::Validity root_window{e::certificate_facts(short_bundle.root,e::KeyPurpose::authority).validity.before,now+days{31}};
    const e::Validity leaf_window{e::certificate_facts(short_bundle.client,e::KeyPurpose::client).validity.before,now+days{8}};
    auto root_id=e::certificate_facts(short_bundle.root,e::KeyPurpose::authority).serial;root_id[0]^=std::byte{1};
    auto server_id=e::certificate_facts(short_bundle.server,e::KeyPurpose::server,h.transcript.host.desktop_ipv4).serial;server_id[0]^=std::byte{1};
    auto client_id=e::certificate_facts(short_bundle.client,e::KeyPurpose::client).serial;client_id[0]^=std::byte{1};
    short_bundle.root=e::root_certificate(*issuer,root_id,root_window);const e::AlternativeName address{e::Bytes(h.transcript.host.desktop_ipv4.begin(),h.transcript.host.desktop_ipv4.end()),{}};
    short_bundle.server=e::leaf_certificate(*issuer,server_id,h.transcript.host.identity_key,e::Role::server,leaf_window,root_window,std::span{&address,1});
    short_bundle.client=e::leaf_certificate(*issuer,client_id,h.transcript.client.identity_key,e::Role::client,leaf_window,root_window);
    const auto issued=std::max(first.issued+seconds{1},now-seconds{20});const e::Validity status{leaf_window.before,now+hours{23}};
    short_bundle.crl=e::revocation_list(*issuer,2,status,root_window,{});
    short_bundle.server_ocsp=e::ocsp_response(*issuer,server_id,e::Status::good,issued,status,root_window);
    short_bundle.client_ocsp=e::ocsp_response(*issuer,client_id,e::Status::good,issued,status,root_window);
    const auto short_wire=credential_wire(h,short_bundle,*issuer,issued,status.after);
    auto wrong_key=short_bundle;wrong_key.client=e::leaf_certificate(*issuer,client_id,h.transcript.host.identity_key,e::Role::client,leaf_window,root_window);
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,credential_wire(h,wrong_key,*issuer,issued,status.after),now);});
    (void)e::EnrollmentStatus::accept(host,ids,verifier,short_wire,now);(void)e::EnrollmentStatus::accept(client,ids,verifier,short_wire,now);
    auto hs=e::CredentialInstaller::install(host,keys,ids,verifier,now),cs=e::CredentialInstaller::install(client,keys,ids,verifier,now);check(count()==4 && hs.created && cs.created);
    // Archive/clear interruption while the same target is retried transfers
    // ownership back; it must not delete the newly selected certificate.
    std::filesystem::rename(host_root/"credential.current",host_root/"credential.retired");
    check(e::CredentialInstaller::install(host,keys,ids,verifier,now).native_reference==hs.native_reference && ids.ready(hs) && count()==4 && !std::filesystem::exists(host_root/"credential.retired"));
    const auto renewed=e::EnrollmentStatus::issue(host,keys,ids,verifier,now,true);(void)e::EnrollmentStatus::accept(client,ids,verifier,renewed.wire,now);
    check(renewed.bundle.root!=short_bundle.root && renewed.bundle.server!=short_bundle.server && renewed.bundle.client!=short_bundle.client);
    InterruptedCredentialStore before(ids,false);reject([&]{e::CredentialInstaller::install(host,keys,before,verifier,now);});check(ids.ready(hs) && count()==4);
    hs=e::CredentialInstaller::install(host,keys,ids,verifier,now);check(count()==4);
    InterruptedCredentialStore lost(ids,true);reject([&]{e::CredentialInstaller::install(client,keys,lost,verifier,now);});check(count()==5 && ids.ready(cs));
    cs=e::CredentialInstaller::install(client,keys,ids,verifier,now);check(count()==4 && !std::filesystem::exists(client_root/"credential.retired"));
    check(ids.remove_created(original_host) && ids.remove_created(original_client) && count()==2);
    // A decided pairing must remain replayable after its original certificate
    // was replaced. Saving bootstrap settings is not current TLS admission.
    {
        auto hp=e::DurablePairing::resume(host,nullptr,ids,verifier),cp=e::DurablePairing::resume(client,nullptr,ids,verifier);
        check(hp->persistable()->descriptor_only() && cp->persistable()->descriptor_only());
        check(e::encode_enrollment_commit(hp->record())==hbytes && e::encode_enrollment_commit(cp->record())==cbytes);
        auto denied=e::DurablePairing::resume(client,nullptr,before,verifier);reject([&]{denied->persistable();});
    }
    // Replay-only recovery must not manufacture a new decision from PREPARED.
    auto prepared=h;for(unsigned i=2;i<5;++i)prepared.receipts[i].clear();status_write(host_root/"enrollment.pending",e::encode_enrollment_commit(prepared));
    auto host_signer=keys.open(h.staged.keys.back().reference),client_signer=keys.open(c.staged.keys.back().reference);
    {auto pending=e::DurablePairing::resume(host,host_signer.get(),ids,verifier);
        check(!pending->persistable());reject([&]{pending->decide_commit(e::PairingSession::Clock::now());});check(pending->record().receipts[2].empty());}
    status_write(host_root/"enrollment.pending",hbytes);
    // Both sides crash after COMMIT_DECISION, before CLIENT_COMMITTED. Real
    // sockets and fresh key proofs must drain the same old decision, without
    // certificate re-import, a new key, or another comparison/approval dialog.
    auto pending_host=h,pending_client=c;for(unsigned i=3;i<5;++i){pending_host.receipts[i].clear();pending_client.receipts[i].clear();}
    const auto pending_h=e::encode_enrollment_commit(pending_host),pending_c=e::encode_enrollment_commit(pending_client);
    status_write(host_root/"enrollment.pending",pending_h);status_write(client_root/"enrollment.pending",pending_c);
    reject([&]{e::DurablePairing::resume(client,nullptr,ids,verifier);});
    reject([&]{e::DurablePairing::resume(client,client_signer.get(),before,verifier);});
    check(status_bytes(client_root/"enrollment.pending")==pending_c);
    auto recovered=recover_pair(host,client,keys,ids,verifier,h.transcript.host.desktop_ipv4,random);
    if(recovered.host_error)std::rethrow_exception(recovered.host_error);
    if(recovered.client_error)std::rethrow_exception(recovered.client_error);
    check(recovered.host && recovered.client && recovered.host->descriptor_only() && recovered.client->descriptor_only() && count()==2);
    check(recovered.host->record().receipts[2]==h.receipts[2] && recovered.client->record().receipts[2]==c.receipts[2] &&
          recovered.host->record().receipts[4]==recovered.client->record().receipts[4]);
    const auto recovered_h=status_bytes(host_root/"enrollment.pending"),recovered_c=status_bytes(client_root/"enrollment.pending");
    auto replay=recover_pair(host,client,keys,ids,verifier,h.transcript.host.desktop_ipv4,random,false,recovered.client_proof);
    check(replay.host_error && replay.client_error && status_bytes(host_root/"enrollment.pending")==recovered_h && status_bytes(client_root/"enrollment.pending")==recovered_c);
    status_write(host_root/"enrollment.pending",hbytes);status_write(client_root/"enrollment.pending",cbytes);
    // Neither a stored nor a time-valid original leaf is needed. The existing
    // private key and immutable signed pairing are the continuity authority.
    check(ids.describe(c.staged.keys.back().reference,c.staged.bundle.client,c.transcript.host.desktop_ipv4)==original_client.native_reference);
    unsigned fetches{};const auto selected=e::EnrollmentStatus::connection_credentials(client,keys,ids,verifier,c.staged.bundle.root,core::sha256(c.staged.bundle.server),original_client.native_reference,now,[&]{++fetches;return renewed.wire;});
    check(fetches==1 && selected.bundle.client==renewed.bundle.client && e::CredentialInstaller::install(client,keys,ids,verifier,now).native_reference==cs.native_reference && count()==2);
    const auto expired_counter=expired_status(h,keys,now);
    status_write(host_root/"revocation.current",expired_counter.wire);status_write(client_root/"revocation.current",expired_counter.wire);
#if defined(_WIN32)
    const auto profile_path=client_root/"connections"/"default.json";const auto profile=status_bytes(profile_path);
    check(e::EnrollmentConfigurationHandoff::recover(client,keys,ids,verifier).has_value());std::filesystem::remove(profile_path);
    reject([&]{e::EnrollmentConfigurationHandoff::recover(client,keys,before,verifier);});check(!std::filesystem::exists(profile_path));
    check(e::EnrollmentConfigurationHandoff::recover(client,keys,ids,verifier)->created && status_bytes(profile_path)==profile);
#else
    const auto profile_path=host_root/"service.conf";const auto profile=status_bytes(profile_path);
    check(e::EnrollmentConfigurationHandoff::recover(host,keys,ids,verifier).has_value());std::filesystem::remove(profile_path);
    reject([&]{e::EnrollmentConfigurationHandoff::recover(host,keys,before,verifier);});check(!std::filesystem::exists(profile_path));
    check(e::EnrollmentConfigurationHandoff::recover(host,keys,ids,verifier)->created && status_bytes(profile_path)==profile);
#endif
    status_write(host_root/"revocation.current",renewed.wire);status_write(client_root/"revocation.current",renewed.wire);
    auto damaged=renewed.wire;damaged.at(damaged.size()-1)^=std::byte{1};reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,damaged,now);});
    reject([&]{e::EnrollmentStatus::accept(client,ids,verifier,short_wire,now);});
    const auto proof=e::EnrollmentStatus::identity_proof(client,ids,verifier,now);reject([&]{ids.associate_renewed(proof,h.staged.keys.back().reference);});
    const auto current_path=client_root/"credential.current";const auto saved=status_bytes(current_path);auto bad=e::decode_enrollment_record(saved);bad.keys.back().existed=false;status_write(current_path,e::encode_enrollment_record(bad));
    reject([&]{e::CredentialInstaller::install(client,keys,ids,verifier,now);});status_write(current_path,saved);
    std::filesystem::create_hard_link(current_path,client_root/"alias.fixture");reject([&]{e::CredentialInstaller::install(client,keys,ids,verifier,now);});std::filesystem::remove(client_root/"alias.fixture");
    check(e::encode_enrollment_commit(*e::DurablePairing::inspect(host,verifier))==hbytes && e::encode_enrollment_commit(*e::DurablePairing::inspect(client,verifier))==cbytes);
    check(keys.creates==0 && ids.ready(hs) && ids.ready(cs));hs.created=true;cs.created=true;
    check(ids.remove_created(hs) && ids.remove_created(cs) && count()==0);
    std::cout<<"enrollment_native_credentials=PASS generations=2 old_leaf_absent=1 decided_recovery_without_old_certificate=1 new_commit_without_approval_rejected=1 missing_key_proof_rejected=1 unchanged_private_keys=1 immutable_pairing=1 native_positive=1 lost_add_receipt_recovered=1 archive_interruption_recovered=1 retired_certificates_removed=1 key_replacement_blocked=1 stale_replay_rejected=1 tamper_rejected=1 linked_journal_rejected=1 installed_changes=0\n";
}
}
