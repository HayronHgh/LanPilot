#include "rwn/core/enrollment_commit.hpp"
#include <algorithm>
#include <cstring>
#include <limits>

namespace rwn::core::enrollment {
namespace {
void require(bool v){if(!v)throw std::runtime_error("invalid durable pairing completion");}
void append(Bytes& out,std::span<const std::byte> bytes){out.insert(out.end(),bytes.begin(),bytes.end());}
void number(Bytes& out,std::uint64_t n,unsigned width){for(unsigned i=width;i>0;--i)out.push_back(static_cast<std::byte>(n>>((i-1)*8)));}
bool nonzero(std::span<const std::byte> b){return std::any_of(b.begin(),b.end(),[](auto x){return x!=std::byte{};});}
struct Reader {
    std::span<const std::byte> bytes;std::size_t at{};
    std::span<const std::byte> take(std::size_t n){require(n<=bytes.size()-at);auto b=bytes.subspan(at,n);at+=n;return b;}
    std::uint64_t number(unsigned width){std::uint64_t n{};for(auto x:take(width))n=(n<<8)|std::to_integer<unsigned>(x);return n;}
    template<class T>void array(T& t){auto b=take(t.size());std::memcpy(t.data(),b.data(),b.size());}
};
Bytes hello(const PairHello& h){Bytes b;number(b,static_cast<unsigned>(h.role),1);append(b,h.nonce);append(b,h.identity_key);append(b,h.authority_key);
    append(b,h.root_sha256);append(b,h.desktop_ipv4);number(b,h.desktop_port,2);return b;}
PairHello hello(Reader& in){PairHello h{};h.role=static_cast<PairRole>(in.number(1));in.array(h.nonce);in.array(h.identity_key);
    in.array(h.authority_key);in.array(h.root_sha256);in.array(h.desktop_ipv4);h.desktop_port=static_cast<std::uint16_t>(in.number(2));return h;}
Sha256Digest bundle_hash(const PublicIdentityBundle& b){Bytes bytes;for(const auto* object:{&b.root,&b.server,&b.client,&b.crl,&b.server_ocsp,&b.client_ocsp}){
    require(!object->empty() && object->size()<=65536);number(bytes,object->size(),4);append(bytes,*object);}return sha256(bytes);}
bool host_receipt(std::size_t index){return index==0 || index==2 || index==4 || index==5;}
Sha256Digest parent(const EnrollmentCommitRecord& r,std::size_t index){
    if(index==0)return {};
    const auto previous=index==5?0:index-1;require(!r.receipts[previous].empty());return sha256(r.receipts[previous]);
}
Bytes receipt_message(std::span<const std::byte> header){
    constexpr std::string_view domain="LanPilot durable pairing receipt v1";
    Bytes b(std::as_bytes(std::span{domain}).begin(),std::as_bytes(std::span{domain}).end());b.push_back(std::byte{});append(b,header);return b;
}
Bytes receipt_header(const EnrollmentCommitRecord& r,std::size_t index){
    Bytes b{std::byte{'L'},std::byte{'P'},std::byte{'C'},std::byte{'1'},static_cast<std::byte>(index+1)};
    append(b,r.round);append(b,std::as_bytes(std::span{r.transcript.binding}));append(b,bundle_hash(r.staged.bundle));append(b,parent(r,index));return b;
}
Bytes sign(const EnrollmentCommitRecord& r,std::size_t index,Signer& signer,const PairProofVerifier& verifier){
    auto b=receipt_header(r,index);const auto& point=host_receipt(index)?r.transcript.host.identity_key:r.transcript.client.identity_key;
    require(signer.public_key()==point);const auto message=receipt_message(b),signature=signer.sign_sha256(message);(void)pairing_signature_raw(signature);
    require(verifier.verify(point,message,signature));number(b,signature.size(),2);append(b,signature);require(b.size()<=commit_receipt_cap);return b;
}
std::size_t receipt_index(std::span<const std::byte> bytes){
    require(bytes.size()>=143 && bytes.size()<=commit_receipt_cap && std::memcmp(bytes.data(),"LPC1",4)==0);
    const auto kind=std::to_integer<unsigned>(bytes[4]);require(kind>=1 && kind<=6);return kind-1;
}
void verify(const EnrollmentCommitRecord& r,std::size_t index,std::span<const std::byte> b,const PairProofVerifier& verifier){
    require(receipt_index(b)==index);const auto expected=receipt_header(r,index);require(expected.size()==133 && std::ranges::equal(expected,b.first(133)));
    const auto size=(std::to_integer<unsigned>(b[133])<<8)|std::to_integer<unsigned>(b[134]);require(size>=8 && size<=72 && b.size()==135+size);
    const auto signature=b.subspan(135);(void)pairing_signature_raw(signature);
    require(verifier.verify(host_receipt(index)?r.transcript.host.identity_key:r.transcript.client.identity_key,receipt_message(b.first(133)),signature));
}
void validate(const EnrollmentCommitRecord& r){
    require(r.revision>0 && r.revision<std::numeric_limits<std::uint64_t>::max());(void)encode_enrollment_record(r.staged);
    require(r.staged.phase==EnrollmentPhase::staged && nonzero(r.round));
    const auto& h=r.transcript.host;const auto& c=r.transcript.client;
    require(h.role==PairRole::host && c.role==PairRole::client && nonzero(h.nonce) && nonzero(c.nonce) && h.nonce!=c.nonce && h.identity_key!=c.identity_key);
    require(!nonzero(c.authority_key) && !nonzero(c.root_sha256) && !nonzero(c.desktop_ipv4) && c.desktop_port==0);
    const auto a=std::to_integer<unsigned>(h.desktop_ipv4[0]),b=std::to_integer<unsigned>(h.desktop_ipv4[1]);
    require(h.desktop_port>=1024 && (a==10 || a==127 || (a==172 && b>=16 && b<=31) || (a==192 && b==168)));
    require(h.root_sha256==sha256(r.staged.bundle.root) && r.staged.server_ipv4==h.desktop_ipv4 && r.staged.approval_binding==r.transcript.binding);
    constexpr std::string_view domain="LanPilot first-contact transcript v1";
    Bytes transcript(std::as_bytes(std::span{domain}).begin(),std::as_bytes(std::span{domain}).end());transcript.push_back(std::byte{});append(transcript,hello(h));append(transcript,hello(c));
    require(std::ranges::equal(sha256(transcript),std::as_bytes(std::span{r.transcript.binding})));
    const bool host=r.staged.role==PairRole::host;
    require(r.staged.keys.back().point==(host?h.identity_key:c.identity_key));if(host)require(r.staged.keys.front().point==h.authority_key && r.round==r.staged.transaction);
    require(!r.receipts[0].empty());if(!host)require(!r.receipts[1].empty());
    for(std::size_t i=0;i<r.receipts.size();++i){require(r.receipts[i].size()<=commit_receipt_cap);if(i>0 && i<5 && !r.receipts[i].empty())require(!r.receipts[i-1].empty());}
    require(r.receipts[5].empty() || (r.receipts[2].empty() && r.receipts[3].empty() && r.receipts[4].empty()));
    require(!r.aborted_objects_removed || !r.receipts[5].empty());
}
}
Bytes encode_enrollment_commit(const EnrollmentCommitRecord& r){
    validate(r);auto stage=encode_enrollment_record(r.staged);Bytes b{std::byte{'L'},std::byte{'P'},std::byte{'J'},std::byte{2}};
    number(b,r.revision,8);number(b,stage.size(),4);append(b,stage);append(b,hello(r.transcript.host));append(b,hello(r.transcript.client));
    append(b,std::as_bytes(std::span{r.transcript.binding}));append(b,r.round);number(b,r.aborted_objects_removed?1:0,1);
    for(const auto& receipt:r.receipts){number(b,receipt.size(),2);append(b,receipt);}append(b,sha256(b));require(b.size()<=enrollment_storage_cap);return b;
}
EnrollmentCommitRecord decode_enrollment_commit(std::span<const std::byte> bytes,const PairProofVerifier& verifier){
    require(bytes.size()>700 && bytes.size()<=enrollment_storage_cap);const auto payload=bytes.first(bytes.size()-32);require(std::ranges::equal(sha256(payload),bytes.last(32)));
    Reader in{payload};require(in.number(4)==0x4c504a02);EnrollmentCommitRecord r;r.revision=in.number(8);const auto length=in.number(4);require(length<=enrollment_record_cap);
    r.staged=decode_enrollment_record(in.take(static_cast<std::size_t>(length)));r.transcript.host=hello(in);r.transcript.client=hello(in);in.array(r.transcript.binding);in.array(r.round);
    const auto cleaned=in.number(1);require(cleaned<=1);r.aborted_objects_removed=cleaned==1;
    for(auto& receipt:r.receipts){auto n=in.number(2);require(n<=commit_receipt_cap);auto b=in.take(static_cast<std::size_t>(n));receipt.assign(b.begin(),b.end());}
    require(in.at==payload.size());validate(r);for(std::size_t i=0;i<r.receipts.size();++i)if(!r.receipts[i].empty())verify(r,i,r.receipts[i],verifier);return r;
}
std::size_t CommitReceiptReader::consume(std::span<const std::byte> input){
    require(!failed_);std::size_t used{};try{while(used<input.size() && !ready()){
        const auto n=std::min(input.size()-used,target_-bytes_.size());append(bytes_,input.subspan(used,n));used+=n;
        if(bytes_.size()==135 && target_==135){require(std::memcmp(bytes_.data(),"LPC1",4)==0);const auto kind=std::to_integer<unsigned>(bytes_[4]);require(kind>=1 && kind<=6);
            const auto size=(std::to_integer<unsigned>(bytes_[133])<<8)|std::to_integer<unsigned>(bytes_[134]);require(size>=8 && size<=72);target_=135+size;}
    }return used;}catch(...){failed_=true;throw;}
}
Bytes CommitReceiptReader::take(){require(ready());auto b=bytes_;bytes_.clear();target_=135;return b;}
void CommitReceiptReader::eof(){if(failed_ || !bytes_.empty()){failed_=true;require(false);}}
DurablePairing::DurablePairing(FileEnrollmentJournal& f,Signer* s,IdentityStore& i,const PairProofVerifier& v):file_(f),signer_(s),identities_(i),verifier_(v){}
bool DurablePairing::require_local_identity(){
    const auto& s=record_.staged;const auto& k=s.keys.back();auto found=identities_.locate(k.reference,s.role==PairRole::host?s.bundle.server:s.bundle.client,s.server_ipv4);
    require(!found || found->subject_key==k.point);
    if(found && identities_.ready(*found))return false;
    // A resumed irrevocable decision is bound to the original device keys,
    // not the continued presence/validity of their old leaf certificates.
    // This proof only drains saved receipts or republishes bootstrap settings;
    // it cannot revive approval, decide a new commit or admit a TLS session.
    require(!approval_ && !record_.receipts[2].empty() && record_.receipts[5].empty() && identities_.key_ready(k.reference,k.point));
    return true;
}
void DurablePairing::save(EnrollmentCommitRecord next){
    require(last_bytes_==file_.read_record().value_or(Bytes{}));require(next.revision==record_.revision+1);
    for(std::size_t i=0;i<record_.receipts.size();++i)require(record_.receipts[i].empty() || record_.receipts[i]==next.receipts[i]);
    const auto bytes=encode_enrollment_commit(next);(void)decode_enrollment_commit(bytes,verifier_);file_.replace_record(bytes);record_=std::move(next);last_bytes_=bytes;
}
std::unique_ptr<DurablePairing> DurablePairing::prepare(FileEnrollmentJournal& file,std::unique_ptr<ApprovedPairing> approval,Signer& signer,
    IdentityStore& identities,const PairProofVerifier& verifier,Clock::time_point now,std::span<const std::byte> host_prepared){
    require(approval && approval->valid_at(std::max(now,Clock::now())));const auto original=file.read_record();
    require(original.has_value());auto stage=decode_enrollment_record(*original);require(stage.phase==EnrollmentPhase::staged);
    const auto& k=stage.keys.back();require(stage.role==approval->local_role() && stage.approval_binding==approval->transcript().binding && signer.public_key()==k.point);
    // Native current chain/revocation/private proof again, before durable prepare.
    const auto identity=identities.associate(*approval,k.reference,stage.bundle,now);require(!identity.created && identities.ready(identity));
    auto out=std::unique_ptr<DurablePairing>(new DurablePairing(file,&signer,identities,verifier));out->record_.staged=stage;out->record_.transcript=approval->transcript();
    out->record_.revision=1;const bool host=stage.role==PairRole::host;
    if(host){require(host_prepared.empty());out->record_.round=stage.transaction;out->record_.receipts[0]=sign(out->record_,0,signer,verifier);}
    else {require(receipt_index(host_prepared)==0);std::copy_n(host_prepared.begin()+5,32,out->record_.round.begin());
        out->record_.receipts[0]=Bytes(host_prepared.begin(),host_prepared.end());verify(out->record_,0,host_prepared,verifier);
        out->record_.receipts[1]=sign(out->record_,1,signer,verifier);}
    const auto bytes=encode_enrollment_commit(out->record_);(void)decode_enrollment_commit(bytes,verifier);
    require(approval->valid_at(std::max(now,Clock::now())) && file.read_record()==original);
    // Store LPJ2 before exposing ANY receipt. LPJ1 methods reject its version.
    file.replace_record(bytes);out->last_bytes_=bytes;out->approval_=std::move(approval);return out;
}
std::unique_ptr<DurablePairing> DurablePairing::resume(FileEnrollmentJournal& f,Signer* s,IdentityStore& i,const PairProofVerifier& v){
    auto out=std::unique_ptr<DurablePairing>(new DurablePairing(f,s,i,v));auto bytes=f.read_record();require(bytes.has_value());
    out->record_=decode_enrollment_commit(*bytes,v);out->last_bytes_=*bytes;out->advance();return out;
}
std::optional<EnrollmentCommitRecord> DurablePairing::inspect(FileEnrollmentJournal& f,const PairProofVerifier& v){
    const auto bytes=f.read_record();if(!bytes)return {};
    if(bytes->size()>=4 && std::memcmp(bytes->data(),"LPJ\1",4)==0){(void)decode_enrollment_record(*bytes);return {};}
    return decode_enrollment_commit(*bytes,v);
}
void DurablePairing::receive(std::span<const std::byte> bytes){
    const auto index=receipt_index(bytes);const bool host=record_.staged.role==PairRole::host;require(host?!host_receipt(index):host_receipt(index));
    verify(record_,index,bytes,verifier_);if(!record_.receipts[index].empty()){require(std::ranges::equal(record_.receipts[index],bytes));advance();return;}
    // A client's delayed PREPARED may cross a durable abort. Keep replaying the
    // signed abort instead of making recovery depend on a clean new exchange.
    if(host && index==1 && !record_.receipts[5].empty())return;
    require(record_.receipts[5].empty() && (index!=5 || record_.receipts[2].empty()));
    auto next=record_;++next.revision;next.receipts[index]=Bytes(bytes.begin(),bytes.end());save(std::move(next));advance();
}
void DurablePairing::decide_commit(Clock::time_point now){
    require(record_.staged.role==PairRole::host && approval_ && approval_->valid_at(std::max(now,Clock::now())) && signer_ && record_.receipts[5].empty());
    if(!record_.receipts[2].empty())return;
    require(!record_.receipts[1].empty());require_local_identity();auto next=record_;++next.revision;next.receipts[2]=sign(next,2,*signer_,verifier_);
    require(approval_->valid_at(std::max(now,Clock::now())));save(std::move(next));
}
void DurablePairing::decide_abort(){
    require(record_.staged.role==PairRole::host && signer_ && record_.receipts[2].empty());if(!record_.receipts[5].empty())return;
    auto next=record_;++next.revision;next.receipts[5]=sign(next,5,*signer_,verifier_);save(std::move(next));
}
void DurablePairing::advance(){
    if(!record_.receipts[5].empty())return;
    const auto index=record_.staged.role==PairRole::host?4U:3U;
    if(record_.receipts[index-1].empty() || !record_.receipts[index].empty())return;
    require(signer_!=nullptr);require_local_identity();auto next=record_;++next.revision;next.receipts[index]=sign(next,index,*signer_,verifier_);save(std::move(next));
}
std::vector<Bytes> DurablePairing::outgoing()const{
    std::vector<Bytes> result;for(std::size_t i=0;i<record_.receipts.size();++i)if(host_receipt(i)==(record_.staged.role==PairRole::host) && !record_.receipts[i].empty())result.push_back(record_.receipts[i]);return result;
}
std::optional<PersistablePairing> DurablePairing::persistable(){
    if(record_.receipts[4].empty())return {};
    const auto descriptor_only=require_local_identity();const auto& s=record_.staged;const auto& k=s.keys.back();
    if(descriptor_only){const auto& cert=s.role==PairRole::host?s.bundle.server:s.bundle.client;
        AssociatedIdentity identity{k.reference,k.point,sha256(cert),s.server_ipv4,identities_.describe(k.reference,cert,s.server_ipv4),cert,false};
        return PersistablePairing(record_,std::move(identity),true);}
    auto identity=identities_.locate(k.reference,s.role==PairRole::host?s.bundle.server:s.bundle.client,s.server_ipv4);require(identity.has_value());return PersistablePairing(record_,std::move(*identity));
}
bool DurablePairing::cleanup_aborted(KeyStore& keys){
    require(!record_.receipts[5].empty() && record_.receipts[2].empty());if(record_.aborted_objects_removed)return true;
    if(!EnrollmentStager::rollback_objects(record_.staged,keys,identities_))return false;
    auto next=record_;++next.revision;next.aborted_objects_removed=true;save(std::move(next));return true;
}
void DurablePairing::retire_abort(FileEnrollmentJournal& file,KeyStore& keys,IdentityStore& identities,const PairProofVerifier& verifier){
    auto pairing=resume(file,nullptr,identities,verifier);
    require(!pairing->record_.receipts[5].empty() && pairing->record_.receipts[2].empty());
    require(pairing->cleanup_aborted(keys));const auto bytes=encode_enrollment_commit(pairing->record_);
    require(file.read_record()==std::optional<Bytes>{bytes});
    file.store_abort(pairing->record_.round,bytes);
    require(file.read_abort(pairing->record_.round)==std::optional<Bytes>{bytes} && file.read_record()==std::optional<Bytes>{bytes});
    file.remove_record();
}
std::optional<EnrollmentCommitRecord> DurablePairing::archived_abort(FileEnrollmentJournal& file,const std::array<std::byte,32>& round,const PairProofVerifier& verifier){
    const auto bytes=file.read_abort(round);if(!bytes)return {};
    auto r=decode_enrollment_commit(*bytes,verifier);
    require(r.round==round && !r.receipts[5].empty() && r.receipts[2].empty() && r.aborted_objects_removed);return r;
}
} // namespace rwn::core::enrollment
