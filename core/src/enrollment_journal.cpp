#include "rwn/core/enrollment_journal.hpp"
#include <algorithm>
#include <limits>

namespace rwn::core::enrollment {
namespace {
void require(bool b){if(!b)throw std::runtime_error("invalid local enrollment transaction");}
template<class T>bool nonzero(const T& a){return std::any_of(a.begin(),a.end(),[](auto b){return b!=0;});}
bool nonzero(const PublicKey& a){return std::any_of(a.begin(),a.end(),[](auto b){return b!=std::byte{};});}
bool nonzero(const std::array<std::byte,32>& a){return std::any_of(a.begin(),a.end(),[](auto b){return b!=std::byte{};});}
void number(Bytes& b,std::uint64_t n,unsigned width){for(unsigned i=width;i>0;--i)b.push_back(static_cast<std::byte>(n>>((i-1)*8)));}
void append(Bytes& b,std::span<const std::byte> a){b.insert(b.end(),a.begin(),a.end());}
struct Reader {
    std::span<const std::byte> b;std::size_t at{};
    std::span<const std::byte> take(std::size_t n){require(n<=b.size()-at);auto r=b.subspan(at,n);at+=n;return r;}
    std::uint64_t number(unsigned width){std::uint64_t n{};for(auto x:take(width))n=(n<<8)|std::to_integer<unsigned>(x);return n;}
    template<class T>void array(T& t){auto a=take(t.size());std::copy(a.begin(),a.end(),t.begin());}
    Bytes bytes(){auto n=number(4);require(n<=65536);auto a=take(static_cast<std::size_t>(n));return {a.begin(),a.end()};}
};
auto objects(PublicIdentityBundle& b){return std::array{&b.root,&b.server,&b.client,&b.crl,&b.server_ocsp,&b.client_ocsp};}
void validate(const EnrollmentRecord& r){
    require(nonzero(r.transaction) && r.revision>0 && r.revision<std::numeric_limits<std::uint64_t>::max());
    const bool host=r.role==PairRole::host;require(host || r.role==PairRole::client);
    require(r.keys.size()==(host?2U:1U));
    for(std::size_t i=0;i<r.keys.size();++i){const auto& k=r.keys[i];(void)key_reference_name(k.reference);
        require(k.reference.purpose==(host?(i==0?KeyPurpose::authority:KeyPurpose::server):KeyPurpose::client));
        require(!k.existed || nonzero(k.point));
        if(i)require(k.reference.id!=r.keys[0].reference.id);
    }
    auto b=r.bundle;std::size_t total{};for(const auto* a:objects(b)){require(a->size()<=65536);total+=a->size();}require(total<=131072);
    if(r.phase==EnrollmentPhase::keys){require(total==0 && !nonzero(r.approval_binding) && r.server_ipv4==std::array<std::byte,4>{} && !r.certificate_existed);}
    else {
        require(r.phase==EnrollmentPhase::association_intent || r.phase==EnrollmentPhase::staged);
        require(nonzero(r.approval_binding));for(const auto& k:r.keys)require(nonzero(k.point));
        for(const auto* a:objects(b))require(!a->empty());
        require_identity_certificate_profile(b.root,KeyPurpose::authority);
        require_identity_certificate_profile(b.server,KeyPurpose::server,r.server_ipv4);
        require_identity_certificate_profile(b.client,KeyPurpose::client,r.server_ipv4);
    }
}
const EnrollmentKeyIntent& local_key(const EnrollmentRecord& r){return r.keys.back();}
const Bytes& local_certificate(const EnrollmentRecord& r){return r.role==PairRole::host?r.bundle.server:r.bundle.client;}
}
Bytes encode_enrollment_record(const EnrollmentRecord& r){
    validate(r);Bytes b{std::byte{'L'},std::byte{'P'},std::byte{'J'},std::byte{1}};
    append(b,r.transaction);number(b,r.revision,8);number(b,static_cast<unsigned>(r.role),1);number(b,static_cast<unsigned>(r.phase),1);
    number(b,r.keys.size(),1);number(b,r.certificate_existed?1:0,1);
    for(const auto& k:r.keys){number(b,static_cast<unsigned>(k.reference.purpose),1);append(b,k.reference.id);number(b,k.existed?1:0,1);append(b,k.point);}
    for(auto n:r.approval_binding)number(b,n,1);
    append(b,r.server_ipv4);
    auto bundle=r.bundle;for(const auto* a:objects(bundle)){number(b,a->size(),4);append(b,*a);}
    append(b,sha256(b));require(b.size()<=enrollment_record_cap);return b;
}
EnrollmentRecord decode_enrollment_record(std::span<const std::byte> bytes){
    require(bytes.size()>=200 && bytes.size()<=enrollment_record_cap);const auto payload=bytes.first(bytes.size()-32);
    require(std::ranges::equal(sha256(payload),bytes.last(32)));Reader in{payload};
    require(in.number(4)==0x4c504a01);EnrollmentRecord r;in.array(r.transaction);r.revision=in.number(8);
    r.role=static_cast<PairRole>(in.number(1));r.phase=static_cast<EnrollmentPhase>(in.number(1));auto count=in.number(1);require(count<=2);
    const auto existed=in.number(1);require(existed<=1);r.certificate_existed=existed==1;
    for(std::size_t i=0;i<count;++i){EnrollmentKeyIntent k{};k.reference.purpose=static_cast<KeyPurpose>(in.number(1));in.array(k.reference.id);
        const auto present=in.number(1);require(present<=1);k.existed=present==1;in.array(k.point);r.keys.push_back(k);}
    for(auto& n:r.approval_binding)n=static_cast<std::uint8_t>(in.number(1));
    in.array(r.server_ipv4);
    for(auto* a:objects(r.bundle))*a=in.bytes();
    require(in.at==payload.size());validate(r);return r;
}
std::optional<EnrollmentRecord> FileEnrollmentJournal::load(){auto bytes=read_record();if(!bytes)return {};return decode_enrollment_record(*bytes);}
void FileEnrollmentJournal::save(const EnrollmentRecord& next){
    const auto bytes=encode_enrollment_record(next);const auto old=load();
    require(old?(old->transaction==next.transaction && next.revision==old->revision+1):next.revision==1);
    replace_record(bytes);
}
void FileEnrollmentJournal::clear(const std::array<std::byte,32>& id){auto old=load();require(old && old->transaction==id);remove_record();}
EnrollmentStager::EnrollmentStager(EnrollmentJournal& j,KeyStore& k,IdentityStore& i):journal_(j),keys_(k),identities_(i){}
EnrollmentRecord EnrollmentStager::record(){auto r=journal_.load();require(r.has_value());return *r;}
void EnrollmentStager::save(EnrollmentRecord& r){++r.revision;journal_.save(r);}
void EnrollmentStager::begin(std::array<std::byte,32> id,PairRole role,std::span<const KeyReference> refs){
    require(nonzero(id) && (role==PairRole::host || role==PairRole::client) && refs.size()==(role==PairRole::host?2U:1U));
    require(!journal_.load());EnrollmentRecord r;r.transaction=id;r.role=role;r.revision=1;
    for(const auto& ref:refs){auto key=keys_.open(ref);r.keys.push_back({ref,key!=nullptr,key?key->public_key():PublicKey{}});}
    (void)encode_enrollment_record(r);journal_.save(r);
}
void EnrollmentStager::ensure_keys(){
    auto r=record();require(r.phase==EnrollmentPhase::keys);
    for(auto& intent:r.keys){auto key=keys_.open(intent.reference);
        if(nonzero(intent.point)){require(key && key->public_key()==intent.point);continue;}
        require(!intent.existed);if(!key)key=keys_.create_new(intent.reference);
        intent.point=key->public_key();require(nonzero(intent.point));save(r);
    }
}
AssociatedIdentity EnrollmentStager::associate(const ApprovedPairing& approval,PublicIdentityBundle b,PairingConsent::Clock::time_point now){
    auto r=record();require(r.phase==EnrollmentPhase::keys && approval.local_role()==r.role);
    const auto& k=local_key(r);for(const auto& item:r.keys){auto key=keys_.open(item.reference);require(key && key->public_key()==item.point);}
    require_approved_identity_bundle(approval,k.reference,b,k.point,now);
    if(r.role==PairRole::host)require(r.keys.front().point==approval.transcript().host.authority_key);
    r.approval_binding=approval.transcript().binding;r.server_ipv4=approval.transcript().host.desktop_ipv4;r.bundle=std::move(b);
    const auto found=identities_.locate(k.reference,local_certificate(r),r.server_ipv4);
    require(found.has_value() || identities_.certificate_absent(local_certificate(r)));
    r.certificate_existed=found.has_value();r.phase=EnrollmentPhase::association_intent;save(r); // BEFORE native add
    auto identity=identities_.associate(approval,k.reference,r.bundle,now);
    require(identity.created==!r.certificate_existed && identities_.ready(identity));
    r.phase=EnrollmentPhase::staged;save(r);return identity;
}
AssociatedIdentity EnrollmentStager::associate_renewed(const RenewedIdentity& proof){
    auto r=record();require(r.phase==EnrollmentPhase::keys && r.role==proof.role());
    for(const auto& k:r.keys){auto key=keys_.open(k.reference);require(k.existed && key && key->public_key()==k.point);}
    const auto& k=local_key(r);require_renewed_identity(proof,k.reference,k.point,std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
    if(r.role==PairRole::host)require(r.keys.front().point==proof.transcript().host.authority_key);
    r.approval_binding=proof.transcript().binding;r.server_ipv4=proof.transcript().host.desktop_ipv4;r.bundle=proof.bundle();
    const auto found=identities_.locate(k.reference,local_certificate(r),r.server_ipv4);require(found || identities_.certificate_absent(local_certificate(r)));
    r.certificate_existed=found.has_value();r.phase=EnrollmentPhase::association_intent;save(r);
    auto identity=identities_.associate_renewed(proof,k.reference);require(identity.created==!r.certificate_existed && identities_.ready(identity));
    r.phase=EnrollmentPhase::staged;save(r);return identity;
}
std::optional<AssociatedIdentity> EnrollmentStager::recover_staged(){
    auto r=record();if(r.phase==EnrollmentPhase::keys)return {};
    const auto& k=local_key(r);auto identity=identities_.locate(k.reference,local_certificate(r),r.server_ipv4);
    if(!identity || identity->subject_key!=k.point || !identities_.ready(*identity))return {};
    identity->created=!r.certificate_existed;
    if(r.phase!=EnrollmentPhase::staged){r.phase=EnrollmentPhase::staged;save(r);}return identity;
}
bool EnrollmentStager::rollback(){
    auto r=record();
    if(!rollback_objects(r,keys_,identities_))return false;
    journal_.clear(r.transaction);return true;
}
bool EnrollmentStager::rollback_objects(const EnrollmentRecord& r,KeyStore& keys,IdentityStore& identities){
    if(r.phase!=EnrollmentPhase::keys && !r.certificate_existed){
        const auto& k=local_key(r);auto found=identities.locate(k.reference,local_certificate(r),r.server_ipv4);
        if(found){if(found->subject_key!=k.point)return false;found->created=true;if(!identities.remove_created(*found))return false;}
        if(!identities.certificate_absent(local_certificate(r)))return false;
    }
    for(auto i=r.keys.rbegin();i!=r.keys.rend();++i){if(i->existed)continue;auto key=keys.open(i->reference);if(!key)continue;
        // A crash after native create and before saving its public point is
        // reconciled under the same durable absent-before-create intent.
        if(nonzero(i->point) && key->public_key()!=i->point)return false;
        const auto point=key->public_key();key.reset();if(!keys.remove_if_matches(i->reference,point))return false;
    }
    return true;
}
} // namespace rwn::core::enrollment
