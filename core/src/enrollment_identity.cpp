#include "rwn/core/enrollment_identity.hpp"
#include <algorithm>

namespace rwn::core::enrollment {
namespace {
[[noreturn]] void invalid(){throw std::invalid_argument("invalid approved identity bundle");}
bool equals(std::span<const std::byte> data,std::initializer_list<unsigned> values){
    if(data.size()!=values.size())return false;
    auto it=data.begin();for(auto value:values)if(*it++!=static_cast<std::byte>(value))return false;return true;
}
struct Field{unsigned tag;std::span<const std::byte> value,encoded;};
class Der {
public:
    explicit Der(std::span<const std::byte> data):data_(data){}
    bool empty()const{return data_.empty();}
    Field next(){
        if(data_.size()<2)invalid();
        const auto tag=std::to_integer<unsigned>(data_[0]);
        if((tag&31)==31)invalid();
        auto length=std::to_integer<unsigned>(data_[1]);std::size_t header=2;
        if(length&128){const auto count=length&127;if(count==0 || count>2 || data_.size()<2+count || data_[2]==std::byte{})invalid();
            length=0;for(unsigned i=0;i<count;++i)length=(length<<8)|std::to_integer<unsigned>(data_[2+i]);
            if(length<128 || (count==2 && length<=255))invalid();
            header+=count;}
        if(length>data_.size()-header)invalid();
        auto value=data_.subspan(header,length),encoded=data_.first(header+length);data_=data_.subspan(header+length);return {tag,value,encoded};
    }
    std::span<const std::byte> read(unsigned expected){auto f=next();if(f.tag!=expected)invalid();return f.value;}
    void end()const{if(!empty())invalid();}
private:std::span<const std::byte> data_;
};
void same(std::span<const std::byte> bytes,std::initializer_list<unsigned> expected){if(!equals(bytes,expected))invalid();}
std::span<const std::byte> sequence(std::span<const std::byte> bytes){Der d(bytes);auto out=d.read(0x30);d.end();return out;}
void names(std::span<const std::byte> bytes,const std::array<std::byte,4>& expected){
    Der all(sequence(bytes));bool found=false;unsigned count{};std::vector<Bytes> seen;
    while(!all.empty()){
        const auto f=all.next();if(++count>8)invalid();
        if(f.tag==0x87){if(f.value.size()!=4 && f.value.size()!=16)invalid();if(std::ranges::equal(f.value,expected))found=true;}
        else if(f.tag==0x82){if(f.value.empty() || f.value.size()>253)invalid();
            for(auto raw:f.value){const auto c=std::to_integer<unsigned>(raw);if(!((c>='a'&&c<='z') || (c>='0'&&c<='9') || c=='-' || c=='.'))invalid();}}
        else invalid();
        Bytes unique{static_cast<std::byte>(f.tag)};unique.insert(unique.end(),f.value.begin(),f.value.end());
        if(std::ranges::any_of(seen,[&](const auto& previous){return std::ranges::equal(previous,unique);}))invalid();
        seen.push_back(std::move(unique));
    }
    if(!found)invalid();
}
}
void require_identity_certificate_profile(std::span<const std::byte> bytes,KeyPurpose purpose,const std::array<std::byte,4>& ip){
    if(bytes.empty() || bytes.size()>8192)invalid();
    if(purpose!=KeyPurpose::authority && purpose!=KeyPurpose::server && purpose!=KeyPurpose::client)invalid();
    const std::initializer_list<unsigned> signature_algorithm{6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2};
    Der certificate(sequence(bytes));const auto tbs=certificate.read(0x30);same(certificate.read(0x30),signature_algorithm);(void)certificate.read(3);certificate.end();
    Der fields(tbs);Der version(fields.read(0xa0));same(version.read(2),{2});version.end();
    const auto serial=fields.read(2);
    if(serial.empty() || serial.size()>17 || (std::to_integer<unsigned>(serial.front())&128)!=0 ||
       (serial.size()==17 && serial.front()!=std::byte{}) ||
       (serial.size()>1 && serial.front()==std::byte{} && (std::to_integer<unsigned>(serial[1])&128)==0) ||
       std::ranges::all_of(serial,[](auto b){return b==std::byte{};}))invalid();
    same(fields.read(0x30),signature_algorithm);
    for(unsigned i=0;i<3;++i)(void)fields.read(0x30); //issuer,validity,subject; native policy checks these
    Der spki(fields.read(0x30));Der algorithm(spki.read(0x30));same(algorithm.read(6),{0x2a,0x86,0x48,0xce,0x3d,2,1});
    same(algorithm.read(6),{0x2a,0x86,0x48,0xce,0x3d,3,1,7});algorithm.end();
    const auto bits=spki.read(3);if(bits.size()!=66 || bits[0]!=std::byte{} || bits[1]!=std::byte{4})invalid();spki.end();
    const auto extensions=fields.read(0xa3);fields.end();Der list(sequence(extensions));
    bool basic=false,usage=false,eku=false,san=false,ski=false,aki=false;
    while(!list.empty()){
        Der extension(list.read(0x30));const auto oid=extension.read(6);auto value=extension.next();bool critical=false;
        if(value.tag==1){same(value.value,{255});critical=true;value=extension.next();}
        if(value.tag!=4)invalid();
        extension.end();
        if(equals(oid,{0x55,0x1d,0x13})){
            if(basic || !critical)invalid();
            basic=true;
            if(purpose==KeyPurpose::authority)same(value.value,{0x30,6,1,1,255,2,1,0});else same(value.value,{0x30,0});
        }else if(equals(oid,{0x55,0x1d,0x0f})){
            if(usage || !critical)invalid();
            usage=true;
            if(purpose==KeyPurpose::authority)same(value.value,{3,2,1,0x86});else same(value.value,{3,2,7,0x80});
        }else if(equals(oid,{0x55,0x1d,0x25})){
            if(eku || critical || purpose==KeyPurpose::authority)invalid();
            eku=true;Der usages(sequence(value.value));
            same(usages.read(6),{0x2b,6,1,5,5,7,3,purpose==KeyPurpose::server?1U:2U});usages.end();
        }else if(equals(oid,{0x55,0x1d,0x11})){
            if(san || critical || purpose!=KeyPurpose::server)invalid();
            san=true;names(value.value,ip);
        }else if(equals(oid,{0x55,0x1d,0x0e})){
            if(ski || critical)invalid();
            ski=true;Der id(value.value);if(id.read(4).size()!=32)invalid();id.end();
        }else if(equals(oid,{0x55,0x1d,0x23})){
            if(aki || critical)invalid();
            aki=true;Der id(sequence(value.value));if(id.read(0x80).size()!=32)invalid();id.end();
        }else invalid();
    }
    if(!basic || !usage || !ski || !aki || (eku!=(purpose!=KeyPurpose::authority)) || (san!=(purpose==KeyPurpose::server)))invalid();
}
void require_approved_identity_bundle(const ApprovedPairing& approval,const KeyReference& key,const PublicIdentityBundle& b,const PublicKey& local,PairingConsent::Clock::time_point now){
    (void)key_reference_name(key);
    if(!approval.valid_at(now))invalid();
    const auto& t=approval.transcript();const bool is_host=approval.local_role()==PairRole::host;
    if(key.purpose!=(is_host?KeyPurpose::server:KeyPurpose::client) || local!=(is_host?t.host.identity_key:t.client.identity_key))invalid();
    std::size_t total{};
    for(const auto* part:{&b.root,&b.server,&b.client,&b.crl,&b.server_ocsp,&b.client_ocsp}){
        if(part->empty() || part->size()>65536 || total>131072-part->size())invalid();
        total+=part->size();
    }
    const auto digest=core::sha256(b.root);if(digest!=t.host.root_sha256)invalid();
    require_identity_certificate_profile(b.root,KeyPurpose::authority);
    require_identity_certificate_profile(b.server,KeyPurpose::server,t.host.desktop_ipv4);
    require_identity_certificate_profile(b.client,KeyPurpose::client);
}
CertificateFacts certificate_facts(std::span<const std::byte> bytes,KeyPurpose purpose,const std::array<std::byte,4>& ip){
    require_identity_certificate_profile(bytes,purpose,ip);Der certificate(sequence(bytes));Der fields(certificate.read(0x30));
    (void)fields.read(0xa0);auto id=fields.read(2);if(id.size()==17)id=id.subspan(1);if(id.size()>16)invalid();
    CertificateFacts result{};std::copy(id.begin(),id.end(),result.serial.end()-static_cast<std::ptrdiff_t>(id.size()));
    (void)fields.read(0x30);(void)fields.read(0x30);Der validity(fields.read(0x30));
    auto time=[&](){const auto f=validity.next();const auto n=f.value.size();
        if(!((f.tag==0x17 && n==13) || (f.tag==0x18 && n==15)) || f.value.back()!=std::byte{'Z'})invalid();
        std::size_t at{};auto number=[&](unsigned count){unsigned v{};for(unsigned i=0;i<count;++i){const auto c=std::to_integer<unsigned>(f.value[at++]);if(c<'0' || c>'9')invalid();v=v*10+c-'0';}return v;};
        const auto y=f.tag==0x17?2000+number(2):number(4);const auto m=number(2),d=number(2),h=number(2),minute=number(2),s=number(2);
        using namespace std::chrono;const year_month_day date{year{static_cast<int>(y)},month{m},day{d}};
        if(y<2020 || y>=2100 || !date.ok() || h>23 || minute>59 || s>59 || (f.tag==0x17 && y>=2050))invalid();
        return sys_days{date}+hours{h}+minutes{minute}+seconds{s};};
    result.validity={time(),time()};validity.end();if(result.validity.before>=result.validity.after)invalid();
    (void)fields.read(0x30);Der key(fields.read(0x30));(void)key.read(0x30);const auto bits=key.read(3);key.end();
    if(bits.size()!=66 || bits[0]!=std::byte{} || bits[1]!=std::byte{4})invalid();
    std::copy(bits.begin()+2,bits.end(),result.subject_key.begin());return result;
}
void require_renewed_identity(const RenewedIdentity& proof,const KeyReference& ref,const PublicKey& local,Time now){
    (void)key_reference_name(ref);if(!proof.valid_at(now))invalid();const auto& t=proof.transcript();const auto& b=proof.bundle();
    const bool host=proof.role()==PairRole::host;if(!host && proof.role()!=PairRole::client)invalid();
    if(ref.purpose!=(host?KeyPurpose::server:KeyPurpose::client) || local!=(host?t.host.identity_key:t.client.identity_key))invalid();
    if(certificate_facts(b.root,KeyPurpose::authority).subject_key!=t.host.authority_key ||
       certificate_facts(b.server,KeyPurpose::server,t.host.desktop_ipv4).subject_key!=t.host.identity_key ||
       certificate_facts(b.client,KeyPurpose::client).subject_key!=t.client.identity_key)invalid();
}
void require_good_ocsp(std::span<const std::byte> response,std::span<const std::byte> root,
    const Serial& expected_serial,const PublicKey& authority,const PairProofVerifier& verifier,Time now){
    if(response.empty() || response.size()>65536)invalid();
    Der cert(sequence(root)),root_fields(cert.read(0x30));
    (void)root_fields.read(0xa0);(void)root_fields.read(2);(void)root_fields.read(0x30);(void)root_fields.read(0x30);(void)root_fields.read(0x30);
    const auto subject=root_fields.next();if(subject.tag!=0x30)invalid();
    Der outer(sequence(response));same(outer.read(0x0a),{0});Der explicit_response(outer.read(0xa0));outer.end();
    Der wrapped(explicit_response.read(0x30));explicit_response.end();same(wrapped.read(6),{0x2b,6,1,5,5,7,0x30,1,1});
    const auto encoded_basic=wrapped.read(4);wrapped.end();Der basic(sequence(encoded_basic));const auto body=basic.next();if(body.tag!=0x30)invalid();
    same(basic.read(0x30),{6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2});const auto bits=basic.read(3);basic.end();
    if(bits.size()<9 || bits.size()>73 || bits[0]!=std::byte{})invalid();
    const auto signature=bits.subspan(1);(void)pairing_signature_raw(signature);
    if(!verifier.verify(authority,body.encoded,signature))invalid();
    Der data(body.value);if(!std::ranges::equal(data.read(0xa1),subject.encoded))invalid();
    auto time=[](Der& d){const auto text=d.read(0x18);if(text.size()!=15 || text[14]!=std::byte{'Z'})invalid();std::size_t at{};
        auto number=[&](unsigned n){unsigned value{};for(unsigned i=0;i<n;++i){const auto c=std::to_integer<unsigned>(text[at++]);if(c<'0' || c>'9')invalid();value=value*10+c-'0';}return value;};
        const auto y=number(4),m=number(2),day=number(2),h=number(2),minute=number(2),s=number(2);using namespace std::chrono;
        const year_month_day date{year{static_cast<int>(y)},month{m},std::chrono::day{day}};if(y<2020 || y>=2100 || !date.ok() || h>23 || minute>59 || s>59)invalid();
        return Time{sys_days{date}+hours{h}+minutes{minute}+seconds{s}};};
    const auto produced=time(data);Der responses(data.read(0x30));data.end();Der single(responses.read(0x30));responses.end();
    Der id(single.read(0x30));Der algorithm(id.read(0x30));same(algorithm.read(6),{0x60,0x86,0x48,1,0x65,3,4,2,1});same(algorithm.read(5),{});algorithm.end();
    if(!std::ranges::equal(id.read(4),core::sha256(subject.encoded)))invalid();
    Bytes encoded_key{std::byte{4}};encoded_key.insert(encoded_key.end(),authority.begin(),authority.end());
    if(!std::ranges::equal(id.read(4),core::sha256(encoded_key)))invalid();
    auto serial=id.read(2);id.end();if(serial.empty() || serial.size()>17 || (std::to_integer<unsigned>(serial[0])&128)!=0 ||
        (serial.size()>1 && serial[0]==std::byte{} && (std::to_integer<unsigned>(serial[1])&128)==0))invalid();
    if(serial.size()==17){if(serial[0]!=std::byte{})invalid();serial=serial.subspan(1);}
    Serial actual{};std::copy(serial.begin(),serial.end(),actual.end()-static_cast<std::ptrdiff_t>(serial.size()));if(actual!=expected_serial)invalid();
    same(single.read(0x80),{});const auto before=time(single);Der next(single.read(0xa0));const auto after=time(next);next.end();single.end();
    if(before>now || now>=after || after<=before || after-before>std::chrono::hours{24} || produced<before || produced>after || produced>now+std::chrono::minutes{5})invalid();
}
} // namespace rwn::core::enrollment
