#include "rwn/core/enrollment_certificate.hpp"
#include "rwn/core/content_hash.hpp"
#include <algorithm>
#include <cstdio>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace rwn::core::enrollment {
namespace {
[[noreturn]] void invalid(){throw std::invalid_argument("invalid enrollment certificate input");}
constexpr std::size_t cap=65536;
Bytes bytes(std::initializer_list<unsigned> input){Bytes result;for(auto value:input)result.push_back(static_cast<std::byte>(value));return result;}
Bytes join(std::initializer_list<Bytes> input){
    Bytes result;
    for(const auto& item:input){if(item.size()>cap-result.size())invalid();result.insert(result.end(),item.begin(),item.end());}
    return result;
}
Bytes tag(unsigned type,std::span<const std::byte> value){
    if(value.size()>=cap)invalid();
    auto result=bytes({type});
    if(value.size()<128)result.push_back(static_cast<std::byte>(value.size()));
    else if(value.size()<=255){result.push_back(std::byte{0x81});result.push_back(static_cast<std::byte>(value.size()));}
    else{result.push_back(std::byte{0x82});result.push_back(static_cast<std::byte>(value.size()>>8));result.push_back(static_cast<std::byte>(value.size()));}
    result.insert(result.end(),value.begin(),value.end());return result;
}
Bytes sequence(std::initializer_list<Bytes> values){return tag(0x30,join(values));}
Bytes oid(std::initializer_list<unsigned> value){return tag(6,bytes(value));}
Bytes integer(std::span<const std::byte> value){
    while(value.size()>1 && value.front()==std::byte{})value=value.subspan(1);
    if(value.empty())invalid();
    Bytes positive;
    if((std::to_integer<unsigned>(value.front())&0x80U)!=0)positive.push_back(std::byte{});
    positive.insert(positive.end(),value.begin(),value.end());return tag(2,positive);
}
Bytes number(std::uint64_t value){
    std::array<std::byte,8> data{};
    for(std::size_t i=0;i<8;++i)data[7-i]=static_cast<std::byte>(value>>(i*8));
    return integer(data);
}
Bytes serial(Serial value){if(std::ranges::all_of(value,[](auto b){return b==std::byte{};}))invalid();return integer(value);}
Bytes algorithm(){return sequence({oid({0x2a,0x86,0x48,0xce,0x3d,4,3,2})});}
Bytes point(const PublicKey& key){auto result=bytes({4});result.insert(result.end(),key.begin(),key.end());return result;}
Bytes bit_string(std::span<const std::byte> value){auto data=bytes({0});data.insert(data.end(),value.begin(),value.end());return tag(3,data);}
Bytes spki(const PublicKey& key){return sequence({sequence({oid({0x2a,0x86,0x48,0xce,0x3d,2,1}),oid({0x2a,0x86,0x48,0xce,0x3d,3,1,7})}),bit_string(point(key))});}
Bytes name(std::string_view text){return sequence({tag(0x31,sequence({oid({0x55,4,3}),tag(0x0c,std::as_bytes(std::span{text}))}))});}
Bytes issuer_name(){return name("LanPilot Pairing Authority");}
Bytes subject_name(Role role){
    if(role==Role::server)return name("LanPilot Host");
    if(role==Role::client)return name("LanPilot Client");
    invalid();
}
void valid_time(Time value){
    using namespace std::chrono;
    if(value<sys_days{year{2020}/1/1} || value>=sys_days{year{2100}/1/1})invalid();
}
Bytes time(Time value,bool generalized=false){
    using namespace std::chrono;
    valid_time(value);const auto day=floor<days>(value);const year_month_day date(day);
    const hh_mm_ss clock(value-day);const int y=int(date.year());
    char output[20]{};const bool utc=!generalized && y<2050;
    const int count=std::snprintf(output,sizeof(output),utc?"%02d%02u%02u%02lld%02lld%02lldZ":"%04d%02u%02u%02lld%02lld%02lldZ",
        utc?y%100:y,unsigned(date.month()),unsigned(date.day()),static_cast<long long>(clock.hours().count()),
        static_cast<long long>(clock.minutes().count()),static_cast<long long>(clock.seconds().count()));
    if(count!=(utc?13:15))invalid();
    return tag(utc?0x17:0x18,std::as_bytes(std::span{output,static_cast<std::size_t>(count)}));
}
void validity(Validity window,std::chrono::days maximum){
    valid_time(window.before);valid_time(window.after);
    if(window.before>=window.after || window.after-window.before>maximum)invalid();
}
void within(Validity window,Validity issuer){
    validity(issuer,std::chrono::days{3660});
    if(window.before<issuer.before || window.after>issuer.after)invalid();
}
Bytes extension(Bytes id,Bytes value,bool critical=false){
    return critical?sequence({std::move(id),tag(1,bytes({255})),tag(4,value)}):sequence({std::move(id),tag(4,value)});
}
Bytes identifier(const PublicKey& key){const auto id=sha256(point(key));return Bytes(id.begin(),id.end());}
Bytes authority_id(const PublicKey& key){return extension(oid({0x55,0x1d,0x23}),sequence({tag(0x80,identifier(key))}));}
Bytes subject_id(const PublicKey& key){return extension(oid({0x55,0x1d,0x0e}),tag(4,identifier(key)));}
void valid_key(Signer& signer,const PublicKey& key){if(!signer.accepts_public_key(key))invalid();}
Bytes signed_object(Signer& signer,Bytes body){
    const auto signature=signer.sign_sha256(body);
    if(signature.size()<8 || signature.size()>72 || signature[0]!=std::byte{0x30} ||
       std::to_integer<unsigned>(signature[1])!=signature.size()-2)invalid();
    std::size_t offset=2;
    for(unsigned i=0;i<2;++i){
        if(offset+2>signature.size() || signature[offset++]!=std::byte{2})invalid();
        const auto size=std::to_integer<unsigned>(signature[offset++]);
        if(size==0 || size>33 || size>signature.size()-offset || (std::to_integer<unsigned>(signature[offset])&0x80U)!=0 ||
           (size>1 && signature[offset]==std::byte{} && (std::to_integer<unsigned>(signature[offset+1])&0x80U)==0))invalid();
        if(std::ranges::all_of(std::span(signature).subspan(offset,size),[](auto b){return b==std::byte{};}))invalid();
        offset+=size;
    }
    if(offset!=signature.size())invalid();
    return sequence({std::move(body),algorithm(),bit_string(signature)});
}
Bytes alternatives(std::span<const AlternativeName> names){
    if(names.empty() || names.size()>8)invalid();
    struct ByteOrder{bool operator()(const Bytes& a,const Bytes& b)const{
        const auto size=std::min(a.size(),b.size());
        for(std::size_t i=0;i<size;++i){if(a[i]!=b[i])return a[i]<b[i];}
        return a.size()<b.size();
    }};
    std::set<Bytes,ByteOrder> encoded;
    for(const auto& value:names){
        Bytes data;
        if(!value.ip.empty()){
            if(!value.dns.empty() || (value.ip.size()!=4 && value.ip.size()!=16) ||
               std::ranges::all_of(value.ip,[](auto b){return b==std::byte{};}))invalid();
            data=tag(0x87,value.ip);
        }else{
            const auto& text=value.dns;if(text.empty() || text.size()>253)invalid();
            std::size_t begin=0;
            while(begin<text.size()){
                auto end=text.find('.',begin);if(end==std::string::npos)end=text.size();
                if(end==begin || end-begin>63 || text[begin]=='-' || text[end-1]=='-')invalid();
                for(std::size_t i=begin;i<end;++i)if(!((text[i]>='a'&&text[i]<='z') || (text[i]>='0'&&text[i]<='9') || text[i]=='-'))invalid();
                if(end==text.size())break;
                begin=end+1;if(begin==text.size())invalid();
            }
            data=tag(0x82,std::as_bytes(std::span{text}));
        }
        if(!encoded.insert(std::move(data)).second)invalid();
    }
    Bytes values;for(const auto& item:encoded)values.insert(values.end(),item.begin(),item.end());
    return extension(oid({0x55,0x1d,0x11}),tag(0x30,values));
}
}

Bytes root_certificate(Signer& signer,Serial id,Validity window){
    validity(window,std::chrono::days{3660});const auto key=signer.public_key();valid_key(signer,key);
    const auto extensions=sequence({extension(oid({0x55,0x1d,0x13}),sequence({tag(1,bytes({255})),number(0)}),true),
        extension(oid({0x55,0x1d,0x0f}),tag(3,bytes({1,0x86})),true),subject_id(key),authority_id(key)});
    return signed_object(signer,sequence({tag(0xa0,number(2)),serial(id),algorithm(),issuer_name(),
        sequence({time(window.before),time(window.after)}),issuer_name(),spki(key),tag(0xa3,extensions)}));
}
Bytes leaf_certificate(Signer& signer,Serial id,const PublicKey& key,Role role,Validity window,Validity issuer,std::span<const AlternativeName> names){
    validity(window,std::chrono::days{366});within(window,issuer);valid_key(signer,key);
    const auto name_der=subject_name(role);const auto authority=signer.public_key();valid_key(signer,authority);
    if(role==Role::client && !names.empty())invalid();
    Bytes extensions=join({extension(oid({0x55,0x1d,0x13}),sequence({}),true),
        extension(oid({0x55,0x1d,0x0f}),tag(3,bytes({7,0x80})),true),subject_id(key),authority_id(authority),
        extension(oid({0x55,0x1d,0x25}),sequence({oid({0x2b,6,1,5,5,7,3,role==Role::server?1U:2U})}))});
    if(role==Role::server){const auto san=alternatives(names);extensions.insert(extensions.end(),san.begin(),san.end());}
    return signed_object(signer,sequence({tag(0xa0,number(2)),serial(id),algorithm(),issuer_name(),sequence({time(window.before),time(window.after)}),
        name_der,spki(key),tag(0xa3,tag(0x30,extensions))}));
}
Bytes certificate_request(Signer& signer,Role role){
    const auto key=signer.public_key();valid_key(signer,key);
    return signed_object(signer,sequence({number(0),subject_name(role),spki(key),tag(0xa0,{})}));
}
Bytes revocation_list(Signer& signer,std::uint64_t count,Validity window,Validity issuer,std::span<const Revocation> revoked){
    validity(window,std::chrono::days{1});within(window,issuer);
    if(count==0 || count>std::uint64_t(std::numeric_limits<std::int64_t>::max()) || revoked.size()>256)invalid();
    const auto key=signer.public_key();valid_key(signer,key);std::set<Serial> seen;Bytes entries;
    for(const auto& item:revoked){
        valid_time(item.occurred);if(item.occurred>window.before || !seen.insert(item.serial).second)invalid();
        const auto entry=sequence({serial(item.serial),time(item.occurred)});entries.insert(entries.end(),entry.begin(),entry.end());
    }
    Bytes fields=join({number(1),algorithm(),issuer_name(),time(window.before),time(window.after)});
    if(!entries.empty()){const auto list=tag(0x30,entries);fields.insert(fields.end(),list.begin(),list.end());}
    const auto extensions=tag(0xa0,sequence({authority_id(key),extension(oid({0x55,0x1d,0x14}),number(count))}));
    fields.insert(fields.end(),extensions.begin(),extensions.end());return signed_object(signer,tag(0x30,fields));
}
Bytes ocsp_response(Signer& signer,Serial id,Status status,Time produced,Validity window,Validity issuer,Time revoked_at){
    validity(window,std::chrono::days{1});within(window,issuer);valid_time(produced);
    if(produced<window.before || produced>window.after)invalid();
    const auto key=signer.public_key();valid_key(signer,key);
    const auto name_hash=sha256(issuer_name()),key_hash=sha256(point(key));
    const auto cert_id=sequence({sequence({oid({0x60,0x86,0x48,1,0x65,3,4,2,1}),tag(5,{})}),tag(4,name_hash),tag(4,key_hash),serial(id)});
    Bytes state;
    switch(status){
        case Status::good:state=tag(0x80,{});break;
        case Status::unknown:state=tag(0x82,{});break;
        case Status::revoked:
            valid_time(revoked_at);if(revoked_at>window.before)invalid();state=tag(0xa1,time(revoked_at,true));break;
        default:invalid();
    }
    const auto response=sequence({cert_id,state,time(window.before,true),tag(0xa0,time(window.after,true))});
    const auto basic=signed_object(signer,sequence({tag(0xa1,issuer_name()),time(produced,true),sequence({response})}));
    return sequence({tag(0x0a,bytes({0})),tag(0xa0,sequence({oid({0x2b,6,1,5,5,7,0x30,1,1}),tag(4,basic)}))});
}
} // namespace rwn::core::enrollment
