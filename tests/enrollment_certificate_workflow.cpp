#include "rwn/core/enrollment_certificate.hpp"
#include <iostream>
#include <stdexcept>

namespace e=rwn::core::enrollment;
namespace {
void check(bool value){if(!value)throw std::runtime_error("enrollment bounds workflow failed");}
class Fixture final:public e::Signer {
public:
    unsigned signs{};bool valid{true},bad_signature{};
    e::PublicKey public_key()const override{e::PublicKey key{};key[0]=std::byte{1};return key;}
    bool accepts_public_key(const e::PublicKey&)const override{return valid;}
    e::Bytes sign_sha256(std::span<const std::byte>)override{
        ++signs;if(bad_signature)return {};
        return {std::byte{0x30},std::byte{6},std::byte{2},std::byte{1},std::byte{1},std::byte{2},std::byte{1},std::byte{1}};
    }
};
template<class Action>void rejects_before_sign(Fixture& fixture,Action action){
    const auto before=fixture.signs;bool denied=false;
    try{action();}catch(const std::invalid_argument&){denied=true;}
    check(denied && before==fixture.signs);
}
}
int main(){
    try {
        using namespace std::chrono;
        Fixture fixture;e::Serial id{};id.back()=std::byte{1};
        const e::Time now=sys_days{year{2026}/10/25};
        const e::Validity authority{now-days{5},now+days{365}},leaf{now-days{1},now+days{30}},window{now-minutes{1},now+minutes{30}};
        const e::AlternativeName dns{{},"lanpilot.test"};
        check(!e::root_certificate(fixture,id,authority).empty());
        check(!e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::server,leaf,authority,std::span{&dns,1}).empty());
        check(!e::certificate_request(fixture,e::Role::client).empty());
        check(!e::revocation_list(fixture,1,window,authority,{}).empty());
        check(!e::ocsp_response(fixture,id,e::Status::good,now,window,authority).empty());
        rejects_before_sign(fixture,[&]{e::root_certificate(fixture,{},authority);});
        rejects_before_sign(fixture,[&]{e::root_certificate(fixture,id,{now,now});});
        rejects_before_sign(fixture,[&]{e::root_certificate(fixture,id,{now,now+days{3661}});});
        rejects_before_sign(fixture,[&]{e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::client,{now,now+days{367}},{now,now+days{500}});});
        rejects_before_sign(fixture,[&]{e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::client,leaf,{now,now+days{365}});});
        rejects_before_sign(fixture,[&]{e::certificate_request(fixture,static_cast<e::Role>(999));});
        rejects_before_sign(fixture,[&]{e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::server,leaf,authority);});
        rejects_before_sign(fixture,[&]{e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::client,leaf,authority,std::span{&dns,1});});
        for(const auto& name:std::vector<std::string>{"*.test","UPPER.test","x..test","-x.test","x-.test","x.test.","x\ntest",std::string(254,'a')}){
            const e::AlternativeName bad{{},name};
            rejects_before_sign(fixture,[&]{e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::server,leaf,authority,std::span{&bad,1});});
        }
        const std::array<e::AlternativeName,2> repeated{dns,dns};
        rejects_before_sign(fixture,[&]{e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::server,leaf,authority,repeated);});
        const e::AlternativeName wildcard_ip{e::Bytes(4),{}};
        rejects_before_sign(fixture,[&]{e::leaf_certificate(fixture,id,fixture.public_key(),e::Role::server,leaf,authority,std::span{&wildcard_ip,1});});
        fixture.valid=false;
        rejects_before_sign(fixture,[&]{e::root_certificate(fixture,id,authority);});fixture.valid=true;
        rejects_before_sign(fixture,[&]{e::revocation_list(fixture,0,window,authority,{});});
        rejects_before_sign(fixture,[&]{e::revocation_list(fixture,1,{now,now+hours{25}},authority,{});});
        const std::array<e::Revocation,2> duplicate{{{id,now-minutes{2}},{id,now-minutes{2}}}};
        rejects_before_sign(fixture,[&]{e::revocation_list(fixture,1,window,authority,duplicate);});
        const std::vector<e::Revocation> excessive(257,{id,now-minutes{2}});
        rejects_before_sign(fixture,[&]{e::revocation_list(fixture,1,window,authority,excessive);});
        rejects_before_sign(fixture,[&]{e::ocsp_response(fixture,id,e::Status::good,now+hours{2},window,authority);});
        rejects_before_sign(fixture,[&]{e::ocsp_response(fixture,id,static_cast<e::Status>(999),now,window,authority);});
        rejects_before_sign(fixture,[&]{e::ocsp_response(fixture,id,e::Status::revoked,now,window,authority,now);});
        fixture.bad_signature=true;bool signature_denied=false;
        try{e::root_certificate(fixture,id,authority);}catch(const std::invalid_argument&){signature_denied=true;}
        check(signature_denied);
        std::cout<<"enrollment_bounds=PASS rejected_before_sign=1 signature_mode=fixture keys_created=0\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
