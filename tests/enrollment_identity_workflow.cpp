#include "rwn/core/enrollment_identity.hpp"
#include "test_support.hpp"
#include <algorithm>
#include <iostream>
namespace e=rwn::core::enrollment;
namespace {
// Structural decoder fixture only; native chain/signature/revocation/identity
// binding is tested separately by rwn-enrollment-key-probe on both platforms.
struct Signer final:e::Signer {
    e::PublicKey public_key()const override{e::PublicKey p{};p.fill(std::byte{1});return p;}
    bool accepts_public_key(const e::PublicKey&)const override{return true;}
    e::Bytes sign_sha256(std::span<const std::byte>)override{return {std::byte{0x30},std::byte{6},std::byte{2},std::byte{1},std::byte{1},std::byte{2},std::byte{1},std::byte{1}};}
};
template<class F>void rejected(F f){rwn::test::require_throws<std::invalid_argument>(f,"invalid fresh identity profile");}
void change(e::Bytes& bytes,std::initializer_list<unsigned> pattern,std::byte replacement){
    e::Bytes needle;for(auto b:pattern)needle.push_back(static_cast<std::byte>(b));
    const auto position=std::search(bytes.begin(),bytes.end(),needle.begin(),needle.end());RWN_CHECK(position!=bytes.end());
    *(position+static_cast<std::ptrdiff_t>(needle.size()-1))=replacement;
}
}
int main(){
    try {
        using namespace std::chrono;Signer signer;const auto now=floor<seconds>(system_clock::now());const e::Validity window{now-days{1},now+days{30}};
        e::Serial serial{};serial.back()=std::byte{1};
        const e::AlternativeName ip{{std::byte{127},std::byte{},std::byte{},std::byte{1}}, {}};const std::array<std::byte,4> address{std::byte{127},std::byte{},std::byte{},std::byte{1}};
        const auto root=e::root_certificate(signer,serial,window);
        const auto server=e::leaf_certificate(signer,serial,signer.public_key(),e::Role::server,window,window,std::span{&ip,1});
        const auto client=e::leaf_certificate(signer,serial,signer.public_key(),e::Role::client,window,window);
        e::require_identity_certificate_profile(root,e::KeyPurpose::authority);e::require_identity_certificate_profile(server,e::KeyPurpose::server,address);e::require_identity_certificate_profile(client,e::KeyPurpose::client);
        rejected([&](){e::require_identity_certificate_profile(root,e::KeyPurpose::client);});
        rejected([&](){e::require_identity_certificate_profile(client,e::KeyPurpose::server,address);});
        rejected([&](){e::require_identity_certificate_profile(server,e::KeyPurpose::client);});
        auto wrong=address;wrong.back()=std::byte{2};rejected([&](){e::require_identity_certificate_profile(server,e::KeyPurpose::server,wrong);});
        for(int fault=0;fault<9;++fault){auto bad=server;
            if(fault==0)bad[1]=std::byte{0x80};
            if(fault==1)bad[1]=std::byte{0x83};
            if(fault==2)bad.push_back(std::byte{});
            if(fault==3)bad.resize(10);
            if(fault==4)change(bad,{6,8,0x2b,6,1,5,5,7,3,1},std::byte{2});
            if(fault==5)change(bad,{0x55,0x1d,0x13,1,1,255},std::byte{});
            if(fault==6)change(bad,{6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7},std::byte{8});
            if(fault==7)change(bad,{0xa0,3,2,1,2,2,1,1},std::byte{});
            if(fault==8)bad.resize(8193);
            rejected([&](){e::require_identity_certificate_profile(bad,e::KeyPurpose::server,address);});
        }
        std::cout<<"enrollment_identity_profile=PASS structural_fixture=1 native_crypto_claim=0\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
