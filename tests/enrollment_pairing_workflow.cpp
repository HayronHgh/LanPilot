#include "rwn/core/enrollment_pairing.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/core/release_compatibility.hpp"
#include "test_support.hpp"
#include <iostream>
#include <algorithm>
namespace e=rwn::core::enrollment;
using namespace std::chrono_literals;
using Session=e::PairingSession;
namespace {
// Deliberately non-cryptographic deterministic workflow fixture. Real ECDSA is
// exercised by the OS-native key probe, never by this fake verification rule.
e::Bytes fixture_signature(const e::PublicKey& point,std::span<const std::byte> message){
    e::Bytes input(point.begin(),point.end());input.insert(input.end(),message.begin(),message.end());
    auto digest=rwn::core::sha256(input);digest[0]&=std::byte{0x7f};digest[0]|=std::byte{1};
    std::array<std::byte,64> raw{};std::copy(digest.begin(),digest.end(),raw.begin());std::copy(digest.begin(),digest.end(),raw.begin()+32);
    return rwn::core::ecdsa_p256_signature_der(raw);
}
struct Signer final:e::Signer {
    e::PublicKey point{};unsigned signs{};
    explicit Signer(unsigned id){point.fill(static_cast<std::byte>(id));}
    e::PublicKey public_key()const override{return point;}
    bool accepts_public_key(const e::PublicKey& p)const override{return std::ranges::any_of(p,[](auto b){return b!=std::byte{};});}
    e::Bytes sign_sha256(std::span<const std::byte> message)override{++signs;return fixture_signature(point,message);}
};
struct Verifier final:e::PairProofVerifier {
    bool verify(const e::PublicKey& p,std::span<const std::byte> m,std::span<const std::byte> s)const override {
        const auto expected=fixture_signature(p,m);return std::ranges::equal(expected,s);
    }
};
e::PairHello hello(bool host,unsigned salt=1){
    e::PairHello h{};h.role=host?e::PairRole::host:e::PairRole::client;
    h.nonce.fill(static_cast<std::byte>(salt+(host?1:2)));h.identity_key=Signer(host?5:7).point;
    if(host){h.authority_key=Signer(9).point;h.root_sha256.fill(std::byte{4});h.desktop_ipv4={std::byte{127},std::byte{},std::byte{},std::byte{1}};h.desktop_port=45443;}
    return h;
}
struct Fixture {
    Session::Clock::time_point now{};Signer a{5},b{7};Verifier verifier;
    Session host{hello(true),a,verifier,now},client{hello(false),b,verifier,now};
    void exchange(){auto h=host.send_hello(now),c=client.send_hello(now);host.receive(c,now);client.receive(h,now);
        h=host.send_proof(now);c=client.send_proof(now);host.receive(c,now);client.receive(h,now);}
};
template<class F>void rejected(F f){rwn::test::require_throws<std::invalid_argument>(f,"invalid public pairing exchange");}
void workflow(){
    {Fixture f;const auto frame=f.host.send_hello(f.now);e::PairFrameReader reader;
        for(const auto b:frame)RWN_CHECK(reader.consume(std::span{&b,1})==1);
        RWN_CHECK(reader.ready() && reader.take()==frame);reader.eof();
        e::Bytes joined=frame;joined.insert(joined.end(),frame.begin(),frame.end());
        const auto used=reader.consume(joined);RWN_CHECK(used==frame.size() && reader.take()==frame);
        RWN_CHECK(reader.consume(std::span(joined).subspan(used))==frame.size() && reader.take()==frame);}
    for(bool first:{false,true}){
        Fixture f;f.exchange();auto binding=f.host.consent_for_local_ui(f.now).binding();RWN_CHECK(binding==f.client.consent_for_local_ui(f.now).binding());
        f.host.local_decision(true,f.now);f.client.local_decision(true,f.now);
        const auto a=f.host.send_local_approval(f.now),b=f.client.send_local_approval(f.now);
        if(first){f.host.receive(b,f.now);f.client.receive(a,f.now);}else{f.client.receive(a,f.now);f.host.receive(b,f.now);}
        RWN_CHECK(f.host.state(f.now)==Session::State::ready_to_stage);auto result=f.host.take_approved(f.now+1s);
        RWN_CHECK(result->transcript().binding==binding && result->local_role()==e::PairRole::host && result->valid_at(f.now+1s));
        RWN_CHECK(!result->valid_at(f.now) && !result->valid_at(f.now+120s));
        auto client=f.client.take_approved(f.now+1s);RWN_CHECK(client->transcript().host==result->transcript().host);
        rejected([&](){f.host.take_approved(f.now+1s);});
    }
    {Fixture f;f.exchange();f.client.local_decision(true,f.now);const auto approval=f.client.send_local_approval(f.now);f.host.receive(approval,f.now);
        RWN_CHECK(f.host.state(f.now)==Session::State::awaiting_comparison);
        RWN_CHECK(f.host.consent_for_local_ui(f.now).state(f.now)==rwn::core::PairingConsent::State::awaiting_both);
        f.host.local_decision(true,f.now);(void)f.host.send_local_approval(f.now);RWN_CHECK(f.host.take_approved(f.now)!=nullptr);}
    {Fixture f;f.exchange();auto& native_model=f.host.consent_for_local_ui(f.now);
        RWN_CHECK(native_model.local_decision(native_model.binding(),true,f.now)); //existing native dialog handoff
        f.client.local_decision(true,f.now);f.host.receive(f.client.send_local_approval(f.now),f.now);(void)f.host.send_local_approval(f.now);
        RWN_CHECK(f.host.take_approved(f.now)!=nullptr);}
}
void security(){
    {Fixture f;auto frame=f.host.send_hello(f.now);e::PairFrameReader reader;
        frame[8]=std::byte{0x7f};rejected([&](){reader.consume(frame);});rejected([&](){reader.consume({});});}
    {e::PairFrameReader reader;const std::byte partial{'L'};reader.consume(std::span{&partial,1});rejected([&](){reader.eof();});}
    for(int fault=0;fault<10;++fault){
        Fixture f;auto h=f.host.send_hello(f.now),c=f.client.send_hello(f.now);
        if(fault==0)c[0]^=std::byte{1};
        if(fault==1)c[4]=std::byte{2};
        if(fault==2)c[6]=std::byte{1};
        if(fault==3)c[11]^=std::byte{1};
        if(fault==4)c[15]=std::byte{2};
        if(fault==5)c.push_back(std::byte{});
        if(fault==6)c=h;
        if(fault==7)c.resize(15);
        if(fault==8)c[16]=std::byte{99};
        if(fault==9)c[150]=std::byte{1};
        rejected([&](){f.host.receive(c,f.now);});RWN_CHECK(f.host.state(f.now)==Session::State::failed);
        rejected([&](){f.host.take_approved(f.now);});RWN_CHECK(f.a.signs==0);
    }
    for(int fault=0;fault<9;++fault){
        Fixture f;f.exchange();
        if(fault==0)f.host.local_decision(false,f.now);
        else if(fault==1)f.host.cancel(f.now);
        else if(fault==2)(void)f.host.state(f.now+120s);
        else if(fault==3)(void)f.host.state(f.now-1s);
        else if(fault==4){f.host.local_decision(true,f.now);rejected([&](){f.host.send_local_approval(f.now);f.host.send_local_approval(f.now);});}
        else if(fault==5){f.client.local_decision(true,f.now);auto b=f.client.send_local_approval(f.now);b.back()^=std::byte{1};rejected([&](){f.host.receive(b,f.now);});}
        else if(fault==6){f.client.local_decision(true,f.now);auto b=f.client.send_local_approval(f.now);b[5]=std::byte{2};rejected([&](){f.host.receive(b,f.now);});}
        else if(fault==7){auto& ui=f.host.consent_for_local_ui(f.now);ui.local_decision(ui.binding(),true,f.now);ui.authenticated_peer_confirmed(ui.binding(),f.now);
            (void)f.host.send_local_approval(f.now);RWN_CHECK(f.host.state(f.now)==Session::State::awaiting_comparison);}
        else{f.client.local_decision(true,f.now);const auto b=f.client.send_local_approval(f.now);f.host.receive(b,f.now);
            rejected([&](){f.host.receive(b,f.now);});}
        rejected([&](){f.host.take_approved(f.now+121s);});RWN_CHECK(f.host.state(f.now+121s)!=Session::State::ready_to_stage);
    }
    {Fixture f;rejected([&](){f.host.consent_for_local_ui(f.now);});}
    {Fixture old;old.exchange();old.client.local_decision(true,old.now);auto replay=old.client.send_local_approval(old.now);
        Signer a(5),b(7);Verifier v;Session fresh(hello(true,9),a,v,old.now),client(hello(false,9),b,v,old.now);
        auto h=fresh.send_hello(old.now),c=client.send_hello(old.now);fresh.receive(c,old.now);client.receive(h,old.now);
        h=fresh.send_proof(old.now);c=client.send_proof(old.now);fresh.receive(c,old.now);client.receive(h,old.now);
        rejected([&](){fresh.receive(replay,old.now);});}
    {Signer a(5);Verifier v;auto h=hello(true);h.identity_key=Signer(6).point;rejected([&](){Session s(h,a,v,{});});}
    {Signer a(5);Verifier v;rejected([&](){Session s(hello(true),a,v,{},121s);});}
    const e::Bytes good{std::byte{0x30},std::byte{6},std::byte{2},std::byte{1},std::byte{1},std::byte{2},std::byte{1},std::byte{1}};
    RWN_CHECK(e::pairing_signature_raw(good)[31]==std::byte{1});
    for(int fault=0;fault<7;++fault){auto der=good;
        if(fault==0)der[4]=std::byte{};
        if(fault==1)der[4]=std::byte{0x80};
        if(fault==2)der.push_back(std::byte{});
        if(fault==3)der[3]=std::byte{0x81};
        if(fault==4)der[2]=std::byte{3};
        if(fault==5)der.resize(7);
        if(fault==6)der[1]=std::byte{7};
        rejected([&](){e::pairing_signature_raw(der);});}
}
}
int main(){try{workflow();security();std::cout<<"enrollment_pairing=PASS signature_mode=workflow_fixture desktop_grants=0\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
