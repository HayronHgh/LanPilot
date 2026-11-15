// Real native ECDSA exchange fixture; no listener, consent automation, persistent
// identity, certificate store, pairing record, input, clipboard or screen access.
#include "enrollment_fixture_key.hpp"
#include "rwn/core/enrollment_pairing.hpp"
#include <iostream>
#include <source_location>
#if defined(_WIN32)
#include "rwn/platform/windows/enrollment_key.hpp"
#else
#include "rwn/platform/macos/enrollment_key.hpp"
#endif
namespace e=rwn::core::enrollment;
namespace {
void check(bool value,std::source_location at=std::source_location::current()){
    if(!value)throw std::runtime_error("native pairing fixture failed at line "+std::to_string(at.line()));
}
std::unique_ptr<e::PairProofVerifier> verifier(){
#if defined(_WIN32)
    return rwn::platform::windows::enrollment_pairing_verifier();
#else
    return rwn::platform::macos::enrollment_pairing_verifier();
#endif
}
void random(std::span<std::byte> bytes){
#if defined(_WIN32)
    check(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(bytes.data()),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0);
#else
    check(SecRandomCopyBytes(kSecRandomDefault,bytes.size(),reinterpret_cast<std::uint8_t*>(bytes.data()))==errSecSuccess);
#endif
}
struct Record{e::PublicKey key;e::Bytes message,signature;};
struct Recorder final:e::Signer {
    rwn::probe::EphemeralSigner inner;std::vector<Record> signed_data;
    e::PublicKey public_key()const override{return inner.public_key();}
    bool accepts_public_key(const e::PublicKey& key)const override{return inner.accepts_public_key(key);}
    e::Bytes sign_sha256(std::span<const std::byte> bytes)override{
        const auto result=inner.sign_sha256(bytes);signed_data.push_back({public_key(),{bytes.begin(),bytes.end()},result});return result;
    }
};
void append(e::Bytes& to,std::span<const std::byte> value){to.insert(to.end(),value.begin(),value.end());}
void sized(e::Bytes& out,std::span<const std::byte> bytes){check(bytes.size()<=512);out.push_back(static_cast<std::byte>(bytes.size()>>8));out.push_back(static_cast<std::byte>(bytes.size()));append(out,bytes);}
e::Bytes run_fixture(){
    using namespace std::chrono;Recorder host,client;rwn::probe::EphemeralSigner authority;auto native=verifier();
    e::PairHello h{},c{};h.role=e::PairRole::host;c.role=e::PairRole::client;random(h.nonce);random(c.nonce);
    h.identity_key=host.public_key();c.identity_key=client.public_key();h.authority_key=authority.public_key();
    e::Serial serial{};random(serial);const auto wall=floor<seconds>(system_clock::now());
    const auto root=e::root_certificate(authority,serial,{wall-minutes{1},wall+days{30}});h.root_sha256=rwn::core::sha256(root);
    h.desktop_ipv4={std::byte{127},std::byte{},std::byte{},std::byte{1}};h.desktop_port=45443;
    const auto now=e::PairingSession::Clock::now();e::PairingSession a(h,host,*native,now),b(c,client,*native,now);
    const auto hf=a.send_hello(now),cf=b.send_hello(now);a.receive(cf,now);b.receive(hf,now);
    const auto hp=a.send_proof(now),cp=b.send_proof(now);a.receive(cp,now);b.receive(hp,now);
    const auto binding=a.consent_for_local_ui(now).binding();check(binding==b.consent_for_local_ui(now).binding());
    // Explicit synthetic decisions, never calls a native user dialog or feeds
    // an RPC boolean to authenticated_peer_confirmed(). Session verifies proof.
    a.local_decision(true,now);b.local_decision(true,now);const auto ha=a.send_local_approval(now),ca=b.send_local_approval(now);
    a.receive(ca,now);b.receive(ha,now);auto approved=a.take_approved(now);auto other=b.take_approved(now);
    check(approved->transcript().binding==other->transcript().binding && approved->valid_at(now));
    e::Bytes out{std::byte{'L'},std::byte{'P'},std::byte{'F'},std::byte{'1'}};
    sized(out,hf);sized(out,cf);append(out,std::as_bytes(std::span{binding}));
    const std::array<const Record*,4> records{&host.signed_data.at(0),&client.signed_data.at(0),&host.signed_data.at(1),&client.signed_data.at(1)};
    for(const auto* record:records){append(out,record->key);sized(out,record->message);sized(out,record->signature);}
    check(out.size()<=4096);return out;
}
void verify_fixture(std::span<const std::byte> input){
    check(input.size()<=4096 && input.size()>4 && std::memcmp(input.data(),"LPF1",4)==0);std::size_t offset=4;
    auto read=[&](std::size_t size){check(size<=input.size()-offset);auto out=input.subspan(offset,size);offset+=size;return out;};
    auto sized_read=[&](){const auto n=read(2);const auto size=(std::to_integer<unsigned>(n[0])<<8)|std::to_integer<unsigned>(n[1]);check(size<=512);return read(size);};
    const auto h=sized_read(),c=sized_read();
    for(const auto frame:{h,c}){
        e::PairFrameReader reader;check(reader.consume(frame)==frame.size() && reader.ready() && reader.take().size()==215);
        check(frame[12]==std::byte{} && frame[13]==std::byte{} && frame[14]==std::byte{} && frame[15]==std::byte{1});
    }
    check(h[16]==std::byte{1} && c[16]==std::byte{2});
    constexpr std::string_view domain="LanPilot first-contact transcript v1";
    e::Bytes transcript(std::as_bytes(std::span{domain}).begin(),std::as_bytes(std::span{domain}).end());transcript.push_back(std::byte{});
    append(transcript,h.subspan(16));append(transcript,c.subspan(16));const auto expected_binding=rwn::core::sha256(transcript);
    const auto binding=read(32);check(std::ranges::equal(expected_binding,binding));auto native=verifier();
    for(unsigned i=0;i<4;++i){
        const auto key_bytes=read(64);e::PublicKey key{};std::copy(key_bytes.begin(),key_bytes.end(),key.begin());
        check(std::ranges::equal(key_bytes,(i%2==0?h:c).subspan(49,64)));
        const auto message=sized_read(),signature=sized_read();
        const std::string prefix=std::string("LanPilot pairing v1 ")+(i<2?"proof ":"approve ")+(i%2==0?"host":"client");
        e::Bytes expected(std::as_bytes(std::span{prefix}).begin(),std::as_bytes(std::span{prefix}).end());expected.push_back(std::byte{});append(expected,binding);
        check(std::ranges::equal(message,expected) && native->verify(key,message,signature));
        auto changed=e::Bytes(message.begin(),message.end());changed.back()^=std::byte{1};check(!native->verify(key,changed,signature));
        auto bad=e::Bytes(signature.begin(),signature.end());bad.back()^=std::byte{1};check(!native->verify(key,message,bad));
    }
    check(offset==input.size());
}
}
int main(int argc,char** argv){
    try {
        if(argc==2 && std::string_view(argv[1])=="--verify-public-fixture"){
            e::Bytes bytes;unsigned pending=16;std::size_t chars{};
            for(char ch;std::cin.get(ch);){
                if(ch=='\r'){check(std::cin.get()=='\n' && std::cin.peek()==std::char_traits<char>::eof());break;}
                if(ch=='\n'){check(std::cin.peek()==std::char_traits<char>::eof());break;}
                check(++chars<=8192);const unsigned value=(ch>='0' && ch<='9')?static_cast<unsigned>(ch-'0'):(ch>='a' && ch<='f')?static_cast<unsigned>(ch-'a'+10):16;
                check(value<16);if(pending==16)pending=value;else{bytes.push_back(static_cast<std::byte>((pending<<4)|value));pending=16;}
            }
            check(pending==16 && !bytes.empty());verify_fixture(bytes);
            std::cout<<"pairing_cross_native=PASS public_only=1 keys_created=0 stores_changed=0 desktop_grants=0\n";return 0;
        }
        check(argc==1 || (argc==2 && std::string_view(argv[1])=="--emit-public-fixture"));
        const auto fixture=run_fixture();verify_fixture(fixture);
        if(argc==2){for(auto byte:fixture){const auto n=std::to_integer<unsigned>(byte);std::cout<<"0123456789abcdef"[n>>4]<<"0123456789abcdef"[n&15];}std::cout<<'\n';}
        else std::cout<<"enrollment_native_pairing=PASS native_proof=1 two_fixture_approvals=1 ephemeral_keys=3 stores_changed=0 desktop_grants=0\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
