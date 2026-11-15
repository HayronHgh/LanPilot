#include "rwn/core/enrollment_pairing.hpp"
#include "rwn/core/content_hash.hpp"
#include <algorithm>
#include <cstring>

namespace rwn::core::enrollment {
namespace {
bool zero(std::span<const std::byte> value){return std::ranges::all_of(value,[](auto b){return b==std::byte{};});}
[[noreturn]] void invalid(){throw std::invalid_argument("invalid pairing public exchange");}
void append(Bytes& to,std::span<const std::byte> from){to.insert(to.end(),from.begin(),from.end());}
void u32(Bytes& to,std::uint32_t v){for(int shift=24;shift>=0;shift-=8)to.push_back(static_cast<std::byte>(v>>shift));}
std::uint32_t u32(std::span<const std::byte> value){std::uint32_t n{};for(auto b:value)n=(n<<8)|std::to_integer<unsigned>(b);return n;}
bool host(PairRole role){if(role!=PairRole::host && role!=PairRole::client)invalid();return role==PairRole::host;}
Bytes hello_bytes(const PairHello& hello){
    Bytes out{static_cast<std::byte>(hello.role)};append(out,hello.nonce);append(out,hello.identity_key);
    append(out,hello.authority_key);append(out,hello.root_sha256);append(out,hello.desktop_ipv4);
    out.push_back(static_cast<std::byte>(hello.desktop_port>>8));out.push_back(static_cast<std::byte>(hello.desktop_port));return out;
}
PairHello parse_hello(std::span<const std::byte> bytes){
    if(bytes.size()!=199)invalid();
    PairHello out{};out.role=static_cast<PairRole>(bytes[0]);
    std::size_t offset=1;
    auto copy=[&](auto& field){std::copy_n(bytes.begin()+static_cast<std::ptrdiff_t>(offset),field.size(),field.begin());offset+=field.size();};
    copy(out.nonce);copy(out.identity_key);copy(out.authority_key);copy(out.root_sha256);copy(out.desktop_ipv4);
    out.desktop_port=static_cast<std::uint16_t>(u32(bytes.subspan(offset,2)));return out;
}
void validate(const PairHello& h,Signer& signer){
    if(zero(h.nonce) || !signer.accepts_public_key(h.identity_key))invalid();
    if(host(h.role)){
        const auto a=std::to_integer<unsigned>(h.desktop_ipv4[0]),b=std::to_integer<unsigned>(h.desktop_ipv4[1]);
        if(h.authority_key==h.identity_key || !signer.accepts_public_key(h.authority_key) || zero(h.root_sha256) || h.desktop_port<1024 ||
           !(a==10 || a==127 || (a==172 && b>=16 && b<=31) || (a==192 && b==168)))invalid();
    }else if(!zero(h.authority_key) || !zero(h.root_sha256) || !zero(h.desktop_ipv4) || h.desktop_port!=0)invalid();
}
PairTranscript transcript(const PairHello& local,const PairHello& peer){
    PairTranscript out{host(local.role)?local:peer,host(local.role)?peer:local,{}};
    constexpr std::string_view domain="LanPilot first-contact transcript v1";
    auto bytes=Bytes(std::as_bytes(std::span{domain}).begin(),std::as_bytes(std::span{domain}).end());
    bytes.push_back(std::byte{});append(bytes,hello_bytes(out.host));append(bytes,hello_bytes(out.client));
    const auto hash=core::sha256(bytes);std::memcpy(out.binding.data(),hash.data(),hash.size());return out;
}
}
std::array<std::byte,64> pairing_signature_raw(std::span<const std::byte> der){
    if(der.size()<8 || der.size()>72 || der[0]!=std::byte{0x30} || std::to_integer<unsigned>(der[1])!=der.size()-2)invalid();
    std::array<std::byte,64> out{};std::size_t offset=2;
    for(unsigned part=0;part<2;++part){
        if(offset+2>der.size() || der[offset++]!=std::byte{2})invalid();
        const auto size=std::to_integer<unsigned>(der[offset++]);
        if(size==0 || size>33 || size>der.size()-offset || (std::to_integer<unsigned>(der[offset])&128)!=0 ||
           (size>1 && der[offset]==std::byte{} && (std::to_integer<unsigned>(der[offset+1])&128)==0))invalid();
        auto value=der.subspan(offset,size);offset+=size;
        if(value.size()==33){if(value.front()!=std::byte{})invalid();value=value.subspan(1);}
        if(zero(value))invalid();
        std::copy(value.begin(),value.end(),out.begin()+static_cast<std::ptrdiff_t>(part*32+32-value.size()));
    }
    if(offset!=der.size())invalid();
    return out;
}
std::size_t PairFrameReader::consume(std::span<const std::byte> input){
    if(failed_)invalid();
    std::size_t used{};
    try {
        while(used<input.size() && !ready()){
            const auto count=std::min(input.size()-used,target_-bytes_.size());
            append(bytes_,input.subspan(used,count));used+=count;
            if(bytes_.size()==16 && target_==16){
                if(std::memcmp(bytes_.data(),"LPP1",4)!=0 || bytes_[4]!=std::byte{1} || bytes_[6]!=std::byte{} || bytes_[7]!=std::byte{})invalid();
                const auto kind=std::to_integer<unsigned>(bytes_[5]),length=u32(std::span(bytes_).subspan(8,4));
                if(!((kind==1 && length==199) || ((kind==2 || kind==3) && length>=8 && length<=72)))invalid();
                target_=16+length;
            }
        }
        return used;
    }catch(...){failed_=true;throw;}
}
Bytes PairFrameReader::take(){if(!ready())invalid();auto out=bytes_;bytes_.clear();target_=16;return out;}
void PairFrameReader::eof(){if(failed_ || !bytes_.empty()){failed_=true;invalid();}}
PairingSession::PairingSession(PairHello local,Signer& signer,const PairProofVerifier& verifier,Clock::time_point now,std::chrono::seconds lifetime)
    :local_(local),signer_(signer),verifier_(verifier),created_(now),last_(now),lifetime_(lifetime){
    if(lifetime<=std::chrono::seconds::zero() || lifetime>std::chrono::seconds{120} || Clock::time_point::max()-lifetime<now)invalid();
    deadline_=now+lifetime;validate(local_,signer_);if(local_.identity_key!=signer_.public_key())invalid();
}
PairingSession::~PairingSession()=default;
[[noreturn]] void PairingSession::fail(){state_=State::failed;if(consent_)consent_->cancel(last_);invalid();}
void PairingSession::refresh(Clock::time_point now){
    if(state_==State::consumed || state_==State::denied || state_==State::cancelled || state_==State::expired || state_==State::failed)return;
    if(now<last_){state_=State::failed;if(consent_)consent_->cancel(last_);return;}
    last_=now;
    if(now>=deadline_){state_=State::expired;if(consent_)consent_->cancel(now);return;}
    if(consent_){
        const auto s=consent_->state(now);
        if(s==PairingConsent::State::denied)state_=State::denied;
        else if(s==PairingConsent::State::cancelled)state_=State::cancelled;
        else if(s==PairingConsent::State::expired)state_=State::expired;
        else if(s==PairingConsent::State::failed)state_=State::failed;
    }
}
void PairingSession::live(Clock::time_point now){refresh(now);if(state_!=State::exchanging && state_!=State::awaiting_comparison && state_!=State::ready_to_stage)invalid();}
bool PairingSession::comparison_ready()const{return transcript_ && proof_sent_ && proof_received_;}
bool PairingSession::local_allowed(Clock::time_point now){
    if(!consent_)return false;
    const auto s=consent_->state(now);
    return s==PairingConsent::State::awaiting_peer || s==PairingConsent::State::ready_to_persist;
}
Bytes PairingSession::signed_message(bool approval,PairRole role)const{
    if(!transcript_)invalid();
    const std::string domain=std::string("LanPilot pairing v1 ")+(approval?"approve ":"proof ")+(host(role)?"host":"client");
    Bytes out(std::as_bytes(std::span{domain}).begin(),std::as_bytes(std::span{domain}).end());out.push_back(std::byte{});
    append(out,std::as_bytes(std::span{transcript_->binding}));return out;
}
Bytes PairingSession::frame(std::uint8_t kind,std::span<const std::byte> payload){
    if(payload.empty() || payload.size()>199 || sent_>=3)fail();
    Bytes out{std::byte{'L'},std::byte{'P'},std::byte{'P'},std::byte{'1'},std::byte{1},static_cast<std::byte>(kind),std::byte{},std::byte{}};
    u32(out,static_cast<std::uint32_t>(payload.size()));u32(out,++sent_);append(out,payload);return out;
}
Bytes PairingSession::send_hello(Clock::time_point now){
    live(now);if(hello_sent_)fail();hello_sent_=true;return frame(1,hello_bytes(local_));
}
Bytes PairingSession::send_proof(Clock::time_point now){
    live(now);if(!hello_sent_ || !peer_ || proof_sent_)fail();
    try {auto signature=signer_.sign_sha256(signed_message(false,local_.role));(void)pairing_signature_raw(signature);
        proof_sent_=true;auto out=frame(2,signature);advance(now);return out;
    }catch(...){state_=State::failed;if(consent_)consent_->cancel(now);throw;}
}
void PairingSession::advance(Clock::time_point now){
    if(!comparison_ready())return;
    if(!consent_)consent_=std::make_shared<PairingConsent>(transcript_->binding,created_,lifetime_);
    if(approval_received_ && local_allowed(now) && consent_->state(now)==PairingConsent::State::awaiting_peer)
        if(!consent_->authenticated_peer_confirmed(transcript_->binding,now))fail();
    state_=(approval_sent_ && approval_received_ && local_allowed(now))?State::ready_to_stage:State::awaiting_comparison;
}
void PairingSession::receive(std::span<const std::byte> input,Clock::time_point now){
    live(now);
    try {
        if(input.size()<16 || input.size()>frame_limit || std::memcmp(input.data(),"LPP1",4)!=0 || input[4]!=std::byte{1} || input[6]!=std::byte{} || input[7]!=std::byte{} ||
           u32(input.subspan(8,4))!=input.size()-16 || u32(input.subspan(12,4))!=received_+1 || received_>=3)fail();
        const auto kind=std::to_integer<unsigned>(input[5]);const auto payload=input.subspan(16);
        if(received_==0){
            if(kind!=1 || !hello_sent_)fail();
            auto hello=parse_hello(payload);validate(hello,signer_);
            if(hello.role==local_.role || hello.nonce==local_.nonce || hello.identity_key==local_.identity_key)fail();
            if((host(hello.role)?hello.authority_key:local_.authority_key)==(host(hello.role)?local_.identity_key:hello.identity_key))fail();
            peer_=std::make_unique<PairHello>(hello);transcript_=std::make_unique<PairTranscript>(transcript(local_,hello));
        }else if(received_==1){
            if(kind!=2 || !peer_)fail();
            (void)pairing_signature_raw(payload);
            if(!verifier_.verify(peer_->identity_key,signed_message(false,peer_->role),payload))fail();
            proof_received_=true;
        }else{
            if(kind!=3 || !comparison_ready() || approval_received_)fail();
            (void)pairing_signature_raw(payload);
            if(!verifier_.verify(peer_->identity_key,signed_message(true,peer_->role),payload))fail();
            approval_received_=true;
        }
        ++received_;advance(now);
    }catch(...){state_=State::failed;if(consent_)consent_->cancel(now);throw;}
}
PairingConsent& PairingSession::consent_for_local_ui(Clock::time_point now){
    live(now);if(!comparison_ready() || !consent_)fail();return *consent_;
}
std::shared_ptr<PairingConsent> PairingSession::shared_consent_for_local_ui(Clock::time_point now){
    (void)consent_for_local_ui(now);return consent_;
}
void PairingSession::local_decision(bool allow,Clock::time_point now){
    auto& model=consent_for_local_ui(now);
    if(!model.local_decision(transcript_->binding,allow,now))fail();
    if(!allow){state_=State::denied;return;}advance(now);
}
Bytes PairingSession::send_local_approval(Clock::time_point now){
    live(now);if(!comparison_ready() || !local_allowed(now) || approval_sent_)fail();
    try {auto signature=signer_.sign_sha256(signed_message(true,local_.role));(void)pairing_signature_raw(signature);
        approval_sent_=true;auto out=frame(3,signature);advance(now);return out;
    }catch(...){state_=State::failed;if(consent_)consent_->cancel(now);throw;}
}
std::unique_ptr<ApprovedPairing> PairingSession::take_approved(Clock::time_point now){
    live(now);advance(now);if(state_!=State::ready_to_stage || !consent_->begin_persistence(transcript_->binding,now))fail();
    auto out=std::unique_ptr<ApprovedPairing>(new ApprovedPairing(*transcript_,local_.role,now,deadline_));state_=State::consumed;return out;
}
void PairingSession::cancel(Clock::time_point now){
    refresh(now);if(state_==State::exchanging || state_==State::awaiting_comparison || state_==State::ready_to_stage){state_=State::cancelled;if(consent_)consent_->cancel(now);}
}
PairingSession::State PairingSession::state(Clock::time_point now){refresh(now);return state_;}
} // namespace rwn::core::enrollment
