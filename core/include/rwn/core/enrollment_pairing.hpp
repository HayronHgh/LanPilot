#pragma once
#include "rwn/core/enrollment_certificate.hpp"
#include "rwn/core/pairing_consent.hpp"
#include <memory>

namespace rwn::core::enrollment {
enum class PairRole : std::uint8_t { host=1,client=2 };
struct PairHello {
    PairRole role;
    std::array<std::byte,32> nonce;
    PublicKey identity_key;
    // Host supplies its LOCAL authority, root hash and desktop endpoint. Client
    // must send zero in these fields. No certificate/path/capability is accepted.
    PublicKey authority_key{};
    std::array<std::byte,32> root_sha256{};
    std::array<std::byte,4> desktop_ipv4{};
    std::uint16_t desktop_port{};
    bool operator==(const PairHello&)const=default;
};
class PairProofVerifier {
public:
    virtual ~PairProofVerifier()=default;
    virtual bool verify(const PublicKey&,std::span<const std::byte> message,
                        std::span<const std::byte> der_signature)const=0;
};

// Canonical signature decoder for the native CNG/Security verifier. Invalid,
// nonminimal, negative, zero, trailing or overflowing integers throw.
std::array<std::byte,64> pairing_signature_raw(std::span<const std::byte> der);

struct PairTranscript {
    PairHello host,client;
    PairingConsent::Binding binding;
};

// One bounded frame at a time. consume() reports how many stream bytes it used;
// caller retains/retries the remainder after take(). No peer length controls an
// allocation above 215 bytes, even when TCP coalesces multiple complete frames.
class PairFrameReader final {
public:
    PairFrameReader(){bytes_.reserve(215);}
    std::size_t consume(std::span<const std::byte>);
    bool ready()const{return !failed_ && bytes_.size()==target_ && target_>16;}
    Bytes take();
    void eof();
private:
    Bytes bytes_;std::size_t target_{16};bool failed_{};
};

// This is approval to STAGE an enrollment, not an authenticated TLS peer,
// persisted pairing, desktop grant or an input capability. Only a session with
// native key proofs AND explicit local/full-binding comparison can create it.
// Controller must durably complete BOTH ends before admitting desktop traffic.
class ApprovedPairing final {
public:
    const PairTranscript& transcript()const{return transcript_;}
    PairRole local_role()const{return local_;}
    bool valid_at(PairingConsent::Clock::time_point now)const{return now>=created_ && now<deadline_;}
    ApprovedPairing(const ApprovedPairing&)=delete;
    ApprovedPairing& operator=(const ApprovedPairing&)=delete;
private:
    friend class PairingSession;
    ApprovedPairing(PairTranscript t,PairRole r,PairingConsent::Clock::time_point created,
                    PairingConsent::Clock::time_point deadline):transcript_(t),local_(r),created_(created),deadline_(deadline){}
    PairTranscript transcript_;PairRole local_;
    PairingConsent::Clock::time_point created_,deadline_;
};

// Single-threaded session owner; its mutex-protected consent model may be shown
// by the existing native UI. Never expose that model or these methods to RPC.
// The caller supplies a fresh OS CSPRNG nonce and LOCAL key/root/endpoint data.
// Public exchange framing carries neither private keys nor desktop payloads.
class PairingSession final {
public:
    using Clock=PairingConsent::Clock;
    enum class State { exchanging,awaiting_comparison,ready_to_stage,consumed,denied,cancelled,expired,failed };
    PairingSession(PairHello local,Signer&,const PairProofVerifier&,Clock::time_point,
                   std::chrono::seconds lifetime=std::chrono::seconds{120});
    ~PairingSession();
    Bytes send_hello(Clock::time_point);
    Bytes send_proof(Clock::time_point);
    void receive(std::span<const std::byte> complete_frame,Clock::time_point);
    PairingConsent& consent_for_local_ui(Clock::time_point);
    // Pins only the thread-safe local UI model across asynchronous native
    // dialogs. The session/keys can finish after cancelling without a stale UI
    // pointer. This is not approval or transport admission.
    std::shared_ptr<PairingConsent> shared_consent_for_local_ui(Clock::time_point);
    // Only local UI may call this; the native consent dialog can alternatively
    // set the same model directly, then the owner calls send_local_approval.
    void local_decision(bool allow,Clock::time_point);
    Bytes send_local_approval(Clock::time_point);
    std::unique_ptr<ApprovedPairing> take_approved(Clock::time_point);
    void cancel(Clock::time_point);
    State state(Clock::time_point);
    static constexpr std::size_t frame_limit=215; //16 header +199 fixed hello
private:
    [[noreturn]] void fail();
    void refresh(Clock::time_point);
    void live(Clock::time_point);
    void advance(Clock::time_point);
    bool comparison_ready()const;
    bool local_allowed(Clock::time_point);
    Bytes signed_message(bool approval,PairRole)const;
    Bytes frame(std::uint8_t kind,std::span<const std::byte> payload);
    PairHello local_;
    Signer& signer_;const PairProofVerifier& verifier_;
    Clock::time_point created_,last_,deadline_;std::chrono::seconds lifetime_;
    State state_{State::exchanging};
    std::unique_ptr<PairHello> peer_;
    std::shared_ptr<PairingConsent> consent_;
    std::unique_ptr<PairTranscript> transcript_;
    std::uint32_t sent_{},received_{};
    bool hello_sent_{},proof_sent_{},proof_received_{},approval_sent_{},approval_received_{};
};
} // namespace rwn::core::enrollment
