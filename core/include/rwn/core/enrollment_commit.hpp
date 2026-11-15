#pragma once
#include "rwn/core/enrollment_journal.hpp"

namespace rwn::core::enrollment {
enum class CommitReceiptKind:std::uint8_t {
    host_prepared=1,client_prepared=2,commit_decision=3,
    client_committed=4,host_committed=5,abort_decision=6
};
struct EnrollmentCommitRecord {
    std::uint64_t revision{};
    EnrollmentRecord staged;
    PairTranscript transcript;
    std::array<std::byte,32> round{}; // host's durable local random transaction
    std::array<Bytes,6> receipts;
    bool aborted_objects_removed{};
};
inline constexpr std::size_t commit_receipt_cap=207;
// Closed, bounded wire receipt reader: one frame, partial/coalesced TCP input,
// no peer-sized allocation, EOF fails closed. Unrelated to desktop RWC1/RWV2.
class CommitReceiptReader final {
public:
    CommitReceiptReader(){bytes_.reserve(commit_receipt_cap);}
    std::size_t consume(std::span<const std::byte>);
    bool ready()const{return !failed_ && target_>135 && bytes_.size()==target_;}
    Bytes take();void eof();
private:Bytes bytes_;std::size_t target_{135};bool failed_{};
};
Bytes encode_enrollment_commit(const EnrollmentCommitRecord&);
EnrollmentCommitRecord decode_enrollment_commit(std::span<const std::byte>,const PairProofVerifier&);

// Proof for SAVING connection configuration, not a current TLS authorization,
// desktop capability, physical connection, scan-out or OS permission grant.
class PersistablePairing final {
public:
    const EnrollmentCommitRecord& record()const{return record_;}
    const AssociatedIdentity& local_identity()const{return identity_;}
    bool descriptor_only()const{return descriptor_only_;} // Saving bootstrap settings only; never TLS admission.
private:
    friend class DurablePairing;
    friend class EnrollmentConfigurationHandoff;
    PersistablePairing(EnrollmentCommitRecord r,AssociatedIdentity i):record_(std::move(r)),identity_(std::move(i)){}
    PersistablePairing(EnrollmentCommitRecord r,AssociatedIdentity i,bool key_only):record_(std::move(r)),identity_(std::move(i)),descriptor_only_(key_only){}
    EnrollmentCommitRecord record_;AssociatedIdentity identity_;bool descriptor_only_{};
};

// One owner, under FileEnrollmentJournal's existing native product lease.
// LPJ1->LPJ2 atomic handoff permanently disables LPJ1 unilateral rollback.
// Every outgoing signed receipt is persisted BEFORE it can be returned.
class DurablePairing final {
public:
    using Clock=PairingConsent::Clock;
    static std::unique_ptr<DurablePairing> prepare(FileEnrollmentJournal&,
        std::unique_ptr<ApprovedPairing>,Signer&,IdentityStore&,const PairProofVerifier&,
        Clock::time_point,std::span<const std::byte> host_prepared={});
    // Reopens public receipts, not expired native consent. A resumed host may
    // replay an existing decision or abort; it cannot create a new commit.
    static std::unique_ptr<DurablePairing> resume(FileEnrollmentJournal&,Signer*,
        IdentityStore&,const PairProofVerifier&);
    // Validated read only. LPJ1 remains pre-PREPARED and is not a receipt.
    static std::optional<EnrollmentCommitRecord> inspect(FileEnrollmentJournal&,
        const PairProofVerifier&);
    // Only an irrevocable signed abort can retire. Preserve its public proof
    // durably before clearing the active slot; owned-object cleanup is restartable.
    static void retire_abort(FileEnrollmentJournal&,KeyStore&,IdentityStore&,const PairProofVerifier&);
    static std::optional<EnrollmentCommitRecord> archived_abort(FileEnrollmentJournal&,
        const std::array<std::byte,32>& round,const PairProofVerifier&);
    void receive(std::span<const std::byte> complete_receipt);
    void decide_commit(Clock::time_point); // host, live original approval only
    void decide_abort(); // host, only BEFORE durable commit decision
    void advance(); // drain an already accepted decision without future input
    std::vector<Bytes> outgoing()const; // bounded idempotent replay, exact bytes
    std::optional<PersistablePairing> persistable();
    bool cleanup_aborted(KeyStore&); // signed abort required; retains its proof
    const EnrollmentCommitRecord& record()const{return record_;}
private:
    DurablePairing(FileEnrollmentJournal&,Signer*,IdentityStore&,const PairProofVerifier&);
    void save(EnrollmentCommitRecord);
    bool require_local_identity(); // true: recovered bootstrap descriptor only
    FileEnrollmentJournal& file_;Signer* signer_;IdentityStore& identities_;const PairProofVerifier& verifier_;
    EnrollmentCommitRecord record_{};Bytes last_bytes_;
    std::unique_ptr<ApprovedPairing> approval_;
};
} // namespace rwn::core::enrollment
