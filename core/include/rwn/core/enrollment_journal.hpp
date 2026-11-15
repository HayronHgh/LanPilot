#pragma once
#include "rwn/core/enrollment_identity.hpp"

namespace rwn::core::enrollment {
// Local write-ahead state ONLY. None of these phases admits a desktop peer.
// Prepared/commit decisions belong to the later authenticated two-end protocol;
// such records must never be added here with unilateral rollback semantics.
enum class EnrollmentPhase : std::uint8_t { keys=1,association_intent=2,staged=3 };
struct EnrollmentKeyIntent {
    KeyReference reference;
    bool existed{};
    PublicKey point{}; // zero only before a newly-owned native create completes
};
struct EnrollmentRecord {
    std::array<std::byte,32> transaction{}; // local OS CSPRNG, never a peer path
    std::uint64_t revision{};
    PairRole role{};
    EnrollmentPhase phase{EnrollmentPhase::keys};
    std::vector<EnrollmentKeyIntent> keys;
    PairingConsent::Binding approval_binding{};
    std::array<std::byte,4> server_ipv4{};
    bool certificate_existed{};
    PublicIdentityBundle bundle;
};
inline constexpr std::size_t enrollment_record_cap=134144;
inline constexpr std::size_t enrollment_storage_cap=138240; // LPJ1 or closed LPJ2
inline constexpr std::size_t enrollment_abort_history_cap=128;
Bytes encode_enrollment_record(const EnrollmentRecord&);
EnrollmentRecord decode_enrollment_record(std::span<const std::byte>);

// Owns the native cross-process lease until destruction. Uses fixed filenames,
// protected local storage and atomic durable replace, not a network path. Save
// requires revision 1 for creation or exactly old+1 for the same transaction.
class EnrollmentJournal {
public:
    virtual ~EnrollmentJournal()=default;
    virtual std::optional<EnrollmentRecord> load()=0;
    virtual void save(const EnrollmentRecord&)=0;
    virtual void clear(const std::array<std::byte,32>& transaction)=0;
};
struct EnrollmentConfigurationLayout {
    enum class Kind { windows_client,macos_host } kind;
    std::string profile_path,trust_directory;
};

// Native implementations provide protected fixed-file I/O and hold the lease.
// This shared layer enforces bounded canonical records and compare-and-replace
// revisions. The checksum detects damage; OS ownership/ACLs provide protection.
class FileEnrollmentJournal:public EnrollmentJournal {
public:
    std::optional<EnrollmentRecord> load()final;
    void save(const EnrollmentRecord&)final;
    void clear(const std::array<std::byte,32>&)final;
protected:
    friend class DurablePairing;
    friend class EnrollmentConfigurationHandoff;
    friend class EnrollmentStatus;
    friend class CredentialInstaller;
    virtual std::optional<Bytes> read_record()=0;
    virtual void replace_record(std::span<const std::byte>)=0;
    virtual void remove_record()=0;
    virtual std::optional<Bytes> read_abort(const std::array<std::byte,32>&){throw std::runtime_error("abort history unavailable");}
    virtual void store_abort(const std::array<std::byte,32>&,std::span<const std::byte>){throw std::runtime_error("abort history unavailable");}
    virtual std::optional<Bytes> read_status(){throw std::runtime_error("native status storage unavailable");}
    virtual void store_status(std::span<const std::byte>){throw std::runtime_error("native status storage unavailable");}
    virtual std::optional<Bytes> read_credential(bool){throw std::runtime_error("credential journal unavailable");}
    virtual void store_credential(bool,std::span<const std::byte>){throw std::runtime_error("credential journal unavailable");}
    virtual void clear_credential(bool){throw std::runtime_error("credential journal unavailable");}
    // Fixed LOCAL product paths only; no peer filename or store selector. The
    // native backend borrows this object's lease for the whole publication.
    virtual EnrollmentConfigurationLayout configuration_layout(const Sha256Digest&){throw std::runtime_error("configuration backend unavailable");}
    virtual bool publish_configuration(const Sha256Digest&,const std::array<Bytes,6>&,
        std::span<const std::byte>){throw std::runtime_error("configuration backend unavailable");}
};

class EnrollmentStager final {
public:
    EnrollmentStager(EnrollmentJournal&,KeyStore&,IdentityStore&);
    // Record each absent/present key BEFORE creating anything. Host requires
    // authority+server, client requires client. Existing keys are never rekeyed.
    void begin(std::array<std::byte,32> local_transaction,PairRole,
               std::span<const KeyReference> local_references);
    void ensure_keys();
    AssociatedIdentity associate(const ApprovedPairing&,PublicIdentityBundle,
                                 PairingConsent::Clock::time_point);
    AssociatedIdentity associate_renewed(const RenewedIdentity&);
    // Reconcile a completed native add whose result was lost. No new key,
    // certificate, consent or admission is created; unresolved state stays put.
    std::optional<AssociatedIdentity> recover_staged();
    // Only pre-PREPARED staging can roll back. Deletes exact newly-owned
    // material only, never reused keys/certificates. Ambiguity retains journal.
    bool rollback();
private:
    friend class DurablePairing;
    static bool rollback_objects(const EnrollmentRecord&,KeyStore&,IdentityStore&);
    EnrollmentRecord record();
    void save(EnrollmentRecord&);
    EnrollmentJournal& journal_;KeyStore& keys_;IdentityStore& identities_;
};
} // namespace rwn::core::enrollment
