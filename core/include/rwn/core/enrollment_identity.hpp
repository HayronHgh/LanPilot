#pragma once
#include "rwn/core/enrollment_key.hpp"
#include "rwn/core/enrollment_pairing.hpp"
#include "rwn/core/content_hash.hpp"
#include <optional>

namespace rwn::core::enrollment {
// Public objects only; no imported private key or remote path is permitted.
struct PublicIdentityBundle {
    Bytes root,server,client,crl,server_ocsp,client_ocsp;
};
struct AssociatedIdentity {
    KeyReference key;
    PublicKey subject_key;
    Sha256Digest certificate_sha256;
    std::array<std::byte,4> server_ipv4;
    // Windows:20-byte CurrentUser/My lookup hash. Mac:bounded app-owned public
    // certificate/key description. Neither is a private key or authorization.
    Bytes native_reference;
    Bytes certificate_der;
    bool created{};
};
// Same paired device keys, fresh certificates. Only the authenticated status
// reader may construct this; it neither revives consent nor grants a session.
class RenewedIdentity final {
public:
    const PairTranscript& transcript()const{return transcript_;}
    const PublicIdentityBundle& bundle()const{return bundle_;}
    PairRole role()const{return role_;}
    bool valid_at(Time now)const{return now<expires_;}
private:
    friend class EnrollmentStatus;
    RenewedIdentity(PairTranscript t,PublicIdentityBundle b,PairRole r,Time expires)
        :transcript_(std::move(t)),bundle_(std::move(b)),role_(r),expires_(expires){}
    PairTranscript transcript_;PublicIdentityBundle bundle_;PairRole role_;Time expires_;
};
class IdentityStore {
public:
    virtual ~IdentityStore()=default;
    // Controller holds its protected enrollment lease/pending journal. This
    // associates a public leaf with an EXISTING local nonexportable key only.
    // Both chains/revocation proofs and the full approval binding are verified
    // before any store mutation; it still does not activate a desktop pairing.
    virtual AssociatedIdentity associate(const ApprovedPairing&,const KeyReference&,
        PublicIdentityBundle,PairingConsent::Clock::time_point)=0;
    virtual AssociatedIdentity associate_renewed(const RenewedIdentity&,const KeyReference&){throw std::runtime_error("native credential renewal unavailable");}
    virtual bool key_ready(const KeyReference&,const PublicKey&){return false;}
    // Public native lookup descriptor only. Does not require the old leaf to
    // be time-valid or stored; actual renewed identity must prove possession.
    virtual Bytes describe(const KeyReference& key,Bytes certificate,std::array<std::byte,4> ip){
        auto found=locate(key,std::move(certificate),ip);if(!found)throw std::runtime_error("identity descriptor unavailable");return found->native_reference;
    }
    virtual bool ready(const AssociatedIdentity&)=0; // no consent/key generation
    // Read-only reconciliation for a protected write-ahead record after an
    // interruption between native add and saving the returned opaque reference.
    virtual std::optional<AssociatedIdentity> locate(const KeyReference&,Bytes certificate,
        std::array<std::byte,4> server_ipv4)=0;
    // Strict scoped absence check for write-ahead recovery. False includes
    // collision, partial association, unavailable store or lookup error; a
    // failed locate() alone must NEVER authorize deleting its private key.
    virtual bool certificate_absent(std::span<const std::byte>){return false;}
    // Roll back only a newly created exact certificate/key association. Reused
    // certificates, private keys and roots are never removed by this method.
    virtual bool remove_created(const AssociatedIdentity&)=0;
    // Native positive chain/revocation check only. The controller separately
    // pins the unchanged root/leaves. Supplied time affects this trust object,
    // never the OS clock or a TLS session; zero means native current time.
    virtual bool verify_revocation(const PublicIdentityBundle&,std::array<std::byte,4>,Time={}){return false;}
};

// Shared bounded profile checks. Native adapters ALSO perform real X.509 TLS
// chain, time, hostname and positive revocation verification. No custom EC math
// or trust verifier is implemented here. Bundle is owned by associate() so a
// network reader cannot swap its bytes after validation.
void require_approved_identity_bundle(const ApprovedPairing&,const KeyReference&,
    const PublicIdentityBundle&,const PublicKey& local_key,PairingConsent::Clock::time_point);
void require_identity_certificate_profile(std::span<const std::byte>,KeyPurpose,
    const std::array<std::byte,4>& server_ipv4={});
struct CertificateFacts {Serial serial;Validity validity;PublicKey subject_key;};
// Bounded facts from this project's canonical DER profile, not a trust check.
CertificateFacts certificate_facts(std::span<const std::byte>,KeyPurpose,
    const std::array<std::byte,4>& server_ipv4={});
void require_renewed_identity(const RenewedIdentity&,const KeyReference&,const PublicKey&,Time);
// Exact bounded OCSP profile emitted by our native issuer. Uses the supplied
// native verifier for signature checking; the caller must ALSO evaluate the
// native certificate chain/revocation policy. Prevents OS caches from masking
// stale or damaged supplied evidence, including historical fixture dates.
void require_good_ocsp(std::span<const std::byte> response,std::span<const std::byte> root,
    const Serial&,const PublicKey& authority,const PairProofVerifier&,Time);
} // namespace rwn::core::enrollment
