#pragma once
#include "rwn/core/enrollment_setup.hpp"

namespace rwn::core::enrollment {
struct StatusSnapshot {Bytes wire;PublicIdentityBundle bundle;Time issued,expires;};
// LPS1 renews revocation evidence;LPS2 may renew certificates for exactly the
// same paired authority/device keys. Neither changes permissions nor admits a
// session. The original enrollment remains the immutable bootstrap anchor.
class EnrollmentStatus final {
public:
    static StatusSnapshot issue(FileEnrollmentJournal&,KeyStore&,IdentityStore&,
        const PairProofVerifier&,Time now,bool renew_certificates=false);
    static StatusSnapshot accept(FileEnrollmentJournal&,IdentityStore&,
        const PairProofVerifier&,Bytes,Time now);
    static std::optional<StatusSnapshot> cached(FileEnrollmentJournal&,IdentityStore&,
        const PairProofVerifier&,Time now);
    static RenewedIdentity identity_proof(FileEnrollmentJournal&,IdentityStore&,
        const PairProofVerifier&,Time now);
    static Bytes connection_crl(FileEnrollmentJournal&,IdentityStore&,const PairProofVerifier&,
        std::span<const std::byte> root,std::span<const std::byte> server_sha256,
        std::span<const std::byte> local_reference,Time,std::function<Bytes()> fetch);
    static StatusSnapshot connection_credentials(FileEnrollmentJournal&,KeyStore&,IdentityStore&,const PairProofVerifier&,
        std::span<const std::byte> original_root,std::span<const std::byte> original_server_sha256,
        std::span<const std::byte> original_local_reference,Time,std::function<Bytes()> fetch);
};
inline constexpr std::size_t status_wire_cap=131104;
Bytes status_request(const EnrollmentCommitRecord&);
void serve_status(EnrollmentChannel&,FileEnrollmentJournal&,KeyStore&,IdentityStore&,
    const PairProofVerifier&,Time,const std::atomic_bool&);
StatusSnapshot fetch_status(EnrollmentChannel&,FileEnrollmentJournal&,IdentityStore&,
    const PairProofVerifier&,Time,const std::atomic_bool&);
Bytes exchange_status(EnrollmentChannel&,std::span<const std::byte> request,const std::atomic_bool&);
} // namespace rwn::core::enrollment
