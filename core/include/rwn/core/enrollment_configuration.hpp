#pragma once
#include "rwn/core/enrollment_commit.hpp"

namespace rwn::core::enrollment {
struct EnrollmentConfigurationReceipt {
    std::string profile_path;
    Sha256Digest profile_sha256,resource_generation;
    bool created{};
};
class EnrollmentConfigurationHandoff final {
public:
    // Actual native protected write, not a filesystem-authority message. The
    // LPJ2 proof stays durable for recovery. Existing different config fails
    // closed; no identity, grant, installed service or old profile is replaced.
    static EnrollmentConfigurationReceipt persist(FileEnrollmentJournal&,
        const PersistablePairing&,IdentityStore&,const PairProofVerifier&);
    // Startup repair from the protected LPJ2 record, without an in-memory UI
    // approval or remembered receipt. Never decides commit/rekeys. A known
    // accepted decision can drain; incomplete/aborted pairing returns empty.
    static std::optional<EnrollmentConfigurationReceipt> recover(FileEnrollmentJournal&,
        KeyStore&,IdentityStore&,const PairProofVerifier&);
};
inline constexpr std::array<const char*,6> enrollment_resource_names{
    "root.der","server.der","client.der","revocation.der","server-ocsp.der","client-ocsp.der"};
} // namespace rwn::core::enrollment
