#pragma once
#include "rwn/core/enrollment_status.hpp"

namespace rwn::core::enrollment {
// Local native association transaction. Original consent/LPJ2/settings remain
// immutable. Only same-key, issuer-signed, currently native-valid credentials
// may reach this installer; no new key, trust root or desktop grant is created.
class CredentialInstaller final {
public:
    static AssociatedIdentity install(FileEnrollmentJournal&,KeyStore&,IdentityStore&,
        const PairProofVerifier&,Time);
};
}
