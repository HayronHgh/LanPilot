#pragma once
#include "rwn/core/enrollment_configuration.hpp"
#include <atomic>
#include <functional>

namespace rwn::core::enrollment {
// Public first-contact data only. Deliberately NOT ReliableStream/Transport or
// AuthenticatedConnection: cannot open desktop, input, clipboard or agent lanes.
class EnrollmentChannel {
public:
    virtual ~EnrollmentChannel()=default;
    struct Read {std::size_t bytes{};bool eof{};};
    virtual Read read(std::span<std::byte>,std::chrono::milliseconds)=0;
    virtual void write(std::span<const std::byte>,PairingConsent::Clock::time_point,
                       const std::atomic_bool& cancelled)=0;
    virtual void close()noexcept=0;
};
struct EnrollmentSetupCallbacks {
    // Native callback MUST return after scheduling local UI, pin the shared
    // model, and never translate a remote boolean into a local decision.
    std::function<void(std::shared_ptr<PairingConsent>)> show_comparison;
    std::function<void(std::span<std::byte>)> random;
    std::function<void(std::string_view)> progress;
};
struct EnrollmentEndpoint {std::array<std::byte,4> address;std::uint16_t port{45443};};
struct EnrollmentCertificateLifetimes {std::chrono::days root{3650},leaf{180};};
// Runs on a worker, one fresh pairing, existing real stores/lease. Both endpoints
// persist their configuration only after signed two-end durable completion.
// Nonempty journals require explicit recovery; never silently overwrite one.
EnrollmentConfigurationReceipt enroll_host(EnrollmentChannel&,FileEnrollmentJournal&,
    KeyStore&,IdentityStore&,const PairProofVerifier&,EnrollmentEndpoint,
    const EnrollmentSetupCallbacks&,const std::atomic_bool& cancelled,EnrollmentCertificateLifetimes lifetimes={});
EnrollmentConfigurationReceipt enroll_client(EnrollmentChannel&,FileEnrollmentJournal&,
    KeyStore&,IdentityStore&,const PairProofVerifier&,std::array<std::byte,4> expected_host,
    const EnrollmentSetupCallbacks&,const std::atomic_bool& cancelled);
// Explicit local retry only. Authenticates the exact saved peer with fresh
// native-key challenges, then replays durable receipts without new consent or
// a new commit decision. Returns no proof for a signed abort. Publication is a
// separate local operation; existing user settings must not be reset.
std::optional<PersistablePairing> recover_enrollment(EnrollmentChannel&,
    FileEnrollmentJournal&,KeyStore&,IdentityStore&,const PairProofVerifier&,
    std::array<std::byte,4> expected_host,const EnrollmentSetupCallbacks&,
    const std::atomic_bool& cancelled,bool keep_after_abort=false);
// Explicit local retry. An undecided host may sign an abort; no decided commit
// is replaced. Only a validated signed abort releases the active journal slot.
void prepare_enrollment_retry(FileEnrollmentJournal&,KeyStore&,IdentityStore&,
    const PairProofVerifier&,PairRole local_role);
} // namespace rwn::core::enrollment
