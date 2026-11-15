#include "rwn/platform/windows/enrollment_status.hpp"
#include "rwn/platform/windows/enrollment_key.hpp"
#include "rwn/platform/windows/enrollment_identity.hpp"
#include "rwn/platform/windows/enrollment_journal.hpp"
#include "rwn/platform/enrollment_tcp.hpp"
#include "rwn/core/enrollment_status.hpp"
#include "rwn/core/enrollment_credentials.hpp"

namespace rwn::platform::windows {
SchannelFallbackClientOptions refresh_native_credentials(const SchannelFallbackClientOptions& options,const transport::TransportEndpoint& endpoint,core::CancellationToken stop){
    namespace e=core::enrollment;namespace tcp=platform::enrollment;
    auto check_stop=[&]{if(stop.stop_requested())throw transport::TlsTransportInterrupted(transport::TlsTransportInterrupted::Reason::cancelled,"credential refresh cancelled");};
    check_stop();std::atomic_bool cancelled{stop.stop_requested()};
    core::CancellationCallback cancellation(stop,[&]()noexcept{cancelled.store(true);});
    auto file=enrollment_journal();auto keys=enrollment_key_store();auto ids=enrollment_identity_store();auto verifier=enrollment_pairing_verifier();
    const auto saved=e::DurablePairing::inspect(*file,*verifier);const auto address=tcp::parse_private_ipv4(endpoint.host);
    if(!saved || saved->transcript.host.desktop_ipv4!=address || saved->transcript.host.desktop_port!=endpoint.port || options.allowed_server_certificate_sha256.size()!=1)
        throw std::runtime_error("saved native connection does not match this endpoint");
    const auto now=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    const auto snapshot=e::EnrollmentStatus::connection_credentials(*file,*keys,*ids,*verifier,options.exclusive_root_der,
        std::as_bytes(std::span{options.allowed_server_certificate_sha256.front()}),std::as_bytes(std::span{options.client_certificate_sha1}),now,[&]{
            check_stop();auto channel=tcp::connect(address,tcp::pairing_port,std::chrono::seconds{1},cancelled);
            return e::exchange_status(*channel,e::status_request(*saved),cancelled);
        });
    check_stop();
    const auto local=e::CredentialInstaller::install(*file,*keys,*ids,*verifier,now);if(local.native_reference.size()!=20)throw std::runtime_error("renewed native client reference unavailable");
    check_stop();
    auto active=options;active.exclusive_root_der=snapshot.bundle.root;active.exclusive_crl_der=snapshot.bundle.crl;
    for(std::size_t i=0;i<20;++i)active.client_certificate_sha1[i]=std::to_integer<std::uint8_t>(local.native_reference[i]);
    const auto peer=core::sha256(snapshot.bundle.server);for(std::size_t i=0;i<32;++i)active.allowed_server_certificate_sha256.front()[i]=std::to_integer<std::uint8_t>(peer[i]);return active;
}
}
