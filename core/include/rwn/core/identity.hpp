#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace rwn::core {

using WallClock = std::chrono::system_clock;
using TimePoint = WallClock::time_point;

struct PeerCertificate {
    std::string device_id;
    std::string fingerprint;
    std::string serial;
    TimePoint not_before{};
    TimePoint not_after{};
};

struct PairedDevice {
    std::string id;
    std::string display_name;
    std::string fingerprint;
    PeerCertificate certificate;
    bool revoked{};
};

enum class PeerVerification { accepted, unknown_device, fingerprint_mismatch, revoked, not_yet_valid, expired };

class DeviceRegistry {
public:
    void pair(PairedDevice device);
    [[nodiscard]] const PairedDevice* find(std::string_view device_id) const;
    void revoke(std::string_view device_id);
    [[nodiscard]] PeerVerification verify(const PeerCertificate& certificate, TimePoint now) const;

private:
    std::map<std::string, PairedDevice, std::less<>> devices_;
};

struct NodeAdvertisement {
    std::string node_id;
    std::string node_name;
    std::string lan_endpoint;
    std::string fingerprint;
};

class DiscoveryCache {
public:
    explicit DiscoveryCache(
        std::chrono::seconds max_age = std::chrono::seconds{120})
        : max_age_(max_age) {}
    void observe(NodeAdvertisement advertisement, TimePoint now);
    [[nodiscard]] const NodeAdvertisement* find(std::string_view node_id, TimePoint now) const;

private:
    struct ObservedNode {
        NodeAdvertisement advertisement;
        TimePoint observed_at{};
    };
    std::map<std::string, ObservedNode, std::less<>> nodes_;
    std::chrono::seconds max_age_;
};

struct MtlsPeerEvidence {
    bool tls_1_3_negotiated{};
    bool client_certificate_present{};
    bool certificate_chain_valid{};
    bool revocation_checked{};
    PeerCertificate certificate;
};

enum class MtlsVerification {
    accepted,
    tls_version_rejected,
    certificate_missing,
    certificate_chain_rejected,
    revocation_unverified,
    certificate_rejected,
};

class MtlsTrustGate {
public:
    [[nodiscard]] MtlsVerification verify(const MtlsPeerEvidence& evidence, const DeviceRegistry& registry, TimePoint now) const;
};

struct PairingChallenge {
    std::string id;
    NodeAdvertisement node;
    std::string six_digit_code;
    TimePoint expires_at{};
};

class PairingService {
public:
    explicit PairingService(DeviceRegistry& registry) : registry_(registry) {}

    [[nodiscard]] PairingChallenge begin(
        NodeAdvertisement node, std::string six_digit_code, TimePoint now, std::chrono::minutes lifetime);
    [[nodiscard]] PeerCertificate confirm(
        const PairingChallenge& challenge, std::string_view supplied_code, std::string device_id,
        std::string display_name, std::string device_fingerprint, TimePoint now,
        std::chrono::hours certificate_lifetime);

private:
    DeviceRegistry& registry_;
    unsigned long long next_challenge_{};
};

[[nodiscard]] bool is_canonical_fingerprint(std::string_view fingerprint);

}  // namespace rwn::core
