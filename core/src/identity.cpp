#include "rwn/core/identity.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

bool is_six_digits(const std::string_view value) {
    return value.size() == 6 && std::ranges::all_of(value, [](const unsigned char ch) { return std::isdigit(ch) != 0; });
}

bool constant_time_equals(const std::string_view left, const std::string_view right) {
    const auto size = std::max(left.size(), right.size());
    unsigned char difference = static_cast<unsigned char>(left.size() ^ right.size());
    for (std::size_t index = 0; index < size; ++index) {
        const auto lhs = index < left.size() ? static_cast<unsigned char>(left[index]) : 0U;
        const auto rhs = index < right.size() ? static_cast<unsigned char>(right[index]) : 0U;
        difference = static_cast<unsigned char>(difference | (lhs ^ rhs));
    }
    return difference == 0;
}

void require_nonempty(const std::string_view value, const std::string_view label) {
    if (value.empty()) {
        throw std::invalid_argument(std::string(label) + " must not be empty");
    }
}

}  // namespace

bool is_canonical_fingerprint(const std::string_view fingerprint) {
    return fingerprint.size() == 64 && std::ranges::all_of(fingerprint, [](const unsigned char ch) {
        return std::isdigit(ch) != 0 || (ch >= 'a' && ch <= 'f');
    });
}

void DeviceRegistry::pair(PairedDevice device) {
    require_nonempty(device.id, "device id");
    if (!is_canonical_fingerprint(device.fingerprint) || device.certificate.device_id != device.id ||
        device.certificate.fingerprint != device.fingerprint || device.certificate.serial.empty()) {
        throw std::invalid_argument("invalid paired device certificate");
    }
    if (device.certificate.not_before >= device.certificate.not_after) {
        throw std::invalid_argument("invalid certificate lifetime");
    }
    const auto [_, inserted] = devices_.emplace(device.id, std::move(device));
    if (!inserted) {
        throw std::invalid_argument("device is already paired");
    }
}

const PairedDevice* DeviceRegistry::find(const std::string_view device_id) const {
    const auto found = devices_.find(device_id);
    return found == devices_.end() ? nullptr : &found->second;
}

void DeviceRegistry::revoke(const std::string_view device_id) {
    const auto found = devices_.find(device_id);
    if (found == devices_.end()) {
        throw std::invalid_argument("unknown device cannot be revoked");
    }
    found->second.revoked = true;
}

PeerVerification DeviceRegistry::verify(const PeerCertificate& certificate, const TimePoint now) const {
    const auto* device = find(certificate.device_id);
    if (device == nullptr || device->certificate.serial != certificate.serial) {
        return PeerVerification::unknown_device;
    }
    if (!constant_time_equals(device->fingerprint, certificate.fingerprint)) {
        return PeerVerification::fingerprint_mismatch;
    }
    if (device->revoked) {
        return PeerVerification::revoked;
    }
    if (now < certificate.not_before) {
        return PeerVerification::not_yet_valid;
    }
    if (now >= certificate.not_after) {
        return PeerVerification::expired;
    }
    return PeerVerification::accepted;
}

void DiscoveryCache::observe(NodeAdvertisement advertisement, const TimePoint now) {
    if (max_age_ <= std::chrono::seconds::zero()) {
        throw std::logic_error("discovery cache lifetime must be positive");
    }
    require_nonempty(advertisement.node_id, "node id");
    require_nonempty(advertisement.node_name, "node name");
    require_nonempty(advertisement.lan_endpoint, "node endpoint");
    if (!is_canonical_fingerprint(advertisement.fingerprint)) {
        throw std::invalid_argument("invalid node fingerprint");
    }
    const auto node_id = advertisement.node_id;
    nodes_.insert_or_assign(
        node_id,
        ObservedNode{.advertisement = std::move(advertisement), .observed_at = now});
}

const NodeAdvertisement* DiscoveryCache::find(const std::string_view node_id, const TimePoint now) const {
    const auto found = nodes_.find(node_id);
    if (found == nodes_.end() || now < found->second.observed_at ||
        now - found->second.observed_at > max_age_) {
        return nullptr;
    }
    return &found->second.advertisement;
}

MtlsVerification MtlsTrustGate::verify(
    const MtlsPeerEvidence& evidence, const DeviceRegistry& registry, const TimePoint now) const {
    if (!evidence.tls_1_3_negotiated) {
        return MtlsVerification::tls_version_rejected;
    }
    if (!evidence.client_certificate_present) {
        return MtlsVerification::certificate_missing;
    }
    if (!evidence.certificate_chain_valid) {
        return MtlsVerification::certificate_chain_rejected;
    }
    if (!evidence.revocation_checked) {
        return MtlsVerification::revocation_unverified;
    }
    return registry.verify(evidence.certificate, now) == PeerVerification::accepted
        ? MtlsVerification::accepted
        : MtlsVerification::certificate_rejected;
}

PairingChallenge PairingService::begin(
    NodeAdvertisement node, std::string six_digit_code, const TimePoint now, const std::chrono::minutes lifetime) {
    require_nonempty(node.node_id, "node id");
    require_nonempty(node.node_name, "node name");
    require_nonempty(node.lan_endpoint, "node endpoint");
    if (!is_canonical_fingerprint(node.fingerprint) || !is_six_digits(six_digit_code) || lifetime <= std::chrono::minutes::zero()) {
        throw std::invalid_argument("invalid pairing challenge");
    }
    return PairingChallenge{
        .id = "pair-" + std::to_string(++next_challenge_),
        .node = std::move(node),
        .six_digit_code = std::move(six_digit_code),
        .expires_at = now + lifetime,
    };
}

PeerCertificate PairingService::confirm(
    const PairingChallenge& challenge, const std::string_view supplied_code, std::string device_id,
    std::string display_name, std::string device_fingerprint, const TimePoint now,
    const std::chrono::hours certificate_lifetime) {
    if (challenge.id.empty() || now >= challenge.expires_at || !constant_time_equals(challenge.six_digit_code, supplied_code)) {
        throw std::invalid_argument("pairing confirmation rejected");
    }
    require_nonempty(device_id, "device id");
    require_nonempty(display_name, "device name");
    if (!is_canonical_fingerprint(device_fingerprint) || certificate_lifetime <= std::chrono::hours::zero()) {
        throw std::invalid_argument("invalid paired device");
    }
    PeerCertificate certificate{
        .device_id = device_id,
        .fingerprint = device_fingerprint,
        .serial = "paired-" + challenge.id + "-" + device_id,
        .not_before = now,
        .not_after = now + certificate_lifetime,
    };
    registry_.pair(PairedDevice{
        .id = std::move(device_id),
        .display_name = std::move(display_name),
        .fingerprint = std::move(device_fingerprint),
        .certificate = certificate,
        .revoked = false,
    });
    return certificate;
}

}  // namespace rwn::core
