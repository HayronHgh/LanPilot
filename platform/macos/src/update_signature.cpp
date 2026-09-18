#include "rwn/platform/macos/update_signature.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <ranges>
#include <stdexcept>
#include <vector>

namespace rwn::platform::macos {
namespace {

template <typename Value>
class CfOwner {
public:
    explicit CfOwner(Value value = nullptr) : value_(value) {}
    ~CfOwner() {
        if (value_ != nullptr) CFRelease(value_);
    }
    CfOwner(const CfOwner&) = delete;
    CfOwner& operator=(const CfOwner&) = delete;
    [[nodiscard]] Value get() const { return value_; }

private:
    Value value_{};
};

[[nodiscard]] bool all_zero(const std::span<const std::byte> value) {
    return std::ranges::all_of(
        value, [](const std::byte item) { return item == std::byte{}; });
}

}  // namespace

SecurityEcdsaP256UpdateVerifier::SecurityEcdsaP256UpdateVerifier(
    const std::span<const std::byte> public_key_xy) {
    if (public_key_xy.size() != public_key_xy_.size() ||
        all_zero(public_key_xy)) {
        throw std::invalid_argument("update public key must be P-256 X and Y");
    }
    std::ranges::copy(public_key_xy, public_key_xy_.begin());
}

bool SecurityEcdsaP256UpdateVerifier::verify(
    const std::span<const std::byte> canonical_payload,
    const std::span<const std::byte> signature) const {
    if (canonical_payload.empty() || canonical_payload.size() > 64U * 1024U ||
        signature.size() != 64U || all_zero(signature)) {
        return false;
    }
    std::array<std::byte, 65> x963{};
    x963.front() = std::byte{0x04};
    std::ranges::copy(public_key_xy_, x963.begin() + 1);
    const CfOwner<CFDataRef> key_data(CFDataCreate(
        kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(x963.data()),
        static_cast<CFIndex>(x963.size())));
    if (key_data.get() == nullptr) return false;

    std::int32_t key_bits = 256;
    const CfOwner<CFNumberRef> key_size(CFNumberCreate(
        kCFAllocatorDefault, kCFNumberSInt32Type, &key_bits));
    if (key_size.get() == nullptr) return false;
    const void* keys[]{
        kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits};
    const void* values[]{
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic,
        key_size.get()};
    const CfOwner<CFDictionaryRef> attributes(CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks));
    if (attributes.get() == nullptr) return false;

    CFErrorRef raw_error{};
    const CfOwner<SecKeyRef> key(SecKeyCreateWithData(
        key_data.get(), attributes.get(), &raw_error));
    const CfOwner<CFErrorRef> key_error(raw_error);
    if (key.get() == nullptr ||
        !SecKeyIsAlgorithmSupported(
            key.get(), kSecKeyOperationTypeVerify,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256)) {
        return false;
    }

    const auto der_signature = core::ecdsa_p256_signature_der(signature);
    const CfOwner<CFDataRef> message(CFDataCreate(
        kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(canonical_payload.data()),
        static_cast<CFIndex>(canonical_payload.size())));
    const CfOwner<CFDataRef> der(CFDataCreate(
        kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(der_signature.data()),
        static_cast<CFIndex>(der_signature.size())));
    if (message.get() == nullptr || der.get() == nullptr) return false;

    raw_error = nullptr;
    const auto verified = SecKeyVerifySignature(
        key.get(), kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        message.get(), der.get(), &raw_error);
    const CfOwner<CFErrorRef> verify_error(raw_error);
    return verified;
}

}  // namespace rwn::platform::macos
