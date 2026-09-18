#include "rwn/platform/windows/update_signature.hpp"

#include "rwn/core/content_hash.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <stdexcept>

namespace rwn::platform::windows {
namespace {

class AlgorithmHandle {
public:
    explicit AlgorithmHandle(BCRYPT_ALG_HANDLE handle) : handle_(handle) {}
    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
    ~AlgorithmHandle() {
        if (handle_ != nullptr) BCryptCloseAlgorithmProvider(handle_, 0);
    }
    [[nodiscard]] BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_{};
};

class KeyHandle {
public:
    explicit KeyHandle(BCRYPT_KEY_HANDLE handle) : handle_(handle) {}
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    ~KeyHandle() {
        if (handle_ != nullptr) BCryptDestroyKey(handle_);
    }
    [[nodiscard]] BCRYPT_KEY_HANDLE get() const { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_{};
};

[[nodiscard]] bool all_zero(const std::span<const std::byte> value) {
    return std::ranges::all_of(
        value, [](const std::byte item) { return item == std::byte{}; });
}

}  // namespace

CngEcdsaP256UpdateVerifier::CngEcdsaP256UpdateVerifier(
    const std::span<const std::byte> public_key_xy) {
    if (public_key_xy.size() != public_key_xy_.size() ||
        all_zero(public_key_xy)) {
        throw std::invalid_argument("update public key must be P-256 X and Y");
    }
    std::ranges::copy(public_key_xy, public_key_xy_.begin());
}

bool CngEcdsaP256UpdateVerifier::verify(
    const std::span<const std::byte> canonical_payload,
    const std::span<const std::byte> signature) const {
    if (canonical_payload.empty() || signature.size() != 64U ||
        all_zero(signature)) {
        return false;
    }

    BCRYPT_ALG_HANDLE raw_algorithm{};
    if (BCryptOpenAlgorithmProvider(
            &raw_algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) {
        return false;
    }
    const AlgorithmHandle algorithm(raw_algorithm);

    std::array<std::byte, sizeof(BCRYPT_ECCKEY_BLOB) + 64U> blob{};
    BCRYPT_ECCKEY_BLOB header{
        .dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        .cbKey = 32U,
    };
    std::memcpy(blob.data(), &header, sizeof(header));
    std::ranges::copy(public_key_xy_, blob.begin() + sizeof(header));

    BCRYPT_KEY_HANDLE raw_key{};
    if (BCryptImportKeyPair(
            algorithm.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, &raw_key,
            reinterpret_cast<PUCHAR>(blob.data()),
            static_cast<ULONG>(blob.size()), 0) < 0) {
        return false;
    }
    const KeyHandle key(raw_key);
    const auto digest = core::sha256(canonical_payload);
    return BCryptVerifySignature(
               key.get(), nullptr,
               reinterpret_cast<PUCHAR>(
                   const_cast<std::byte*>(digest.data())),
               static_cast<ULONG>(digest.size()),
               reinterpret_cast<PUCHAR>(
                   const_cast<std::byte*>(signature.data())),
               static_cast<ULONG>(signature.size()), 0) >= 0;
}

}  // namespace rwn::platform::windows
