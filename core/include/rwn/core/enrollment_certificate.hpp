#pragma once
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rwn::core::enrollment {
using Bytes=std::vector<std::byte>;
using PublicKey=std::array<std::byte,64>;
using Serial=std::array<std::byte,16>;
// Issuer/controller supplies a unique nonzero serial and approved subject key;
// this formatter cannot authenticate a pairing or authorize certificate issue.
using Time=std::chrono::sys_seconds;
struct Validity {Time before,after;};
enum class Role {server,client};
enum class Status {good,revoked,unknown};
struct AlternativeName {Bytes ip;std::string dns;};
struct Revocation {Serial serial;Time occurred;};

// OS-owned key adapter. Implementations validate P-256 points and sign messages
// with SHA-256/ECDSA, returning canonical X9.62 DER. No key material, commands,
// paths, permission or enrollment decisions enter this encoder.
class Signer {
public:
    virtual ~Signer()=default;
    virtual PublicKey public_key()const=0;
    virtual bool accepts_public_key(const PublicKey&)const=0;
    virtual Bytes sign_sha256(std::span<const std::byte>)=0;
};

Bytes root_certificate(Signer&,Serial,Validity);
Bytes leaf_certificate(Signer& issuer,Serial,const PublicKey& subject,Role,Validity,Validity issuer_validity,
                       std::span<const AlternativeName> names={});
Bytes certificate_request(Signer&,Role);
Bytes revocation_list(Signer&,std::uint64_t number,Validity window,Validity issuer_validity,std::span<const Revocation>);
Bytes ocsp_response(Signer&,Serial,Status,Time produced,Validity window,Validity issuer_validity,Time revoked_at={});
} // namespace rwn::core::enrollment
