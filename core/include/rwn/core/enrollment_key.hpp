#pragma once
#include "rwn/core/enrollment_certificate.hpp"
#include <memory>
#include <string>
#include <stdexcept>

namespace rwn::core::enrollment {
enum class KeyPurpose { authority, server, client };
struct KeyReference {
    KeyPurpose purpose;
    std::array<std::byte,16> id;
};

// Local controller only. A reference is metadata, never enrollment approval.
// Missing identities are not silently replaced. Creation never overwrites an
// existing key. Private key export is deliberately absent from this interface.
// The controller holds its protected cross-process enrollment/installation
// lease while creating or removing a slot. OS storage is not that lease.
class KeyStore {
public:
    virtual ~KeyStore()=default;
    virtual std::unique_ptr<Signer> create_new(const KeyReference&)=0;
    virtual std::unique_ptr<Signer> open(const KeyReference&)=0; // null iff absent
    virtual bool remove_if_matches(const KeyReference&,const PublicKey&)=0;
};

inline std::string key_reference_name(const KeyReference& reference) {
    const char* purpose=nullptr;
    switch(reference.purpose) {
    case KeyPurpose::authority: purpose="authority";break;
    case KeyPurpose::server: purpose="server";break;
    case KeyPurpose::client: purpose="client";break;
    default: throw std::invalid_argument("invalid enrollment key purpose");
    }
    bool nonzero=false;std::string suffix;
    for(const auto value:reference.id) {
        const auto n=std::to_integer<unsigned>(value);nonzero|=n!=0;
        suffix+="0123456789abcdef"[n>>4];suffix+="0123456789abcdef"[n&15];
    }
    if(!nonzero)throw std::invalid_argument("empty enrollment key reference");
    return std::string("LanPilot.NativeEnrollment.v1.")+purpose+'.'+suffix;
}
} // namespace rwn::core::enrollment
