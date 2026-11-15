#pragma once
#include "program_install.hpp"
#include "rwn/core/content_hash.hpp"

namespace rwn::agent::macos {
// Publisher configuration, not a key supplied by a peer, package or settings.
inline std::vector<std::byte> release_public_key(std::string_view hex){
    if(hex.empty())return {};
    if(!lowercase_hex(hex,128,128) || hex==std::string(128,'0'))
        throw std::invalid_argument("invalid pinned release key");
    const auto nibble=[](char c){return static_cast<unsigned>(c<='9'?c-'0':c-'a'+10);};
    std::vector<std::byte> bytes(64);
    for(std::size_t i=0;i<64;++i)bytes[i]=static_cast<std::byte>((nibble(hex[2*i])<<4)|nibble(hex[2*i+1]));
    return bytes;
}
struct ProgramOffer {core::SemanticVersion version;std::string confirmation;};
inline std::string program_offer_token(const core::UpdateManifest& manifest){
    return core::sha256_hex(core::canonical_update_payload(manifest)+manifest.signature_hex);
}
bool program_update_policy_ready();
ProgramOffer inspect_program_update(const std::filesystem::path& package_directory);
ProgramResult apply_program_update(const std::filesystem::path& package_directory,std::string_view confirmed_offer);
int release_verifier_fixture();
} // namespace rwn::agent::macos
