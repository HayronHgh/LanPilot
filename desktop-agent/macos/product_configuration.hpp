#pragma once

#include <array>
#include <charconv>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::agent::macos {

// Metadata only. The opaque Keychain reference never contains a private key.
// No arbitrary executable, launchd key, command or grant can be configured.
struct ServiceConfiguration {
    std::string bind_address;
    std::uint16_t port{};
    std::string identity_reference;
    std::string peer_sha256;
    std::string ca_path;
    std::string ocsp_path;
    std::string control{"view-only"};
    std::string visual{"h264-only"};
    bool clipboard_text{};
    bool operator==(const ServiceConfiguration&) const = default;
};

inline constexpr std::size_t maximum_configuration_bytes=16384;

inline bool canonical_path(std::string_view path) {
    if(path.empty() || path.size()>1024 || path.front()!='/' || path.back()=='/')return false;
    if(path.find_first_of("\\\"\r\n")!=std::string_view::npos)return false;
    for(const char raw:path){const auto c=static_cast<unsigned char>(raw);if(c<32 || c==127)return false;}
    std::size_t start=1;
    while(start<path.size()){
        auto end=path.find('/',start);if(end==std::string_view::npos)end=path.size();
        const auto part=path.substr(start,end-start);
        if(part.empty() || part=="." || part=="..")return false;
        start=end+1;
    }
    return true;
}

inline bool lowercase_hex(std::string_view value,std::size_t minimum,std::size_t maximum) {
    if(value.size()<minimum || value.size()>maximum || value.size()%2!=0)return false;
    for(char c:value)if(!((c>='0' && c<='9') || (c>='a' && c<='f')))return false;
    return true;
}

inline unsigned canonical_unsigned(std::string_view value,unsigned maximum) {
    unsigned number{};
    const auto result=std::from_chars(value.data(),value.data()+value.size(),number);
    if(value.empty() || (value.size()>1 && value.front()=='0') ||
       result.ec!=std::errc{} || result.ptr!=value.data()+value.size() || number>maximum)
        throw std::invalid_argument("noncanonical service number");
    return number;
}

inline void validate_configuration(const ServiceConfiguration& c,std::string_view home) {
    if(!canonical_path(home) || !home.starts_with("/Users/") || home.find('/',7)!=std::string_view::npos)
        throw std::invalid_argument("canonical user home required");
    std::array<unsigned,4> octets{};std::size_t begin=0;
    for(std::size_t index=0;index<4;++index){
        const auto end=c.bind_address.find('.',begin);
        if((index<3 && end==std::string::npos) || (index==3 && end!=std::string::npos))
            throw std::invalid_argument("canonical LAN IPv4 required");
        octets[index]=canonical_unsigned(std::string_view(c.bind_address).substr(begin,
            end==std::string::npos?end:end-begin),255);
        begin=end==std::string::npos?c.bind_address.size():end+1;
    }
    if(!(octets[0]==10 || octets[0]==127 || (octets[0]==172 && octets[1]>=16 && octets[1]<=31) ||
         (octets[0]==192 && octets[1]==168)) || c.port<1024)
        throw std::invalid_argument("private LAN endpoint required");
    if(!lowercase_hex(c.identity_reference,2,8192) || !lowercase_hex(c.peer_sha256,64,64))
        throw std::invalid_argument("invalid protected identity metadata");
    const std::string legacy=std::string(home)+"/.local/share/lanpilot/identity-v1/";
    const std::string canonical=std::string(home)+"/Library/Application Support/LanPilot/identity/";
    for(const auto* path:{&c.ca_path,&c.ocsp_path}){
        if(!canonical_path(*path) || (!path->starts_with(legacy) && !path->starts_with(canonical)))
            throw std::invalid_argument("service trust resource outside owned identity roots");
    }
    if(c.ca_path==c.ocsp_path || (c.control!="view-only" && c.control!="interactive") ||
       (c.visual!="h264-only" && c.visual!="exact-only") ||
       (c.clipboard_text && c.control!="interactive"))
        throw std::invalid_argument("invalid service policy");
}

inline ServiceConfiguration parse_configuration(std::string_view text,std::string_view home) {
    if(text.empty() || text.size()>maximum_configuration_bytes || text.back()!='\n')
        throw std::invalid_argument("invalid bounded service configuration");
    std::map<std::string,std::string,std::less<>> fields;
    while(!text.empty()){
        const auto end=text.find('\n');
        const auto line=text.substr(0,end);text.remove_prefix(end+1);
        const auto separator=line.find('=');
        if(separator==std::string_view::npos || separator==0 || separator+1==line.size() ||
           !fields.emplace(std::string(line.substr(0,separator)),std::string(line.substr(separator+1))).second)
            throw std::invalid_argument("invalid or duplicate service field");
    }
    constexpr std::array<std::string_view,10> keys{
        "schema","bind","port","identity_ref","peer_sha256","ca_path","ocsp_path","control","visual","clipboard_text"};
    if(fields.size()!=keys.size())throw std::invalid_argument("unknown or missing service field");
    for(const auto key:keys)if(!fields.contains(key))throw std::invalid_argument("missing service field");
    if(fields.at("schema")!="1" || (fields.at("clipboard_text")!="true" && fields.at("clipboard_text")!="false"))
        throw std::invalid_argument("invalid service schema or boolean");
    ServiceConfiguration c{fields.at("bind"),static_cast<std::uint16_t>(canonical_unsigned(fields.at("port"),65535)),
        fields.at("identity_ref"),fields.at("peer_sha256"),fields.at("ca_path"),fields.at("ocsp_path"),
        fields.at("control"),fields.at("visual"),fields.at("clipboard_text")=="true"};
    validate_configuration(c,home);return c;
}

inline std::string serialize_configuration(const ServiceConfiguration& c,std::string_view home) {
    validate_configuration(c,home);
    return "schema=1\nbind="+c.bind_address+"\nport="+std::to_string(c.port)+
        "\nidentity_ref="+c.identity_reference+"\npeer_sha256="+c.peer_sha256+"\nca_path="+c.ca_path+
        "\nocsp_path="+c.ocsp_path+"\ncontrol="+c.control+"\nvisual="+c.visual+
        "\nclipboard_text="+(c.clipboard_text?"true\n":"false\n");
}

inline std::vector<std::string> agent_arguments(const ServiceConfiguration& c,std::string_view home) {
    validate_configuration(c,home);
    std::vector<std::string> result{"LanPilot","--stream-visual-tls",c.bind_address,std::to_string(c.port),
        c.identity_reference,c.peer_sha256,c.ca_path,c.control,c.visual,c.ocsp_path};
    if(c.clipboard_text)result.emplace_back("--clipboard-text");
    return result;
}

enum class ServiceReadiness { unconfigured, legacy_owner, wrong_install_location, unsigned_application, ready };
inline ServiceReadiness service_readiness(bool configured,bool legacy,bool installed,bool signed_team) {
    if(!configured)return ServiceReadiness::unconfigured;
    if(legacy)return ServiceReadiness::legacy_owner;
    if(!installed)return ServiceReadiness::wrong_install_location;
    if(!signed_team)return ServiceReadiness::unsigned_application;
    return ServiceReadiness::ready;
}
} // namespace rwn::agent::macos
