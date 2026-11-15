#include "../desktop-agent/macos/product_configuration.hpp"

#include <iostream>

namespace lp=rwn::agent::macos;
namespace {
void check(bool value){if(!value)throw std::runtime_error("configuration workflow failed");}
template<class F> void rejects(F&& action){
    try{action();}catch(const std::invalid_argument&){return;}
    throw std::runtime_error("invalid service configuration accepted");
}
lp::ServiceConfiguration fixture(){
    return {"10.23.45.67",45443,"0011aabb",std::string(64,'a'),
        "/Users/fixture/.local/share/lanpilot/identity-v1/root.der",
        "/Users/fixture/.local/share/lanpilot/identity-v1/client-ocsp.der",
        "interactive","exact-only",true};
}
}
int main(){
    try {
        const auto original=fixture();const std::string home="/Users/fixture";
        const auto text=lp::serialize_configuration(original,home);
        check(lp::parse_configuration(text,home)==original);
        const auto arguments=lp::agent_arguments(original,home);
        check(arguments.size()==11 && arguments[0]=="LanPilot" && arguments[1]=="--stream-visual-tls" &&
              arguments[4]==original.identity_reference && arguments[10]=="--clipboard-text");
        auto view=original;view.control="view-only";view.clipboard_text=false;
        check(lp::agent_arguments(view,home).size()==10);
        rejects([&]{lp::parse_configuration(text+"bind=127.0.0.1\n",home);});
        rejects([&]{lp::parse_configuration(text+"command=/bin/sh\n",home);});
        rejects([&]{lp::parse_configuration(text.substr(0,text.size()-1),home);});
        rejects([&]{lp::parse_configuration(std::string(lp::maximum_configuration_bytes+1,'x'),home);});
        rejects([&]{lp::parse_configuration("schema=1\n",home);});
        for(const std::string bind:{"0.0.0.0","8.8.8.8","192.168.00.1","127.1","::1","10.1.1.1.5","10.1.1.","+10.1.1.1","10.1.1.256"}){
            auto c=original;c.bind_address=bind;rejects([&]{lp::validate_configuration(c,home);});
        }
        for(const std::string value:{"schema=01","port=045443","port=65536","port=0","clipboard_text=1"}){
            auto modified=text;const auto key=value.substr(0,value.find('=')+1);
            const auto begin=modified.find(key);const auto end=modified.find('\n',begin);
            modified.replace(begin,end-begin,value);rejects([&]{lp::parse_configuration(modified,home);});
        }
        for(const std::string path:{"/tmp/root.der","/Users/other/.local/share/lanpilot/identity-v1/root.der",
            "/Users/fixture/.local/share/lanpilot/identity-v1/../root.der",
            "/Users/fixture/.local/share/lanpilot/identity-v1//root.der",
            "/Users/fixture/.local/share/lanpilot/identity-v1/root.der\ncommand=evil"}){
            auto c=original;c.ca_path=path;rejects([&]{lp::validate_configuration(c,home);});
        }
        auto changed=original;changed.peer_sha256[0]='A';rejects([&]{lp::validate_configuration(changed,home);});
        changed=original;changed.identity_reference="0";rejects([&]{lp::validate_configuration(changed,home);});
        changed=original;changed.control="view-only";rejects([&]{lp::validate_configuration(changed,home);});
        changed=original;changed.ocsp_path=changed.ca_path;rejects([&]{lp::validate_configuration(changed,home);});
        check(lp::service_readiness(false,false,true,true)==lp::ServiceReadiness::unconfigured);
        check(lp::service_readiness(true,true,true,true)==lp::ServiceReadiness::legacy_owner);
        check(lp::service_readiness(true,false,false,true)==lp::ServiceReadiness::wrong_install_location);
        check(lp::service_readiness(true,false,true,false)==lp::ServiceReadiness::unsigned_application);
        check(lp::service_readiness(true,false,true,true)==lp::ServiceReadiness::ready);
        std::cout<<"mac_product_configuration=PASS secrets_accessed=0 service_started=0\n";
        return 0;
    } catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
