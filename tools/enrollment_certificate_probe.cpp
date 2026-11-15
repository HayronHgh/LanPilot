// Native crypto fixture: ephemeral keys, application-only trust, no listener,
// personal key/certificate store, identity provisioning, input or screen access.
#include "rwn/core/enrollment_certificate.hpp"
#include "enrollment_fixture_key.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/core/release_compatibility.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <source_location>
#include <filesystem>
#include <fstream>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#else
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace e=rwn::core::enrollment;
namespace {
using NativeSigner=rwn::probe::EphemeralSigner;
void check(bool value,std::source_location where=std::source_location::current()){
    if(!value)throw std::runtime_error("native enrollment fixture failed at line "+std::to_string(where.line()));
}
#if defined(_WIN32)
bool trust(const e::Bytes& root,const e::Bytes& leaf,const e::Bytes& crl,e::Time at){
    const auto store=CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,CERT_STORE_CREATE_NEW_FLAG,nullptr);check(store!=nullptr);
    struct Store{HCERTSTORE value;~Store(){CertCloseStore(value,0);}} own_store{store};
    check(CertAddEncodedCertificateToStore(store,X509_ASN_ENCODING,reinterpret_cast<const BYTE*>(root.data()),static_cast<DWORD>(root.size()),CERT_STORE_ADD_NEW,nullptr));
    check(CertAddEncodedCRLToStore(store,X509_ASN_ENCODING,reinterpret_cast<const BYTE*>(crl.data()),static_cast<DWORD>(crl.size()),CERT_STORE_ADD_NEW,nullptr));
    const auto certificate=CertCreateCertificateContext(X509_ASN_ENCODING,reinterpret_cast<const BYTE*>(leaf.data()),static_cast<DWORD>(leaf.size()));check(certificate!=nullptr);
    struct Certificate{PCCERT_CONTEXT value;~Certificate(){CertFreeCertificateContext(value);}} own_certificate{certificate};
    CERT_CHAIN_ENGINE_CONFIG config{};config.cbSize=sizeof(config);config.hExclusiveRoot=store;HCERTCHAINENGINE engine{};
    check(CertCreateCertificateChainEngine(&config,&engine));
    struct Engine{HCERTCHAINENGINE value;~Engine(){CertFreeCertificateChainEngine(value);}} own_engine{engine};
    const auto ticks=static_cast<std::uint64_t>((at.time_since_epoch()+std::chrono::seconds{11644473600}).count())*10000000;
    FILETIME date{static_cast<DWORD>(ticks),static_cast<DWORD>(ticks>>32)};
    CERT_CHAIN_PARA parameters{};parameters.cbSize=sizeof(parameters);PCCERT_CHAIN_CONTEXT chain{};
    if(!CertGetCertificateChain(engine,certificate,&date,store,&parameters,CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT|
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL|CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY|CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE,nullptr,&chain))return false;
    struct Chain{PCCERT_CHAIN_CONTEXT value;~Chain(){CertFreeCertificateChain(value);}} own_chain{chain};
    if(chain->TrustStatus.dwErrorStatus!=0){std::cerr<<"fixture_chain_status="<<chain->TrustStatus.dwErrorStatus<<'\n';return false;}
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};ssl.cbSize=sizeof(ssl);ssl.dwAuthType=AUTHTYPE_SERVER;wchar_t host[]=L"lanpilot.test";ssl.pwszServerName=host;
    CERT_CHAIN_POLICY_PARA policy{};policy.cbSize=sizeof(policy);policy.pvExtraPolicyPara=&ssl;
    CERT_CHAIN_POLICY_STATUS status{};status.cbSize=sizeof(status);
    const bool verified=CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,chain,&policy,&status);
    if(!verified || status.dwError)std::cerr<<"fixture_ssl_status="<<status.dwError<<'\n';
    return verified && status.dwError==0;
}
#else
template<class T> struct Owned{T value{};explicit Owned(T v):value(v){}~Owned(){if(value)CFRelease(value);}Owned(const Owned&)=delete;};
bool trust(const e::Bytes& root,const e::Bytes& leaf,const e::Bytes& ocsp,e::Time at){
    auto decode=[](const e::Bytes& bytes){Owned<CFDataRef> data(CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(bytes.data()),static_cast<CFIndex>(bytes.size())));return SecCertificateCreateWithData(nullptr,data.value);};
    Owned<SecCertificateRef> issuer(decode(root)),certificate(decode(leaf));check(issuer.value && certificate.value);
    Owned<SecPolicyRef> tls(SecPolicyCreateSSL(false,nullptr));
    Owned<SecPolicyRef> revocation(SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod|kSecRevocationRequirePositiveResponse));
    const void* rules[]{tls.value,revocation.value};Owned<CFArrayRef> policies(CFArrayCreate(nullptr,rules,2,&kCFTypeArrayCallBacks));
    const void* certificates[]{certificate.value,issuer.value};Owned<CFArrayRef> chain(CFArrayCreate(nullptr,certificates,2,&kCFTypeArrayCallBacks));
    SecTrustRef raw{};check(SecTrustCreateWithCertificates(chain.value,policies.value,&raw)==errSecSuccess);Owned<SecTrustRef> evaluation(raw);
    const void* anchors[]{issuer.value};Owned<CFArrayRef> roots(CFArrayCreate(nullptr,anchors,1,&kCFTypeArrayCallBacks));
    check(SecTrustSetAnchorCertificates(raw,roots.value)==errSecSuccess && SecTrustSetAnchorCertificatesOnly(raw,true)==errSecSuccess && SecTrustSetNetworkFetchAllowed(raw,false)==errSecSuccess);
    Owned<CFDateRef> date(CFDateCreate(nullptr,static_cast<CFAbsoluteTime>(at.time_since_epoch().count())-978307200.0));
    check(SecTrustSetVerifyDate(raw,date.value)==errSecSuccess);
    Owned<CFDataRef> response(CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(ocsp.data()),static_cast<CFIndex>(ocsp.size())));
    check(SecTrustSetOCSPResponse(raw,response.value)==errSecSuccess);CFErrorRef error{};
    const bool accepted=SecTrustEvaluateWithError(raw,&error);if(error)CFRelease(error);return accepted;
}
#endif
e::Serial serial(unsigned n){e::Serial result{};result.back()=static_cast<std::byte>(n);return result;}
void physical_parent(const std::filesystem::path& directory){
    auto current=directory;
    while(!current.empty()){
#if defined(_WIN32)
        const auto attributes=GetFileAttributesW(current.c_str());
        check(attributes!=INVALID_FILE_ATTRIBUTES && (attributes&FILE_ATTRIBUTE_DIRECTORY) && !(attributes&FILE_ATTRIBUTE_REPARSE_POINT));
#else
        const auto state=std::filesystem::symlink_status(current);
        check(std::filesystem::is_directory(state) && !std::filesystem::is_symlink(state));
#endif
        const auto parent=current.parent_path();if(parent==current)break;current=parent;
    }
}
void public_file(const std::filesystem::path& directory,const char* name,const e::Bytes& bytes){
    check(!bytes.empty() && bytes.size()<=65536);
    const auto output=directory/name;check(!std::filesystem::exists(output));
    std::ofstream stream(output,std::ios::binary);check(stream.good());
    stream.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));stream.close();check(stream.good());
}
#if defined(__APPLE__)
e::Bytes read_public_file(const std::filesystem::path& directory,const char* name){
    const auto file=directory/name;const auto state=std::filesystem::symlink_status(file);
    check(std::filesystem::is_regular_file(state) && !std::filesystem::is_symlink(state) && std::filesystem::hard_link_count(file)==1);
    const auto size=std::filesystem::file_size(file);check(size>0 && size<=65536);e::Bytes bytes(static_cast<std::size_t>(size));
    std::ifstream stream(file,std::ios::binary);stream.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(size));
    check(stream.good() && stream.peek()==std::char_traits<char>::eof());return bytes;
}
#endif
}
int main(int argc,char** argv){
    try {
        using namespace std::chrono;
        std::filesystem::path output;
        if(argc==3){
            const std::filesystem::path path(argv[2]);check(path.is_absolute() && path.lexically_normal()==path);
#if defined(__APPLE__)
            if(std::string_view(argv[1])=="--verify-public-fixtures"){
                physical_parent(path);const auto root=read_public_file(path,"root.der");const auto now=floor<seconds>(system_clock::now());
                for(const auto* type:{"good","revoked","unknown","stale"}){
                    const auto cert=read_public_file(path,(std::string("client-")+type+".der").c_str());
                    const auto ocsp=read_public_file(path,(std::string(type)+".ocsp.der").c_str());
                    check(trust(root,cert,ocsp,now)==(std::string_view(type)=="good"));
                }
                std::cout<<"enrollment_cross_platform=PASS received_public_only=1 keys_created=0 personal_store_writes=0 network=0\n";return 0;
            }
#endif
            check(std::string_view(argv[1])=="--write-public-fixtures");physical_parent(path.parent_path());
            check(std::filesystem::create_directory(path));output=path;
        }else check(argc==1);
        NativeSigner issuer,device;const auto now=floor<seconds>(system_clock::now());
        check(!issuer.accepts_public_key(e::PublicKey{}));
        auto invalid_point=e::PublicKey{};invalid_point.front()=std::byte{1};
        check(!issuer.accepts_public_key(invalid_point));
        const e::Validity lifetime{now-days{3},now+days{30}},authority{now-days{4},now+days{30}},status{now-minutes{1},now+minutes{30}};
        const auto root=e::root_certificate(issuer,serial(1),authority);
        const auto request=e::certificate_request(device,e::Role::server);check(!request.empty());
#if defined(_WIN32)
        const e::AlternativeName name{{},"lanpilot.test"};
        const auto leaf=e::leaf_certificate(issuer,serial(2),device.public_key(),e::Role::server,lifetime,authority,std::span{&name,1});
        const auto expired=e::revocation_list(issuer,1,{now-days{2},now-days{1}},authority,{});
        check(!trust(root,leaf,expired,now));
        const auto good=e::revocation_list(issuer,2,status,authority,{});
        check(trust(root,leaf,good,now));
        const e::Revocation record{serial(2),now-minutes{2}};
        const auto revoked=e::revocation_list(issuer,3,status,authority,std::span{&record,1});
        check(!trust(root,leaf,revoked,now));
#else
        for(unsigned n=2;n<5;++n){
            const auto leaf=e::leaf_certificate(issuer,serial(n),device.public_key(),e::Role::client,lifetime,authority);
            const auto expired=e::ocsp_response(issuer,serial(n),e::Status::good,now-days{2},{now-days{2},now-days{1}},authority);
            check(!trust(root,leaf,expired,now));
            const auto state=n==2?e::Status::good:(n==3?e::Status::revoked:e::Status::unknown);
            const auto response=e::ocsp_response(issuer,serial(n),state,now,status,authority,now-minutes{2});
            check(trust(root,leaf,response,now)==(n==2));
        }
#endif
        if(!output.empty()){
            public_file(output,"root.der",root);public_file(output,"request.der",request);
            const std::array<const char*,4> statuses{"good","revoked","unknown","stale"};
            for(unsigned n=0;n<4;++n){
                const auto id=serial(30+n);const auto client_certificate=e::leaf_certificate(issuer,id,device.public_key(),e::Role::client,lifetime,authority);
                const auto state=n==1?e::Status::revoked:(n==2?e::Status::unknown:e::Status::good);
                const auto stamp=n==3?now-days{2}:now;
                const e::Validity window=n==3?e::Validity{now-days{2},now-days{1}}:status;
                const auto response=e::ocsp_response(issuer,id,state,stamp,window,authority,now-minutes{2});
                public_file(output,(std::string("client-")+statuses[n]+".der").c_str(),client_certificate);
                public_file(output,(std::string(statuses[n])+".ocsp.der").c_str(),response);
            }
        }
        std::cout<<"enrollment_certificate=PASS native_chain_and_revocation=1 ephemeral_keys=2 private_exports=0 personal_store_writes=0 network=0\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
