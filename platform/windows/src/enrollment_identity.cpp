#include "rwn/platform/windows/enrollment_identity.hpp"
#include "rwn/platform/windows/enrollment_key.hpp"
#include "rwn/platform/windows/update_signature.hpp"
#include <ncrypt.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <source_location>

namespace rwn::platform::windows {
namespace {
namespace e=core::enrollment;
void require(bool value,std::source_location at=std::source_location::current()){
    if(!value)throw std::runtime_error("native identity association failed at check "+std::to_string(at.line()));
}
struct Certificate {
    PCCERT_CONTEXT value{};explicit Certificate(PCCERT_CONTEXT v):value(v){require(v!=nullptr);}
    ~Certificate(){if(value)CertFreeCertificateContext(value);}Certificate(const Certificate&)=delete;
};
PCCERT_CONTEXT decode(const e::Bytes& bytes){return CertCreateCertificateContext(X509_ASN_ENCODING,reinterpret_cast<const BYTE*>(bytes.data()),static_cast<DWORD>(bytes.size()));}
std::span<const std::byte> encoded(PCCERT_CONTEXT cert){return {reinterpret_cast<const std::byte*>(cert->pbCertEncoded),cert->cbCertEncoded};}
struct CertStore {HCERTSTORE value{};explicit CertStore(HCERTSTORE v):value(v){require(v!=nullptr);}~CertStore(){CertCloseStore(value,0);}CertStore(const CertStore&)=delete;};
e::PublicKey point(PCCERT_CONTEXT cert){
    BCRYPT_KEY_HANDLE key{};require(CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,&cert->pCertInfo->SubjectPublicKeyInfo,0,nullptr,&key));
    std::array<std::byte,sizeof(BCRYPT_ECCKEY_BLOB)+64> data{};ULONG size{};
    const auto status=BCryptExportKey(key,nullptr,BCRYPT_ECCPUBLIC_BLOB,reinterpret_cast<PUCHAR>(data.data()),static_cast<ULONG>(data.size()),&size,0);BCryptDestroyKey(key);
    require(status>=0 && size==data.size());BCRYPT_ECCKEY_BLOB header{};std::memcpy(&header,data.data(),sizeof(header));
    require(header.cbKey==32 && (header.dwMagic==BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header.dwMagic==BCRYPT_ECDH_PUBLIC_P256_MAGIC));
    e::PublicKey out{};std::copy_n(data.begin()+sizeof(header),64,out.begin());return out;
}
bool chain(PCCERT_CONTEXT leaf,PCCERT_CONTEXT root,const e::Bytes& crl,bool server,const std::array<std::byte,4>& ip,e::Time verify_time={}){
    // CertGetCertificateChain's pTime covers certificate validity, but its
    // revocation evidence may be selected at native current time. Explicitly
    // require the supplied CRL's native validity at this operation's time too.
    FILETIME when{};const bool timed=verify_time.time_since_epoch().count()!=0;
    if(timed){const auto ticks=static_cast<std::uint64_t>(verify_time.time_since_epoch().count()+11644473600LL)*10000000ULL;when.dwLowDateTime=static_cast<DWORD>(ticks);when.dwHighDateTime=static_cast<DWORD>(ticks>>32);}
    const auto evidence=CertCreateCRLContext(X509_ASN_ENCODING,reinterpret_cast<const BYTE*>(crl.data()),static_cast<DWORD>(crl.size()));
    if(!evidence)return false;
    struct Crl{PCCRL_CONTEXT value;~Crl(){CertFreeCRLContext(value);}} held_crl{evidence};
    if(CertVerifyCRLTimeValidity(timed?&when:nullptr,evidence->pCrlInfo)!=0)return false;
    // Check THESE bytes, not a different CRL selected from an OS cache. Keep
    // the normal positive-revocation chain policy below as an additional gate.
    const std::array<PCRL_INFO,1> lists{evidence->pCrlInfo};
    if(!CertCompareCertificateName(X509_ASN_ENCODING,&evidence->pCrlInfo->Issuer,&root->pCertInfo->Subject) ||
       !CryptVerifyCertificateSignatureEx(0,X509_ASN_ENCODING,CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL,
            const_cast<CRL_CONTEXT*>(evidence),CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,const_cast<CERT_CONTEXT*>(root),0,nullptr) ||
       !CertIsValidCRLForCertificate(leaf,evidence,0,nullptr) ||
       !CertVerifyCRLRevocation(X509_ASN_ENCODING,leaf->pCertInfo,1,const_cast<PCRL_INFO*>(lists.data())))return false;
    CertStore store(CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,CERT_STORE_CREATE_NEW_FLAG,nullptr));
    require(CertAddCertificateContextToStore(store.value,root,CERT_STORE_ADD_NEW,nullptr));
    require(CertAddEncodedCRLToStore(store.value,X509_ASN_ENCODING,reinterpret_cast<const BYTE*>(crl.data()),static_cast<DWORD>(crl.size()),CERT_STORE_ADD_NEW,nullptr));
    CERT_CHAIN_ENGINE_CONFIG config{};config.cbSize=sizeof(config);config.hExclusiveRoot=store.value;HCERTCHAINENGINE engine{};
    require(CertCreateCertificateChainEngine(&config,&engine));
    struct Engine{HCERTCHAINENGINE value;~Engine(){CertFreeCertificateChainEngine(value);}} own{engine};
    CERT_CHAIN_PARA parameters{};parameters.cbSize=sizeof(parameters);
    LPSTR oid=const_cast<LPSTR>(server?szOID_PKIX_KP_SERVER_AUTH:szOID_PKIX_KP_CLIENT_AUTH);
    parameters.RequestedUsage.dwType=USAGE_MATCH_TYPE_AND;parameters.RequestedUsage.Usage.cUsageIdentifier=1;parameters.RequestedUsage.Usage.rgpszUsageIdentifier=&oid;
    PCCERT_CHAIN_CONTEXT result{};
    if(!CertGetCertificateChain(engine,leaf,timed?&when:nullptr,store.value,&parameters,CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT|
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL|CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY|CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE,nullptr,&result))return false;
    struct Chain{PCCERT_CHAIN_CONTEXT value;~Chain(){CertFreeCertificateChain(value);}} held{result};
    if(result->TrustStatus.dwErrorStatus!=0)return false;
    std::wstring host;
    for(auto b:ip){if(!host.empty())host+=L'.';host+=std::to_wstring(std::to_integer<unsigned>(b));}
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};ssl.cbSize=sizeof(ssl);ssl.dwAuthType=server?AUTHTYPE_SERVER:AUTHTYPE_CLIENT;ssl.pwszServerName=server?host.data():nullptr;
    CERT_CHAIN_POLICY_PARA policy{};policy.cbSize=sizeof(policy);policy.pvExtraPolicyPara=&ssl;CERT_CHAIN_POLICY_STATUS status{};status.cbSize=sizeof(status);
    return CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,result,&policy,&status) && status.dwError==0;
}
std::wstring key_name(const e::KeyReference& reference){const auto n=e::key_reference_name(reference);return {n.begin(),n.end()};}
bool provider_matches(PCCERT_CONTEXT cert,const e::KeyReference& reference){
    DWORD size{};if(!CertGetCertificateContextProperty(cert,CERT_KEY_PROV_INFO_PROP_ID,nullptr,&size) || size<sizeof(CRYPT_KEY_PROV_INFO) || size>16384)return false;
    std::vector<BYTE> bytes(size);if(!CertGetCertificateContextProperty(cert,CERT_KEY_PROV_INFO_PROP_ID,bytes.data(),&size))return false;
    const auto* info=reinterpret_cast<const CRYPT_KEY_PROV_INFO*>(bytes.data());
    auto text=[&](const wchar_t* pointer,const std::wstring& expected){
        const auto address=reinterpret_cast<std::uintptr_t>(pointer),begin=reinterpret_cast<std::uintptr_t>(bytes.data());
        if(!pointer || address<begin || address-begin>size || (address-begin)%alignof(wchar_t)!=0)return false;
        const auto available=(size-(address-begin))/sizeof(wchar_t);return expected.size()<available && pointer[expected.size()]==0 && std::equal(expected.begin(),expected.end(),pointer);
    };
    return info->dwProvType==0 && info->dwFlags==0 && info->cProvParam==0 && info->dwKeySpec==CERT_NCRYPT_KEY_SPEC &&
        text(info->pwszProvName,MS_KEY_STORAGE_PROVIDER) && text(info->pwszContainerName,key_name(reference));
}
bool possession(PCCERT_CONTEXT cert,const e::PublicKey& expected){
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle{};DWORD specification{};BOOL caller_free{};
    if(!CryptAcquireCertificatePrivateKey(cert,CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
        nullptr,&handle,&specification,&caller_free))return false;
    struct Key{NCRYPT_HANDLE value;BOOL release;~Key(){if(release)NCryptFreeObject(value);}} owner{handle,caller_free};
    if(specification!=CERT_NCRYPT_KEY_SPEC)return false;
    std::array<std::byte,64> message{},signature{};ULONG size{};
    constexpr std::string_view domain="LanPilot native identity possession v1";
    std::memcpy(message.data(),domain.data(),domain.size());
    if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(message.data()+40),24,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return false;
    auto digest=core::sha256(message);
    if(NCryptSignHash(handle,nullptr,reinterpret_cast<PBYTE>(digest.data()),32,reinterpret_cast<PBYTE>(signature.data()),64,&size,NCRYPT_SILENT_FLAG)!=ERROR_SUCCESS || size!=64)return false;
    return CngEcdsaP256UpdateVerifier(expected).verify(message,signature);
}
e::Bytes reference(PCCERT_CONTEXT cert){e::Bytes out(20);DWORD size=20;require(CertGetCertificateContextProperty(cert,CERT_HASH_PROP_ID,out.data(),&size) && size==20);return out;}
class Store final:public e::IdentityStore {
public:
    explicit Store(HCERTSTORE store):store_(store?CertDuplicateStore(store):nullptr){}
    ~Store(){if(store_)CertCloseStore(store_,0);}
    bool verify_revocation(const e::PublicIdentityBundle& b,std::array<std::byte,4> ip,e::Time when={})override{
        try{Certificate root(decode(b.root)),server(decode(b.server)),client(decode(b.client));
            return chain(server.value,root.value,b.crl,true,ip,when) && chain(client.value,root.value,b.crl,false,ip,when);
        }catch(...){return false;}
    }
    e::AssociatedIdentity associate(const e::ApprovedPairing& approval,const e::KeyReference& ref,e::PublicIdentityBundle bundle,core::PairingConsent::Clock::time_point now)override{
        require(approval.valid_at(std::max(now,core::PairingConsent::Clock::now())));
        auto keys=enrollment_key_store();auto key=keys->open(ref);require(key!=nullptr);
        e::require_approved_identity_bundle(approval,ref,bundle,key->public_key(),now);
        Certificate root(decode(bundle.root)),server(decode(bundle.server)),client(decode(bundle.client));const auto& t=approval.transcript();
        require(point(root.value)==t.host.authority_key && point(server.value)==t.host.identity_key && point(client.value)==t.client.identity_key);
        require(chain(server.value,root.value,bundle.crl,true,t.host.desktop_ipv4) && chain(client.value,root.value,bundle.crl,false,t.host.desktop_ipv4));
        const auto local=approval.local_role()==e::PairRole::host?server.value:client.value;
        return attach_certificate(ref,local,t.host.desktop_ipv4,key->public_key(),[&]{require(approval.valid_at(std::max(now,core::PairingConsent::Clock::now())));});
    }
    e::AssociatedIdentity associate_renewed(const e::RenewedIdentity& proof,const e::KeyReference& ref)override{
        auto keys=enrollment_key_store();auto key=keys->open(ref);require(key!=nullptr);
        const auto& b=proof.bundle();const auto ip=proof.transcript().host.desktop_ipv4;
        e::require_renewed_identity(proof,ref,key->public_key(),std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
        require(verify_revocation(b,ip));Certificate local(decode(proof.role()==e::PairRole::host?b.server:b.client));
        return attach_certificate(ref,local.value,ip,key->public_key(),[&]{require(proof.valid_at(std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())));});
    }
    e::Bytes describe(const e::KeyReference& ref,e::Bytes bytes,std::array<std::byte,4> ip)override{
        e::require_identity_certificate_profile(bytes,ref.purpose,ip);auto keys=enrollment_key_store();auto key=keys->open(ref);require(key!=nullptr);
        Certificate cert(decode(bytes));require(point(cert.value)==key->public_key());return reference(cert.value);
    }
    bool key_ready(const e::KeyReference& ref,const e::PublicKey& expected)override{
        try{auto keys=enrollment_key_store();auto key=keys->open(ref);if(!key || key->public_key()!=expected)return false;
            std::array<std::byte,64> challenge{};constexpr std::string_view domain="LanPilot config key proof v1";std::memcpy(challenge.data(),domain.data(),domain.size());
            if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(challenge.data()+32),32,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return false;
            return enrollment_pairing_verifier()->verify(expected,challenge,key->sign_sha256(challenge));
        }catch(...){return false;}
    }
    std::optional<e::AssociatedIdentity> locate(const e::KeyReference& ref,e::Bytes bytes,std::array<std::byte,4> ip)override{
        try {
            if(ref.purpose!=e::KeyPurpose::server && ref.purpose!=e::KeyPurpose::client)return {};
            e::require_identity_certificate_profile(bytes,ref.purpose,ip);auto keys=enrollment_key_store();auto key=keys->open(ref);if(!key)return {};
            Certificate cert(decode(bytes));e::AssociatedIdentity out{ref,key->public_key(),core::sha256(bytes),ip,reference(cert.value),std::move(bytes),false};
            auto found=find(out.native_reference);if(!found)return {};Certificate stored(found);if(!matches(found,out))return {};return out;
        }catch(...){return {};}
    }
    bool certificate_absent(std::span<const std::byte> bytes)override{
        if(bytes.empty() || bytes.size()>8192)return false;
        try {Certificate cert(decode(e::Bytes(bytes.begin(),bytes.end())));
            // Only a native not-found result proves an absent store. Access
            // denial/other failures must not become rollback authorization.
            if(!open_store(false))return GetLastError()==static_cast<DWORD>(CRYPT_E_NOT_FOUND);
            auto found=find(reference(cert.value));if(!found)return GetLastError()==static_cast<DWORD>(CRYPT_E_NOT_FOUND);
            CertFreeCertificateContext(found);return false;
        }catch(...){return false;}
    }
    bool ready(const e::AssociatedIdentity& r)override{
        try {auto keys=enrollment_key_store();auto key=keys->open(r.key);if(!key || key->public_key()!=r.subject_key)return false;
            auto cert=find(r.native_reference);if(!cert)return false;Certificate owned(cert);return matches(cert,r) && CertVerifyTimeValidity(nullptr,cert->pCertInfo)==0 && possession(cert,r.subject_key);}
        catch(...){return false;}
    }
    bool remove_created(const e::AssociatedIdentity& r)override{
        if(!r.created)return false;
        try {const auto found=locate(r.key,r.certificate_der,r.server_ipv4);if(!found || found->certificate_sha256!=r.certificate_sha256 || found->subject_key!=r.subject_key)return false;
            if(!r.native_reference.empty() && r.native_reference!=found->native_reference)return false;
            auto cert=find(found->native_reference);if(!cert)return false;Certificate owned(cert);if(!matches(cert,r))return false;return CertDeleteCertificateFromStore(CertDuplicateCertificateContext(cert));}
        catch(...){return false;}
    }
private:
    template<class Live>e::AssociatedIdentity attach_certificate(const e::KeyReference& ref,PCCERT_CONTEXT local,std::array<std::byte,4> ip,const e::PublicKey& key,Live live){
        live();e::AssociatedIdentity receipt{ref,key,core::sha256(encoded(local)),ip,reference(local),e::Bytes(encoded(local).begin(),encoded(local).end()),false};
        auto current=find(receipt.native_reference);
        if(current){Certificate existing(current);require(matches(existing.value,receipt) && possession(existing.value,receipt.subject_key));live();return receipt;}
        auto container=key_name(ref);CRYPT_KEY_PROV_INFO info{};info.pwszContainerName=container.data();info.pwszProvName=const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);info.dwKeySpec=CERT_NCRYPT_KEY_SPEC;
        require(CertSetCertificateContextProperty(local,CERT_KEY_PROV_INFO_PROP_ID,0,&info) && provider_matches(local,ref) && possession(local,receipt.subject_key));live();
        PCCERT_CONTEXT added{};require(CertAddCertificateContextToStore(open_store(),local,CERT_STORE_ADD_NEW,&added));Certificate held(added);receipt.created=true;
        try{require(matches(added,receipt) && possession(added,receipt.subject_key));live();}catch(...){CertDeleteCertificateFromStore(CertDuplicateCertificateContext(added));throw;}return receipt;
    }
    HCERTSTORE open_store(bool create=true){
        if(!store_)store_=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_CURRENT_USER|(create?0:CERT_STORE_OPEN_EXISTING_FLAG),L"MY");
        if(create)require(store_!=nullptr);
        return store_;
    }
    PCCERT_CONTEXT find(const e::Bytes& hash){
        if(hash.size()!=20 || !open_store(false))return nullptr;
        CRYPT_HASH_BLOB blob{20,reinterpret_cast<BYTE*>(const_cast<std::byte*>(hash.data()))};
        return CertFindCertificateInStore(store_,X509_ASN_ENCODING,0,CERT_FIND_SHA1_HASH,&blob,nullptr);
    }
    bool matches(PCCERT_CONTEXT cert,const e::AssociatedIdentity& r){
        if(r.key.purpose!=e::KeyPurpose::server && r.key.purpose!=e::KeyPurpose::client)return false;
        e::require_identity_certificate_profile(encoded(cert),r.key.purpose,r.server_ipv4);
        return std::ranges::equal(encoded(cert),r.certificate_der) && core::sha256(encoded(cert))==r.certificate_sha256 && point(cert)==r.subject_key && provider_matches(cert,r.key);
    }
    HCERTSTORE store_{};
};
}
std::unique_ptr<core::enrollment::IdentityStore> enrollment_identity_store(HCERTSTORE local_store){return std::make_unique<Store>(local_store);}
}
