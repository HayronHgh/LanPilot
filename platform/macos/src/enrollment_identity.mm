#include "rwn/platform/macos/enrollment_identity.hpp"
#include "rwn/platform/macos/enrollment_key.hpp"
#include <algorithm>
#include <cstring>
#include <source_location>

namespace rwn::platform::macos {
namespace {
namespace e=core::enrollment;
void require(bool value,std::source_location at=std::source_location::current()){
    if(!value)throw std::runtime_error("native identity association failed at check "+std::to_string(at.line()));
}
template<class T>struct Owned{T value{};explicit Owned(T v):value(v){}~Owned(){if(value)CFRelease(value);}Owned(const Owned&)=delete;};
CFMutableDictionaryRef dictionary(){return CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);}
CFDataRef cf_data(std::span<const std::byte> bytes){return CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(bytes.data()),static_cast<CFIndex>(bytes.size()));}
e::Bytes copied(CFDataRef bytes){
    require(bytes && CFDataGetLength(bytes)>0 && CFDataGetLength(bytes)<=65536);const auto* p=reinterpret_cast<const std::byte*>(CFDataGetBytePtr(bytes));return {p,p+CFDataGetLength(bytes)};
}
SecCertificateRef decode(const e::Bytes& bytes){Owned<CFDataRef> d(cf_data(bytes));auto cert=SecCertificateCreateWithData(nullptr,d.value);require(cert!=nullptr);return cert;}
e::PublicKey key_point(SecKeyRef key){
    CFErrorRef error{};Owned<CFDataRef> encoded(SecKeyCopyExternalRepresentation(key,&error));if(error)CFRelease(error);
    require(encoded.value && CFDataGetLength(encoded.value)==65 && CFDataGetBytePtr(encoded.value)[0]==4);
    e::PublicKey out{};std::memcpy(out.data(),CFDataGetBytePtr(encoded.value)+1,64);return out;
}
e::PublicKey point(SecCertificateRef cert){Owned<SecKeyRef> key(SecCertificateCopyKey(cert));require(key.value!=nullptr);return key_point(key.value);}
e::Bytes stable_reference(const e::KeyReference& ref,std::span<const std::byte> certificate,const std::array<std::byte,4>& ip){
    (void)e::key_reference_name(ref);require(!certificate.empty() && certificate.size()<=3072);
    require(ref.purpose==e::KeyPurpose::server || ref.purpose==e::KeyPurpose::client);
    e::Bytes bytes{std::byte{'L'},std::byte{'P'},std::byte{'I'},std::byte{'1'},static_cast<std::byte>(ref.purpose)};
    bytes.insert(bytes.end(),ref.id.begin(),ref.id.end());bytes.insert(bytes.end(),ip.begin(),ip.end());bytes.push_back(static_cast<std::byte>(certificate.size()>>8));bytes.push_back(static_cast<std::byte>(certificate.size()));
    bytes.insert(bytes.end(),certificate.begin(),certificate.end());return bytes;
}
SecCertificateRef stored_certificate(SecKeychainRef keychain,SecCertificateRef certificate){
    Owned<CFMutableDictionaryRef> query(dictionary());const void* items[]{keychain};Owned<CFArrayRef> list(CFArrayCreate(nullptr,items,1,&kCFTypeArrayCallBacks));
    Owned<CFDataRef> issuer(SecCertificateCopyNormalizedIssuerSequence(certificate));CFErrorRef error{};
    Owned<CFDataRef> serial(SecCertificateCopySerialNumberData(certificate,&error));if(error)CFRelease(error);
    require(issuer.value && serial.value);
    CFDictionarySetValue(query.value,kSecClass,kSecClassCertificate);CFDictionarySetValue(query.value,kSecAttrIssuer,issuer.value);CFDictionarySetValue(query.value,kSecAttrSerialNumber,serial.value);
    CFDictionarySetValue(query.value,kSecMatchSearchList,list.value);CFDictionarySetValue(query.value,kSecReturnRef,kCFBooleanTrue);CFDictionarySetValue(query.value,kSecMatchLimit,kSecMatchLimitAll);
    CFTypeRef result{};const auto status=SecItemCopyMatching(query.value,&result);Owned<CFTypeRef> owned(result);
    if(status==errSecItemNotFound)return nullptr;
    require(status==errSecSuccess && result && CFGetTypeID(result)==CFArrayGetTypeID());
    const auto array=static_cast<CFArrayRef>(result);require(CFArrayGetCount(array)==1);
    const auto found=static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(array,0)));require(CFGetTypeID(found)==SecCertificateGetTypeID());
    Owned<CFDataRef> actual(SecCertificateCopyData(found)),expected(SecCertificateCopyData(certificate));require(actual.value && expected.value && CFEqual(actual.value,expected.value));
    CFRetain(found);return found;
}
bool chain(SecCertificateRef cert,SecCertificateRef root,const e::Bytes& ocsp,bool server,const std::array<std::byte,4>& ip,e::Time verify_time={}){
    std::string text;for(auto b:ip){if(!text.empty())text+='.';text+=std::to_string(std::to_integer<unsigned>(b));}
    Owned<CFStringRef> host(CFStringCreateWithCString(nullptr,text.c_str(),kCFStringEncodingUTF8));
    Owned<SecPolicyRef> tls(SecPolicyCreateSSL(server,server?host.value:nullptr));
    Owned<SecPolicyRef> revocation(SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod|kSecRevocationRequirePositiveResponse));
    const void* rules[]{tls.value,revocation.value};Owned<CFArrayRef> policies(CFArrayCreate(nullptr,rules,2,&kCFTypeArrayCallBacks));
    const void* certs[]{cert,root};Owned<CFArrayRef> list(CFArrayCreate(nullptr,certs,2,&kCFTypeArrayCallBacks));
    SecTrustRef raw{};require(SecTrustCreateWithCertificates(list.value,policies.value,&raw)==errSecSuccess);Owned<SecTrustRef> trust(raw);
    const void* roots[]{root};Owned<CFArrayRef> anchors(CFArrayCreate(nullptr,roots,1,&kCFTypeArrayCallBacks));
    require(SecTrustSetAnchorCertificates(raw,anchors.value)==errSecSuccess && SecTrustSetAnchorCertificatesOnly(raw,true)==errSecSuccess && SecTrustSetNetworkFetchAllowed(raw,false)==errSecSuccess);
    if(verify_time.time_since_epoch().count()!=0){Owned<CFDateRef> date(CFDateCreate(nullptr,static_cast<double>(verify_time.time_since_epoch().count())-978307200.0));require(date.value && SecTrustSetVerifyDate(raw,date.value)==errSecSuccess);}
    Owned<CFDataRef> response(cf_data(ocsp));require(SecTrustSetOCSPResponse(raw,response.value)==errSecSuccess);CFErrorRef error{};
    const bool accepted=SecTrustEvaluateWithError(raw,&error);if(error)CFRelease(error);return accepted;
}
class Store final:public e::IdentityStore {
public:
    explicit Store(SecKeychainRef keychain):keychain_(keychain){if(keychain_)CFRetain(keychain_);else require(SecKeychainCopyDefault(&keychain_)==errSecSuccess && keychain_);}
    ~Store(){CFRelease(keychain_);}
    bool verify_revocation(const e::PublicIdentityBundle& b,std::array<std::byte,4> ip,e::Time when={})override{
        try{Owned<SecCertificateRef> root(decode(b.root)),server(decode(b.server)),client(decode(b.client));
            if(when.time_since_epoch().count()==0)when=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
            auto verifier=enrollment_pairing_verifier();const auto authority=point(root.value);
            e::require_good_ocsp(b.server_ocsp,b.root,e::certificate_facts(b.server,e::KeyPurpose::server,ip).serial,authority,*verifier,when);
            e::require_good_ocsp(b.client_ocsp,b.root,e::certificate_facts(b.client,e::KeyPurpose::client).serial,authority,*verifier,when);
            return chain(server.value,root.value,b.server_ocsp,true,ip,when) && chain(client.value,root.value,b.client_ocsp,false,ip,when);
        }catch(...){return false;}
    }
    e::AssociatedIdentity associate(const e::ApprovedPairing& approval,const e::KeyReference& ref,e::PublicIdentityBundle bundle,core::PairingConsent::Clock::time_point now)override {
        require(approval.valid_at(std::max(now,core::PairingConsent::Clock::now())));
        auto keys=enrollment_key_store(keychain_);auto key=keys->open(ref);require(key!=nullptr);
        e::require_approved_identity_bundle(approval,ref,bundle,key->public_key(),now);const auto& t=approval.transcript();
        Owned<SecCertificateRef> root(decode(bundle.root)),server(decode(bundle.server)),client(decode(bundle.client));
        require(point(root.value)==t.host.authority_key && point(server.value)==t.host.identity_key && point(client.value)==t.client.identity_key);
        require(chain(server.value,root.value,bundle.server_ocsp,true,t.host.desktop_ipv4) && chain(client.value,root.value,bundle.client_ocsp,false,t.host.desktop_ipv4));
        const auto certificate=approval.local_role()==e::PairRole::host?server.value:client.value;
        const auto& encoded=approval.local_role()==e::PairRole::host?bundle.server:bundle.client;
        return attach_certificate(ref,certificate,encoded,t.host.desktop_ipv4,key->public_key(),[&]{require(approval.valid_at(std::max(now,core::PairingConsent::Clock::now())));});
    }
    e::AssociatedIdentity associate_renewed(const e::RenewedIdentity& proof,const e::KeyReference& ref)override{
        auto keys=enrollment_key_store(keychain_);auto key=keys->open(ref);require(key!=nullptr);const auto& b=proof.bundle();const auto ip=proof.transcript().host.desktop_ipv4;
        e::require_renewed_identity(proof,ref,key->public_key(),std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));require(verify_revocation(b,ip));
        const auto& bytes=proof.role()==e::PairRole::host?b.server:b.client;Owned<SecCertificateRef> cert(decode(bytes));
        return attach_certificate(ref,cert.value,bytes,ip,key->public_key(),[&]{require(proof.valid_at(std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now())));});
    }
    e::Bytes describe(const e::KeyReference& ref,e::Bytes bytes,std::array<std::byte,4> ip)override{
        e::require_identity_certificate_profile(bytes,ref.purpose,ip);auto keys=enrollment_key_store(keychain_);auto key=keys->open(ref);require(key!=nullptr);
        Owned<SecCertificateRef> cert(decode(bytes));require(point(cert.value)==key->public_key());return stable_reference(ref,bytes,ip);
    }
    bool key_ready(const e::KeyReference& ref,const e::PublicKey& expected)override{
        try{auto keys=enrollment_key_store(keychain_);auto key=keys->open(ref);if(!key || key->public_key()!=expected)return false;
            std::array<std::byte,64> challenge{};constexpr std::string_view domain="LanPilot config key proof v1";std::memcpy(challenge.data(),domain.data(),domain.size());
            if(SecRandomCopyBytes(kSecRandomDefault,32,reinterpret_cast<std::uint8_t*>(challenge.data()+32))!=errSecSuccess)return false;
            return enrollment_pairing_verifier()->verify(expected,challenge,key->sign_sha256(challenge));
        }catch(...){return false;}
    }
    bool certificate_absent(std::span<const std::byte> bytes)override {
        if(bytes.empty() || bytes.size()>8192)return false;
        try {Owned<SecCertificateRef> cert(decode(e::Bytes(bytes.begin(),bytes.end())));
            Owned<SecCertificateRef> found(stored_certificate(keychain_,cert.value));return !found.value;
        }catch(...){return false;}
    }
    bool ready(const e::AssociatedIdentity& r)override {
        try {
            auto keys=enrollment_key_store(keychain_);auto key=keys->open(r.key);if(!key || key->public_key()!=r.subject_key)return false;
            Owned<SecIdentityRef> identity(load(r.native_reference));return identity.value && matches(identity.value,r) && possession(identity.value,r.subject_key);
        }catch(...){return false;}
    }
    std::optional<e::AssociatedIdentity> locate(const e::KeyReference& ref,e::Bytes bytes,std::array<std::byte,4> ip)override {
        try {
            if(ref.purpose!=e::KeyPurpose::server && ref.purpose!=e::KeyPurpose::client)return {};
            e::require_identity_certificate_profile(bytes,ref.purpose,ip);auto keys=enrollment_key_store(keychain_);auto key=keys->open(ref);if(!key)return {};
            Owned<SecCertificateRef> cert(decode(bytes));if(point(cert.value)!=key->public_key())return {};
            // Native identity creation alone can combine an unstored public
            // certificate with a matching key. Require the stored leaf too.
            Owned<SecCertificateRef> stored(stored_certificate(keychain_,cert.value));if(!stored.value)return {};
            SecIdentityRef raw{};if(SecIdentityCreateWithCertificate(keychain_,stored.value,&raw)!=errSecSuccess)return {};Owned<SecIdentityRef> identity(raw);
            auto reference=stable_reference(ref,bytes,ip);
            e::AssociatedIdentity out{ref,key->public_key(),core::sha256(bytes),ip,std::move(reference),std::move(bytes),false};
            if(out.native_reference.size()>4096 || !matches(identity.value,out))return {};return out;
        }catch(...){return {};}
    }
    bool remove_created(const e::AssociatedIdentity& r)override {
        if(!r.created)return false;
        try {const auto found=locate(r.key,r.certificate_der,r.server_ipv4);if(!found || found->certificate_sha256!=r.certificate_sha256 || found->subject_key!=r.subject_key)return false;
            if(!r.native_reference.empty() && r.native_reference!=found->native_reference)return false;
            Owned<SecIdentityRef> identity(load(found->native_reference));if(!identity.value || !matches(identity.value,r))return false;
            SecCertificateRef raw{};require(SecIdentityCopyCertificate(identity.value,&raw)==errSecSuccess);Owned<SecCertificateRef> cert(raw);return delete_certificate(cert.value);
        }catch(...){return false;}
    }
private:
    template<class Live>e::AssociatedIdentity attach_certificate(const e::KeyReference& ref,SecCertificateRef certificate,const e::Bytes& bytes,std::array<std::byte,4> ip,const e::PublicKey& key,Live live){
        live();e::AssociatedIdentity receipt{ref,key,core::sha256(bytes),ip,{},bytes,false};
        Owned<CFMutableDictionaryRef> add(dictionary());CFDictionarySetValue(add.value,kSecClass,kSecClassCertificate);CFDictionarySetValue(add.value,kSecValueRef,certificate);CFDictionarySetValue(add.value,kSecUseKeychain,keychain_);
        const auto status=SecItemAdd(add.value,nullptr);require(status==errSecSuccess || status==errSecDuplicateItem);receipt.created=status==errSecSuccess;
        try{Owned<SecCertificateRef> stored(stored_certificate(keychain_,certificate));require(stored.value!=nullptr);
            SecIdentityRef raw{};require(SecIdentityCreateWithCertificate(keychain_,stored.value,&raw)==errSecSuccess);Owned<SecIdentityRef> identity(raw);
            receipt.native_reference=stable_reference(ref,bytes,ip);require(receipt.native_reference.size()<=4096 && matches(identity.value,receipt) && possession(identity.value,receipt.subject_key));live();return receipt;
        }catch(...){if(receipt.created)delete_certificate(certificate);throw;}
    }
    CFArrayRef search()const{const void* items[]{keychain_};return CFArrayCreate(nullptr,items,1,&kCFTypeArrayCallBacks);}
    SecIdentityRef load(const e::Bytes& reference){
        return load_enrollment_identity(reference,keychain_);
    }
    bool matches(SecIdentityRef identity,const e::AssociatedIdentity& r){
        if(r.key.purpose!=e::KeyPurpose::server && r.key.purpose!=e::KeyPurpose::client)return false;
        SecCertificateRef raw{};require(SecIdentityCopyCertificate(identity,&raw)==errSecSuccess);Owned<SecCertificateRef> cert(raw);
        Owned<CFDataRef> d(SecCertificateCopyData(cert.value));const auto bytes=copied(d.value);
        e::require_identity_certificate_profile(bytes,r.key.purpose,r.server_ipv4);
        if(bytes!=r.certificate_der || core::sha256(bytes)!=r.certificate_sha256 || point(cert.value)!=r.subject_key)return false;
        auto keys=enrollment_key_store(keychain_);auto key=keys->open(r.key);return key && key->public_key()==r.subject_key;
    }
    bool possession(SecIdentityRef identity,const e::PublicKey& expected){
        SecKeyRef raw{};require(SecIdentityCopyPrivateKey(identity,&raw)==errSecSuccess);Owned<SecKeyRef> key(raw);
        Owned<SecKeyRef> public_key(SecKeyCopyPublicKey(key.value));if(!public_key.value || key_point(public_key.value)!=expected)return false;
        std::array<std::byte,64> message{};constexpr std::string_view domain="LanPilot native identity possession v1";
        std::memcpy(message.data(),domain.data(),domain.size());require(SecRandomCopyBytes(kSecRandomDefault,24,reinterpret_cast<std::uint8_t*>(message.data()+40))==errSecSuccess);
        Owned<CFDataRef> input(cf_data(message));CFErrorRef error{};
        Owned<CFDataRef> signature(SecKeyCreateSignature(key.value,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,input.value,&error));if(error)CFRelease(error);
        return signature.value && enrollment_pairing_verifier()->verify(expected,message,copied(signature.value));
    }
    bool delete_certificate(SecCertificateRef certificate){
        Owned<SecCertificateRef> stored(stored_certificate(keychain_,certificate));if(!stored.value)return false;
        Owned<CFMutableDictionaryRef> query(dictionary());Owned<CFArrayRef> list(search());
        CFDictionarySetValue(query.value,kSecClass,kSecClassCertificate);CFDictionarySetValue(query.value,kSecValueRef,stored.value);CFDictionarySetValue(query.value,kSecMatchSearchList,list.value);
        return SecItemDelete(query.value)==errSecSuccess;
    }
    SecKeychainRef keychain_{};
};
}
std::unique_ptr<core::enrollment::IdentityStore> enrollment_identity_store(SecKeychainRef local_keychain){return std::make_unique<Store>(local_keychain);}
bool is_enrollment_identity_reference(std::span<const std::byte> bytes){return bytes.size()>=4 && std::memcmp(bytes.data(),"LPI1",4)==0;}
SecIdentityRef load_enrollment_identity(std::span<const std::byte> bytes,SecKeychainRef keychain){
    require(bytes.size()>=27 && bytes.size()<=3099 && is_enrollment_identity_reference(bytes));
    e::KeyReference ref{static_cast<e::KeyPurpose>(bytes[4]),{}};std::copy_n(bytes.begin()+5,16,ref.id.begin());
    std::array<std::byte,4> ip{};std::copy_n(bytes.begin()+21,4,ip.begin());
    const auto length=(std::to_integer<unsigned>(bytes[25])<<8)|std::to_integer<unsigned>(bytes[26]);
    require(length>0 && length<=3072 && bytes.size()==27+length && (ref.purpose==e::KeyPurpose::server || ref.purpose==e::KeyPurpose::client));
    (void)e::key_reference_name(ref);
    Owned<SecKeychainRef> default_keychain([&](){if(keychain){CFRetain(keychain);return keychain;}SecKeychainRef own{};require(SecKeychainCopyDefault(&own)==errSecSuccess);return own;}());
    const e::Bytes encoded(bytes.begin()+27,bytes.end());e::require_identity_certificate_profile(encoded,ref.purpose,ip);Owned<SecCertificateRef> cert(decode(encoded));
    auto keys=enrollment_key_store(default_keychain.value);auto key=keys->open(ref);require(key && key->public_key()==point(cert.value));
    Owned<SecCertificateRef> stored(stored_certificate(default_keychain.value,cert.value));require(stored.value!=nullptr);
    SecIdentityRef identity{};require(SecIdentityCreateWithCertificate(default_keychain.value,stored.value,&identity)==errSecSuccess);return identity;
}
}
