#include "rwn/platform/macos/enrollment_key.hpp"
#include "rwn/platform/macos/update_signature.hpp"
#include <cstring>
#include <stdexcept>
#include <source_location>

namespace rwn::platform::macos {
namespace {
namespace e=core::enrollment;
void require(bool ok,std::source_location at=std::source_location::current()){
    if(!ok)throw std::runtime_error("protected enrollment key operation failed at check "+std::to_string(at.line()));
}
template<class T> struct Owned {
    T value{};explicit Owned(T v):value(v){}~Owned(){if(value)CFRelease(value);}
    Owned(const Owned&)=delete;
};
Owned<CFDataRef> tag(const e::KeyReference& reference) {
    const auto s=e::key_reference_name(reference);
    return Owned<CFDataRef>(CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(s.data()),static_cast<CFIndex>(s.size())));
}
CFMutableDictionaryRef dictionary(){return CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);}
e::PublicKey public_point(SecKeyRef source) {
    Owned<SecKeyRef> key(SecKeyCopyPublicKey(source));require(key.value!=nullptr);CFErrorRef error{};
    Owned<CFDataRef> data(SecKeyCopyExternalRepresentation(key.value,&error));if(error)CFRelease(error);
    require(data.value && CFDataGetLength(data.value)==65 && CFDataGetBytePtr(data.value)[0]==4);
    e::PublicKey result{};std::memcpy(result.data(),CFDataGetBytePtr(data.value)+1,64);return result;
}
class Key final:public e::Signer {
public:
    explicit Key(SecKeyRef key):key_(key){
        try {
            Owned<CFDictionaryRef> attributes(SecKeyCopyAttributes(key_));require(attributes.value!=nullptr);
            const auto type=CFDictionaryGetValue(attributes.value,kSecAttrKeyType);
            require(type && CFEqual(type,kSecAttrKeyTypeECSECPrimeRandom));
            require(CFDictionaryGetValue(attributes.value,kSecAttrIsExtractable)==kCFBooleanFalse);
            require(CFDictionaryGetValue(attributes.value,kSecAttrCanSign)==kCFBooleanTrue);
            for(const auto attribute:{kSecAttrCanDecrypt,kSecAttrCanDerive,kSecAttrCanUnwrap})
                require(CFDictionaryGetValue(attributes.value,attribute)==kCFBooleanFalse);
            const auto kind=CFDictionaryGetValue(attributes.value,kSecAttrKeyClass);
            require(kind && CFEqual(kind,kSecAttrKeyClassPrivate));
            require(SecKeyIsAlgorithmSupported(key_,kSecKeyOperationTypeSign,kSecKeyAlgorithmECDSASignatureMessageX962SHA256));
            (void)public_key();
        }catch(...){CFRelease(key_);key_=nullptr;throw;}
    }
    ~Key(){if(key_)CFRelease(key_);}
    e::PublicKey public_key()const override {
        return public_point(key_);
    }
    bool accepts_public_key(const e::PublicKey& point)const override {
        std::array<std::byte,65> encoded{};encoded[0]=std::byte{4};std::memcpy(encoded.data()+1,point.data(),64);
        Owned<CFDataRef> data(CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(encoded.data()),65));
        Owned<CFMutableDictionaryRef> attributes(dictionary());
        CFDictionarySetValue(attributes.value,kSecAttrKeyType,kSecAttrKeyTypeECSECPrimeRandom);
        CFDictionarySetValue(attributes.value,kSecAttrKeyClass,kSecAttrKeyClassPublic);
        CFErrorRef error{};Owned<SecKeyRef> key(SecKeyCreateWithData(data.value,attributes.value,&error));if(error)CFRelease(error);return key.value!=nullptr;
    }
    e::Bytes sign_sha256(std::span<const std::byte> message)override {
        Owned<CFDataRef> data(CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(message.data()),static_cast<CFIndex>(message.size())));
        CFErrorRef error{};Owned<CFDataRef> signature(SecKeyCreateSignature(key_,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,data.value,&error));
        if(error)CFRelease(error);
        require(signature.value!=nullptr);
        const auto* p=reinterpret_cast<const std::byte*>(CFDataGetBytePtr(signature.value));return {p,p+CFDataGetLength(signature.value)};
    }
    CFDataRef copy_label()const {
        Owned<CFDictionaryRef> attributes(SecKeyCopyAttributes(key_));require(attributes.value!=nullptr);
        const auto label=CFDictionaryGetValue(attributes.value,kSecAttrApplicationLabel);
        require(label && CFGetTypeID(label)==CFDataGetTypeID());CFRetain(label);return static_cast<CFDataRef>(label);
    }
private:SecKeyRef key_{};
};
class Store final:public e::KeyStore {
public:
    explicit Store(SecKeychainRef keychain):keychain_(keychain){
        if(keychain_)CFRetain(keychain_);
        else require(SecKeychainCopyDefault(&keychain_)==errSecSuccess && keychain_);
    }
    ~Store(){CFRelease(keychain_);}
    std::unique_ptr<e::Signer> create_new(const e::KeyReference& reference)override {
        if(open(reference))throw std::runtime_error("enrollment key already exists");
        const auto application_tag=tag(reference);
        Owned<CFMutableDictionaryRef> attributes(dictionary()),private_attributes(dictionary());
        CFDictionarySetValue(attributes.value,kSecAttrKeyType,kSecAttrKeyTypeECSECPrimeRandom);
        int bits=256;Owned<CFNumberRef> size(CFNumberCreate(nullptr,kCFNumberIntType,&bits));
        CFDictionarySetValue(attributes.value,kSecAttrKeySizeInBits,size.value);
        CFDictionarySetValue(attributes.value,kSecUseKeychain,keychain_);
        // The legacy login-keychain implementation reads extractability from
        // the top-level parameters, not the private-key overrides. Set both
        // and validate the persisted result instead of trusting the request.
        CFDictionarySetValue(attributes.value,kSecAttrIsExtractable,kCFBooleanFalse);
        CFDictionarySetValue(private_attributes.value,kSecAttrIsPermanent,kCFBooleanTrue);
        CFDictionarySetValue(private_attributes.value,kSecAttrApplicationTag,application_tag.value);
        CFDictionarySetValue(private_attributes.value,kSecAttrIsExtractable,kCFBooleanFalse);
        CFDictionarySetValue(private_attributes.value,kSecAttrCanSign,kCFBooleanTrue);
        for(const auto attribute:{kSecAttrCanDecrypt,kSecAttrCanDerive,kSecAttrCanUnwrap})
            CFDictionarySetValue(private_attributes.value,attribute,kCFBooleanFalse);
        CFDictionarySetValue(attributes.value,kSecPrivateKeyAttrs,private_attributes.value);
        CFErrorRef error{};Owned<SecKeyRef> key(SecKeyCreateRandomKey(attributes.value,&error));if(error)CFRelease(error);require(key.value!=nullptr);
        // SecKeyCreateRandomKey can return an in-memory software reference.
        // Validate the keychain-owned reference and release the transient one
        // at this call's boundary; never mistake
        // requested attributes on a transient key for persisted protection.
        try {
            auto persisted=open(reference);require(persisted!=nullptr && persisted->public_key()==public_point(key.value));return persisted;
        }catch(...) {
            // Only the item this operation created may be removed. Never
            // erase a tag-wide replacement after a failed open/validation.
            Owned<CFDictionaryRef> actual(SecKeyCopyAttributes(key.value));
            if(actual.value){
                const auto label=CFDictionaryGetValue(actual.value,kSecAttrApplicationLabel);
                if(label && CFGetTypeID(label)==CFDataGetTypeID()){
                    Owned<CFMutableDictionaryRef> query(key_query(application_tag.value));
                    CFDictionarySetValue(query.value,kSecAttrApplicationLabel,label);SecItemDelete(query.value);
                }
            }
            throw;
        }
    }
    std::unique_ptr<e::Signer> open(const e::KeyReference& reference)override {
        const auto application_tag=tag(reference);Owned<CFMutableDictionaryRef> query(key_query(application_tag.value));
        CFDictionarySetValue(query.value,kSecMatchLimit,kSecMatchLimitAll);CFDictionarySetValue(query.value,kSecReturnRef,kCFBooleanTrue);
        CFTypeRef found{};const auto status=SecItemCopyMatching(query.value,&found);Owned<CFTypeRef> result(found);
        if(status==errSecItemNotFound)return {};
        require(status==errSecSuccess && found && CFGetTypeID(found)==CFArrayGetTypeID());
        auto array=static_cast<CFArrayRef>(found);require(CFArrayGetCount(array)==1);
        auto key=static_cast<SecKeyRef>(const_cast<void*>(CFArrayGetValueAtIndex(array,0)));require(CFGetTypeID(key)==SecKeyGetTypeID());
        CFRetain(key);return std::make_unique<Key>(key);
    }
    bool remove_if_matches(const e::KeyReference& reference,const e::PublicKey& expected)override {
        auto key=open(reference);if(!key || key->public_key()!=expected)return false;
        const auto application_tag=tag(reference);Owned<CFMutableDictionaryRef> query(key_query(application_tag.value));
        // Match both the fixed local tag and the OS public-key label, so a
        // different replacement at this tag cannot be deleted after the check.
        Owned<CFDataRef> label(static_cast<Key&>(*key).copy_label());
        CFDictionarySetValue(query.value,kSecAttrApplicationLabel,label.value);
        return SecItemDelete(query.value)==errSecSuccess;
    }
private:
    CFMutableDictionaryRef key_query(CFDataRef application_tag)const {
        auto result=dictionary();CFDictionarySetValue(result,kSecClass,kSecClassKey);
        CFDictionarySetValue(result,kSecAttrKeyType,kSecAttrKeyTypeECSECPrimeRandom);
        CFDictionarySetValue(result,kSecAttrKeyClass,kSecAttrKeyClassPrivate);
        CFDictionarySetValue(result,kSecAttrApplicationTag,application_tag);
        const void* items[]{keychain_};Owned<CFArrayRef> search(CFArrayCreate(nullptr,items,1,&kCFTypeArrayCallBacks));
        CFDictionarySetValue(result,kSecMatchSearchList,search.value);
        CFDictionarySetValue(result,kSecUseAuthenticationUI,kSecUseAuthenticationUIFail);return result;
    }
    SecKeychainRef keychain_{};
};
class ProofVerifier final:public e::PairProofVerifier {
public:
    bool verify(const e::PublicKey& key,std::span<const std::byte> message,std::span<const std::byte> signature)const override {
        if(message.empty() || message.size()>512)return false;
        try {const auto raw=e::pairing_signature_raw(signature);return SecurityEcdsaP256UpdateVerifier(key).verify(message,raw);}
        catch(...){return false;}
    }
};
}
std::unique_ptr<core::enrollment::KeyStore> enrollment_key_store(SecKeychainRef keychain){return std::make_unique<Store>(keychain);}
std::unique_ptr<core::enrollment::PairProofVerifier> enrollment_pairing_verifier(){return std::make_unique<ProofVerifier>();}
}
