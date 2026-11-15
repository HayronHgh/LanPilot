#pragma once
// Ephemeral native software signer for probes only. No personal stores or
// persistent identity creation; only public keys/signatures may leave a probe.
#include "rwn/core/enrollment_certificate.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/core/release_compatibility.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif
namespace rwn::probe {
namespace e=core::enrollment;
inline void check(bool ok){if(!ok)throw std::runtime_error("ephemeral native signing fixture failed");}
#if defined(_WIN32)
class EphemeralSigner final:public e::Signer {
public:
    EphemeralSigner(){
        check(BCryptOpenAlgorithmProvider(&algorithm_,BCRYPT_ECDSA_P256_ALGORITHM,nullptr,0)>=0);
        if(BCryptGenerateKeyPair(algorithm_,&key_,256,0)<0 || BCryptFinalizeKeyPair(key_,0)<0){
            if(key_)BCryptDestroyKey(key_);
            BCryptCloseAlgorithmProvider(algorithm_,0);throw std::runtime_error("ephemeral key fixture failed");
        }
    }
    ~EphemeralSigner(){BCryptDestroyKey(key_);BCryptCloseAlgorithmProvider(algorithm_,0);}
    e::PublicKey public_key()const override{
        std::array<std::byte,sizeof(BCRYPT_ECCKEY_BLOB)+64> data{};ULONG size{};
        check(BCryptExportKey(key_,nullptr,BCRYPT_ECCPUBLIC_BLOB,reinterpret_cast<PUCHAR>(data.data()),static_cast<ULONG>(data.size()),&size,0)>=0 && size==data.size());
        e::PublicKey result{};std::copy_n(data.begin()+sizeof(BCRYPT_ECCKEY_BLOB),64,result.begin());return result;
    }
    bool accepts_public_key(const e::PublicKey& point)const override{
        std::array<std::byte,sizeof(BCRYPT_ECCKEY_BLOB)+64> data{};
        const BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC,32};std::memcpy(data.data(),&header,sizeof(header));
        std::copy(point.begin(),point.end(),data.begin()+sizeof(header));BCRYPT_KEY_HANDLE key{};
        const auto status=BCryptImportKeyPair(algorithm_,nullptr,BCRYPT_ECCPUBLIC_BLOB,&key,reinterpret_cast<PUCHAR>(data.data()),static_cast<ULONG>(data.size()),0);
        if(key)BCryptDestroyKey(key);
        return status>=0;
    }
    e::Bytes sign_sha256(std::span<const std::byte> message)override{
        auto digest=rwn::core::sha256(message);e::Bytes signature(64);ULONG size{};
        check(BCryptSignHash(key_,nullptr,reinterpret_cast<PUCHAR>(digest.data()),32,reinterpret_cast<PUCHAR>(signature.data()),64,&size,0)>=0 && size==64);
        return rwn::core::ecdsa_p256_signature_der(signature);
    }
private:BCRYPT_ALG_HANDLE algorithm_{};BCRYPT_KEY_HANDLE key_{};
};
#else
template<class T> struct Owned{T value{};explicit Owned(T v):value(v){}~Owned(){if(value)CFRelease(value);}Owned(const Owned&)=delete;};
class EphemeralSigner final:public e::Signer {
public:
    EphemeralSigner(){
        const void* names[]{kSecAttrKeyType,kSecAttrKeySizeInBits,kSecAttrIsPermanent};
        int bits=256;Owned<CFNumberRef> size(CFNumberCreate(nullptr,kCFNumberIntType,&bits));
        const void* values[]{kSecAttrKeyTypeECSECPrimeRandom,size.value,kCFBooleanFalse};
        Owned<CFDictionaryRef> attributes(CFDictionaryCreate(nullptr,names,values,3,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks));
        CFErrorRef error{};key_=SecKeyCreateRandomKey(attributes.value,&error);if(error)CFRelease(error);check(key_!=nullptr);
    }
    ~EphemeralSigner(){CFRelease(key_);}
    e::PublicKey public_key()const override{
        Owned<SecKeyRef> key(SecKeyCopyPublicKey(key_));check(key.value!=nullptr);CFErrorRef error{};
        Owned<CFDataRef> data(SecKeyCopyExternalRepresentation(key.value,&error));if(error)CFRelease(error);
        check(data.value && CFDataGetLength(data.value)==65 && CFDataGetBytePtr(data.value)[0]==4);
        e::PublicKey result{};std::memcpy(result.data(),CFDataGetBytePtr(data.value)+1,64);return result;
    }
    bool accepts_public_key(const e::PublicKey& point)const override{
        e::Bytes encoded{std::byte{4}};encoded.insert(encoded.end(),point.begin(),point.end());
        Owned<CFDataRef> data(CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(encoded.data()),static_cast<CFIndex>(encoded.size())));
        int bits=256;Owned<CFNumberRef> size(CFNumberCreate(nullptr,kCFNumberIntType,&bits));
        const void* names[]{kSecAttrKeyType,kSecAttrKeyClass,kSecAttrKeySizeInBits};
        const void* values[]{kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeyClassPublic,size.value};
        Owned<CFDictionaryRef> attributes(CFDictionaryCreate(nullptr,names,values,3,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks));
        CFErrorRef error{};Owned<SecKeyRef> key(SecKeyCreateWithData(data.value,attributes.value,&error));if(error)CFRelease(error);return key.value!=nullptr;
    }
    e::Bytes sign_sha256(std::span<const std::byte> message)override{
        Owned<CFDataRef> data(CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(message.data()),static_cast<CFIndex>(message.size())));
        CFErrorRef error{};Owned<CFDataRef> signature(SecKeyCreateSignature(key_,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,data.value,&error));
        if(error)CFRelease(error);check(signature.value!=nullptr);
        const auto* p=reinterpret_cast<const std::byte*>(CFDataGetBytePtr(signature.value));return {p,p+CFDataGetLength(signature.value)};
    }
private:SecKeyRef key_{};
};
#endif
} // namespace rwn::probe
