#include "rwn/platform/windows/enrollment_key.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/core/release_compatibility.hpp"
#include "rwn/platform/windows/update_signature.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace rwn::platform::windows {
namespace {
namespace e=core::enrollment;
void require(bool ok){if(!ok)throw std::runtime_error("protected enrollment key operation failed");}
std::wstring name(const e::KeyReference& reference){const auto s=e::key_reference_name(reference);return {s.begin(),s.end()};}
struct Handle {
    NCRYPT_HANDLE value{};
    ~Handle(){if(value)NCryptFreeObject(value);}
    Handle()=default;Handle(const Handle&)=delete;
};
class Key final:public e::Signer {
public:
    explicit Key(NCRYPT_KEY_HANDLE key):key_(key){
            DWORD policy{},usage{},length{},size{};
            require(NCryptGetProperty(key_,NCRYPT_EXPORT_POLICY_PROPERTY,reinterpret_cast<PBYTE>(&policy),sizeof(policy),&size,0)==ERROR_SUCCESS && size==sizeof(policy) && policy==0);
            require(NCryptGetProperty(key_,NCRYPT_KEY_USAGE_PROPERTY,reinterpret_cast<PBYTE>(&usage),sizeof(usage),&size,0)==ERROR_SUCCESS && size==sizeof(usage) && usage==NCRYPT_ALLOW_SIGNING_FLAG);
            require(NCryptGetProperty(key_,NCRYPT_LENGTH_PROPERTY,reinterpret_cast<PBYTE>(&length),sizeof(length),&size,0)==ERROR_SUCCESS && length==256);
            (void)public_key();
    }
    ~Key(){if(key_)NCryptFreeObject(key_);}
    e::PublicKey public_key()const override {
        std::array<std::byte,sizeof(BCRYPT_ECCKEY_BLOB)+64> data{};DWORD size{};
        require(NCryptExportKey(key_,0,BCRYPT_ECCPUBLIC_BLOB,nullptr,reinterpret_cast<PBYTE>(data.data()),static_cast<DWORD>(data.size()),&size,0)==ERROR_SUCCESS && size==data.size());
        BCRYPT_ECCKEY_BLOB header{};std::memcpy(&header,data.data(),sizeof(header));
        require(header.dwMagic==BCRYPT_ECDSA_PUBLIC_P256_MAGIC && header.cbKey==32);
        e::PublicKey result{};std::copy_n(data.begin()+sizeof(header),64,result.begin());return result;
    }
    bool accepts_public_key(const e::PublicKey& point)const override {
        BCRYPT_ALG_HANDLE algorithm{};
        if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_ECDSA_P256_ALGORITHM,nullptr,0)<0)return false;
        std::array<std::byte,sizeof(BCRYPT_ECCKEY_BLOB)+64> data{};
        const BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC,32};std::memcpy(data.data(),&header,sizeof(header));
        std::copy(point.begin(),point.end(),data.begin()+sizeof(header));BCRYPT_KEY_HANDLE key{};
        const auto status=BCryptImportKeyPair(algorithm,nullptr,BCRYPT_ECCPUBLIC_BLOB,&key,reinterpret_cast<PUCHAR>(data.data()),static_cast<ULONG>(data.size()),0);
        if(key)BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm,0);return status>=0;
    }
    e::Bytes sign_sha256(std::span<const std::byte> message)override {
        const auto digest=core::sha256(message);e::Bytes result(64);DWORD size{};
        require(NCryptSignHash(key_,nullptr,reinterpret_cast<PBYTE>(const_cast<std::byte*>(digest.data())),32,reinterpret_cast<PBYTE>(result.data()),64,&size,NCRYPT_SILENT_FLAG)==ERROR_SUCCESS && size==64);
        return core::ecdsa_p256_signature_der(result);
    }
    bool erase(){const auto status=NCryptDeleteKey(key_,NCRYPT_SILENT_FLAG);if(status==ERROR_SUCCESS)key_=0;return status==ERROR_SUCCESS;}
private:NCRYPT_KEY_HANDLE key_{};
};
class Store final:public e::KeyStore {
public:
    Store(){require(NCryptOpenStorageProvider(&provider_.value,MS_KEY_STORAGE_PROVIDER,0)==ERROR_SUCCESS);}
    std::unique_ptr<e::Signer> create_new(const e::KeyReference& reference)override {
        const auto label=name(reference);Handle key;
        require(NCryptCreatePersistedKey(provider_.value,&key.value,BCRYPT_ECDSA_P256_ALGORITHM,label.c_str(),0,0)==ERROR_SUCCESS);
        bool finalized=false;
        try {
            DWORD export_policy=0,usage=NCRYPT_ALLOW_SIGNING_FLAG;
            require(NCryptSetProperty(key.value,NCRYPT_EXPORT_POLICY_PROPERTY,reinterpret_cast<PBYTE>(&export_policy),sizeof(export_policy),0)==ERROR_SUCCESS);
            require(NCryptSetProperty(key.value,NCRYPT_KEY_USAGE_PROPERTY,reinterpret_cast<PBYTE>(&usage),sizeof(usage),0)==ERROR_SUCCESS);
            require(NCryptFinalizeKey(key.value,NCRYPT_SILENT_FLAG)==ERROR_SUCCESS);finalized=true;
            auto result=std::make_unique<Key>(key.value);key.value=0;return result;
        }catch(...) {
            if(finalized && key.value && NCryptDeleteKey(key.value,NCRYPT_SILENT_FLAG)==ERROR_SUCCESS)key.value=0;
            throw;
        }
    }
    std::unique_ptr<e::Signer> open(const e::KeyReference& reference)override {
        const auto label=name(reference);Handle key;
        const auto status=NCryptOpenKey(provider_.value,&key.value,label.c_str(),0,NCRYPT_SILENT_FLAG);
        if(status==NTE_BAD_KEYSET || status==NTE_NOT_FOUND)return {};
        require(status==ERROR_SUCCESS);auto result=std::make_unique<Key>(key.value);key.value=0;return result;
    }
    bool remove_if_matches(const e::KeyReference& reference,const e::PublicKey& expected)override {
        auto key=open(reference);if(!key || key->public_key()!=expected)return false;
        return static_cast<Key&>(*key).erase();
    }
private:Handle provider_;
};
class ProofVerifier final:public e::PairProofVerifier {
public:
    bool verify(const e::PublicKey& key,std::span<const std::byte> message,std::span<const std::byte> signature)const override {
        if(message.empty() || message.size()>512)return false;
        try {const auto raw=e::pairing_signature_raw(signature);return CngEcdsaP256UpdateVerifier(key).verify(message,raw);}
        catch(...){return false;}
    }
};
}
std::unique_ptr<core::enrollment::KeyStore> enrollment_key_store(){return std::make_unique<Store>();}
std::unique_ptr<core::enrollment::PairProofVerifier> enrollment_pairing_verifier(){return std::make_unique<ProofVerifier>();}
}
