// Deliberate, isolated storage fixture: fresh random CNG test containers on
// Windows; a temporary standalone keychain on Mac. Deletes only its own keys.
// Identity binding uses a memory certificate store / temporary Keychain only.
// Only explicit loopback recovery sockets; no installed identity, personal
// certificate store, external network or desktop access.
#include "rwn/core/enrollment_key.hpp"
#include "enrollment_journal_fixture.hpp"
#include "enrollment_commit_fixture.hpp"
#include <filesystem>
#include <iostream>
#include <source_location>
#include <cstring>
#include <algorithm>
#if defined(_WIN32)
#include "rwn/platform/windows/enrollment_key.hpp"
#include "rwn/platform/windows/enrollment_identity.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#else
#include "rwn/platform/macos/enrollment_key.hpp"
#include "rwn/platform/macos/enrollment_identity.hpp"
#include <unistd.h>
#endif
namespace e=rwn::core::enrollment;
namespace {
void check(bool value,std::source_location at=std::source_location::current()) {
    if(!value)throw std::runtime_error("native key fixture failed at line "+std::to_string(at.line()));
}
template<class F> void rejected(F function){bool threw=false;try{function();}catch(...){threw=true;}check(threw);}
void random(std::span<std::byte> bytes) {
#if defined(_WIN32)
    check(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(bytes.data()),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0);
#else
    check(SecRandomCopyBytes(kSecRandomDefault,bytes.size(),reinterpret_cast<std::uint8_t*>(bytes.data()))==errSecSuccess);
#endif
}
void verify_self_signed(e::Signer& key) {
    using namespace std::chrono;
    e::Serial serial{};random(serial);const auto now=floor<seconds>(system_clock::now());
    const auto root=e::root_certificate(key,serial,{now-minutes{1},now+days{1}});
#if defined(_WIN32)
    const auto cert=CertCreateCertificateContext(X509_ASN_ENCODING,reinterpret_cast<const BYTE*>(root.data()),static_cast<DWORD>(root.size()));check(cert!=nullptr);
    const auto ok=CryptVerifyCertificateSignatureEx(0,X509_ASN_ENCODING,CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,const_cast<PCERT_CONTEXT>(cert),CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,const_cast<PCERT_CONTEXT>(cert),0,nullptr);
    CertFreeCertificateContext(cert);check(ok);
#else
    auto data=CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(root.data()),static_cast<CFIndex>(root.size()));
    auto cert=SecCertificateCreateWithData(nullptr,data);CFRelease(data);check(cert!=nullptr);
    // Real certificate parsing and key extraction, plus a fresh native sign /
    // verify challenge on the reopened persistent private key.
    auto public_key=SecCertificateCopyKey(cert);CFRelease(cert);check(public_key!=nullptr);
    const std::array<std::byte,4> challenge{std::byte{1},std::byte{7},std::byte{3},std::byte{8}};
    const auto signature=key.sign_sha256(challenge);
    auto message=CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(challenge.data()),4);
    auto signed_data=CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(signature.data()),static_cast<CFIndex>(signature.size()));
    CFErrorRef error{};const bool ok=SecKeyVerifySignature(public_key,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,message,signed_data,&error);
    if(error)CFRelease(error);
    CFRelease(public_key);CFRelease(message);CFRelease(signed_data);check(ok);
#endif
}
void verify_export_denied(const e::KeyReference& reference
#if defined(__APPLE__)
    ,SecKeychainRef keychain
#endif
) {
    const auto name=e::key_reference_name(reference);
#if defined(_WIN32)
    NCRYPT_PROV_HANDLE provider{};NCRYPT_KEY_HANDLE key{};
    check(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)==ERROR_SUCCESS);
    const std::wstring wide(name.begin(),name.end());const auto opened=NCryptOpenKey(provider,&key,wide.c_str(),0,NCRYPT_SILENT_FLAG);
    if(opened!=ERROR_SUCCESS){NCryptFreeObject(provider);check(false);}
    std::array<BYTE,512> attempted{};DWORD size{};
    const auto status=NCryptExportKey(key,0,BCRYPT_ECCPRIVATE_BLOB,nullptr,attempted.data(),static_cast<DWORD>(attempted.size()),&size,NCRYPT_SILENT_FLAG);
    SecureZeroMemory(attempted.data(),attempted.size());NCryptFreeObject(key);NCryptFreeObject(provider);
    check(status==NTE_PERM || status==NTE_NOT_SUPPORTED);
#else
    auto query=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    auto tag=CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(name.data()),static_cast<CFIndex>(name.size()));
    const void* items[]{keychain};auto search=CFArrayCreate(nullptr,items,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(query,kSecClass,kSecClassKey);CFDictionarySetValue(query,kSecAttrKeyClass,kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query,kSecAttrApplicationTag,tag);CFDictionarySetValue(query,kSecMatchSearchList,search);
    CFDictionarySetValue(query,kSecReturnRef,kCFBooleanTrue);CFTypeRef result{};
    const auto status=SecItemCopyMatching(query,&result);CFRelease(query);CFRelease(tag);CFRelease(search);
    check(status==errSecSuccess && result && CFGetTypeID(result)==SecKeyGetTypeID());CFErrorRef error{};
    auto exported=SecKeyCopyExternalRepresentation(static_cast<SecKeyRef>(const_cast<void*>(result)),&error);CFRelease(result);
    if(error)CFRelease(error);
    const bool denied=exported==nullptr;if(exported)CFRelease(exported);check(denied);
#endif
}
void reject_exportable_key(e::KeyStore& store,const e::KeyReference& reference
#if defined(__APPLE__)
    ,SecKeychainRef keychain
#endif
) {
    const auto name=e::key_reference_name(reference);
#if defined(_WIN32)
    NCRYPT_PROV_HANDLE provider{};NCRYPT_KEY_HANDLE key{};
    check(NCryptOpenStorageProvider(&provider,MS_KEY_STORAGE_PROVIDER,0)==ERROR_SUCCESS);
    const std::wstring wide(name.begin(),name.end());
    auto status=NCryptCreatePersistedKey(provider,&key,BCRYPT_ECDSA_P256_ALGORITHM,wide.c_str(),0,0);
    if(status!=ERROR_SUCCESS){NCryptFreeObject(provider);check(false);}
    try {
        DWORD policy=NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        check(NCryptSetProperty(key,NCRYPT_EXPORT_POLICY_PROPERTY,reinterpret_cast<PBYTE>(&policy),sizeof(policy),0)==ERROR_SUCCESS);
        check(NCryptFinalizeKey(key,NCRYPT_SILENT_FLAG)==ERROR_SUCCESS);
        rejected([&](){store.open(reference);});
    }catch(...){NCryptDeleteKey(key,NCRYPT_SILENT_FLAG);NCryptFreeObject(provider);throw;}
    check(NCryptDeleteKey(key,NCRYPT_SILENT_FLAG)==ERROR_SUCCESS);NCryptFreeObject(provider);
#else
    auto attributes=CFDictionaryCreateMutable(nullptr,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    auto tag=CFDataCreate(nullptr,reinterpret_cast<const UInt8*>(name.data()),static_cast<CFIndex>(name.size()));
    int bits=256;auto size=CFNumberCreate(nullptr,kCFNumberIntType,&bits);
    CFDictionarySetValue(attributes,kSecAttrKeyType,kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(attributes,kSecAttrKeySizeInBits,size);CFDictionarySetValue(attributes,kSecUseKeychain,keychain);
    CFDictionarySetValue(attributes,kSecAttrApplicationTag,tag);CFDictionarySetValue(attributes,kSecAttrIsPermanent,kCFBooleanTrue);
    CFDictionarySetValue(attributes,kSecAttrIsExtractable,kCFBooleanTrue);CFErrorRef error{};
    auto key=SecKeyCreateRandomKey(attributes,&error);CFRelease(attributes);CFRelease(tag);CFRelease(size);
    if(error)CFRelease(error);
    check(key!=nullptr);CFRelease(key);
    // Only this temporary keychain contains the intentionally weak fixture.
    // KeychainFixture removes it even if this assertion fails.
    rejected([&](){store.open(reference);});
#endif
}
template<class Factory,class Count>void identity_fixture(e::KeyStore& keys,Factory factory,Count count){
    using namespace std::chrono;
    struct Cleanup{e::KeyStore& keys;std::vector<std::pair<e::KeyReference,e::PublicKey>> refs;
        ~Cleanup(){for(const auto& [r,p]:refs)try{keys.remove_if_matches(r,p);}catch(...){}}} cleanup{keys,{}};
    auto make=[&](e::KeyPurpose purpose){e::KeyReference ref{purpose,{}};random(ref.id);auto key=keys.create_new(ref);cleanup.refs.emplace_back(ref,key->public_key());return std::pair{ref,std::move(key)};};
    auto [authority_ref,authority]=make(e::KeyPurpose::authority);auto [host_ref,host]=make(e::KeyPurpose::server);auto [client_ref,client]=make(e::KeyPurpose::client);
    const auto wall=floor<seconds>(system_clock::now());const e::Validity issuer{wall-days{3},wall+days{30}},leaf{wall-minutes{1},wall+days{7}},status{wall-minutes{1},wall+minutes{30}};
    e::Serial root_id{},host_id{},client_id{};random(root_id);random(host_id);random(client_id);
    e::PublicIdentityBundle b;b.root=e::root_certificate(*authority,root_id,issuer);
    const e::AlternativeName ip{{std::byte{127},std::byte{},std::byte{},std::byte{1}}, {}};
    b.server=e::leaf_certificate(*authority,host_id,host->public_key(),e::Role::server,leaf,issuer,std::span{&ip,1});
    b.client=e::leaf_certificate(*authority,client_id,client->public_key(),e::Role::client,leaf,issuer);
    b.crl=e::revocation_list(*authority,1,status,issuer,{});
    b.server_ocsp=e::ocsp_response(*authority,host_id,e::Status::good,wall,status,issuer);
    b.client_ocsp=e::ocsp_response(*authority,client_id,e::Status::good,wall,status,issuer);
    e::PairHello h{},c{};h.role=e::PairRole::host;c.role=e::PairRole::client;random(h.nonce);random(c.nonce);
    h.identity_key=host->public_key();c.identity_key=client->public_key();h.authority_key=authority->public_key();h.root_sha256=rwn::core::sha256(b.root);
    h.desktop_ipv4={std::byte{127},std::byte{},std::byte{},std::byte{1}};h.desktop_port=45443;
#if defined(_WIN32)
    auto verifier=rwn::platform::windows::enrollment_pairing_verifier();
#else
    auto verifier=rwn::platform::macos::enrollment_pairing_verifier();
#endif
    const auto now=e::PairingSession::Clock::now();e::PairingSession a(h,*host,*verifier,now),other(c,*client,*verifier,now);
    auto x=a.send_hello(now),y=other.send_hello(now);a.receive(y,now);other.receive(x,now);
    x=a.send_proof(now);y=other.send_proof(now);a.receive(y,now);other.receive(x,now);a.local_decision(true,now);other.local_decision(true,now);
    x=a.send_local_approval(now);y=other.send_local_approval(now);a.receive(y,now);other.receive(x,now);
    auto host_approval=a.take_approved(now),client_approval=other.take_approved(now);auto store=factory();check(count()==0);
    check(!store->locate(host_ref,b.server,h.desktop_ipv4) && !store->locate(client_ref,b.client,h.desktop_ipv4));
    // Test stale proof FIRST, before native caches have seen valid evidence for
    // this fresh issuer. OS CRL/OCSP caches must not hide the negative fixture.
    auto stale=b;const e::Validity expired{wall-days{2},wall-days{1}};
    stale.crl=e::revocation_list(*authority,2,expired,issuer,{});
    stale.server_ocsp=e::ocsp_response(*authority,host_id,e::Status::good,wall-days{2},expired,issuer);
    stale.client_ocsp=e::ocsp_response(*authority,client_id,e::Status::good,wall-days{2},expired,issuer);
    rejected([&](){store->associate(*host_approval,host_ref,stale,now);});check(count()==0);
    auto bad=b;bad.root.back()^=std::byte{1};rejected([&](){store->associate(*host_approval,host_ref,bad,now);});check(count()==0);
    rejected([&](){store->associate(*host_approval,client_ref,b,now);});check(count()==0);
    bad=b;bad.client=b.server;rejected([&](){store->associate(*client_approval,client_ref,bad,now);});check(count()==0);
    bad=b;bad.crl.resize(131073);rejected([&](){store->associate(*host_approval,host_ref,bad,now);});check(count()==0);
    rejected([&](){store->associate(*host_approval,host_ref,b,now+seconds{121});});check(count()==0);
    const auto hs=store->associate(*host_approval,host_ref,b,now),cs=store->associate(*client_approval,client_ref,b,now);
    check(hs.created && cs.created && store->ready(hs) && store->ready(cs) && count()==2);
    const auto reuse=store->associate(*host_approval,host_ref,b,now);check(!reuse.created && reuse.native_reference==hs.native_reference && !store->remove_created(reuse));
    store.reset();store=factory();check(store->ready(hs) && store->ready(cs));
    const auto recovered=store->locate(host_ref,b.server,h.desktop_ipv4);check(recovered && !recovered->created && recovered->native_reference==hs.native_reference);
    auto wrong=hs;wrong.certificate_sha256[0]^=std::byte{1};check(!store->ready(wrong) && !store->remove_created(wrong));
    wrong=hs;wrong.certificate_der.back()^=std::byte{1};check(!store->ready(wrong) && !store->remove_created(wrong));
    wrong=hs;wrong.key=client_ref;check(!store->ready(wrong) && !store->remove_created(wrong));
#if defined(__APPLE__)
    wrong=hs;wrong.native_reference[4]=std::byte{99};check(!store->ready(wrong) && !store->remove_created(wrong));
    wrong=hs;wrong.native_reference[25]=std::byte{0x7f};check(!store->ready(wrong) && !store->remove_created(wrong));
#endif
    auto interrupted=hs;interrupted.native_reference.clear(); //native add finished; receipt was not saved
    check(store->remove_created(interrupted) && !store->ready(hs));check(store->remove_created(cs) && !store->ready(cs));check(count()==0);
    // Exercise the actual native stores behind a protected write-ahead file.
    // Interrupt AFTER native add but BEFORE saving its returned receipt.
    rwn::fixture::JournalDirectory directory;auto journal=directory.open();
    rwn::fixture::InterruptedJournal interrupted_journal(*journal,3);
    std::array<std::byte,32> transaction{};random(transaction);const std::array refs{authority_ref,host_ref};
    e::EnrollmentStager stage(interrupted_journal,keys,*store);stage.begin(transaction,e::PairRole::host,refs);stage.ensure_keys();
    rejected([&](){stage.associate(*host_approval,b,now);});
    check(journal->load()->phase==e::EnrollmentPhase::association_intent && count()==1);
    journal.reset();journal=directory.open();
    e::EnrollmentStager recovered_stage(*journal,keys,*store);auto restored=recovered_stage.recover_staged();
    check(restored && restored->created && store->ready(*restored) && journal->load()->phase==e::EnrollmentPhase::staged);
    check(recovered_stage.rollback() && count()==0 && !journal->load());
    // Reused/shared host material must survive rollback unchanged.
    const auto existing=store->associate(*host_approval,host_ref,b,now);check(existing.created);
    e::EnrollmentStager reused_stage(*journal,keys,*store);random(transaction);reused_stage.begin(transaction,e::PairRole::host,refs);reused_stage.ensure_keys();
    auto shared=reused_stage.associate(*host_approval,b,now);check(!shared.created && reused_stage.rollback() && count()==1 && store->ready(existing));
    check(store->remove_created(existing) && count()==0);
    // The one-key client role follows the same real association/rollback path.
    random(transaction);e::EnrollmentStager client_stage(*journal,keys,*store);client_stage.begin(transaction,e::PairRole::client,std::span{&client_ref,1});client_stage.ensure_keys();
    rejected([&](){client_stage.associate(*host_approval,b,now);});check(journal->load()->phase==e::EnrollmentPhase::keys && count()==0);
    const auto staged_client=client_stage.associate(*client_approval,b,now);
    check(staged_client.created && count()==1 && client_stage.rollback() && count()==0);
    // Native key creation interrupted before its point was saved. Reconcile
    // that exact owned key, then remove it; never generate a replacement.
    rwn::fixture::InterruptedJournal key_interruption(*journal,2);e::KeyReference fresh{e::KeyPurpose::client,{}};random(fresh.id);random(transaction);
    e::EnrollmentStager key_stage(key_interruption,keys,*store);key_stage.begin(transaction,e::PairRole::client,std::span{&fresh,1});
    rejected([&](){key_stage.ensure_keys();});auto actual_key=keys.open(fresh);check(actual_key!=nullptr);const auto actual_point=actual_key->public_key();actual_key.reset();
    cleanup.refs.emplace_back(fresh,actual_point);
    journal.reset();journal=directory.open();e::EnrollmentStager key_recovery(*journal,keys,*store);key_recovery.ensure_keys();
    check(keys.open(fresh)->public_key()==actual_point);
    auto changed=*journal->load();++changed.revision;changed.keys[0].point[0]^=std::byte{1};journal->save(changed);
    check(!key_recovery.rollback() && journal->load().has_value() && keys.open(fresh)->public_key()==actual_point);
    ++changed.revision;changed.keys[0].point=actual_point;journal->save(changed);
    check(keys.remove_if_matches(fresh,actual_point));
    rejected([&](){key_recovery.ensure_keys();}); // saved-but-missing key is not rekeyed
    check(!keys.open(fresh) && key_recovery.rollback() && !journal->load());
    cleanup.refs.pop_back();
    // Native revocation failure AFTER the durable association intent still
    // rolls back safely when strict native lookup proves no certificate exists.
    random(transaction);e::EnrollmentStager denied_stage(*journal,keys,*store);denied_stage.begin(transaction,e::PairRole::host,refs);denied_stage.ensure_keys();
    rejected([&](){denied_stage.associate(*host_approval,stale,now);});
    check(journal->load()->phase==e::EnrollmentPhase::association_intent && denied_stage.rollback() && !journal->load() && count()==0);
    rwn::fixture::durable_completion_fixture(keys,*store,*host,*client,authority_ref,host_ref,client_ref,h,c,b,*verifier,
        [](bool v){check(v);},[](auto f){rejected(f);},[](auto& bytes){random(bytes);},count);
    std::cout<<"enrollment_durable_completion=PASS scenarios=10 native_signatures=1 protected_journal=1 stale_consent_not_revived=1 lost_decision_replay=1 drain_after_restart=1 signed_abort=1 unilateral_rollback_blocked=1 recovery_socket_scenarios=4 tampered_recovery_rejected=1 stale_recovery_proof_rejected=1 abort_retirement=1 archived_abort_tamper_rejected=1 archived_abort_hardlink_rejected=1 committed_retirement_rejected=1 config_persistence_proof_only=1 live_admission=0\n";
    std::cout<<"enrollment_configuration=PASS native_protected_files=1 product_format_reader=1 interrupted_resource_repair=1 existing_config_preserved=1 tampered_resource_rejected=1 linked_resource_rejected=1 default_control_view_only=1 installed_changes=0\n";
    auto revoked=b;const e::Revocation revoked_client{client_id,wall-minutes{2}};
    revoked.crl=e::revocation_list(*authority,3,status,issuer,std::span{&revoked_client,1});
    revoked.client_ocsp=e::ocsp_response(*authority,client_id,e::Status::revoked,wall,status,issuer,wall-minutes{2});
    rejected([&](){store->associate(*host_approval,host_ref,revoked,now);});check(count()==0);
    check(keys.open(host_ref)->public_key()==host->public_key() && keys.open(client_ref)->public_key()==client->public_key());
    std::cout<<"enrollment_native_identity=PASS roles=2 association=1 reopen=1 native_private_proof=1 stale_rejected=1 reuse_preserved=1 rollback_certificate_only=1 write_ahead_recovery=1 owned_key_recovery=1 installed_identity_changes=0\n";
}
#if defined(__APPLE__)
struct KeychainFixture {
    SecKeychainRef value{};std::filesystem::path directory;
    KeychainFixture() {
        check(SecKeychainSetUserInteractionAllowed(false)==errSecSuccess);
        std::string path=(std::filesystem::temp_directory_path()/"lanpilot-key-fixture-XXXXXX").string();
        auto created=mkdtemp(path.data());check(created!=nullptr);directory=created;
        std::array<std::byte,32> password{};random(password);
        CFArrayRef previous{};check(SecKeychainCopySearchList(&previous)==errSecSuccess);
        const auto status=SecKeychainCreate((directory/"fixture.keychain").c_str(),static_cast<UInt32>(password.size()),password.data(),false,nullptr,&value);
        // SecKeychainCreate can add its new keychain to the user's search list.
        // Restore that list immediately; all queries below explicitly scope to
        // this temporary keychain and never search the login keychain.
        const auto restored=SecKeychainSetSearchList(previous);CFRelease(previous);
        std::fill(password.begin(),password.end(),std::byte{});
        if(status!=errSecSuccess || !value || restored!=errSecSuccess){
            if(value){SecKeychainDelete(value);CFRelease(value);value=nullptr;}
            std::error_code error;std::filesystem::remove(directory,error);check(false);
        }
    }
    ~KeychainFixture(){if(value){SecKeychainDelete(value);CFRelease(value);}std::error_code error;std::filesystem::remove(directory,error);}
    void finish(){
        check(SecKeychainDelete(value)==errSecSuccess);CFRelease(value);value=nullptr;
        check(std::filesystem::remove(directory) && !std::filesystem::exists(directory));
    }
};
#endif
}
int main() {
    try {
#if defined(_WIN32)
        auto factory=[](){return rwn::platform::windows::enrollment_key_store();};
#else
        KeychainFixture fixture;auto factory=[&](){return rwn::platform::macos::enrollment_key_store(fixture.value);};
#endif
        auto store=factory();
        struct Cleanup {
            e::KeyStore& store;std::vector<std::pair<e::KeyReference,e::PublicKey>> created;
            ~Cleanup(){for(const auto& [ref,point]:created)try{store.remove_if_matches(ref,point);}catch(...){}}
        } cleanup{*store,{}};
        e::KeyReference empty{e::KeyPurpose::client,{}};
        rejected([&](){store->create_new(empty);});rejected([&](){store->open(empty);});
        for(const auto role:{e::KeyPurpose::authority,e::KeyPurpose::server,e::KeyPurpose::client}) {
            e::KeyReference reference{role,{}};random(reference.id);check(!store->open(reference));
            auto key=store->create_new(reference);const auto public_key=key->public_key();cleanup.created.emplace_back(reference,public_key);
            check(key->accepts_public_key(public_key) && !key->accepts_public_key({}));verify_self_signed(*key);
            key.reset();auto reopened_store=factory();auto reopened=reopened_store->open(reference);check(reopened && reopened->public_key()==public_key);
            reopened_store.reset();verify_self_signed(*reopened);
            const std::array<std::byte,4> pairing_message{std::byte{'P'},std::byte{'O'},std::byte{'P'},std::byte{1}};
#if defined(_WIN32)
            auto pairing_verifier=rwn::platform::windows::enrollment_pairing_verifier();
#else
            auto pairing_verifier=rwn::platform::macos::enrollment_pairing_verifier();
#endif
            const auto proof=reopened->sign_sha256(pairing_message);check(pairing_verifier->verify(public_key,pairing_message,proof));
            auto different=pairing_message;different.back()^=std::byte{1};check(!pairing_verifier->verify(public_key,different,proof));
            reopened.reset();
            rejected([&](){store->create_new(reference);});check(store->open(reference)->public_key()==public_key);
            verify_export_denied(reference
#if defined(__APPLE__)
                ,fixture.value
#endif
            );
            auto wrong=public_key;wrong[0]^=std::byte{1};check(!store->remove_if_matches(reference,wrong));
            check(store->open(reference)->public_key()==public_key);
            check(store->remove_if_matches(reference,public_key) && !store->open(reference));cleanup.created.pop_back();
        }
        empty.purpose=static_cast<e::KeyPurpose>(99);empty.id[0]=std::byte{1};rejected([&](){store->open(empty);});
        e::KeyReference weak{e::KeyPurpose::client,{}};random(weak.id);
        reject_exportable_key(*store,weak
#if defined(__APPLE__)
            ,fixture.value
#endif
        );
#if defined(_WIN32)
        const auto memory=CertOpenStore(CERT_STORE_PROV_MEMORY,0,0,CERT_STORE_CREATE_NEW_FLAG,nullptr);check(memory!=nullptr);
        struct Memory{HCERTSTORE store;~Memory(){CertCloseStore(store,0);}} memory_owner{memory};
        identity_fixture(*store,[&](){return rwn::platform::windows::enrollment_identity_store(memory);},[&](){
            unsigned count{};PCCERT_CONTEXT cert{};while((cert=CertEnumCertificatesInStore(memory,cert))!=nullptr)++count;return count;});
#else
        identity_fixture(*store,[&](){return rwn::platform::macos::enrollment_identity_store(fixture.value);},[&](){
            const void* items[]{fixture.value};auto search=CFArrayCreate(nullptr,items,1,&kCFTypeArrayCallBacks);
            const void* names[]{kSecClass,kSecMatchSearchList,kSecMatchLimit,kSecReturnRef};const void* values[]{kSecClassCertificate,search,kSecMatchLimitAll,kCFBooleanTrue};
            auto query=CFDictionaryCreate(nullptr,names,values,4,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);CFTypeRef result{};
            const auto status=SecItemCopyMatching(query,&result);CFRelease(query);CFRelease(search);
            if(status==errSecItemNotFound)return CFIndex{0};check(status==errSecSuccess && result && CFGetTypeID(result)==CFArrayGetTypeID());
            const auto count=CFArrayGetCount(static_cast<CFArrayRef>(result));CFRelease(result);return count;});
#endif
#if defined(__APPLE__)
        fixture.finish();
#endif
        std::cout<<"enrollment_native_keys=PASS roles=3 reopen=1 duplicate_rejected=1 export_denied=1 weak_existing_rejected=1 cleanup=1 installed_identity_changes=0 external_network=0 loopback_recovery=1\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
