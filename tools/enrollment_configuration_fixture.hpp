#pragma once
#include "rwn/core/enrollment_configuration.hpp"
#include <fstream>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include "../desktop-agent/macos/product_configuration.hpp"
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif
namespace rwn::fixture {
inline core::enrollment::Bytes fixture_bytes(const std::filesystem::path& p){
    const auto size=std::filesystem::file_size(p);if(size==0 || size>65536)throw std::runtime_error("fixture file outside bounds");
    core::enrollment::Bytes b(static_cast<std::size_t>(size));std::ifstream f(p,std::ios::binary);f.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size()));
    if(!f || f.peek()!=std::char_traits<char>::eof())throw std::runtime_error("fixture read failed");
    return b;
}
inline void fixture_write(const std::filesystem::path& p,std::span<const std::byte> b){std::ofstream f(p,std::ios::binary|std::ios::trunc);f.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));if(!f)throw std::runtime_error("fixture write failed");}
inline std::string fixture_hex(const core::Sha256Digest& h){std::string s;for(auto x:h){const auto n=std::to_integer<unsigned>(x);s+="0123456789abcdef"[n>>4];s+="0123456789abcdef"[n&15];}return s;}
#if defined(_WIN32)
inline bool read_with_product_parser(const std::filesystem::path& p){
    auto quote=[](const std::wstring& value){std::wstring s=L"\"";std::size_t slash{};for(auto c:value){if(c==L'\\'){++slash;continue;}s.append(c==L'"'?slash*2+1:slash,L'\\');slash=0;s+=c;}s.append(slash*2,L'\\');return s+L'"';};
    wchar_t system[MAX_PATH]{};if(!GetSystemDirectoryW(system,MAX_PATH))return false;
    const auto host=std::filesystem::path(system)/L"WindowsPowerShell"/L"v1.0"/L"powershell.exe";
    auto command=quote(host.wstring())+L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+
        quote(std::filesystem::path(LANPILOT_CONFIGURATION_READER).wstring())+L" -ProfilePath "+quote(p.wstring());
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    if(!CreateProcessW(host.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process))return false;
    const auto wait=WaitForSingleObject(process.hProcess,10000);DWORD exit=1;
    if(wait==WAIT_OBJECT_0)GetExitCodeProcess(process.hProcess,&exit);else {TerminateProcess(process.hProcess,91);WaitForSingleObject(process.hProcess,1000);}
    CloseHandle(process.hThread);CloseHandle(process.hProcess);return wait==WAIT_OBJECT_0 && exit==0;
}
#endif
template<class Check,class Reject>void configuration_fixture(core::enrollment::FileEnrollmentJournal& journal,
    const core::enrollment::PersistablePairing& proof,core::enrollment::KeyStore& keys,core::enrollment::IdentityStore& identities,
    const core::enrollment::PairProofVerifier& verifier,const std::filesystem::path& root,Check check,Reject reject){
    namespace e=core::enrollment;
    const auto result=e::EnrollmentConfigurationHandoff::persist(journal,proof,identities,verifier);check(result.created);
    const auto again=e::EnrollmentConfigurationHandoff::persist(journal,proof,identities,verifier);check(!again.created && again.profile_sha256==result.profile_sha256);
#if defined(_WIN32)
    const auto profile=root/"connections"/"default.json";
#else
    const auto profile=root/"service.conf";
#endif
    auto profile_bytes=fixture_bytes(profile);check(core::sha256(profile_bytes)==result.profile_sha256);
    const auto generation=root/"identity"/"enrolled-v1"/fixture_hex(result.resource_generation);
    const auto& b=proof.record().staged.bundle;const std::array expected{b.root,b.server,b.client,b.crl,b.server_ocsp,b.client_ocsp};
    for(std::size_t i=0;i<expected.size();++i)check(fixture_bytes(generation/e::enrollment_resource_names[i])==expected[i]);
    // Recreate the precise recoverable disk state: complete public resources,
    // missing visible config, one missing object, another partial staging file.
    std::filesystem::remove(profile);std::filesystem::remove(generation/"server.der");
#if defined(_WIN32)
    const auto staging=generation/"client.der.enrollment-next";
#else
    const auto staging=generation/".client.der.enrollment-next";
#endif
    std::filesystem::rename(generation/"client.der",staging);std::filesystem::resize_file(staging,7);
    const auto repaired=e::EnrollmentConfigurationHandoff::recover(journal,keys,identities,verifier);
    check(repaired && repaired->created && repaired->profile_sha256==result.profile_sha256 && !std::filesystem::exists(staging));
    for(std::size_t i=0;i<expected.size();++i)check(fixture_bytes(generation/e::enrollment_resource_names[i])==expected[i]);
#if defined(_WIN32)
    check(read_with_product_parser(profile));
#else
    const std::string text(reinterpret_cast<const char*>(profile_bytes.data()),profile_bytes.size());
    const auto saved=agent::macos::parse_configuration(text,"/Users/fixture");
    check(saved.control=="view-only" && !saved.clipboard_text && saved.visual=="h264-only" && saved.ocsp_path.ends_with("/client-ocsp.der"));
    const auto lock=open((root/"runtime.lock").c_str(),O_RDWR);check(lock>=0 && flock(lock,LOCK_EX|LOCK_NB)==0);
    reject([&](){e::EnrollmentConfigurationHandoff::persist(journal,proof,identities,verifier);});close(lock);
#endif
    auto changed=profile_bytes;changed.push_back(std::byte{'!'});fixture_write(profile,changed);
    reject([&](){e::EnrollmentConfigurationHandoff::persist(journal,proof,identities,verifier);});check(fixture_bytes(profile)==changed);
    fixture_write(profile,profile_bytes);
    // Corrupt or linked trust material is never overwritten as an automatic
    // "repair". The exact committed profile remains untouched on rejection.
    auto bad=expected[0];bad.back()^=std::byte{1};fixture_write(generation/"root.der",bad);
    reject([&](){e::EnrollmentConfigurationHandoff::persist(journal,proof,identities,verifier);});check(fixture_bytes(profile)==profile_bytes && fixture_bytes(generation/"root.der")==bad);
    fixture_write(generation/"root.der",expected[0]);std::filesystem::create_hard_link(generation/"root.der",root/"alias.fixture");
    reject([&](){e::EnrollmentConfigurationHandoff::persist(journal,proof,identities,verifier);});std::filesystem::remove(root/"alias.fixture");
    check(!e::EnrollmentConfigurationHandoff::persist(journal,proof,identities,verifier).created);
}
}
