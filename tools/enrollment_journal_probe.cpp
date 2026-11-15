// Isolated fixed-file journal fixture. No product config, listener, keychain,
// desktop, input or clipboard access. The parent actually kills a lease owner.
#include "rwn/core/enrollment_journal.hpp"
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <source_location>
#include <thread>
#if defined(_WIN32)
#include "rwn/platform/windows/enrollment_journal.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include "rwn/platform/macos/enrollment_journal.hpp"
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
extern char** environ;
#endif
namespace e=rwn::core::enrollment;
namespace {
void check(bool v,std::source_location s=std::source_location::current()){if(!v)throw std::runtime_error("journal fixture failed at "+std::to_string(s.line()));}
template<class F>void reject(F f){bool caught=false;try{f();}catch(...){caught=true;}check(caught);}
auto open(const std::filesystem::path& p){
#if defined(_WIN32)
    return rwn::platform::windows::enrollment_journal_fixture(p);
#else
    return rwn::platform::macos::enrollment_journal_fixture(p);
#endif
}
e::EnrollmentRecord record(){e::EnrollmentRecord r;r.transaction[0]=std::byte{91};r.revision=1;r.role=e::PairRole::client;
    e::KeyReference ref{e::KeyPurpose::client,{}};ref.id[0]=std::byte{27};r.keys.push_back({ref,false,{}});return r;}
struct Child {
#if defined(_WIN32)
    PROCESS_INFORMATION value{};
    Child(const std::filesystem::path& exe,const std::string& mode,const std::filesystem::path& root){
        const std::wstring wide_mode(mode.begin(),mode.end());auto command=L"\""+exe.wstring()+L"\" "+wide_mode+L" \""+root.wstring()+L"\"";STARTUPINFOW startup{};startup.cb=sizeof(startup);
        check(CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&value));}
    int finish(bool kill){if(kill)check(TerminateProcess(value.hProcess,91));check(WaitForSingleObject(value.hProcess,5000)==WAIT_OBJECT_0);DWORD code{};check(GetExitCodeProcess(value.hProcess,&code));CloseHandle(value.hThread);CloseHandle(value.hProcess);value={};return static_cast<int>(code);}
    ~Child(){if(value.hProcess){TerminateProcess(value.hProcess,92);WaitForSingleObject(value.hProcess,5000);CloseHandle(value.hThread);CloseHandle(value.hProcess);}}
#else
    pid_t value{};
    Child(const std::filesystem::path& exe,const std::string& mode,const std::filesystem::path& root){auto executable=exe.string(),directory=root.string();
        char* args[]{executable.data(),const_cast<char*>(mode.c_str()),directory.data(),nullptr};check(posix_spawn(&value,executable.c_str(),nullptr,nullptr,args,environ)==0);}
    int finish(bool terminate){if(terminate)check(::kill(value,SIGKILL)==0);const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);int status{};
        while(std::chrono::steady_clock::now()<deadline){const auto n=waitpid(value,&status,WNOHANG);if(n==value){value=0;return WIFEXITED(status)?WEXITSTATUS(status):91;}check(n==0);std::this_thread::sleep_for(std::chrono::milliseconds(2));}throw std::runtime_error("journal child timeout");}
    ~Child(){if(value){::kill(value,SIGKILL);waitpid(value,nullptr,0);}}
#endif
};
}
int main(int argc,char** argv){try{
    if(argc==3){auto journal=open(argv[2]);if(std::string_view(argv[1])=="--hold"){
        journal->save(record());std::ofstream marker(std::filesystem::path(argv[2])/"ready.fixture");marker<<"ready";marker.close();
        for(;;)std::this_thread::sleep_for(std::chrono::seconds(1));
    }check(std::string_view(argv[1])=="--resume");auto r=journal->load();check(r && r->revision==1);++r->revision;journal->save(*r);return 0;}
    check(argc==1);const auto parent=std::filesystem::canonical(std::filesystem::temp_directory_path());
    const auto root=parent/("lanpilot-journal-fixture-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
#if !defined(_WIN32)
    check(mkdir(root.c_str(),0700)==0);
#endif
    auto j=open(root);check(!j->load());reject([&](){open(root);});j.reset();
    struct Cleanup{std::filesystem::path root;~Cleanup(){for(auto name:{"enrollment.pending",".enrollment.next","owner.lock","ready.fixture","alias.fixture"}){std::error_code error;std::filesystem::remove(root/name,error);}std::error_code error;std::filesystem::remove(root,error);}} cleanup{root};
    const auto exe=std::filesystem::absolute(argv[0]);Child owner(exe,"--hold",root);
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(!std::filesystem::exists(root/"ready.fixture") && std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(2));
    check(std::filesystem::exists(root/"ready.fixture"));reject([&](){open(root);});check(owner.finish(true)==91);
    Child resume(exe,"--resume",root);check(resume.finish(false)==0);j=open(root);check(j->load()->revision==2);
    auto r=*j->load();reject([&](){j->save(r);});++r.revision;auto wrong=r;wrong.transaction[0]^=std::byte{1};reject([&](){j->save(wrong);});
    auto id=r.transaction;id[0]^=std::byte{1};reject([&](){j->clear(id);});j->save(r);check(j->load()->revision==3);j.reset();
    // Link count is checked before reading or replacing an authoritative file.
    std::filesystem::create_hard_link(root/"enrollment.pending",root/"alias.fixture");j=open(root);reject([&](){j->load();});j.reset();std::filesystem::remove(root/"alias.fixture");
    // A crash BEFORE rename leaves only a partial non-authoritative staging
    // file. Its known owned inode is discarded on the next exclusive opening.
    std::filesystem::rename(root/"enrollment.pending",root/".enrollment.next");std::filesystem::resize_file(root/".enrollment.next",7);
    j=open(root);check(!j->load() && !std::filesystem::exists(root/".enrollment.next"));j->save(record());j.reset();
    std::filesystem::resize_file(root/"enrollment.pending",12);j=open(root);reject([&](){j->load();});reject([&](){j->save(record());});j.reset();
    std::filesystem::remove(root/"enrollment.pending");
#if !defined(_WIN32)
    std::filesystem::create_symlink(root/"ready.fixture",root/"enrollment.pending");j=open(root);reject([&](){j->load();});j.reset();std::filesystem::remove(root/"enrollment.pending");
    check(chmod(root.c_str(),0755)==0);reject([&](){open(root);});check(chmod(root.c_str(),0700)==0);
#endif
    auto bytes=e::encode_enrollment_record(record());check(e::decode_enrollment_record(bytes).revision==1);
    for(std::size_t n=0;n<bytes.size();++n){auto bad=bytes;bad[n]^=std::byte{1};reject([&](){e::decode_enrollment_record(bad);});}
    // Recompute the damage checksum to test semantic validation too. The
    // checksum is deliberately not represented as authentication/consent.
    for(auto offset:{44U,45U,46U,47U,48U,65U}){auto bad=bytes;bad[offset]=std::byte{255};
        const auto digest=rwn::core::sha256(std::span(bad).first(bad.size()-32));std::copy(digest.begin(),digest.end(),bad.end()-32);
        reject([&](){e::decode_enrollment_record(bad);});}
    auto invalid=record();invalid.transaction={};reject([&](){e::encode_enrollment_record(invalid);});
    invalid=record();invalid.revision=0;reject([&](){e::encode_enrollment_record(invalid);});
    invalid=record();invalid.revision=~std::uint64_t{};reject([&](){e::encode_enrollment_record(invalid);});
    invalid=record();invalid.keys[0].existed=true;reject([&](){e::encode_enrollment_record(invalid);});
    invalid=record();invalid.phase=e::EnrollmentPhase::staged;reject([&](){e::encode_enrollment_record(invalid);});
    invalid=record();invalid.bundle.crl.resize(65537);reject([&](){e::encode_enrollment_record(invalid);});
    bytes.resize(e::enrollment_record_cap+1);reject([&](){e::decode_enrollment_record(bytes);});
    std::cout<<"enrollment_native_journal=PASS killed_owner=1 cold_process_resume=1 lease_exclusion=1 atomic_revision=1 incomplete_staging=1 corrupted_record_rejected=1 hardlink_rejected=1 installed_changes=0\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
