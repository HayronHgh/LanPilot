#pragma once
// Test-only protected directory and one precise injected interruption point.
#include "rwn/core/enrollment_journal.hpp"
#include <filesystem>
#if defined(_WIN32)
#include "rwn/platform/windows/enrollment_journal.hpp"
#else
#include "rwn/platform/macos/enrollment_journal.hpp"
#include <sys/stat.h>
#endif
namespace rwn::fixture {
struct JournalDirectory {
    std::filesystem::path root;
    JournalDirectory(){root=std::filesystem::canonical(std::filesystem::temp_directory_path())/
        ("lanpilot-stage-fixture-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
#if !defined(_WIN32)
        if(mkdir(root.c_str(),0700)!=0)throw std::runtime_error("fixture mkdir failed");
#endif
    }
    auto open(){
#if defined(_WIN32)
        return platform::windows::enrollment_journal_fixture(root);
#else
        return platform::macos::enrollment_journal_fixture(root);
#endif
    }
    ~JournalDirectory(){
        // Only known files in this unique local fixture namespace, no recursive
        // deletion and no traversal through unknown/symlinked generation dirs.
        const auto generations=root/"identity"/"enrolled-v1";std::error_code error;
        if(std::filesystem::is_directory(std::filesystem::symlink_status(root/"aborted",error))){
            for(const auto& entry:std::filesystem::directory_iterator(root/"aborted",error)){
                const auto name=entry.path().filename().string();
                if(name.size()==68 && name.substr(64)==".lpj" && name.substr(0,64).find_first_not_of("0123456789abcdef")==std::string::npos)
                    std::filesystem::remove(entry.path(),error);
            }std::filesystem::remove(root/"aborted",error);
        }
        if(std::filesystem::is_directory(std::filesystem::symlink_status(root/"identity",error)) &&
            std::filesystem::is_directory(std::filesystem::symlink_status(generations,error))){
            for(const auto& entry:std::filesystem::directory_iterator(generations,error)){
                const auto name=entry.path().filename().string();
                if(name.size()!=64 || name.find_first_not_of("0123456789abcdef")!=std::string::npos ||
                    !std::filesystem::is_directory(entry.symlink_status(error)))continue;
                for(const auto* resource:{"root.der","server.der","client.der","revocation.der","server-ocsp.der","client-ocsp.der"}){
                    std::filesystem::remove(entry.path()/resource,error);
                    std::filesystem::remove(entry.path()/(std::string(resource)+".enrollment-next"),error);
                    std::filesystem::remove(entry.path()/("."+std::string(resource)+".enrollment-next"),error);
                }std::filesystem::remove(entry.path(),error);
            }std::filesystem::remove(generations,error);std::filesystem::remove(root/"identity",error);
        }
        if(std::filesystem::is_directory(std::filesystem::symlink_status(root/"connections",error))){
            std::filesystem::remove(root/"connections"/"default.json",error);std::filesystem::remove(root/"connections"/"default.json.enrollment-next",error);
        }
        std::filesystem::remove(root/"connections",error);
        for(const auto* name:{"enrollment.pending",".enrollment.next","revocation.current",".revocation.next","credential.current","credential.retired","credential.current.next","credential.retired.next","owner.lock","runtime.lock","service.conf",".service.conf.enrollment-next","alias.fixture"}){
        std::error_code ec;std::filesystem::remove(root/name,ec);}std::error_code ec;std::filesystem::remove(root,ec);}
};
struct InterruptedJournal:core::enrollment::EnrollmentJournal {
    core::enrollment::EnrollmentJournal& base;std::uint64_t revision;
    InterruptedJournal(core::enrollment::EnrollmentJournal& b,std::uint64_t n):base(b),revision(n){}
    std::optional<core::enrollment::EnrollmentRecord> load()override{return base.load();}
    void save(const core::enrollment::EnrollmentRecord& r)override{
        if(r.revision==revision)throw std::runtime_error("fixture interruption before receipt save");
        base.save(r);}
    void clear(const std::array<std::byte,32>& id)override{base.clear(id);}
};
}
