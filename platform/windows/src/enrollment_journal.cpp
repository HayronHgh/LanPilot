#include "rwn/platform/windows/enrollment_journal.hpp"
#include "rwn/core/enrollment_configuration.hpp"
#include "rwn/core/enrollment_status.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <algorithm>

namespace rwn::platform::windows {
namespace {
namespace e=core::enrollment;
[[noreturn]]void fail(){throw std::runtime_error("protected enrollment journal unavailable");}
struct Handle {
    HANDLE value{INVALID_HANDLE_VALUE};explicit Handle(HANDLE h=INVALID_HANDLE_VALUE):value(h){}~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
    Handle(Handle&& o)noexcept:value(o.value){o.value=INVALID_HANDLE_VALUE;}
};
struct Local {void* value{};~Local(){if(value)LocalFree(value);}};
struct User {
    std::vector<std::byte> token;PSID sid{};PSECURITY_DESCRIPTOR security{};
    User(){HANDLE raw{};if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))fail();Handle h(raw);DWORD size{};
        GetTokenInformation(raw,TokenUser,nullptr,0,&size);if(size<sizeof(TOKEN_USER) || size>65536)fail();token.resize(size);
        if(!GetTokenInformation(raw,TokenUser,token.data(),size,&size))fail();
        sid=reinterpret_cast<TOKEN_USER*>(token.data())->User.Sid;
        LPWSTR text{};if(!ConvertSidToStringSidW(sid,&text))fail();Local owner{text};
        std::wstring sddl=L"O:";sddl+=text;sddl+=L"D:P(A;;FA;;;";sddl+=text;sddl+=L")(A;;FA;;;SY)";
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&security,nullptr))fail();}
    ~User(){if(security)LocalFree(security);}
    SECURITY_ATTRIBUTES attributes(){return {sizeof(SECURITY_ATTRIBUTES),security,FALSE};}
    void check(HANDLE handle,bool directory,bool private_object){
        BY_HANDLE_FILE_INFORMATION info{};if(handle==INVALID_HANDLE_VALUE || !GetFileInformationByHandle(handle,&info) ||
            (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) || ((info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0)!=directory || (!directory && info.nNumberOfLinks!=1))fail();
        PSID owner{};PACL acl{};PSECURITY_DESCRIPTOR raw{};
        if(GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&raw)!=ERROR_SUCCESS)fail();
        Local sd{raw};
        if(!owner || !EqualSid(owner,sid) || !acl)fail();
        SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision{};if(!GetSecurityDescriptorControl(raw,&control,&revision) || (private_object && !(control&SE_DACL_PROTECTED)))fail();
        std::array<std::byte,SECURITY_MAX_SID_SIZE> system{},admin{};DWORD s=static_cast<DWORD>(system.size()),a=static_cast<DWORD>(admin.size());
        if(!CreateWellKnownSid(WinLocalSystemSid,nullptr,system.data(),&s) || !CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admin.data(),&a))fail();
        for(DWORD i=0;i<acl->AceCount;++i){void* raw_ace{};if(!GetAce(acl,i,&raw_ace))fail();auto* header=static_cast<ACE_HEADER*>(raw_ace);
            if(header->AceFlags&INHERIT_ONLY_ACE)continue;
            if(header->AceType==ACCESS_DENIED_ACE_TYPE)continue;
            if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE)fail();
            auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);auto* granted=&ace->SidStart;
            if(EqualSid(granted,sid) || EqualSid(granted,system.data()) || (!private_object && EqualSid(granted,admin.data())))continue;
            const DWORD unsafe=private_object?0xffffffffU:(FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL|FILE_DELETE_CHILD);
            if(ace->Mask&unsafe)fail();
        }
    }
};
bool exists_local(const std::filesystem::path& p){const auto a=GetFileAttributesW(p.c_str());if(a!=INVALID_FILE_ATTRIBUTES)return true;const auto error=GetLastError();if(error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PATH_NOT_FOUND)fail();return false;}
std::wstring hex(const core::Sha256Digest& hash){std::wstring s;for(auto x:hash){const auto n=std::to_integer<unsigned>(x);s+=L"0123456789abcdef"[n>>4];s+=L"0123456789abcdef"[n&15];}return s;}
std::string utf8(const std::filesystem::path& path){const auto& w=path.native();if(w.empty() || w.size()>32768)fail();
    const auto size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);if(size<=0)fail();std::string text(static_cast<std::size_t>(size),'\0');
    if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),static_cast<int>(w.size()),text.data(),size,nullptr,nullptr)!=size)fail();
    return text;}
class Journal final:public e::FileEnrollmentJournal {
public:
    Journal(std::filesystem::path root,std::filesystem::path operation={},std::filesystem::path product={}):root_(std::move(root)),product_(product.empty()?root_:std::move(product)){
        if(!root_.is_absolute() || root_!=root_.lexically_normal() || root_.wstring().starts_with(L"\\\\"))fail();
        if(product_!=root_ && product_!=root_.parent_path())fail();
        // Pin all ancestors against rename; reject every junction/symlink.
        auto current=root_.root_path();for(const auto& part:root_.relative_path()){
            if(part==L"." || part==L".." || part.empty())fail();
            current/=part;
            if(current==root_){auto sa=user_.attributes();if(!CreateDirectoryW(current.c_str(),&sa) && GetLastError()!=ERROR_ALREADY_EXISTS)fail();}
            Handle h(CreateFileW(current.c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            BY_HANDLE_FILE_INFORMATION info{};if(h.value==INVALID_HANDLE_VALUE || !GetFileInformationByHandle(h.value,&info) || (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) || !(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))fail();
            if(current==root_)user_.check(h.value,true,true);
            parents_.push_back(std::move(h));
        }
        if(!operation.empty())lock(operation,false);
        lock(root_/L"owner.lock",true);
        const auto staging=root_/L".enrollment.next";
        if(exists_local(staging)){auto stale=open(staging,GENERIC_READ,OPEN_EXISTING,0);user_.check(stale.value,false,true);
            LARGE_INTEGER size{};if(!GetFileSizeEx(stale.value,&size) || size.QuadPart<0 || size.QuadPart>static_cast<LONGLONG>(e::enrollment_storage_cap))fail();
            // Scope-close before deleting a validated interrupted staging file.
        }
        if(exists_local(staging) && !DeleteFileW(staging.c_str()))fail();
    }
private:
    Handle directory(const std::filesystem::path& path,bool private_object){auto sa=user_.attributes();if(!CreateDirectoryW(path.c_str(),&sa) && GetLastError()!=ERROR_ALREADY_EXISTS)fail();
        Handle h(CreateFileW(path.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));user_.check(h.value,true,private_object);return h;}
    std::optional<e::Bytes> read_file(const std::filesystem::path& path,std::size_t cap){
        if(!exists_local(path))return {};
        auto h=open(path,GENERIC_READ,OPEN_EXISTING,0);user_.check(h.value,false,true);LARGE_INTEGER size{};
        if(!GetFileSizeEx(h.value,&size) || size.QuadPart<=0 || size.QuadPart>static_cast<LONGLONG>(cap))fail();
        e::Bytes bytes(static_cast<std::size_t>(size.QuadPart));DWORD n{};
        if(!ReadFile(h.value,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr) || n!=bytes.size())fail();
        char extra{};if(!ReadFile(h.value,&extra,1,&n,nullptr) || n!=0)fail();return bytes;
    }
    void create_file(const std::filesystem::path& path,std::span<const std::byte> bytes,std::size_t cap){
        if(bytes.empty() || bytes.size()>cap)fail();
        if(const auto old=read_file(path,cap)){if(!std::ranges::equal(*old,bytes))fail();return;}
        auto staging=path;staging+=L".enrollment-next";
        if(exists_local(staging)){{auto h=open(staging,GENERIC_READ,OPEN_EXISTING,0);user_.check(h.value,false,true);LARGE_INTEGER size{};
            if(!GetFileSizeEx(h.value,&size) || size.QuadPart<0 || size.QuadPart>static_cast<LONGLONG>(cap))fail();}if(!DeleteFileW(staging.c_str()))fail();}
        {auto h=open(staging,GENERIC_WRITE,CREATE_NEW,FILE_FLAG_WRITE_THROUGH);user_.check(h.value,false,true);DWORD n{};
            if(!WriteFile(h.value,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr) || n!=bytes.size() || !FlushFileBuffers(h.value))fail();}
        if(!MoveFileExW(staging.c_str(),path.c_str(),MOVEFILE_WRITE_THROUGH))fail();
    }
    e::EnrollmentConfigurationLayout configuration_layout(const core::Sha256Digest& g)override{
        return {e::EnrollmentConfigurationLayout::Kind::windows_client,utf8(product_/L"connections"/L"default.json"),utf8(product_/L"identity"/L"enrolled-v1"/hex(g))};
    }
    bool publish_configuration(const core::Sha256Digest& g,const std::array<e::Bytes,6>& objects,std::span<const std::byte> profile)override{
        if(profile.empty() || profile.size()>16384)fail();
        auto connections=directory(product_/L"connections",false);const auto profile_path=product_/L"connections"/L"default.json";
        const auto old=read_file(profile_path,16384);if(old && !std::ranges::equal(*old,profile))fail();
        auto identity=directory(product_/L"identity",false),enrolled=directory(product_/L"identity"/L"enrolled-v1",true),target=directory(product_/L"identity"/L"enrolled-v1"/hex(g),true);
        for(std::size_t i=0;i<objects.size();++i)create_file(product_/L"identity"/L"enrolled-v1"/hex(g)/e::enrollment_resource_names[i],objects[i],65536);
        create_file(profile_path,profile,16384);return !old.has_value();
    }
    Handle open(const std::filesystem::path& p,DWORD access,DWORD disposition,DWORD flags){auto sa=user_.attributes();
        return Handle(CreateFileW(p.c_str(),access|READ_CONTROL,0,&sa,disposition,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|flags,nullptr));}
    void lock(const std::filesystem::path& p,bool private_object){auto h=open(p,GENERIC_READ|GENERIC_WRITE,OPEN_ALWAYS,0);user_.check(h.value,false,private_object);leases_.push_back(std::move(h));}
    std::optional<e::Bytes> read_record()override{
        auto p=root_/L"enrollment.pending";if(!exists_local(p))return {};auto h=open(p,GENERIC_READ,OPEN_EXISTING,0);user_.check(h.value,false,true);LARGE_INTEGER size{};
        if(!GetFileSizeEx(h.value,&size) || size.QuadPart<=0 || size.QuadPart>static_cast<LONGLONG>(e::enrollment_storage_cap))fail();
        e::Bytes bytes(static_cast<std::size_t>(size.QuadPart));DWORD read{};
        if(!ReadFile(h.value,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr) || read!=bytes.size())fail();
        char extra{};if(!ReadFile(h.value,&extra,1,&read,nullptr) || read!=0)fail();return bytes;
    }
    void replace_record(std::span<const std::byte> bytes)override{
        const auto stage=root_/L".enrollment.next",target=root_/L"enrollment.pending";
        {auto h=open(stage,GENERIC_WRITE,CREATE_NEW,FILE_FLAG_WRITE_THROUGH);user_.check(h.value,false,true);DWORD written{};
            if(!WriteFile(h.value,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr) || written!=bytes.size() || !FlushFileBuffers(h.value))fail();}
        if(!MoveFileExW(stage.c_str(),target.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))fail();
    }
    void remove_record()override{if(!DeleteFileW((root_/L"enrollment.pending").c_str()))fail();}
    std::optional<e::Bytes> read_status()override{return read_file(root_/L"revocation.current",e::status_wire_cap);}
    std::optional<e::Bytes> read_credential(bool retired)override{return read_file(root_/(retired?L"credential.retired":L"credential.current"),e::enrollment_record_cap);}
    void store_credential(bool retired,std::span<const std::byte> bytes)override{
        if(bytes.empty() || bytes.size()>e::enrollment_record_cap)fail();
        (void)read_credential(retired);
        const auto target=root_/(retired?L"credential.retired":L"credential.current");auto stage=target;stage+=L".next";
        if(exists_local(stage)){{auto h=open(stage,GENERIC_READ,OPEN_EXISTING,0);user_.check(h.value,false,true);LARGE_INTEGER size{};
            if(!GetFileSizeEx(h.value,&size) || size.QuadPart<0 || size.QuadPart>static_cast<LONGLONG>(e::enrollment_record_cap))fail();}if(!DeleteFileW(stage.c_str()))fail();}
        {auto h=open(stage,GENERIC_WRITE,CREATE_NEW,FILE_FLAG_WRITE_THROUGH);user_.check(h.value,false,true);DWORD n{};
            if(!WriteFile(h.value,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr) || n!=bytes.size() || !FlushFileBuffers(h.value))fail();}
        if(!MoveFileExW(stage.c_str(),target.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))fail();
    }
    void clear_credential(bool retired)override{
        if(!read_credential(retired) || !DeleteFileW((root_/(retired?L"credential.retired":L"credential.current")).c_str()))fail();
    }
    void store_status(std::span<const std::byte> bytes)override{
        if(bytes.empty() || bytes.size()>e::status_wire_cap)fail();
        (void)read_status();const auto stage=root_/L".revocation.next";
        if(exists_local(stage)){{auto h=open(stage,GENERIC_READ,OPEN_EXISTING,0);user_.check(h.value,false,true);LARGE_INTEGER size{};
            if(!GetFileSizeEx(h.value,&size) || size.QuadPart<0 || size.QuadPart>static_cast<LONGLONG>(e::status_wire_cap))fail();}
            if(!DeleteFileW(stage.c_str()))fail();}
        {auto h=open(stage,GENERIC_WRITE,CREATE_NEW,FILE_FLAG_WRITE_THROUGH);user_.check(h.value,false,true);DWORD n{};
            if(!WriteFile(h.value,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr) || n!=bytes.size() || !FlushFileBuffers(h.value))fail();}
        if(!MoveFileExW(stage.c_str(),(root_/L"revocation.current").c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))fail();
    }
    std::optional<e::Bytes> read_abort(const std::array<std::byte,32>& round)override{
        const auto path=root_/L"aborted";if(!exists_local(path))return {};
        Handle pinned(CreateFileW(path.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        user_.check(pinned.value,true,true);return read_file(path/(hex(round)+L".lpj"),e::enrollment_storage_cap);
    }
    void store_abort(const std::array<std::byte,32>& round,std::span<const std::byte> bytes)override{
        const auto path=root_/L"aborted";auto pinned=directory(path,true);std::size_t count{};
        WIN32_FIND_DATAW data{};const auto finder=FindFirstFileW((path/L"*").c_str(),&data);
        if(finder==INVALID_HANDLE_VALUE && GetLastError()!=ERROR_FILE_NOT_FOUND)fail();
        struct CloseFind{HANDLE h;~CloseFind(){if(h!=INVALID_HANDLE_VALUE)FindClose(h);}} close{finder};
        if(finder!=INVALID_HANDLE_VALUE){do {const std::wstring name(data.cFileName);if(name==L"." || name==L"..")continue;
            const auto current=hex(round)+L".lpj.enrollment-next";if(name==current)continue;
            if(name.size()!=68 || name.substr(64)!=L".lpj" || name.substr(0,64).find_first_not_of(L"0123456789abcdef")!=std::wstring::npos)fail();
            if(++count>e::enrollment_abort_history_cap)fail();
        }while(FindNextFileW(finder,&data));if(GetLastError()!=ERROR_NO_MORE_FILES)fail();}
        const auto target=path/(hex(round)+L".lpj");if(!exists_local(target) && count>=e::enrollment_abort_history_cap)fail();
        create_file(target,bytes,e::enrollment_storage_cap);
    }
    User user_;std::filesystem::path root_,product_;std::vector<Handle> parents_,leases_;
};
}
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal_fixture(const std::filesystem::path& root){return std::make_unique<Journal>(root);}
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal(){
    PWSTR raw{};if(SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&raw)!=S_OK || !raw)fail();const std::filesystem::path local(raw);CoTaskMemFree(raw);
    // Installer supplies the product/maintenance parents. Reuse its operation
    // lease; activation must borrow this lease rather than recursively acquire.
    const auto product=local/L"LanPilot",maintenance=product/L"maintenance";
    User user;for(const auto& path:{product,maintenance}){Handle h(CreateFileW(path.c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));user.check(h.value,true,false);}
    return std::make_unique<Journal>(product/L"enrollment",maintenance/L"program-update.lock",product);
}
}
