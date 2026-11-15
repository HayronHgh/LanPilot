// A stable GUI-subsystem entry point. Payload updates never rename this file
// or its bootstrap directory. No shell text, peer data or arbitrary script path.
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::wstring quote(const std::wstring& value) {
    std::wstring result=L"\"";std::size_t slashes{};
    for(const auto ch:value){
        if(ch==L'\\'){++slashes;continue;}
        result.append(ch==L'\"'?slashes*2+1:slashes,L'\\');slashes=0;result+=ch;
    }
    result.append(slashes*2,L'\\');return result+L'\"';
}
bool local_path(const std::wstring& value) {
    if(value.size()<3 || value.size()>16000 || value[1]!=L':' ||
       (value[2]!=L'\\' && value[2]!=L'/') ||
       !((value[0]>=L'A'&&value[0]<=L'Z')||(value[0]>=L'a'&&value[0]<=L'z')))return false;
    for(std::size_t i=2;i<value.size();++i)
        if(value[i]<L' ' || value[i]==L'\"' || value[i]==L':')return false;
    return true;
}
bool unlinked_file(std::filesystem::path path) {
    const auto first=GetFileAttributesW(path.c_str());
    if(first==INVALID_FILE_ATTRIBUTES || (first&FILE_ATTRIBUTE_DIRECTORY))return false;
    while(!path.empty()){
        const auto attributes=GetFileAttributesW(path.c_str());
        if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_REPARSE_POINT))return false;
        const auto parent=path.parent_path();if(parent==path)break;path=parent;
    }
    return true;
}
}

int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    bool quiet{};
    try {
        int argc{};auto** argv=CommandLineToArgvW(GetCommandLineW(),&argc);
        if(!argv)return ERROR_INVALID_PARAMETER;
        bool check{},maintenance{},data_seen{},connection_seen{};
        std::wstring data,connection=L"configure";
        bool valid=true;
        for(int i=1;i<argc;++i){
            const std::wstring flag(argv[i]);
            if(flag==L"--check-startup" && !check){check=true;quiet=true;}
            else if(flag==L"--maintenance" && !maintenance){maintenance=true;quiet=true;}
            else if(flag==L"--data-root" && !data_seen && i+1<argc){data=argv[++i];data_seen=true;}
            else if(flag==L"--connection" && !connection_seen && i+1<argc){connection=argv[++i];connection_seen=true;}
            else valid=false;
        }
        LocalFree(argv);
        if(!valid || (check&&maintenance) || (connection!=L"configure"&&connection!=L"ssh"))return ERROR_INVALID_PARAMETER;
        if(data.empty()){
            PWSTR known{};
            if(FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_DEFAULT,nullptr,&known)))return ERROR_PATH_NOT_FOUND;
            data=std::wstring(known)+L"\\LanPilot";CoTaskMemFree(known);
        }
        if(!local_path(data))return ERROR_INVALID_PARAMETER;
        std::vector<wchar_t> module(32768);
        const auto length=GetModuleFileNameW(nullptr,module.data(),static_cast<DWORD>(module.size()));
        if(!length || length>=module.size())return ERROR_BAD_PATHNAME;
        const auto root=std::filesystem::path(std::wstring(module.data(),length)).parent_path();
        if(root.filename()!=L"LanPilot" || !local_path(root.wstring()))return ERROR_BAD_PATHNAME;
        const auto script=root/L"bootstrap"/L"Start-LanPilotBootstrap.ps1";
        if(!unlinked_file(script))throw std::runtime_error("bootstrap unavailable");
        wchar_t system[MAX_PATH]{};
        if(!GetSystemDirectoryW(system,MAX_PATH))return ERROR_PATH_NOT_FOUND;
        const auto host=std::wstring(system)+L"\\WindowsPowerShell\\v1.0\\powershell.exe";
        auto command=quote(host)+L" -NoProfile -STA -ExecutionPolicy Bypass -File "+quote(script.wstring())+
            L" -DataRoot "+quote(data)+L" -Connection "+quote(connection);
        if(check)command+=L" -CheckOnly";
        if(maintenance)command+=L" -Maintenance";
        STARTUPINFOW startup{};startup.cb=sizeof(startup);
        // CREATE_NO_WINDOW hides the console. SW_HIDE also suppresses the first
        // WinForms dialog, so reserve that flag for noninteractive operations.
        if(quiet){startup.dwFlags=STARTF_USESHOWWINDOW;startup.wShowWindow=SW_HIDE;}
        PROCESS_INFORMATION process{};
        HANDLE job{};
        if(maintenance){
            job=CreateJobObjectW(nullptr,nullptr);
            if(!job)return static_cast<int>(GetLastError());
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))){
                const auto error=GetLastError();CloseHandle(job);return static_cast<int>(error);
            }
        }
        if(!CreateProcessW(host.c_str(),command.data(),nullptr,nullptr,FALSE,
            CREATE_NO_WINDOW|(maintenance?CREATE_SUSPENDED:0),nullptr,root.c_str(),&startup,&process)){
            if(job)CloseHandle(job);
            throw std::runtime_error("start bootstrap failed");
        }
        if(maintenance && (!AssignProcessToJobObject(job,process.hProcess) ||
            ResumeThread(process.hThread)==static_cast<DWORD>(-1))){
            const auto error=GetLastError();TerminateProcess(process.hProcess,error);
            CloseHandle(process.hThread);CloseHandle(process.hProcess);CloseHandle(job);return static_cast<int>(error);
        }
        CloseHandle(process.hThread);
        const auto wait=WaitForSingleObject(process.hProcess,maintenance?170000:INFINITE);
        DWORD result=ERROR_TIMEOUT;
        if(wait==WAIT_OBJECT_0){if(!GetExitCodeProcess(process.hProcess,&result))result=GetLastError();}
        else if(job)TerminateJobObject(job,ERROR_TIMEOUT);
        CloseHandle(process.hProcess);if(job)CloseHandle(job);
        return static_cast<int>(result);
    }catch(...){
        if(!quiet)MessageBoxW(nullptr,L"LanPilot could not start. Its installed bootstrap is missing or unavailable. Your saved connection and identity were not replaced.",L"LanPilot",MB_OK|MB_ICONERROR);
        return ERROR_FILE_NOT_FOUND;
    }
}
