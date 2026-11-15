// GUI-subsystem task entry point: a console PowerShell host can flash before
// processing -WindowStyle Hidden. Never create that console in the first place.
#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

namespace {
std::wstring quote(const std::wstring& value) {
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (const auto ch : value) {
        if (ch == L'\\') {
            ++slashes;
        } else {
            result.append(ch == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
            slashes = 0;
            result += ch;
        }
    }
    result.append(slashes * 2, L'\\');
    return result + L'\"';
}

bool absolute_data_path(const std::wstring& path) {
    if (path.size() < 3 || path.size() > 16000 || path[1] != L':' ||
        (path[2] != L'\\' && path[2] != L'/') ||
        !((path[0] >= L'A' && path[0] <= L'Z') ||
          (path[0] >= L'a' && path[0] <= L'z'))) {
        return false;
    }
    for (std::size_t i = 2; i < path.size(); ++i) {
        if (path[i] < L' ' || path[i] == L'\"' || path[i] == L':') {
            return false;
        }
    }
    return true; // The worker additionally rejects reparse points.
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    auto** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) { return ERROR_INVALID_PARAMETER; }
    const bool valid = argc == 3 && std::wstring(argv[1]) == L"--data-root" &&
                       absolute_data_path(argv[2]);
    const std::wstring data_root = valid ? argv[2] : L"";
    LocalFree(argv);
    if (!valid) { return ERROR_INVALID_PARAMETER; }

    std::vector<wchar_t> module(32768);
    const auto length = GetModuleFileNameW(nullptr, module.data(),
                                          static_cast<DWORD>(module.size()));
    if (!length || length >= module.size()) { return ERROR_BAD_PATHNAME; }
    const std::wstring executable(module.data(), length);
    const auto slash = executable.find_last_of(L"\\/");
    if (slash == std::wstring::npos) { return ERROR_BAD_PATHNAME; }
    const auto directory = executable.substr(0, slash);
    const auto worker = directory + L"\\Invoke-LanPilotTrustMaintenance.ps1";
    const auto attributes = GetFileAttributesW(worker.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        return ERROR_FILE_NOT_FOUND;
    }
    wchar_t system[MAX_PATH]{};
    if (!GetSystemDirectoryW(system, MAX_PATH)) { return ERROR_BAD_PATHNAME; }
    const auto host = std::wstring(system) + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    auto command = quote(host) + L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
                   quote(worker) + L" -DataRoot " + quote(data_root);

    // Own the complete process tree. A timeout or Task Scheduler termination
    // must not leave an orphaned PowerShell/SSH/SCP maintenance process.
    const auto job = CreateJobObjectW(nullptr, nullptr);
    if (!job) { return static_cast<int>(GetLastError()); }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        const auto error = GetLastError();
        CloseHandle(job);
        return static_cast<int>(error);
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(host.c_str(), command.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                        directory.c_str(), &startup, &process)) {
        const auto error = GetLastError();
        CloseHandle(job);
        return static_cast<int>(error);
    }
    if (!AssignProcessToJobObject(job, process.hProcess) ||
        ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
        const auto error = GetLastError();
        TerminateProcess(process.hProcess, error);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        return static_cast<int>(error);
    }
    CloseHandle(process.hThread);
    const auto wait = WaitForSingleObject(process.hProcess, 170000);
    DWORD result = ERROR_TIMEOUT;
    if (wait == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(process.hProcess, &result)) { result = GetLastError(); }
    } else {
        TerminateJobObject(job, ERROR_TIMEOUT);
    }
    CloseHandle(process.hProcess);
    CloseHandle(job);
    return static_cast<int>(result);
}
