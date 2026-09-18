#include "rwn/platform/windows/command_executor.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace rwn::platform::windows {
namespace {

constexpr std::size_t max_captured_stream = 16U * 1024U * 1024U;
constexpr std::size_t max_windows_text = 32767U;

class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : handle_(handle) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.handle_, INVALID_HANDLE_VALUE));
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const { return handle_; }
    [[nodiscard]] bool valid() const {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }
    void reset(HANDLE replacement = INVALID_HANDLE_VALUE) noexcept {
        if (valid()) static_cast<void>(CloseHandle(handle_));
        handle_ = replacement;
    }

private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

std::wstring utf8_to_wide(const std::string_view value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<std::size_t>(
                           std::numeric_limits<int>::max())) {
        throw std::length_error("command text exceeds Windows conversion limit");
    }
    const auto input_size = static_cast<int>(value.size());
    const auto required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, nullptr, 0);
    if (required <= 0) {
        throw std::invalid_argument("command text is not valid UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size,
            result.data(), required) != required) {
        throw std::runtime_error("UTF-8 command conversion failed");
    }
    return result;
}

std::wstring quote_argument(const std::wstring_view value) {
    if (!value.empty() &&
        value.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring(value);
    }
    std::wstring result(1, L'"');
    std::size_t backslashes{};
    for (const auto character : value) {
        if (character == L'\\') {
            ++backslashes;
        } else if (character == L'"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
        } else {
            result.append(backslashes, L'\\');
            backslashes = 0;
            result.push_back(character);
        }
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::wstring command_line(const std::vector<std::string>& arguments) {
    std::wstring result;
    for (const auto& argument : arguments) {
        if (!result.empty()) result.push_back(L' ');
        result += quote_argument(utf8_to_wide(argument));
        if (result.size() >= max_windows_text) {
            throw std::length_error("Windows command line exceeds 32766 characters");
        }
    }
    return result;
}

bool valid_environment_name(const std::string_view name) {
    if (name.empty() || name.size() > 128 ||
        !(std::isalpha(static_cast<unsigned char>(name.front())) != 0 ||
          name.front() == '_')) {
        return false;
    }
    return std::ranges::all_of(name.substr(1), [](const unsigned char value) {
        return std::isalnum(value) != 0 || value == '_';
    });
}

std::vector<wchar_t> environment_block(
    const std::map<std::string, std::string, std::less<>>& environment) {
    struct Entry { std::wstring key; std::wstring pair; };
    std::vector<Entry> entries;
    std::set<std::wstring, std::less<>> folded_names;
    for (const auto& [name, value] : environment) {
        if (!valid_environment_name(name) || value.find('\0') != std::string::npos) {
            throw std::invalid_argument("invalid command environment entry");
        }
        auto key = utf8_to_wide(name);
        std::ranges::transform(key, key.begin(), [](const wchar_t character) {
            return static_cast<wchar_t>(std::towlower(character));
        });
        if (!folded_names.insert(key).second) {
            throw std::invalid_argument(
                "duplicate case-insensitive environment variable");
        }
        entries.push_back({.key = std::move(key),
                           .pair = utf8_to_wide(name + "=" + value)});
    }
    std::ranges::sort(entries, {}, &Entry::key);
    std::vector<wchar_t> result;
    for (const auto& entry : entries) {
        result.insert(result.end(), entry.pair.begin(), entry.pair.end());
        result.push_back(L'\0');
    }
    result.push_back(L'\0');
    if (environment.empty()) result.push_back(L'\0');
    if (result.size() > max_windows_text) {
        throw std::length_error("Windows environment block exceeds limit");
    }
    return result;
}

struct Pipe {
    UniqueHandle read;
    UniqueHandle write;
};

Pipe create_pipe() {
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    attributes.bInheritHandle = TRUE;
    HANDLE read{INVALID_HANDLE_VALUE};
    HANDLE write{INVALID_HANDLE_VALUE};
    if (CreatePipe(&read, &write, &attributes, 0) == 0) {
        throw std::runtime_error("command output pipe creation failed");
    }
    Pipe pipe{.read = UniqueHandle(read), .write = UniqueHandle(write)};
    if (SetHandleInformation(pipe.read.get(), HANDLE_FLAG_INHERIT, 0) == 0) {
        throw std::runtime_error("command pipe inheritance configuration failed");
    }
    return pipe;
}

class AttributeList {
public:
    explicit AttributeList(const std::span<HANDLE> handles) {
        SIZE_T size{};
        static_cast<void>(InitializeProcThreadAttributeList(nullptr, 1, 0, &size));
        if (size == 0) {
            throw std::runtime_error("command handle-list sizing failed");
        }
        storage_.resize(size);
        list_ = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
        if (InitializeProcThreadAttributeList(list_, 1, 0, &size) == 0) {
            list_ = nullptr;
            throw std::runtime_error("command handle-list initialization failed");
        }
        if (UpdateProcThreadAttribute(
                list_, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.data(),
                handles.size_bytes(), nullptr, nullptr) == 0) {
            DeleteProcThreadAttributeList(list_);
            list_ = nullptr;
            throw std::runtime_error("command inherited handle-list failed");
        }
    }
    ~AttributeList() {
        if (list_ != nullptr) DeleteProcThreadAttributeList(list_);
    }
    AttributeList(const AttributeList&) = delete;
    AttributeList& operator=(const AttributeList&) = delete;
    [[nodiscard]] PPROC_THREAD_ATTRIBUTE_LIST get() const { return list_; }

private:
    std::vector<std::byte> storage_;
    PPROC_THREAD_ATTRIBUTE_LIST list_{};
};

void read_pipe(HANDLE pipe, std::string& output, bool& truncated) noexcept {
    std::array<char, 16U * 1024U> buffer{};
    DWORD count{};
    while (ReadFile(
               pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &count,
               nullptr) != 0) {
        const auto available = max_captured_stream - output.size();
        const auto accepted = std::min<std::size_t>(available, count);
        output.append(buffer.data(), accepted);
        if (accepted < count) truncated = true;
    }
}

}  // namespace

rwn::core::BuildEvidence WindowsCommandExecutor::execute(
    const rwn::core::CommandSpec& command,
    const rwn::core::CancellationToken stop_token) {
    rwn::core::validate_command(command, [&] {
        std::set<std::string, std::less<>> names;
        for (const auto& [name, _] : command.environment) names.insert(name);
        return names;
    }());
    const auto executable = std::filesystem::path(command.argv.front());
    if (!executable.is_absolute() || !std::filesystem::is_regular_file(executable)) {
        throw std::invalid_argument(
            "command executable must be an existing absolute file");
    }
    const auto working_directory = scope_.resolve(command.working_directory);
    if (!std::filesystem::is_directory(working_directory)) {
        throw std::invalid_argument("command working directory does not exist");
    }

    auto stdout_pipe = create_pipe();
    auto stderr_pipe = create_pipe();
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    attributes.bInheritHandle = TRUE;
    UniqueHandle standard_input(CreateFileW(
        L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!standard_input.valid()) {
        throw std::runtime_error("command null input could not be opened");
    }
    UniqueHandle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.valid()) {
        throw std::runtime_error("command job object creation failed");
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (SetInformationJobObject(
            job.get(), JobObjectExtendedLimitInformation, &limits,
            sizeof(limits)) == 0) {
        throw std::runtime_error("command job object configuration failed");
    }
    std::array inherited{
        standard_input.get(), stdout_pipe.write.get(), stderr_pipe.write.get()};
    AttributeList attribute_list(inherited);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = standard_input.get();
    startup.StartupInfo.hStdOutput = stdout_pipe.write.get();
    startup.StartupInfo.hStdError = stderr_pipe.write.get();
    startup.lpAttributeList = attribute_list.get();
    PROCESS_INFORMATION raw_process{};
    auto mutable_command_line = command_line(command.argv);
    auto environment = environment_block(command.environment);
    const auto executable_wide = executable.wstring();
    const auto start = std::chrono::steady_clock::now();
    if (CreateProcessW(
            executable_wide.c_str(), mutable_command_line.data(), nullptr, nullptr,
            TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
                EXTENDED_STARTUPINFO_PRESENT,
            environment.data(), working_directory.c_str(), &startup.StartupInfo,
            &raw_process) == 0) {
        throw std::runtime_error("CreateProcessW failed");
    }
    UniqueHandle process(raw_process.hProcess);
    UniqueHandle process_thread(raw_process.hThread);
    if (AssignProcessToJobObject(job.get(), process.get()) == 0) {
        static_cast<void>(TerminateProcess(process.get(), ERROR_CANCELLED));
        throw std::runtime_error("command process job assignment failed");
    }
    if (ResumeThread(process_thread.get()) == static_cast<DWORD>(-1)) {
        static_cast<void>(TerminateJobObject(job.get(), ERROR_CANCELLED));
        throw std::runtime_error("command process resume failed");
    }
    process_thread.reset();
    standard_input.reset();
    stdout_pipe.write.reset();
    stderr_pipe.write.reset();

    rwn::core::BuildEvidence evidence;
    std::jthread stdout_reader(
        read_pipe, stdout_pipe.read.get(), std::ref(evidence.stdout_log),
        std::ref(evidence.stdout_truncated));
    std::jthread stderr_reader(
        read_pipe, stderr_pipe.read.get(), std::ref(evidence.stderr_log),
        std::ref(evidence.stderr_truncated));
    bool wait_failed{};
    while (true) {
        const auto wait = WaitForSingleObject(process.get(), 20);
        if (wait == WAIT_OBJECT_0) break;
        if (wait != WAIT_TIMEOUT) {
            wait_failed = true;
            static_cast<void>(TerminateJobObject(job.get(), ERROR_CANCELLED));
            static_cast<void>(WaitForSingleObject(process.get(), INFINITE));
            break;
        }
        const auto elapsed = std::chrono::steady_clock::now() - start;
        if (stop_token.stop_requested()) {
            evidence.cancelled = true;
            static_cast<void>(TerminateJobObject(job.get(), ERROR_CANCELLED));
            static_cast<void>(WaitForSingleObject(process.get(), INFINITE));
            break;
        }
        if (elapsed >= command.timeout) {
            evidence.timed_out = true;
            static_cast<void>(TerminateJobObject(job.get(), ERROR_TIMEOUT));
            static_cast<void>(WaitForSingleObject(process.get(), INFINITE));
            break;
        }
    }
    DWORD exit_code{};
    const auto exit_read = GetExitCodeProcess(process.get(), &exit_code) != 0;
    process.reset();
    job.reset();
    stdout_reader.join();
    stderr_reader.join();
    if (wait_failed) {
        throw std::runtime_error("command process wait failed");
    }
    if (!exit_read) {
        throw std::runtime_error("command exit code could not be read");
    }
    evidence.exit_code = static_cast<int>(exit_code);
    evidence.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return evidence;
}

}  // namespace rwn::platform::windows
