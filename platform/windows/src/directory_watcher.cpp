#include "rwn/platform/windows/directory_watcher.hpp"

#include <array>
#include <limits>
#include <stdexcept>
#include <string>

namespace rwn::platform::windows {
namespace {

rwn::core::WorkspaceTriggerKind trigger_kind(const DWORD action) {
    switch (action) {
        case FILE_ACTION_ADDED: return rwn::core::WorkspaceTriggerKind::added;
        case FILE_ACTION_REMOVED: return rwn::core::WorkspaceTriggerKind::removed;
        case FILE_ACTION_MODIFIED: return rwn::core::WorkspaceTriggerKind::modified;
        case FILE_ACTION_RENAMED_OLD_NAME:
            return rwn::core::WorkspaceTriggerKind::renamed_from;
        case FILE_ACTION_RENAMED_NEW_NAME:
            return rwn::core::WorkspaceTriggerKind::renamed_to;
        default: return rwn::core::WorkspaceTriggerKind::overflow;
    }
}

}  // namespace

DirectoryWatcher::DirectoryWatcher(const std::filesystem::path& root) {
    if (!std::filesystem::is_directory(root)) {
        throw std::invalid_argument("watch root is not a directory");
    }
    directory_ = CreateFileW(
        root.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (directory_ == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("ReadDirectoryChangesW directory open failed");
    }
}

DirectoryWatcher::~DirectoryWatcher() {
    if (directory_ != INVALID_HANDLE_VALUE) {
        static_cast<void>(CancelIoEx(directory_, nullptr));
        static_cast<void>(CloseHandle(directory_));
    }
}

std::vector<rwn::core::WorkspaceTrigger> DirectoryWatcher::poll(
    const std::chrono::milliseconds timeout) {
    if (timeout < std::chrono::milliseconds::zero() ||
        timeout.count() > static_cast<long long>(std::numeric_limits<DWORD>::max() - 1U)) {
        throw std::invalid_argument("watch timeout is outside Windows range");
    }
    alignas(FILE_NOTIFY_INFORMATION) std::array<std::byte, 64U * 1024U> buffer{};
    const auto event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (event == nullptr) {
        throw std::runtime_error("watch event creation failed");
    }
    OVERLAPPED overlapped{};
    overlapped.hEvent = event;
    const auto started = ReadDirectoryChangesW(
        directory_, buffer.data(), static_cast<DWORD>(buffer.size()), TRUE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_CREATION,
        nullptr, &overlapped, nullptr);
    if (started == 0 && GetLastError() != ERROR_IO_PENDING) {
        static_cast<void>(CloseHandle(event));
        throw std::runtime_error("ReadDirectoryChangesW request failed");
    }

    const auto wait_status = WaitForSingleObject(
        event, static_cast<DWORD>(timeout.count()));
    if (wait_status == WAIT_TIMEOUT) {
        static_cast<void>(CancelIoEx(directory_, &overlapped));
        static_cast<void>(WaitForSingleObject(event, INFINITE));
        static_cast<void>(CloseHandle(event));
        return {};
    }
    if (wait_status != WAIT_OBJECT_0) {
        static_cast<void>(CancelIoEx(directory_, &overlapped));
        static_cast<void>(CloseHandle(event));
        throw std::runtime_error("directory watch wait failed");
    }

    DWORD transferred{};
    if (GetOverlappedResult(directory_, &overlapped, &transferred, FALSE) == 0) {
        static_cast<void>(CloseHandle(event));
        throw std::runtime_error("directory watch completion failed");
    }
    static_cast<void>(CloseHandle(event));
    if (transferred == 0) {
        return {{.kind = rwn::core::WorkspaceTriggerKind::overflow, .path = {}}};
    }

    std::vector<rwn::core::WorkspaceTrigger> result;
    std::size_t offset{};
    while (offset < transferred) {
        const auto* record = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
            buffer.data() + offset);
        const std::wstring name(
            record->FileName, record->FileNameLength / sizeof(wchar_t));
        const auto path = std::filesystem::path(name).generic_string();
        result.push_back({.kind = trigger_kind(record->Action), .path = path});
        if (record->NextEntryOffset == 0) {
            break;
        }
        offset += record->NextEntryOffset;
    }
    return result;
}

}  // namespace rwn::platform::windows
