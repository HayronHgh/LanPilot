#include "rwn/platform/windows/durable_filesystem.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdexcept>

namespace rwn::platform::windows {

void WindowsDurableFileSystem::flush_file(const std::filesystem::path& path) {
    const auto handle = CreateFileW(
        path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("staging file could not be opened for durable flush");
    }
    const auto flushed = FlushFileBuffers(handle);
    const auto closed = CloseHandle(handle);
    if (flushed == 0 || closed == 0) {
        throw std::runtime_error("staging file durable flush failed");
    }
}

void WindowsDurableFileSystem::atomic_replace(
    const std::filesystem::path& staging,
    const std::filesystem::path& destination) {
    if (MoveFileExW(
            staging.c_str(), destination.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        throw std::runtime_error("atomic workspace file replacement failed");
    }
}

}  // namespace rwn::platform::windows
