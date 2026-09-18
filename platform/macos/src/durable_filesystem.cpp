#include "rwn/platform/macos/durable_filesystem.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdio>
#include <fcntl.h>
#include <stdexcept>
#include <unistd.h>

namespace rwn::platform::macos {
namespace {

void fsync_path(const std::filesystem::path& path, const int flags) {
    const auto descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0) {
        throw std::runtime_error("durable path open failed");
    }
    const auto synced = ::fsync(descriptor);
    const auto closed = ::close(descriptor);
    if (synced != 0 || closed != 0) {
        throw std::runtime_error("durable path fsync failed");
    }
}

}  // namespace

void MacDurableFileSystem::flush_file(const std::filesystem::path& path) {
    fsync_path(path, O_RDONLY);
}

void MacDurableFileSystem::atomic_replace(
    const std::filesystem::path& staging,
    const std::filesystem::path& destination) {
    if (::rename(staging.c_str(), destination.c_str()) != 0) {
        throw std::runtime_error("atomic workspace file replacement failed");
    }
    fsync_path(destination.parent_path(), O_RDONLY | O_DIRECTORY);
}

}  // namespace rwn::platform::macos
