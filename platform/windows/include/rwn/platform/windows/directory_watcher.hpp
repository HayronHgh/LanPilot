#pragma once

#include "rwn/core/workspace_watcher.hpp"

#include <chrono>
#include <filesystem>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace rwn::platform::windows {

class DirectoryWatcher {
public:
    explicit DirectoryWatcher(const std::filesystem::path& root);
    ~DirectoryWatcher();

    DirectoryWatcher(const DirectoryWatcher&) = delete;
    DirectoryWatcher& operator=(const DirectoryWatcher&) = delete;

    [[nodiscard]] std::vector<rwn::core::WorkspaceTrigger> poll(
        std::chrono::milliseconds timeout);

private:
    HANDLE directory_{INVALID_HANDLE_VALUE};
};

}  // namespace rwn::platform::windows
