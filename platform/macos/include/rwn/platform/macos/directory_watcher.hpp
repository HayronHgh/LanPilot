#pragma once

#include "rwn/core/workspace_watcher.hpp"

#include <chrono>
#include <filesystem>
#include <memory>
#include <vector>

namespace rwn::platform::macos {

class DirectoryWatcher {
public:
    explicit DirectoryWatcher(const std::filesystem::path& root);
    ~DirectoryWatcher();

    DirectoryWatcher(const DirectoryWatcher&) = delete;
    DirectoryWatcher& operator=(const DirectoryWatcher&) = delete;

    [[nodiscard]] std::vector<rwn::core::WorkspaceTrigger> poll(
        std::chrono::milliseconds timeout);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::platform::macos
