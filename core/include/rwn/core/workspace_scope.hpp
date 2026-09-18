#pragma once

#include <filesystem>

namespace rwn::core {

class WorkspaceScope {
public:
    explicit WorkspaceScope(std::filesystem::path root);

    [[nodiscard]] const std::filesystem::path& root() const { return root_; }
    [[nodiscard]] std::filesystem::path resolve(const std::filesystem::path& relative_path) const;
    [[nodiscard]] bool contains_resolved(const std::filesystem::path& resolved_path) const;

private:
    std::filesystem::path root_;
};

}  // namespace rwn::core
