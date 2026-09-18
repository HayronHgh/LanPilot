#include "rwn/core/workspace_scope.hpp"

#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

bool has_prefix(const std::filesystem::path& path, const std::filesystem::path& prefix) {
    auto path_part = path.begin();
    for (auto prefix_part = prefix.begin(); prefix_part != prefix.end(); ++prefix_part, ++path_part) {
        if (path_part == path.end() || *path_part != *prefix_part) {
            return false;
        }
    }
    return true;
}

}  // namespace

WorkspaceScope::WorkspaceScope(std::filesystem::path root) {
    if (root.empty()) {
        throw std::invalid_argument("workspace root must not be empty");
    }
    root_ = std::filesystem::weakly_canonical(std::filesystem::absolute(std::move(root)));
}

std::filesystem::path WorkspaceScope::resolve(const std::filesystem::path& relative_path) const {
    if (relative_path.empty() || relative_path.is_absolute()) {
        throw std::invalid_argument("workspace path must be non-empty and relative");
    }
    const auto candidate = std::filesystem::weakly_canonical(root_ / relative_path);
    if (!contains_resolved(candidate)) {
        throw std::invalid_argument("workspace path escapes authorized root");
    }
    return candidate;
}

bool WorkspaceScope::contains_resolved(const std::filesystem::path& resolved_path) const {
    const auto canonical = std::filesystem::weakly_canonical(std::filesystem::absolute(resolved_path));
    return has_prefix(canonical, root_);
}

}  // namespace rwn::core
