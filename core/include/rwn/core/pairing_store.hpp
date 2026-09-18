#pragma once

#include "rwn/core/file_transfer.hpp"
#include "rwn/core/identity.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <filesystem>
#include <string_view>

namespace rwn::core {

class PairingStore {
public:
    PairingStore(
        std::filesystem::path root,
        std::filesystem::path relative_state_file,
        DurableFileSystem& filesystem);

    [[nodiscard]] bool exists() const;
    [[nodiscard]] PairedDevice load() const;
    void create(const PairedDevice& device);
    void replace_revoked(const PairedDevice& device);
    [[nodiscard]] PairedDevice revoke(std::string_view device_id);

    [[nodiscard]] const std::filesystem::path& state_path() const noexcept {
        return state_path_;
    }

private:
    void persist(const PairedDevice& device, bool require_absent);

    WorkspaceScope scope_;
    std::filesystem::path state_path_;
    std::filesystem::path staging_path_;
    DurableFileSystem& filesystem_;
};

}  // namespace rwn::core
