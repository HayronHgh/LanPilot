#pragma once

#include "rwn/core/file_transfer.hpp"

namespace rwn::platform::macos {

class MacDurableFileSystem final : public rwn::core::DurableFileSystem {
public:
    void flush_file(const std::filesystem::path& path) override;
    void atomic_replace(
        const std::filesystem::path& staging,
        const std::filesystem::path& destination) override;
};

}  // namespace rwn::platform::macos
