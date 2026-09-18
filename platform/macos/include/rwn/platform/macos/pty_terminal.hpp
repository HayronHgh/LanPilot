#pragma once

#include "rwn/core/terminal.hpp"

#include <sys/types.h>

namespace rwn::platform::macos {

class PtyTerminal final : public rwn::core::TerminalBackend {
public:
    PtyTerminal() = default;
    ~PtyTerminal() override;
    PtyTerminal(const PtyTerminal&) = delete;
    PtyTerminal& operator=(const PtyTerminal&) = delete;

    void open(
        const rwn::core::CommandSpec& command,
        const std::filesystem::path& resolved_working_directory,
        rwn::core::TerminalSize size) override;
    void resize(rwn::core::TerminalSize size) override;
    [[nodiscard]] std::size_t write(
        std::span<const std::byte> input) override;
    [[nodiscard]] std::vector<std::byte> read(std::size_t maximum) override;
    void close() noexcept override;

private:
    int master_fd_{-1};
    pid_t child_{-1};
};

}  // namespace rwn::platform::macos
