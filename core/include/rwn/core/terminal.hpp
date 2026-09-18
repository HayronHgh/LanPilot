#pragma once

#include "rwn/core/authorization.hpp"
#include "rwn/core/build.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <cstddef>
#include <filesystem>
#include <map>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace rwn::core {

struct TerminalSize {
    std::size_t columns{};
    std::size_t rows{};
};

enum class TerminalState { created, open, closed };

class TerminalBackend {
public:
    virtual ~TerminalBackend() = default;
    virtual void open(
        const CommandSpec& command,
        const std::filesystem::path& resolved_working_directory,
        TerminalSize size) = 0;
    virtual void resize(TerminalSize size) = 0;
    [[nodiscard]] virtual std::size_t write(std::span<const std::byte> input) = 0;
    [[nodiscard]] virtual std::vector<std::byte> read(std::size_t maximum) = 0;
    virtual void close() noexcept = 0;
};

class TerminalSession {
public:
    static constexpr std::size_t max_input = 64U * 1024U;
    static constexpr std::size_t max_output_read = 1024U * 1024U;

    TerminalSession(
        std::string id, AuthorizationResult authorization,
        std::filesystem::path workspace_root, TerminalBackend& backend);

    void open(
        const CommandSpec& command,
        const std::set<std::string, std::less<>>& environment_allowlist,
        TerminalSize size);
    void resize(TerminalSize size);
    [[nodiscard]] std::size_t write(std::span<const std::byte> input);
    [[nodiscard]] std::vector<std::byte> read(std::size_t maximum);
    void close();

    [[nodiscard]] const std::string& id() const { return id_; }
    [[nodiscard]] TerminalState state() const { return state_; }
    [[nodiscard]] TerminalSize size() const { return size_; }

private:
    static void validate_size(TerminalSize size);
    void require_open() const;

    std::string id_;
    AuthorizationResult authorization_;
    WorkspaceScope workspace_scope_;
    TerminalBackend& backend_;
    TerminalState state_{TerminalState::created};
    TerminalSize size_{};
};

}  // namespace rwn::core
