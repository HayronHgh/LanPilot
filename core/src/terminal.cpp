#include "rwn/core/terminal.hpp"

#include <stdexcept>
#include <utility>

namespace rwn::core {

TerminalSession::TerminalSession(
    std::string id, AuthorizationResult authorization,
    std::filesystem::path workspace_root, TerminalBackend& backend)
    : id_(std::move(id)),
      authorization_(std::move(authorization)),
      workspace_scope_(std::move(workspace_root)),
      backend_(backend) {
    if (id_.empty()) {
        throw std::invalid_argument("terminal session id must not be empty");
    }
}

void TerminalSession::validate_size(const TerminalSize size) {
    if (size.columns == 0 || size.columns > 512 ||
        size.rows == 0 || size.rows > 512) {
        throw std::invalid_argument("terminal dimensions are outside bounds");
    }
}

void TerminalSession::require_open() const {
    if (state_ != TerminalState::open) {
        throw std::logic_error("terminal session is not open");
    }
}

void TerminalSession::open(
    const CommandSpec& command,
    const std::set<std::string, std::less<>>& environment_allowlist,
    const TerminalSize size) {
    if (state_ != TerminalState::created) {
        throw std::logic_error("terminal session cannot be reopened");
    }
    if (!authorization_.permits(Capability::terminal_open)) {
        throw std::logic_error("terminal capability is not granted");
    }
    validate_command(command, environment_allowlist);
    if (!std::filesystem::path(command.argv.front()).is_absolute()) {
        throw std::invalid_argument("terminal executable must be absolute");
    }
    validate_size(size);
    const auto working_directory =
        workspace_scope_.resolve(command.working_directory);
    if (!std::filesystem::is_directory(working_directory)) {
        throw std::invalid_argument("terminal working directory does not exist");
    }
    backend_.open(command, working_directory, size);
    size_ = size;
    state_ = TerminalState::open;
}

void TerminalSession::resize(const TerminalSize size) {
    require_open();
    validate_size(size);
    backend_.resize(size);
    size_ = size;
}

std::size_t TerminalSession::write(const std::span<const std::byte> input) {
    require_open();
    if (input.empty() || input.size() > max_input) {
        throw std::invalid_argument("terminal input is empty or exceeds bound");
    }
    return backend_.write(input);
}

std::vector<std::byte> TerminalSession::read(const std::size_t maximum) {
    require_open();
    if (maximum == 0 || maximum > max_output_read) {
        throw std::invalid_argument("terminal output request exceeds bound");
    }
    auto output = backend_.read(maximum);
    if (output.size() > maximum) {
        throw std::runtime_error("terminal backend violated output bound");
    }
    return output;
}

void TerminalSession::close() {
    require_open();
    backend_.close();
    state_ = TerminalState::closed;
}

}  // namespace rwn::core
