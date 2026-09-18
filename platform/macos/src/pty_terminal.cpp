#include "rwn/platform/macos/pty_terminal.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <util.h>
#include <utility>

namespace rwn::platform::macos {
namespace {

winsize native_size(const rwn::core::TerminalSize size) {
    return {
        .ws_row = static_cast<unsigned short>(size.rows),
        .ws_col = static_cast<unsigned short>(size.columns),
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };
}

std::vector<char*> pointers(std::vector<std::string>& values) {
    std::vector<char*> result;
    result.reserve(values.size() + 1);
    for (auto& value : values) {
        result.push_back(value.data());
    }
    result.push_back(nullptr);
    return result;
}

}  // namespace

PtyTerminal::~PtyTerminal() {
    close();
}

void PtyTerminal::open(
    const rwn::core::CommandSpec& command,
    const std::filesystem::path& resolved_working_directory,
    const rwn::core::TerminalSize size) {
    if (master_fd_ != -1 || child_ != -1 ||
        command.argv.empty() || command.argv.front().empty()) {
        throw std::logic_error("PTY terminal cannot be opened");
    }
    auto window = native_size(size);
    const auto pid = forkpty(&master_fd_, nullptr, nullptr, &window);
    if (pid < 0) {
        master_fd_ = -1;
        throw std::runtime_error("forkpty failed");
    }
    if (pid == 0) {
        if (::chdir(resolved_working_directory.c_str()) != 0) {
            _exit(126);
        }
        auto arguments = command.argv;
        auto argument_pointers = pointers(arguments);
        std::vector<std::string> environment;
        environment.reserve(command.environment.size());
        for (const auto& [name, value] : command.environment) {
            environment.push_back(name + "=" + value);
        }
        auto environment_pointers = pointers(environment);
        ::execve(
            arguments.front().c_str(), argument_pointers.data(),
            environment_pointers.data());
        _exit(127);
    }
    child_ = pid;
    const auto flags = fcntl(master_fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(master_fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
        close();
        throw std::runtime_error("PTY nonblocking mode failed");
    }
}

void PtyTerminal::resize(const rwn::core::TerminalSize size) {
    if (master_fd_ == -1) {
        throw std::logic_error("PTY is not open");
    }
    auto window = native_size(size);
    if (ioctl(master_fd_, TIOCSWINSZ, &window) != 0) {
        throw std::runtime_error("PTY resize failed");
    }
}

std::size_t PtyTerminal::write(const std::span<const std::byte> input) {
    if (master_fd_ == -1) {
        throw std::logic_error("PTY is not open");
    }
    const auto count = ::write(master_fd_, input.data(), input.size());
    if (count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        throw std::runtime_error("PTY write failed");
    }
    return static_cast<std::size_t>(count);
}

std::vector<std::byte> PtyTerminal::read(const std::size_t maximum) {
    if (master_fd_ == -1) {
        throw std::logic_error("PTY is not open");
    }
    std::vector<std::byte> output(maximum);
    const auto count = ::read(master_fd_, output.data(), output.size());
    if (count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return {};
        }
        throw std::runtime_error("PTY read failed");
    }
    output.resize(static_cast<std::size_t>(count));
    return output;
}

void PtyTerminal::close() noexcept {
    if (master_fd_ != -1) {
        static_cast<void>(::close(master_fd_));
        master_fd_ = -1;
    }
    if (child_ == -1) {
        return;
    }
    int status{};
    for (int attempt = 0; attempt < 20; ++attempt) {
        if (waitpid(child_, &status, WNOHANG) == child_) {
            child_ = -1;
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    static_cast<void>(::kill(child_, SIGTERM));
    for (int attempt = 0; attempt < 20; ++attempt) {
        if (waitpid(child_, &status, WNOHANG) == child_) {
            child_ = -1;
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    static_cast<void>(::kill(child_, SIGKILL));
    static_cast<void>(waitpid(child_, &status, 0));
    child_ = -1;
}

}  // namespace rwn::platform::macos
