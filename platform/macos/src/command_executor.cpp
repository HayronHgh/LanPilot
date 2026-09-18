#include "rwn/platform/macos/command_executor.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace rwn::platform::macos {
namespace {

constexpr std::size_t max_captured_stream = 16U * 1024U * 1024U;

void close_fd(int& fd) noexcept {
    if (fd != -1) {
        static_cast<void>(::close(fd));
        fd = -1;
    }
}

void make_pipe(int (&pipe)[2]) {
    if (::pipe(pipe) != 0) {
        throw std::runtime_error("command output pipe creation failed");
    }
    static_cast<void>(fcntl(pipe[0], F_SETFD, FD_CLOEXEC));
    static_cast<void>(fcntl(pipe[1], F_SETFD, FD_CLOEXEC));
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

void drain(int fd, std::string& output, bool& truncated) {
    std::array<char, 16U * 1024U> buffer{};
    while (true) {
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            const auto available = max_captured_stream - output.size();
            const auto accepted = std::min<std::size_t>(
                available, static_cast<std::size_t>(count));
            output.append(buffer.data(), accepted);
            truncated = truncated || accepted < static_cast<std::size_t>(count);
            continue;
        }
        if (count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return;
        }
        return;
    }
}

}  // namespace

rwn::core::BuildEvidence CommandExecutor::execute(
    const rwn::core::CommandSpec& command,
    const rwn::core::CancellationToken stop_token) {
    rwn::core::validate_command(command, [&] {
        std::set<std::string, std::less<>> names;
        for (const auto& [name, _] : command.environment) names.insert(name);
        return names;
    }());
    const auto executable = std::filesystem::path(command.argv.front());
    if (!executable.is_absolute() || ::access(executable.c_str(), X_OK) != 0) {
        throw std::invalid_argument(
            "command executable must be an existing absolute executable");
    }
    const auto working_directory = scope_.resolve(command.working_directory);
    if (!std::filesystem::is_directory(working_directory)) {
        throw std::invalid_argument("command working directory does not exist");
    }

    int stdout_pipe[2]{-1, -1};
    int stderr_pipe[2]{-1, -1};
    make_pipe(stdout_pipe);
    try {
        make_pipe(stderr_pipe);
    } catch (...) {
        close_fd(stdout_pipe[0]);
        close_fd(stdout_pipe[1]);
        throw;
    }
    const auto start = std::chrono::steady_clock::now();
    const auto child = ::fork();
    if (child < 0) {
        close_fd(stdout_pipe[0]);
        close_fd(stdout_pipe[1]);
        close_fd(stderr_pipe[0]);
        close_fd(stderr_pipe[1]);
        throw std::runtime_error("command fork failed");
    }
    if (child == 0) {
        static_cast<void>(::setpgid(0, 0));
        static_cast<void>(::dup2(stdout_pipe[1], STDOUT_FILENO));
        static_cast<void>(::dup2(stderr_pipe[1], STDERR_FILENO));
        const auto null_input = ::open("/dev/null", O_RDONLY);
        if (null_input >= 0) static_cast<void>(::dup2(null_input, STDIN_FILENO));
        close_fd(stdout_pipe[0]);
        close_fd(stdout_pipe[1]);
        close_fd(stderr_pipe[0]);
        close_fd(stderr_pipe[1]);
        if (::chdir(working_directory.c_str()) != 0) _exit(126);
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

    close_fd(stdout_pipe[1]);
    close_fd(stderr_pipe[1]);
    static_cast<void>(::setpgid(child, child));
    static_cast<void>(fcntl(
        stdout_pipe[0], F_SETFL, fcntl(stdout_pipe[0], F_GETFL, 0) | O_NONBLOCK));
    static_cast<void>(fcntl(
        stderr_pipe[0], F_SETFL, fcntl(stderr_pipe[0], F_GETFL, 0) | O_NONBLOCK));
    rwn::core::BuildEvidence evidence;
    int status{};
    while (true) {
        drain(stdout_pipe[0], evidence.stdout_log, evidence.stdout_truncated);
        drain(stderr_pipe[0], evidence.stderr_log, evidence.stderr_truncated);
        const auto waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0) {
            static_cast<void>(::kill(-child, SIGKILL));
            static_cast<void>(waitpid(child, &status, 0));
            close_fd(stdout_pipe[0]);
            close_fd(stderr_pipe[0]);
            throw std::runtime_error("command waitpid failed");
        }
        if (stop_token.stop_requested()) {
            evidence.cancelled = true;
            static_cast<void>(::kill(-child, SIGKILL));
            static_cast<void>(waitpid(child, &status, 0));
            break;
        }
        if (std::chrono::steady_clock::now() - start >= command.timeout) {
            evidence.timed_out = true;
            static_cast<void>(::kill(-child, SIGKILL));
            static_cast<void>(waitpid(child, &status, 0));
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    drain(stdout_pipe[0], evidence.stdout_log, evidence.stdout_truncated);
    drain(stderr_pipe[0], evidence.stderr_log, evidence.stderr_truncated);
    close_fd(stdout_pipe[0]);
    close_fd(stderr_pipe[0]);
    evidence.exit_code = WIFEXITED(status)
        ? WEXITSTATUS(status)
        : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1);
    evidence.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return evidence;
}

}  // namespace rwn::platform::macos
