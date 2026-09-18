#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {

std::chrono::milliseconds milliseconds(const char* value) {
    return std::chrono::milliseconds(std::stoll(value));
}

#if defined(_WIN32)
std::wstring current_executable() {
    std::wstring path(32768, L'\0');
    const auto size = GetModuleFileNameW(
        nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (size == 0 || size == path.size()) {
        throw std::runtime_error("fixture executable path unavailable");
    }
    path.resize(size);
    return path;
}

void spawn_delayed_marker(const std::filesystem::path& marker) {
    const auto executable = current_executable();
    auto command = L"\"" + executable + L"\" --delayed-marker \"" +
                   marker.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(STARTUPINFOW);
    PROCESS_INFORMATION process{};
    if (CreateProcessW(
            executable.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) == 0) {
        throw std::runtime_error("fixture child creation failed");
    }
    static_cast<void>(CloseHandle(process.hThread));
    static_cast<void>(CloseHandle(process.hProcess));
}
#endif

}  // namespace

int main(const int argc, char** argv) {
    if (argc < 2) {
        return 64;
    }
    const std::string_view mode = argv[1];
    if (mode == "--success") {
        std::cout << "fixture-out\n";
        std::cerr << "fixture-err\n";
        return 0;
    }
    if (mode == "--fail") {
        std::cout << "failed-out\n";
        std::cerr << "failed-err\n";
        return 7;
    }
    if (mode == "--sleep" && argc == 3) {
        std::this_thread::sleep_for(milliseconds(argv[2]));
        return 0;
    }
    if (mode == "--print-env" && argc == 3) {
        if (const auto* value = std::getenv(argv[2]); value != nullptr) {
            std::cout << value << '\n';
        } else {
            std::cout << "<missing>\n";
        }
        return 0;
    }
    if (mode == "--fail-once" && argc == 3) {
        const std::filesystem::path marker(argv[2]);
        if (std::filesystem::exists(marker)) {
            return 0;
        }
        std::ofstream(marker, std::ios::binary) << "failed";
        return 1;
    }
    if (mode == "--mutate-fail-once" && argc == 4) {
        const std::filesystem::path marker(argv[2]);
        if (std::filesystem::exists(marker)) {
            return 0;
        }
        std::ofstream(argv[3], std::ios::binary | std::ios::trunc)
            << "mutated during update";
        std::ofstream(marker, std::ios::binary) << "failed";
        return 1;
    }
    if (mode == "--spam-stdout" && argc == 3) {
        auto remaining = static_cast<std::size_t>(std::stoull(argv[2]));
        const std::string block(16U * 1024U, 'x');
        while (remaining != 0) {
            const auto count = std::min(remaining, block.size());
            std::cout.write(block.data(), static_cast<std::streamsize>(count));
            remaining -= count;
        }
        return 0;
    }
#if defined(_WIN32)
    if (mode == "--spawn-child" && argc == 3) {
        spawn_delayed_marker(std::filesystem::path(argv[2]));
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return 0;
    }
    if (mode == "--delayed-marker" && argc == 3) {
        std::this_thread::sleep_for(std::chrono::milliseconds(750));
        std::ofstream(argv[2], std::ios::binary) << "child survived";
        return 0;
    }
#endif
    return 64;
}
