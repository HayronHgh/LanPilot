#pragma once

#include "rwn/core/file_transfer.hpp"

#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace rwn::test {

class TestDurableFileSystem final : public rwn::core::DurableFileSystem {
public:
    void flush_file(const std::filesystem::path& path) override {
        if (!std::filesystem::is_regular_file(path)) {
            throw std::runtime_error("test durable flush requires a file");
        }
    }

    void atomic_replace(
        const std::filesystem::path& staging,
        const std::filesystem::path& destination) override {
        std::error_code ignored;
        std::filesystem::remove(destination, ignored);
        std::filesystem::rename(staging, destination);
    }
};

inline void require(const bool condition, const std::string_view expression) {
    if (!condition) {
        throw std::runtime_error("check failed: " + std::string(expression));
    }
}

template <typename Exception, typename Function>
void require_throws(Function&& function, const std::string_view expression) {
    try {
        function();
    } catch (const Exception&) {
        return;
    }
    throw std::runtime_error("expected exception: " + std::string(expression));
}

class Runner {
public:
    template <typename Function>
    void run(const std::string_view name, Function&& function) {
        try {
            function();
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception& error) {
            ++failures_;
            std::cerr << "[FAIL] " << name << ": " << error.what() << '\n';
        }
    }

    [[nodiscard]] int exit_code() const { return failures_ == 0 ? 0 : 1; }

private:
    int failures_{};
};

}  // namespace rwn::test

#define RWN_CHECK(expression) ::rwn::test::require((expression), #expression)
