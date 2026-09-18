#include "rwn/core/release_security.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

int main(const int argc, const char* const argv[]) {
    if (argc != 2) {
        std::cerr << "usage: rwn-release-security-gate <archive-manifest.tsv>\n";
        return 2;
    }
    try {
        const auto path = std::filesystem::path(argv[1]);
        constexpr std::uintmax_t maximum_bytes = 16U * 1024U * 1024U;
        if (!path.is_absolute() || !std::filesystem::is_regular_file(path) ||
            std::filesystem::file_size(path) > maximum_bytes ||
            std::filesystem::file_size(path) >
                static_cast<std::uintmax_t>(
                    std::numeric_limits<std::streamsize>::max())) {
            throw std::invalid_argument("archive manifest file is invalid");
        }
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("archive manifest could not be opened");
        const auto size = static_cast<std::size_t>(
            std::filesystem::file_size(path));
        std::string content(size, '\0');
        input.read(content.data(), static_cast<std::streamsize>(content.size()));
        if (!input || input.peek() != std::ifstream::traits_type::eof()) {
            throw std::runtime_error("archive manifest read failed");
        }
        const auto report = rwn::core::validate_archive_manifest(
            rwn::core::parse_archive_manifest(content));
        std::cout << rwn::core::render_release_security_json(report);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "release security gate failed: " << error.what() << '\n';
        return 1;
    }
}
