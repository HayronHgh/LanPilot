#include "rwn/platform/macos/app_packager.hpp"

#include <chrono>
#include <stdexcept>

namespace rwn::platform::macos {

rwn::core::BuildEvidence AppPackager::package(
    const std::filesystem::path& app_relative_path,
    const std::filesystem::path& archive_relative_path) {
    const auto app = scope_.resolve(app_relative_path);
    const auto archive = scope_.resolve(archive_relative_path);
    if (app.extension() != ".app" || !std::filesystem::is_directory(app) ||
        archive.extension() != ".zip") {
        throw std::invalid_argument("macOS bundle packaging paths are invalid");
    }
    std::filesystem::create_directories(archive.parent_path());
    auto evidence = executor_.execute(
        {.argv = {"/usr/bin/ditto", "-c", "-k", "--sequesterRsrc",
                  "--keepParent", app.string(), archive.string()},
         .working_directory = ".",
         .timeout = std::chrono::minutes(10),
         .environment = {}});
    if (evidence.exit_code == 0 &&
        (!std::filesystem::is_regular_file(archive) ||
         std::filesystem::file_size(archive) == 0)) {
        throw std::runtime_error("ditto reported success without an archive");
    }
    return evidence;
}

}  // namespace rwn::platform::macos
