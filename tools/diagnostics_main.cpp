#include "rwn/core/release_compatibility.hpp"
#include "rwn/core/release_diagnostics.hpp"
#include "rwn/core/release_update.hpp"

#if defined(RWN_DIAGNOSTICS_WINDOWS)
#include "rwn/platform/windows/command_executor.hpp"
#include "rwn/platform/windows/durable_filesystem.hpp"
#elif defined(RWN_DIAGNOSTICS_MACOS)
#include "rwn/platform/macos/command_executor.hpp"
#include "rwn/platform/macos/durable_filesystem.hpp"
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

#if defined(RWN_DIAGNOSTICS_WINDOWS)
using NativeCommandExecutor =
    rwn::platform::windows::WindowsCommandExecutor;
using NativeDurableFileSystem =
    rwn::platform::windows::WindowsDurableFileSystem;
constexpr std::string_view native_platform = "windows";
constexpr std::string_view executable_suffix = ".exe";
#else
using NativeCommandExecutor = rwn::platform::macos::CommandExecutor;
using NativeDurableFileSystem = rwn::platform::macos::MacDurableFileSystem;
constexpr std::string_view native_platform = "macos";
constexpr std::string_view executable_suffix = "";
#endif

struct Role {
    rwn::core::DiagnosticComponent component;
    std::string_view executable;
};

constexpr std::array<Role, 5> roles{{
    {rwn::core::DiagnosticComponent::client, "rwn-client"},
    {rwn::core::DiagnosticComponent::node, "rwn-node"},
    {rwn::core::DiagnosticComponent::broker, "rwn-broker"},
    {rwn::core::DiagnosticComponent::build_worker, "rwn-build-worker"},
    {rwn::core::DiagnosticComponent::desktop_agent, "rwn-desktop-agent"},
}};

[[nodiscard]] rwn::core::BuildEvidence unavailable_evidence() {
    return {
        .exit_code = 2,
        .stdout_log = {},
        .stderr_log = {},
        .elapsed = std::chrono::milliseconds::zero(),
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
    };
}

}  // namespace

int main(const int argc, char** argv) {
    if (argc != 7) {
        std::cerr << "usage: rwn-diagnostics <new-output.json> <install-root> "
                     "<protected-state-root> <version-policy> <platform> "
                     "<architecture>\n";
        return 64;
    }
    try {
        const std::filesystem::path output(argv[1]);
        const std::filesystem::path install_root(argv[2]);
        const std::filesystem::path state_root(argv[3]);
        const std::filesystem::path compatibility_path(argv[4]);
        const std::string platform(argv[5]);
        const std::string architecture(argv[6]);
        if (platform != native_platform || !install_root.is_absolute() ||
            !std::filesystem::is_directory(install_root) ||
            !state_root.is_absolute() || !compatibility_path.is_absolute()) {
            throw std::invalid_argument(
                "diagnostic platform or absolute roots are invalid");
        }

        rwn::core::DiagnosticCompatibilitySummary compatibility;
        bool compatibility_ok{};
        try {
            compatibility = rwn::core::summarize_compatibility(
                rwn::core::load_release_compatibility(compatibility_path));
            compatibility_ok = true;
        } catch (const std::exception&) {
            compatibility = {};
        }

        rwn::core::DiagnosticStateSummary state;
        bool state_ok{};
        try {
            state = rwn::core::summarize_protected_state(
                rwn::core::capture_protected_state(state_root));
            state_ok = true;
        } catch (const std::exception&) {
            state = {};
        }

        std::vector<rwn::core::DiagnosticCheck> checks;
        checks.reserve(roles.size() + 2U);
        NativeCommandExecutor executor(install_root);
        for (const auto& role : roles) {
            const auto executable = install_root / "bin" /
                (std::string(role.executable) +
                 std::string(executable_suffix));
            auto evidence = unavailable_evidence();
            if (std::filesystem::is_regular_file(executable)) {
                try {
                    evidence = executor.execute({
                        .argv = {executable.string()},
                        .working_directory = ".",
                        .timeout = std::chrono::seconds(10),
                        .environment = {},
                    });
                } catch (const std::exception&) {
                    evidence = unavailable_evidence();
                }
            }
            checks.push_back(rwn::core::make_runtime_diagnostic(
                role.component, rwn::core::DiagnosticOperation::self_check,
                evidence));
        }
        checks.push_back(rwn::core::make_boolean_diagnostic(
            rwn::core::DiagnosticComponent::compatibility,
            rwn::core::DiagnosticOperation::compatibility_load,
            compatibility_ok));
        checks.push_back(rwn::core::make_boolean_diagnostic(
            rwn::core::DiagnosticComponent::protected_state,
            rwn::core::DiagnosticOperation::state_inventory, state_ok));

        const auto generated_at = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        rwn::core::ReleaseDiagnosticBundle bundle{
            .schema_version = 1,
            .bundle_id = "diagnostic-" + std::to_string(generated_at),
            .product_version =
                rwn::core::parse_semantic_version(RWN_PROJECT_VERSION),
            .platform = platform,
            .architecture = architecture,
            .generated_at_unix_ms = generated_at,
            .compatibility = compatibility,
            .protected_state = state,
            .update = std::nullopt,
            .checks = std::move(checks),
        };
        NativeDurableFileSystem filesystem;
        rwn::core::write_release_diagnostic_bundle(
            output, bundle, filesystem);
        const auto passed = std::ranges::all_of(
            bundle.checks, [](const auto& check) {
                return check.result == rwn::core::DiagnosticResult::passed;
            });
        std::cout << "diagnostic_bundle_written=1 checks="
                  << bundle.checks.size() << " passed=" << passed << '\n';
        return passed ? 0 : 2;
    } catch (const std::exception& error) {
        std::cerr << "rwn-diagnostics: " << error.what() << '\n';
        return 1;
    }
}
