#pragma once
#include "rwn/core/enrollment_journal.hpp"
#include <filesystem>
namespace rwn::platform::macos {
// Uses the SAME product owner.lock as configuration/program updates.
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal();
// Isolated local fixture only; existing owned private directory, never RPC.
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal_fixture(const std::filesystem::path&);
}
