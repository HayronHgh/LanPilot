#pragma once
#include "rwn/core/enrollment_journal.hpp"
#include <filesystem>
namespace rwn::platform::windows {
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal();
// Local isolated fixture directory. Creates only this one directory with a
// protected CurrentUser/SYSTEM DACL. No remote path/store selector is exposed.
std::unique_ptr<core::enrollment::FileEnrollmentJournal> enrollment_journal_fixture(const std::filesystem::path&);
}
