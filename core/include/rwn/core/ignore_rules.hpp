#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

class IgnoreRules {
public:
    static IgnoreRules parse(std::string_view contents);
    static IgnoreRules load_optional(const std::filesystem::path& path);
    void merge(IgnoreRules additional);

    [[nodiscard]] bool ignores(std::string_view canonical_path, bool directory) const;

private:
    struct Rule {
        std::string pattern;
        bool directory_only{};
        bool anchored{};
    };
    std::vector<Rule> rules_;
};

}  // namespace rwn::core
