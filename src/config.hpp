#pragma once

#include <filesystem>

inline const std::filesystem::path SIGNATURES_PATH = std::filesystem::path(DOZOR_RULES_DIR) / "signatures.yaml";
inline const std::filesystem::path BEHAVIOR_PATH = std::filesystem::path(DOZOR_RULES_DIR) / "behavior.yaml";
inline const std::filesystem::path BLOCKLIST_PATH = std::filesystem::path(DOZOR_RULES_DIR).parent_path() / "state" / "blocked_ips.csv";
