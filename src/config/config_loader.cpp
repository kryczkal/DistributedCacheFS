#include "config_loader.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <system_error>
#include "config_types.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>

#define TRY_ASSIGN(target, json_obj, key, type)                            \
    try {                                                                  \
        if (json_obj.contains(key)) {                                      \
            target = json_obj.at(key).get<type>();                         \
        }                                                                  \
    } catch (const nlohmann::json::exception &e) {                         \
        spdlog::error("JSON parse error for key '{}': {}", key, e.what()); \
        return std::unexpected(LoadError::JsonParseError);                 \
    }

#define TRY_ASSIGN_REQUIRED(target, json_obj, key, type)                            \
    try {                                                                           \
        if (!json_obj.contains(key)) {                                              \
            spdlog::error("Missing required JSON key: '{}'", key);                  \
            return std::unexpected(LoadError::ValidationError);                     \
        }                                                                           \
        target = json_obj.at(key).get<type>();                                      \
    } catch (const nlohmann::json::exception &e) {                                  \
        spdlog::error("JSON parse error for required key '{}': {}", key, e.what()); \
        return std::unexpected(LoadError::JsonParseError);                          \
    }

namespace DistributedCacheFS::Config
{

// Parses a size string (e.g., "500MB", "2GB", "1024") into bytes.
// Returns std::nullopt if parsing fails.
std::optional<uint64_t> ParseSizeStringToBytes(const std::string &size_str)
{
    if (size_str.empty()) {
        return std::nullopt;
    }

    std::string num_part;
    std::string unit_part;

    size_t i = 0;
    while (i < size_str.length() && std::isdigit(size_str[i])) {
        num_part += size_str[i];
        i++;
    }

    // Allow optional space between number and unit
    while (i < size_str.length() && std::isspace(size_str[i])) {
        i++;
    }

    while (i < size_str.length() && std::isalpha(size_str[i])) {
        unit_part += size_str[i];
        i++;
    }

    // If there's anything left after number and unit (and optional space), it's an error
    if (i < size_str.length()) {
        spdlog::warn("Invalid characters found after unit in size string: '{}'", size_str);
        return std::nullopt;
    }

    if (num_part.empty()) {
        spdlog::warn("No numeric part in size string: '{}'", size_str);
        return std::nullopt;
    }

    uint64_t value;
    auto conv_res = std::from_chars(num_part.data(), num_part.data() + num_part.length(), value);
    if (conv_res.ec != std::errc() || conv_res.ptr != num_part.data() + num_part.length()) {
        spdlog::warn("Failed to parse numeric part '{}' of size string: '{}'", num_part, size_str);
        return std::nullopt;
    }

    if (unit_part.empty()) {  // Assume bytes if no unit
        return value;
    }

    std::ranges::transform(unit_part, unit_part.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    static std::unordered_map<std::string, uint64_t> unit_multipliers = {
        { "b",                                     1},
        {"kb",                               1024ULL},
        { "k",                               1024ULL},
        {"mb",                     1024ULL * 1024ULL},
        { "m",                     1024ULL * 1024ULL},
        {"gb",           1024ULL * 1024ULL * 1024ULL},
        { "g",           1024ULL * 1024ULL * 1024ULL},
        {"tb", 1024ULL * 1024ULL * 1024ULL * 1024ULL},
        { "t", 1024ULL * 1024ULL * 1024ULL * 1024ULL}
    };
    auto it = unit_multipliers.find(unit_part);
    if (it != unit_multipliers.end()) {
        value *= it->second;
    } else {
        spdlog::warn("Unknown size unit '{}' in string '{}'", unit_part, size_str);
        return std::nullopt;  // Unknown unit
    }
    return value;
}

LoadResult loadConfigFromFile(const std::filesystem::path &file_path)
{
    spdlog::info("Attempting to load configuration from: {}", file_path.string());

    std::ifstream config_stream(file_path);
    if (!config_stream.is_open()) {
        spdlog::error("Failed to open config file: {}", file_path.string());
        return std::unexpected(LoadError::FileNotFound);
    }

    nlohmann::json j;
    try {
        config_stream >> j;
    } catch (const nlohmann::json::parse_error &e) {
        spdlog::error("Failed to parse JSON config file: {}", e.what());
        return std::unexpected(LoadError::JsonParseError);
    }

    NodeConfig config;

    // Parse Top-Level Keys
    TRY_ASSIGN_REQUIRED(config.node_id, j, "node_id", std::string);

    if (!j.contains("origin") || !j.at("origin").is_object()) {
        spdlog::error("'origin' object is missing or not an object.");
        return std::unexpected(LoadError::ValidationError);
    }
    const auto &origin_json = j.at("origin");
    {
        std::string origin_type_str;
        std::string origin_path_str;
        TRY_ASSIGN_REQUIRED(origin_type_str, origin_json, "type", std::string);
        TRY_ASSIGN_REQUIRED(origin_path_str, origin_json, "path", std::string);

        auto origin_type_opt = StringToStorageType(origin_type_str);
        if (!origin_type_opt) {
            spdlog::error("Invalid 'type' value in origin definition: {}", origin_type_str);
            return std::unexpected(LoadError::ValidationError);
        }
        if (*origin_type_opt != StorageType::Local) {
            spdlog::error("Only 'local' origin type is currently supported in this configuration.");
            return std::unexpected(LoadError::ValidationError);
        }

        config.origin_definition.type = *origin_type_opt;
        config.origin_definition.path = origin_path_str;
    }

    if (!config.origin_definition.IsValid()) {
        spdlog::error("Parsed origin storage definition is invalid.");
        return std::unexpected(LoadError::ValidationError);
    }
    spdlog::info(
        "Parsed origin storage: type='{}', path='{}'",
        StorageTypeToString(config.origin_definition.type), config.origin_definition.path.string()
    );

    if (j.contains("global_settings")) {
        const auto &gs = j.at("global_settings");
        if (!gs.is_object()) {
            spdlog::error("'global_settings' must be an object.");
            return std::unexpected(LoadError::ValidationError);
        }
        std::string log_level_str =
            spdlog::level::to_string_view(Constants::DEFAULT_LOG_LEVEL).data();
        TRY_ASSIGN(log_level_str, gs, "log_level", std::string);  // Assign default first
        if (!log_level_str.empty()) {
            auto level_opt = StringToLogLevel(log_level_str);
            if (!level_opt) {
                spdlog::error(
                    "Invalid 'log_level' value: {}. Using default '{}'.", log_level_str,
                    spdlog::level::to_string_view(config.global_settings.log_level)
                );
                // Keep the default already set in config.global_settings
            } else {
                config.global_settings.log_level = *level_opt;
            }
        }
        TRY_ASSIGN(config.global_settings.mdns_service_name, gs, "mdns_service_name", std::string);
        TRY_ASSIGN(config.global_settings.listen_port, gs, "listen_port", std::uint16_t);
    }
    spdlog::info(
        "Global settings: log_level='{}', mdns='{}', port={}",
        spdlog::level::to_string_view(config.global_settings.log_level),
        config.global_settings.mdns_service_name, config.global_settings.listen_port
    );

    if (j.contains("cache_settings")) {
        const auto &cs = j.at("cache_settings");
        if (!cs.is_object()) {
            spdlog::error("'cache_settings' must be an object.");
            return std::unexpected(LoadError::ValidationError);
        }
        TRY_ASSIGN(config.cache_settings.decay_constant, cs, "decay_constant", double);
        if (config.cache_settings.decay_constant <= 0.0) {
            spdlog::error(
                "Invalid 'decay_constant' value in default cache_settings: {} (must be positive)",
                config.cache_settings.decay_constant
            );
            return std::unexpected(LoadError::ValidationError);
        }
    }
    if (!config.cache_settings.isValid()) {
        spdlog::error("Default cache settings are invalid.");
        return std::unexpected(LoadError::ValidationError);
    }
    spdlog::info("Default cache settings: decay_constant={}", config.cache_settings.decay_constant);

    if (!j.contains("cache_definitions") || !j.at("cache_definitions").is_array() ||
        j.at("cache_definitions").empty()) {
        spdlog::error("'cache_definitions' array is missing, not an array, or empty.");
        return std::unexpected(LoadError::ValidationError);
    }

    try {
        for (const auto &item : j.at("cache_definitions")) {
            if (!item.is_object()) {
                spdlog::error("Item in 'cache_definitions' array is not an object.");
                return std::unexpected(LoadError::ValidationError);
            }

            CacheDefinition cache_def;

            StorageDefinition tier_storage_def;
            std::string path_str;
            TRY_ASSIGN_REQUIRED(path_str, item, "path", std::string);
            tier_storage_def.path = path_str;

            TRY_ASSIGN_REQUIRED(cache_def.tier, item, "tier", int);

            std::string type_str;
            TRY_ASSIGN_REQUIRED(type_str, item, "type", std::string);
            auto type_opt = StringToStorageType(type_str);
            if (!type_opt) {
                spdlog::error(
                    "Invalid 'type' value in cache tier definition (tier {}): {}", cache_def.tier,
                    type_str
                );
                return std::unexpected(LoadError::ValidationError);
            }
            tier_storage_def.type = *type_opt;

            // Parse Shared Storage specific settings if applicable
            if (tier_storage_def.type == StorageType::Shared) {
                std::string policy_str;
                TRY_ASSIGN_REQUIRED(policy_str, item, "policy", std::string);
                auto policy_opt = StringToSharedStoragePolicy(policy_str);
                if (!policy_opt) {
                    spdlog::error(
                        "Invalid 'policy' value for shared cache tier (tier {}): {}",
                        cache_def.tier, policy_str
                    );
                    return std::unexpected(LoadError::ValidationError);
                }
                tier_storage_def.policy = *policy_opt;

                std::string group_str;
                TRY_ASSIGN_REQUIRED(group_str, item, "share_group", std::string);
                if (group_str.empty()) {
                    spdlog::error(
                        "Empty 'share_group' for shared cache tier (tier {})", cache_def.tier
                    );
                    return std::unexpected(LoadError::ValidationError);
                }
                tier_storage_def.share_group = group_str;
            }

            // Parse optional size limits
            if (item.contains("min_size_bytes")) {
                if (item.at("min_size_bytes").is_string()) {
                    std::string min_size_str;
                    TRY_ASSIGN(min_size_str, item, "min_size_bytes", std::string);
                    auto parsed_bytes = ParseSizeStringToBytes(min_size_str);
                    if (parsed_bytes.has_value()) {
                        tier_storage_def.min_size_bytes = parsed_bytes.value();
                    } else {
                        spdlog::warn(
                            "Ignoring invalid 'min_size_bytes' string ('{}') for tier {}",
                            min_size_str, cache_def.tier
                        );
                    }
                } else if (item.at("min_size_bytes").is_number()) {
                    uint64_t min_b = 0;
                    TRY_ASSIGN(min_b, item, "min_size_bytes", uint64_t);
                    tier_storage_def.min_size_bytes = min_b;
                } else {
                    spdlog::warn(
                        "'min_size_bytes' for tier {} must be a string or a number.", cache_def.tier
                    );
                }
            }
            if (item.contains("max_size_bytes")) {
                if (item.at("max_size_bytes").is_string()) {
                    std::string max_size_str;
                    TRY_ASSIGN(max_size_str, item, "max_size_bytes", std::string);
                    auto parsed_bytes = ParseSizeStringToBytes(max_size_str);
                    if (parsed_bytes.has_value()) {
                        tier_storage_def.max_size_bytes = parsed_bytes.value();
                    } else {
                        spdlog::warn(
                            "Ignoring invalid 'max_size_bytes' string ('{}') for tier {}",
                            max_size_str, cache_def.tier
                        );
                    }
                } else if (item.at("max_size_bytes").is_number()) {
                    uint64_t max_b = 0;
                    TRY_ASSIGN(max_b, item, "max_size_bytes", uint64_t);
                    tier_storage_def.max_size_bytes = max_b;
                } else {
                    spdlog::warn(
                        "'max_size_bytes' for tier {} must be a string or a number.", cache_def.tier
                    );
                }
            }

            if (!tier_storage_def.IsValid()) {
                spdlog::error(
                    "Parsed cache tier storage definition is invalid for path: {}, tier: {}",
                    tier_storage_def.path.string(), cache_def.tier
                );
                return std::unexpected(LoadError::ValidationError);
            }
            cache_def.storage_definition = std::move(tier_storage_def);

            cache_def.cache_settings = config.cache_settings;
            if (item.contains("cache_settings")) {
                const auto &tier_cs = item.at("cache_settings");
                if (!tier_cs.is_object()) {
                    spdlog::error(
                        "'cache_settings' within tier {} must be an object.", cache_def.tier
                    );
                    return std::unexpected(LoadError::ValidationError);
                }

                TRY_ASSIGN(
                    cache_def.cache_settings.decay_constant, tier_cs, "decay_constant", double
                );
            }

            if (!cache_def.IsValid()) {
                spdlog::error(
                    "Parsed cache tier definition is invalid for path: {}, tier: {}",
                    cache_def.storage_definition.path.string(), cache_def.tier
                );
                return std::unexpected(LoadError::ValidationError);
            }

            spdlog::info(
                "Parsed cache definition: tier={}, type='{}', path='{}', decay={}", cache_def.tier,
                StorageTypeToString(cache_def.storage_definition.type),
                cache_def.storage_definition.path.string(), cache_def.cache_settings.decay_constant
            );

            config.cache_definitions.push_back(std::move(cache_def));
        }
    } catch (const nlohmann::json::exception &e) {
        spdlog::error("JSON parse error within 'cache_definitions' array: {}", e.what());
        return std::unexpected(LoadError::JsonParseError);
    }

    if (!config.IsValid()) {
        spdlog::error("Overall node configuration is invalid after parsing.");
        return std::unexpected(LoadError::ValidationError);
    }

    spdlog::info("Configuration loaded successfully for node_id: {}", config.node_id);
    spdlog::info("Configured {} cache tiers.", config.cache_definitions.size());
    return config;
}
LoadErrorMsg loadConfigFromFileVerbose(const std::filesystem::path &file_path)
{
    auto result = loadConfigFromFile(file_path);
    if (result.has_value()) {
        return result.value();
    } else {
        std::string error_message = "Failed to load config (" + file_path.string() + "): ";
        switch (result.error()) {
            case LoadError::FileNotFound:
                error_message += "File not found.";
                break;
            case LoadError::JsonParseError:
                error_message += "JSON parsing failed.";
                break;
            case LoadError::ValidationError:
                error_message += "Configuration validation failed.";
                break;
            default:
                error_message += "Unknown error.";
                break;
        }
        return std::unexpected(error_message);
    }
}

}  // namespace DistributedCacheFS::Config
