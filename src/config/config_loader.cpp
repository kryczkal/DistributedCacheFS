#include "config_loader.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <system_error>
#include "config_types.hpp"

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
        if (config.cache_settings.decay_constant <= 0.0) {  // Allow 0 decay? Reverted to > 0 check.
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

                // Parse optional size limits for 'divide' policy
                if (tier_storage_def.policy == SharedStorage::Divide) {
                    if (item.contains("min_size_gb")) {
                        double min_gb = -1.0;
                        TRY_ASSIGN(min_gb, item, "min_size_gb", double);
                        if (min_gb >= 0.0)
                            tier_storage_def.min_size_gb = min_gb;
                        else
                            spdlog::warn(
                                "Ignoring invalid 'min_size_gb' ({}) for tier {}", min_gb,
                                cache_def.tier
                            );
                    }
                    if (item.contains("max_size_gb")) {
                        double max_gb = -1.0;
                        TRY_ASSIGN(max_gb, item, "max_size_gb", double);
                        if (max_gb >= 0.0)
                            tier_storage_def.max_size_gb = max_gb;
                        else
                            spdlog::warn(
                                "Ignoring invalid 'max_size_gb' ({}) for tier {}", max_gb,
                                cache_def.tier
                            );
                    }
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
    if (result) {
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
