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

    // Parse Origin (Required)
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

        auto origin_type_opt = StringToOriginType(origin_type_str);
        if (!origin_type_opt) {
            spdlog::error("Invalid 'type' value in origin definition: {}", origin_type_str);
            return std::unexpected(LoadError::ValidationError);
        }
        config.origin.type = *origin_type_opt;
        config.origin.path = origin_path_str;

        // TODO: Parse other origin type specific parameters here
        if (config.origin.type != OriginType::Local) {
            spdlog::error("Only 'local' origin type is currently supported.");
            return std::unexpected(LoadError::ValidationError);
        }
    }

    if (!config.origin.isValid()) {
        spdlog::error("Parsed origin definition is invalid.");
        return std::unexpected(LoadError::ValidationError);
    }

    // Parse Global Settings (Optional block)
    if (j.contains("global_settings")) {
        const auto &gs = j.at("global_settings");
        if (!gs.is_object()) {
            spdlog::error("'global_settings' must be an object.");
            return std::unexpected(LoadError::ValidationError);
        }
        std::string log_level_str;
        TRY_ASSIGN(log_level_str, gs, "log_level", std::string);
        if (!log_level_str.empty()) {
            auto level_opt = StringToLogLevel(log_level_str);
            if (!level_opt) {
                spdlog::error("Invalid 'log_level' value: {}", log_level_str);
                return std::unexpected(LoadError::ValidationError);
            }
            config.global_settings.log_level = *level_opt;
        }
        TRY_ASSIGN(config.global_settings.mdns_service_name, gs, "mdns_service_name", std::string);
        TRY_ASSIGN(config.global_settings.listen_port, gs, "listen_port", std::uint16_t);
        // TODO: Parse cache-specific global settings
    }

    // Parse Cache Settings (Optional block, under top level)
    if (j.contains("cache_settings")) {
        const auto &cs = j.at("cache_settings");
        if (!cs.is_object()) {
            spdlog::error("'cache_settings' must be an object.");
            return std::unexpected(LoadError::ValidationError);
        }

        TRY_ASSIGN(config.cache_settings.decay_constant, cs, "decay_constant", double);
        if (config.cache_settings.decay_constant < 0.0) {
            spdlog::error(
                "Invalid 'decay_constant' value: {} (must be non-negative)",
                config.cache_settings.decay_constant
            );
            return std::unexpected(LoadError::ValidationError);
        }
    }

    // Parse Cache Tiers (Required Array)
    if (!j.contains("cache_tiers") || !j.at("cache_tiers").is_array() ||
        j.at("cache_tiers").empty()) {
        spdlog::error("'cache_tiers' array is missing, not an array, or empty.");
        return std::unexpected(LoadError::ValidationError);
    }

    try {
        for (const auto &item : j.at("cache_tiers")) {
            if (!item.is_object()) {
                spdlog::error("Item in 'cache_tiers' array is not an object.");
                return std::unexpected(LoadError::ValidationError);
            }

            CacheTierDefinition tier_def;
            std::string path_str;
            TRY_ASSIGN_REQUIRED(path_str, item, "path", std::string);
            tier_def.path = path_str;

            TRY_ASSIGN_REQUIRED(tier_def.tier, item, "tier", int);

            std::string type_str;
            TRY_ASSIGN_REQUIRED(type_str, item, "type", std::string);
            auto type_opt = StringToCacheTierStorageType(type_str);
            if (!type_opt) {
                spdlog::error("Invalid 'type' value in cache tier definition: {}", type_str);
                return std::unexpected(LoadError::ValidationError);
            }
            tier_def.type = *type_opt;

            if (tier_def.type == CacheTierStorageType::Shared) {
                std::string policy_str;
                TRY_ASSIGN_REQUIRED(policy_str, item, "policy", std::string);
                auto policy_opt = StringToSharedCachePolicy(policy_str);
                if (!policy_opt) {
                    spdlog::error("Invalid 'policy' value for shared cache tier: {}", policy_str);
                    return std::unexpected(LoadError::ValidationError);
                }
                tier_def.policy = *policy_opt;

                std::string group_str;
                TRY_ASSIGN_REQUIRED(group_str, item, "share_group", std::string);
                tier_def.share_group = group_str;

                if (tier_def.policy == SharedCachePolicy::Divide) {
                    if (item.contains("min_size_gb")) {
                        TRY_ASSIGN(tier_def.min_size_gb, item, "min_size_gb", double);
                    }
                    if (item.contains("max_size_gb")) {
                        TRY_ASSIGN(tier_def.max_size_gb, item, "max_size_gb", double);
                    }
                }
            }

            if (!tier_def.isValid()) {
                spdlog::error(
                    "Parsed cache tier definition is invalid for path: {}", tier_def.path.string()
                );
                return std::unexpected(LoadError::ValidationError);
            }

            config.cache_tiers.push_back(std::move(tier_def));
        }
    } catch (const nlohmann::json::exception &e) {
        spdlog::error("JSON parse error within 'cache_tiers' array: {}", e.what());
        return std::unexpected(LoadError::JsonParseError);
    }

    if (!config.isValid()) {
        spdlog::error("Overall node configuration is invalid after parsing.");
        return std::unexpected(LoadError::ValidationError);
    }

    spdlog::info("Configuration loaded successfully for node_id: {}", config.node_id);
    spdlog::info(
        "Using origin: type='{}', path='{}'", OriginTypeToString(config.origin.type),
        config.origin.path.string()
    );
    spdlog::info("Configured {} cache tiers.", config.cache_tiers.size());
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
