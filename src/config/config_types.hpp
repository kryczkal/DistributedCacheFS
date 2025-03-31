#ifndef DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_TYPES_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_TYPES_HPP_

#include "app_constants.hpp"

#include <spdlog/spdlog.h>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace DistributedCacheFS::Config
{

//------------------------------------------------------------------------------//
// Enumerations for Configuration Types
//------------------------------------------------------------------------------//

enum class StorageType : std::uint8_t { Local, Shared };

std::optional<StorageType> StringToStorageType(const std::string &type_str);
const char *StorageTypeToString(StorageType type);

enum class SharedPolicy : std::uint8_t { Sync, Divide };

std::optional<SharedPolicy> StringToSharedPolicy(const std::string &policy_str);
const char *SharedPolicyToString(SharedPolicy policy);

// Function to convert string to spdlog::level::level_enum
std::optional<spdlog::level::level_enum> StringToLogLevel(const std::string &level_str);

//------------------------------------------------------------------------------//
// Structs for Configuration Types
//------------------------------------------------------------------------------//

struct GlobalSettings {
    spdlog::level::level_enum log_level = Constants::DEFAULT_LOG_LEVEL;
    std::string mdns_service_name       = std::string(Constants::DEFAULT_MDNS_SERVICE_NAME);
    std::uint16_t listen_port           = Constants::DEFAULT_LISTEN_PORT;
};

struct StorageDefinition {
    std::filesystem::path path;
    int tier         = -1;
    StorageType type = StorageType::Local;

    std::optional<SharedPolicy> policy;
    std::optional<std::string> share_group;

    std::optional<double> min_size_gb;
    std::optional<double> max_size_gb;

    bool isValid() const;
};

struct NodeConfig {
    std::string node_id;
    GlobalSettings global_settings;
    std::vector<StorageDefinition> storages;

    bool isValid() const;
};

//------------------------------------------------------------------------------//
// Implementation of Enum / Logging Conversion Functions
//------------------------------------------------------------------------------//

inline std::optional<spdlog::level::level_enum> StringToLogLevel(const std::string &level_str)
{
    if (level_str == "trace")
        return spdlog::level::trace;
    if (level_str == "debug")
        return spdlog::level::debug;
    if (level_str == "info")
        return spdlog::level::info;
    if (level_str == "warn")
        return spdlog::level::warn;
    if (level_str == "error")
        return spdlog::level::err;
    if (level_str == "fatal" || level_str == "critical")
        return spdlog::level::critical;
    if (level_str == "off")
        return spdlog::level::off;
    return std::nullopt;
}

inline std::optional<StorageType> StringToStorageType(const std::string &type_str)
{
    if (type_str == "local")
        return StorageType::Local;
    if (type_str == "shared")
        return StorageType::Shared;
    return std::nullopt;
}

inline const char *StorageTypeToString(StorageType type)
{
    switch (type) {
        case StorageType::Local:
            return "Local";
        case StorageType::Shared:
            return "Shared";
        default:
            return "Unknown";
    }
}

inline std::optional<SharedPolicy> StringToSharedPolicy(const std::string &policy_str)
{
    if (policy_str == "sync")
        return SharedPolicy::Sync;
    if (policy_str == "divide")
        return SharedPolicy::Divide;
    return std::nullopt;
}

inline const char *SharedPolicyToString(SharedPolicy policy)
{
    switch (policy) {
        case SharedPolicy::Sync:
            return "Sync";
        case SharedPolicy::Divide:
            return "Divide";
        default:
            return "Unknown";
    }
}

//------------------------------------------------------------------------------//
// Implementation of Configuration Structs Functions
//------------------------------------------------------------------------------//

inline bool StorageDefinition::isValid() const
{
    if (path.empty() || tier < 0)
        return false;
    if (type == StorageType::Shared) {
        if (!policy.has_value() || !share_group.has_value() || share_group.value().empty()) {
            return false;
        }
        if (policy.value() == SharedPolicy::Divide) {
            if (min_size_gb.has_value() && max_size_gb.has_value() && *min_size_gb > *max_size_gb) {
                return false;
            }
            if (min_size_gb.has_value() && *min_size_gb < 0)
                return false;
        }
    } else {  // Local type
        if (policy.has_value() || share_group.has_value() || min_size_gb.has_value() ||
            max_size_gb.has_value()) {
            return false;
        }
    }
    return true;
}

inline bool NodeConfig::isValid() const
{
    if (node_id.empty() || storages.empty())
        return false;
    for (const auto &storage : storages) {
        if (!storage.isValid())
            return false;
    }
    return true;
}

}  // namespace DistributedCacheFS::Config

#endif  // DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_TYPES_HPP_
