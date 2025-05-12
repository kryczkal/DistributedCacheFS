#ifndef DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_TYPES_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_TYPES_HPP_

#include "app_constants.hpp"

#include <spdlog/spdlog.h>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace DistributedCacheFS::Config
{

//------------------------------------------------------------------------------//
// Enumerations for Configuration Types
//------------------------------------------------------------------------------//

enum class OriginType : std::uint8_t { Local };

std::optional<OriginType> StringToOriginType(const std::string &type_str);
const char *OriginTypeToString(OriginType type);

enum class StorageType : std::uint8_t { Local, Shared };

std::optional<StorageType> StringToStorageType(const std::string &type_str);
const char *StorageTypeToString(StorageType type);

enum class SharedStorage : std::uint8_t { Sync, Divide };

std::optional<SharedStorage> StringToSharedStoragePolicy(const std::string &policy_str);
const char *SharedStoragePolicyToString(SharedStorage policy);

// Function to convert string to spdlog::level::level_enum
std::optional<spdlog::level::level_enum> StringToLogLevel(const std::string &level_str);

//------------------------------------------------------------------------------//
// Structs for Configuration Types
//------------------------------------------------------------------------------//

struct CacheSettings {
    double decay_constant = Constants::DEFAULT_DECAY_CONSTANT;

    bool isValid() const;
};

struct GlobalSettings {
    spdlog::level::level_enum log_level = Constants::DEFAULT_LOG_LEVEL;
    std::string mdns_service_name       = std::string(Constants::DEFAULT_MDNS_SERVICE_NAME);
    std::uint16_t listen_port           = Constants::DEFAULT_LISTEN_PORT;
};

struct StorageDefinition {
    std::filesystem::path path;  ///< Path for the cache storage
    StorageType type = StorageType::Local;

    std::optional<SharedStorage> policy;     ///< Required if type is Shared
    std::optional<std::string> share_group;  ///< Required if type is Shared

    // Size limits
    std::optional<uint64_t> min_size_bytes;
    std::optional<uint64_t> max_size_bytes;

    bool IsValid() const;
};

struct CacheDefinition {
    StorageDefinition storage_definition;
    CacheSettings cache_settings;
    int tier = -1;  ///< Cache tier priority (lower is checked first)

    bool IsValid() const
    {
        return storage_definition.IsValid() && cache_settings.isValid() && (tier >= 0);
    }
};

struct NodeConfig {
    std::string node_id;
    StorageDefinition origin_definition;
    GlobalSettings global_settings;
    CacheSettings cache_settings;
    std::vector<CacheDefinition> cache_definitions;

    bool IsValid() const;
};

//------------------------------------------------------------------------------//
// Implementation of Enum / Logging Conversion Functions
//------------------------------------------------------------------------------//

inline std::optional<spdlog::level::level_enum> StringToLogLevel(const std::string &level_str)
{
    if (level_str == "trace") {
        return spdlog::level::trace;
    }
    if (level_str == "debug") {
        return spdlog::level::debug;
    }
    if (level_str == "info") {
        return spdlog::level::info;
    }
    if (level_str == "warn") {
        return spdlog::level::warn;
    }
    if (level_str == "error") {
        return spdlog::level::err;
    }
    if (level_str == "fatal" || level_str == "critical") {
        return spdlog::level::critical;
    }
    if (level_str == "off") {
        return spdlog::level::off;
    }
    return std::nullopt;
}

inline std::optional<StorageType> StringToStorageType(const std::string &type_str)
{
    if (type_str == "local") {
        return StorageType::Local;
    }
    if (type_str == "shared") {
        return StorageType::Shared;
    }
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

inline std::optional<SharedStorage> StringToSharedStoragePolicy(const std::string &policy_str)
{
    if (policy_str == "sync") {
        return SharedStorage::Sync;
    }
    if (policy_str == "divide") {
        return SharedStorage::Divide;
    }
    return std::nullopt;
}

inline const char *SharedStoragePolicyToString(SharedStorage policy)
{
    switch (policy) {
        case SharedStorage::Sync:
            return "Sync";
        case SharedStorage::Divide:
            return "Divide";
        default:
            return "Unknown";
    }
}

//------------------------------------------------------------------------------//
// Implementation of Configuration Structs Functions
//------------------------------------------------------------------------------//

inline bool CacheSettings::isValid() const
{
    if (decay_constant <= 0) {
        return false;
    }
    return true;
}

inline bool StorageDefinition::IsValid() const
{
    if (path.empty()) {
        return false;
    }
    if (type == StorageType::Shared) {
        if (!policy.has_value() || !share_group.has_value() || share_group.value().empty()) {
            return false;
        }
        if (policy.value() == SharedStorage::Divide) {
            if (min_size_bytes.has_value() && max_size_bytes.has_value() &&
                *min_size_bytes > *max_size_bytes) {
                return false;
            }
        }
    } else {
        if (policy.has_value() || share_group.has_value()) {
            spdlog::warn("Policy or share_group specified for non-shared storage type.");
        }
        if (min_size_bytes.has_value() && max_size_bytes.has_value() &&
            *min_size_bytes > *max_size_bytes) {
            spdlog::error(
                "min_size_bytes ({}) cannot exceed max_size_bytes ({}) for local storage.",
                *min_size_bytes, *max_size_bytes
            );
            return false;
        }
    }
    return true;
}

inline bool NodeConfig::IsValid() const
{
    if (node_id.empty() || cache_definitions.empty() || !origin_definition.IsValid() ||
        !cache_settings.isValid()) {
        return false;
    }
    for (const auto &tier_def : cache_definitions) {
        if (!tier_def.IsValid()) {
            return false;
        }
    }
    return true;
}

}  // namespace DistributedCacheFS::Config

#endif  // DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_TYPES_HPP_
