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

enum class CacheTierStorageType : std::uint8_t { Local, Shared };

std::optional<CacheTierStorageType> StringToCacheTierStorageType(const std::string &type_str);
const char *CacheTierStorageTypeToString(CacheTierStorageType type);

enum class SharedCachePolicy : std::uint8_t { Sync, Divide };

std::optional<SharedCachePolicy> StringToSharedCachePolicy(const std::string &policy_str);
const char *SharedCachePolicyToString(SharedCachePolicy policy);

// Function to convert string to spdlog::level::level_enum
std::optional<spdlog::level::level_enum> StringToLogLevel(const std::string &level_str);

//------------------------------------------------------------------------------//
// Structs for Configuration Types
//------------------------------------------------------------------------------//

struct CacheSettings {
    double decay_constant = 0.0001;  ///< Decay constant per second

    bool isValid() const;
};

struct GlobalSettings {
    spdlog::level::level_enum log_level = Constants::DEFAULT_LOG_LEVEL;
    std::string mdns_service_name       = std::string(Constants::DEFAULT_MDNS_SERVICE_NAME);
    std::uint16_t listen_port           = Constants::DEFAULT_LISTEN_PORT;
};

struct OriginDefinition {
    OriginType type = OriginType::Local;
    std::filesystem::path path;
    // TODO: Add other origin-specific options
    bool isValid() const;
};

struct CacheTierDefinition {
    std::filesystem::path path;      ///< Path for the cache storage
    int tier                  = -1;  ///< Cache tier priority (lower is checked first)
    CacheTierStorageType type = CacheTierStorageType::Local;  // Local node cache or Shared

    std::optional<SharedCachePolicy> policy;  ///< Required if type is Shared
    std::optional<std::string> share_group;   ///< Required if type is Shared

    // Size limits are relevant for 'divide' policy
    std::optional<double> min_size_gb;
    std::optional<double> max_size_gb;

    bool isValid() const;
};

struct NodeConfig {
    std::string node_id;
    OriginDefinition origin;
    GlobalSettings global_settings;
    CacheSettings cache_settings;
    std::vector<CacheTierDefinition> cache_tiers;

    bool isValid() const;
};

//------------------------------------------------------------------------------//
// Implementation of Enum / Logging Conversion Functions
//------------------------------------------------------------------------------//

inline std::optional<OriginType> StringToOriginType(const std::string &type_str)
{
    if (type_str == "local")
        return OriginType::Local;
    return std::nullopt;
}

inline const char *OriginTypeToString(OriginType type)
{
    switch (type) {
        case OriginType::Local:
            return "Local";
        default:
            return "Unknown";
    }
}

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

inline std::optional<CacheTierStorageType> StringToCacheTierStorageType(const std::string &type_str)
{
    if (type_str == "local") {
        return CacheTierStorageType::Local;
    }
    if (type_str == "shared") {
        return CacheTierStorageType::Shared;
    }
    return std::nullopt;
}

inline const char *CacheTierStorageTypeToString(CacheTierStorageType type)
{
    switch (type) {
        case CacheTierStorageType::Local:
            return "Local";
        case CacheTierStorageType::Shared:
            return "Shared";
        default:
            return "Unknown";
    }
}

inline std::optional<SharedCachePolicy> StringToSharedCachePolicy(const std::string &policy_str)
{
    if (policy_str == "sync") {
        return SharedCachePolicy::Sync;
    }
    if (policy_str == "divide") {
        return SharedCachePolicy::Divide;
    }
    return std::nullopt;
}

inline const char *SharedCachePolicyToString(SharedCachePolicy policy)
{
    switch (policy) {
        case SharedCachePolicy::Sync:
            return "Sync";
        case SharedCachePolicy::Divide:
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

inline bool OriginDefinition::isValid() const
{
    if (path.empty())
        return false;
    return true;
}

inline bool CacheTierDefinition::isValid() const
{
    if (path.empty() || tier < 0) {
        return false;
    }
    if (type == CacheTierStorageType::Shared) {
        if (!policy.has_value() || !share_group.has_value() || share_group.value().empty()) {
            return false;
        }
        if (policy.value() == SharedCachePolicy::Divide) {
            if (min_size_gb.has_value() && max_size_gb.has_value() && *min_size_gb > *max_size_gb) {
                return false;
            }
            if (min_size_gb.has_value() && *min_size_gb < 0) {
                return false;
            }
        }
    } else {
        if (policy.has_value() || share_group.has_value() || min_size_gb.has_value() ||
            max_size_gb.has_value()) {
            return false;
        }
    }
    return true;
}

inline bool NodeConfig::isValid() const
{
    if (node_id.empty() || cache_tiers.empty() || !origin.isValid() || !cache_settings.isValid()) {
        return false;
    }
    for (const auto &tier_def : cache_tiers) {
        if (!tier_def.isValid()) {
            return false;
        }
    }
    return true;
}

}  // namespace DistributedCacheFS::Config

#endif  // DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_TYPES_HPP_
