#ifndef DISTRIBUTEDCACHEFS_SRC_APP_CONSTANTS_HPP_
#define DISTRIBUTEDCACHEFS_SRC_APP_CONSTANTS_HPP_

#include <spdlog/common.h>
#include <cstdint>
#include <string_view>

namespace DistributedCacheFS::Constants
{
// Application Info
constexpr std::string_view APP_NAME = "DistributedCacheFS";
// TODO: Derive from cmake
constexpr std::string_view APP_VERSION_STRING = "DistributedCacheFS version 0.1.0";
constexpr std::string_view APP_VERSION_SHORT  = "0.1.0";

// Logging
constexpr spdlog::level::level_enum DEFAULT_LOG_LEVEL   = spdlog::level::info;
constexpr spdlog::level::level_enum DEFAULT_FLUSH_LEVEL = spdlog::level::warn;
constexpr std::string_view DEFAULT_CONSOLE_LOG_PATTERN =
    "[%Y-%m-%d %H:%M:%S.%e] [ThreadID:%t] [%^%l%$] [%n] %v";

// Networking & Service Discovery
constexpr std::string_view DEFAULT_MDNS_SERVICE_NAME = "_dcachefs._tcp";
constexpr std::uint16_t DEFAULT_LISTEN_PORT          = 9876;

// FUSE
#define FUSE_USE_VERSION 31

}  // namespace DistributedCacheFS::Constants

#endif  // DISTRIBUTEDCACHEFS_SRC_APP_CONSTANTS_HPP_
