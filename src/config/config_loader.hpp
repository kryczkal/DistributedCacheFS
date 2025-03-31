#ifndef DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_LOADER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_LOADER_HPP_

#include "config/config_types.hpp"

#include <expected>
#include <filesystem>
#include <string>

namespace DistributedCacheFS::Config
{

//------------------------------------------------------------------------------//
// Error Handling for Configuration Loading
//------------------------------------------------------------------------------//

enum class LoadError {
    FileNotFound,
    JsonParseError,
    ValidationError,
};

using LoadResult   = std::expected<NodeConfig, LoadError>;
using LoadErrorMsg = std::expected<NodeConfig, std::string>;

LoadResult loadConfigFromFile(const std::filesystem::path &file_path);
LoadErrorMsg loadConfigFromFileVerbose(const std::filesystem::path &file_path);

}  // namespace DistributedCacheFS::Config

#endif  // DISTRIBUTEDCACHEFS_SRC_CONFIG_CONFIG_LOADER_HPP_
