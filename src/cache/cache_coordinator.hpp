#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_COORDINATOR_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_COORDINATOR_HPP_

#include "cache/i_cache_tier.hpp"
#include "config/config_types.hpp"
#include "origin/origin_manager.hpp"
#include "storage/storage_error.hpp"

#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace DistributedCacheFS::Cache
{

/// Helper struct to represent location in cache (if found)
struct CacheLocation {
    ICacheTier* cache_tier;
    std::filesystem::path relative_path;  ///< Should match fuse path relative part
    int tier_level = -1;
};

class CacheCoordinator
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//
    using CacheTierPtr = std::unique_ptr<ICacheTier>;
    using TierCacheMap =
        std::map<int, std::vector<CacheTierPtr>>;  ///< Map tier level -> list of tiers

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    explicit CacheCoordinator(
        const Config::NodeConfig& config, Origin::OriginManager* origin_manager
    );
    ~CacheCoordinator();

    CacheCoordinator(const CacheCoordinator&)            = delete;
    CacheCoordinator& operator=(const CacheCoordinator&) = delete;
    CacheCoordinator(CacheCoordinator&&)                 = delete;
    CacheCoordinator& operator=(CacheCoordinator&&)      = delete;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    // Initialization / Shutdown
    StorageResult<void> InitializeAll();
    StorageResult<void> ShutdownAll();

    // Core FUSE Operation Handlers

    StorageResult<struct stat> GetAttributes(const std::filesystem::path& fuse_path);

    StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const std::filesystem::path& fuse_path
    );

    StorageResult<size_t> ReadFile(
        const std::filesystem::path& fuse_path, off_t offset, std::span<std::byte> buffer
    );

    StorageResult<size_t> WriteFile(
        const std::filesystem::path& fuse_path, off_t offset,
        std::span<const std::byte> data
    );  // Implements write policy

    StorageResult<void> CreateFile(
        const std::filesystem::path& fuse_path, mode_t mode
    );  // Implements write policy

    StorageResult<void> CreateDirectory(
        const std::filesystem::path& fuse_path, mode_t mode
    );  // Implements write policy

    StorageResult<void> Remove(const std::filesystem::path& fuse_path
    );  // Implements write policy + cache invalidation

    StorageResult<void> TruncateFile(
        const std::filesystem::path& fuse_path, off_t size
    );  // Implements write policy + cache invalidation/update

    StorageResult<void> Move(
        const std::filesystem::path& from_fuse_path,
        const std::filesystem::path& to_fuse_path
    );  // Implements write policy + cache invalidation

    // Filesystem Statistics (TODO: How should this work? Origin stats? Cache stats?)
    StorageResult<struct statvfs> GetFilesystemStats(const std::filesystem::path& fuse_path);

    //------------------------------------------------------------------------------//
    // Public Fields
    //------------------------------------------------------------------------------//

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//

    /// Find an item in any cache tier
    StorageResult<CacheLocation> FindInCache(const std::filesystem::path& relative_path);

    /// Fetch from origin and store in an appropriate cache tier
    StorageResult<size_t> FetchAndCache(
        const std::filesystem::path& relative_path, off_t offset,
        std::span<std::byte> buffer  ///< Buffer to potentially fill directly
    );

    /// Selects a cache tier for writing new data (based on tier prio, space)
    StorageResult<ICacheTier*> SelectCacheTierForWrite(
        const std::filesystem::path& relative_path, size_t required_space
    );

    /// Handles cache eviction if necessary
    StorageResult<void> EvictIfNeeded(ICacheTier* target_tier, size_t required_space);

    /// Removes item from all cache tiers
    void InvalidateCacheEntry(const std::filesystem::path& relative_path);

    /// Check cache coherency
    StorageResult<bool> IsCacheValid(
        const CacheLocation& location, const struct stat& current_origin_stat
    );

    /// Helper to sanitize fuse path
    std::filesystem::path SanitizeFusePath(const std::filesystem::path& fuse_path) const;

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//

    const Config::NodeConfig config_;
    Origin::OriginManager* origin_manager_ = nullptr;  // Pointer, owned externally (by main)
    TierCacheMap cache_tier_map_;                      // Map of cache tiers
    // TODO: Add metadata cache (e.g., map<path, cached_stat>)
    // TODO: Add eviction strategy object

    std::recursive_mutex coordinator_mutex_;  // Protects internal state, tier map access

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_COORDINATOR_HPP_
