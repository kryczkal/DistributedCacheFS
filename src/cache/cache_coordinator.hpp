#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_COORDINATOR_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_COORDINATOR_HPP_

#include "cache/i_cache_tier.hpp"
#include "config/config_types.hpp"
#include "origin/origin_manager.hpp"
#include "storage/storage_error.hpp"

#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <span>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

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

    /// Rich metadata stored centrally for each cached item
    struct RichCacheItemInfo {
        fs::path relative_path;
        double cost               = 0.0;  /// Fetch cost
        off_t size                = -1;   // Size (bytes)
        std::time_t last_accessed = 0;
        time_t origin_mtime       = 0;   // For validity checks
        off_t origin_size         = -1;  // For validity checks
        ICacheTier* current_tier  = nullptr;
    };

    // Entry for the eviction priority queue (min-heap)
    // Using pair {Heat, Path}
    using HeatEntry = std::pair<double, fs::path>;

    // Custom comparator for the min-heap priority queue
    struct HeatEntryCompare {
        bool operator()(const HeatEntry& lhs, const HeatEntry& rhs) const
        {
            return lhs.first > rhs.first;  // Compare heats (min-heap)
        }
    };

    using EvictionHeap = std::priority_queue<HeatEntry, std::vector<HeatEntry>, HeatEntryCompare>;

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

    /// Find an item in any cache tier (checks physical presence)
    StorageResult<CacheLocation> FindInCachePhysical(const fs::path& relative_path);

    /// Fetch from origin and store in an appropriate cache tier
    StorageResult<size_t> FetchAndCache(
        const fs::path& relative_path, off_t offset,
        std::span<std::byte> buffer  ///< Buffer to potentially fill directly
    );

    /// Selects a cache tier for writing new data (based on tier prio, space)
    StorageResult<ICacheTier*> SelectCacheTierForWrite(
        const fs::path& relative_path, size_t required_space
    );

    /// Handles cache eviction using heat policy
    StorageResult<void> EvictIfNeeded(ICacheTier* target_tier, size_t required_space);

    /// Removes item from cache tier AND internal metadata/heaps
    void InvalidateCacheEntry(const fs::path& relative_path);

    /// Check cache coherency using stored origin metadata
    StorageResult<bool> IsCacheValid(
        const RichCacheItemInfo& item_info, const struct stat& current_origin_stat
    );

    /// Helper to sanitize fuse path
    fs::path SanitizeFusePath(const fs::path& fuse_path) const;

    /// Calculate the heat value for an item
    double CalculateHeat(const RichCacheItemInfo& info, std::time_t current_time) const;

    /// Attempt to promote an item to a faster tier
    void PromoteItem(const fs::path& relative_path, ICacheTier* current_tier);

    /// Update heap entry (simplistic: re-insert)
    void UpdateHeapEntry(const fs::path& relative_path, double new_heat, int tier_level);

    /// Remove entry from metadata map and corresponding heap
    void RemoveItemFromMetadataAndHeap(const fs::path& relative_path);

    /// Find the next faster tier (lower number)
    ICacheTier* FindNextFasterTier(int current_tier_level);

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//

    const Config::NodeConfig config_;
    Origin::OriginManager* origin_manager_ = nullptr;  ///< Pointer, owned externally (by main)
    TierCacheMap cache_tier_map_;                      ///< Map tier level -> list of cache tiers
    std::unordered_map<fs::path, RichCacheItemInfo> item_metadata_;
    std::map<int, EvictionHeap> tier_eviction_heaps_;
    mutable std::shared_mutex
        metadata_heap_mutex_;  ///< Protects item_metadata_ and tier_eviction_heaps_

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_COORDINATOR_HPP_
