#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_MANAGER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_MANAGER_HPP_

#include "cache/cache_tier.hpp"
#include "config/config_types.hpp"
#include "storage/i_storage.hpp"
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

namespace DistributedCacheFS::Cache
{

namespace fs = std::filesystem;

class CacheManager
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    using IStorage = Storage::IStorage;

    template <typename T>
    using StorageResult = Storage::StorageResult<T>;

    using TierToCacheMap = std::map<int, std::vector<std::shared_ptr<CacheTier>>>;
    using FileToCacheMap = std::unordered_map<fs::path, std::shared_ptr<CacheTier>>;

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    explicit CacheManager(Config::NodeConfig& config, std::shared_ptr<IStorage> origin);
    ~CacheManager();

    CacheManager(const CacheManager&)            = delete;
    CacheManager& operator=(const CacheManager&) = delete;
    CacheManager(CacheManager&&)                 = delete;
    CacheManager& operator=(CacheManager&&)      = delete;

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
        const std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& buffer
    );

    StorageResult<size_t> WriteFile(
        const std::filesystem::path& fuse_path, off_t offset,
        std::span<const std::byte>& data
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

    StorageResult<struct statvfs> GetFilesystemStats(const std::filesystem::path& fuse_path);

    //------------------------------------------------------------------------------//
    // Public Fields
    //------------------------------------------------------------------------------//

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//

    /// Fetch from origin and store in an appropriate cache tier
    StorageResult<size_t> FetchAndCache(
        const fs::path& relative_path, off_t offset,
        std::span<std::byte>& buffer  ///< Buffer to potentially fill directly
    );

    /// Selects a cache tier for writing new data (based on tier prio, space)
    StorageResult<IStorage*> SelectCacheTierForWrite(
        const fs::path& relative_path, size_t required_space
    );

    /// Helper to sanitize fuse path
    fs::path SanitizeFusePath(const fs::path& fuse_path) const;

    /// Attempt to promote an item to a faster tier
    void PromoteItem(const fs::path& fuse_path);

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//

    /** Configuration for this cache coordinator */
    const Config::NodeConfig config_;
    const std::shared_ptr<IStorage> origin_;

    TierToCacheMap tier_to_cache_;  ///< Map of cache tiers by tier number
    FileToCacheMap file_to_cache_;  ///< Map of file paths to cache tiers

    /** Protects item_metadatas_ */
    mutable std::shared_mutex metadata_mutex_;

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_MANAGER_HPP_
