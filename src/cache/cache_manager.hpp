#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_MANAGER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_MANAGER_HPP_

#include "async_io_manager.hpp"
#include "cache/block_metadata.hpp"
#include "cache/cache_tier.hpp"
#include "cache/file_lock_manager.hpp"
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
#include <shared_mutex>
#include <span>
#include <unordered_map>
#include <vector>

namespace DistributedCacheFS::Cache
{

namespace fs = std::filesystem;

class ITierSelector;

class CacheManager
{
    private:
    using IStorage = Storage::IStorage;
    template <typename T>
    using StorageResult = Storage::StorageResult<T>;

    public:
    explicit CacheManager(const Config::NodeConfig& config, std::shared_ptr<IStorage> origin);
    ~CacheManager();

    CacheManager(const CacheManager&)            = delete;
    CacheManager& operator=(const CacheManager&) = delete;
    CacheManager(CacheManager&&)                 = delete;
    CacheManager& operator=(CacheManager&&)      = delete;

    StorageResult<void> InitializeAll();
    StorageResult<void> ShutdownAll();

    StorageResult<struct stat> GetAttributes(std::filesystem::path& fuse_path);

    StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const std::filesystem::path& fuse_path
    );

    StorageResult<size_t> ReadFile(
        std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& buffer
    );

    StorageResult<size_t> WriteFile(
        std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& data
    );

    StorageResult<void> CreateFile(std::filesystem::path& fuse_path, mode_t mode);
    StorageResult<void> CreateSpecialFile(std::filesystem::path& fuse_path, mode_t mode, dev_t rdev);
    StorageResult<void> CreateDirectory(std::filesystem::path& fuse_path, mode_t mode);
    StorageResult<void> Remove(std::filesystem::path& fuse_path);
    StorageResult<void> TruncateFile(std::filesystem::path& fuse_path, off_t size);
    StorageResult<void> Move(
        std::filesystem::path& from_fuse_path, std::filesystem::path& to_fuse_path
    );
    StorageResult<void> CreateHardLink(const fs::path& from_path, const fs::path& to_path);

    StorageResult<struct statvfs> GetFilesystemStats(fs::path& fuse_path);
    StorageResult<void> SetPermissions(const fs::path& fuse_path, mode_t mode);
    StorageResult<void> SetOwner(const fs::path& fuse_path, uid_t uid, gid_t gid);
    StorageResult<void> CheckPermissions(
        const fs::path& fuse_path, int access_mask, uid_t caller_uid, gid_t caller_gid
    );
    StorageResult<void> SetXattr(
        const fs::path& fuse_path, const std::string& name, const char* value, size_t size,
        int flags
    );
    StorageResult<ssize_t> GetXattr(
        const fs::path& fuse_path, const std::string& name, char* value, size_t size
    );
    StorageResult<ssize_t> ListXattr(const fs::path& fuse_path, char* list, size_t size);
    StorageResult<void> RemoveXattr(const fs::path& fuse_path, const std::string& name);

    private:
    void CacheRegionAsync(
        const FileId& file_id, const fs::path& fuse_path, off_t offset,
        std::vector<std::byte> region_data, double fetch_cost_ms
    );

    void InvalidateAndPurgeByPath(const fs::path& fuse_path);

    void TryPromoteBlock(
        const FileId& file_id, const fs::path& fuse_path, off_t offset, size_t size,
        std::shared_ptr<CacheTier> source_tier
    );

    StorageResult<CoherencyMetadata> GetOriginCoherencyMetadata(const fs::path& fuse_path) const;

    const Config::NodeConfig config_;
    const std::shared_ptr<IStorage> origin_;
    std::unique_ptr<AsyncIoManager> io_manager_;
    std::unique_ptr<FileLockManager> file_lock_manager_;
    std::unique_ptr<ITierSelector> tier_selector_;

    TierToCacheMap tier_to_cache_;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_MANAGER_HPP_
