#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_LOCAL_CACHE_TIER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_LOCAL_CACHE_TIER_HPP_

#include <filesystem>
#include <map>
#include <mutex>
#include <system_error>
#include "cache/i_cache_tier.hpp"
#include "config/config_types.hpp"

namespace DistributedCacheFS::Cache
{

// Implements ICacheTier using the local filesystem for caching
class LocalCacheTier : public ICacheTier
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    explicit LocalCacheTier(const Config::CacheTierDefinition& definition);
    ~LocalCacheTier() override = default;

    LocalCacheTier(const LocalCacheTier&)            = delete;
    LocalCacheTier& operator=(const LocalCacheTier&) = delete;
    LocalCacheTier(LocalCacheTier&&)                 = delete;
    LocalCacheTier& operator=(LocalCacheTier&&)      = delete;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    // ICacheTier Implementation
    int GetTier() const override { return definition_.tier; }
    Config::CacheTierStorageType GetType() const override { return definition_.type; }
    const std::filesystem::path& GetPath() const override { return base_path_; }

    StorageResult<std::uint64_t> GetCapacityBytes() const override;
    StorageResult<std::uint64_t> GetUsedBytes(
    ) const override;  // Needs calculation if not tracked live
    StorageResult<std::uint64_t> GetAvailableBytes() const override;

    StorageResult<std::size_t> Read(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte> buffer
    ) override;
    StorageResult<std::size_t> Write(
        const std::filesystem::path& relative_path, off_t offset, std::span<const std::byte> data
    ) override;
    StorageResult<void> Remove(const std::filesystem::path& relative_path) override;
    StorageResult<void> Truncate(const std::filesystem::path& relative_path, off_t size) override;

    StorageResult<bool> Probe(const std::filesystem::path& relative_path) const override;
    StorageResult<struct stat> GetAttributes(const std::filesystem::path& relative_path
    ) const override;
    StorageResult<void> UpdateAccessMeta(const std::filesystem::path& relative_path) override;
    StorageResult<void> SetCacheMetadata(
        const std::filesystem::path& relative_path, const CacheOriginMetadata& metadata
    ) override;
    StorageResult<CacheOriginMetadata> GetCacheMetadata(const std::filesystem::path& relative_path
    ) const override;

    StorageResult<void> Initialize() override;
    StorageResult<void> Shutdown() override;

    std::filesystem::path GetFullPath(const std::filesystem::path& relative_path) const override;

    StorageResult<std::vector<CacheItemInfo>> ListCacheContents() const override;

    //------------------------------------------------------------------------------//
    // Public Fields
    //------------------------------------------------------------------------------//

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//

    std::filesystem::path GetValidatedFullPath(const std::filesystem::path& relative_path) const;
    std::error_code MapFilesystemError(const std::error_code& ec, const std::string& operation = "")
        const;
    void UpdateMetaOnWrite(const std::filesystem::path& full_path);
    void RemoveMeta(const std::filesystem::path& full_path);
    StorageResult<void> SetXattr(
        const std::filesystem::path& full_path, const char* key, const void* value, size_t size
    );
    StorageResult<std::vector<char>> GetXattr(
        const std::filesystem::path& full_path, const char* key
    ) const;
    StorageResult<void> RemoveXattr(const std::filesystem::path& full_path, const char* key);

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//
    static const char* XATTR_ORIGIN_MTIME_KEY;
    static const char* XATTR_ORIGIN_SIZE_KEY;

    const Config::CacheTierDefinition definition_;
    std::filesystem::path base_path_;
    mutable std::recursive_mutex tier_mutex_;
    std::map<std::string, std::time_t> access_times_;

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_LOCAL_CACHE_TIER_HPP_
