#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_ICACHETIER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_ICACHETIER_HPP_

#include "config/config_types.hpp"
#include "storage/storage_error.hpp"

#include <sys/stat.h>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace DistributedCacheFS::Cache
{

using Storage::make_error_code;
using Storage::StorageErrc;
using Storage::StorageResult;

struct CacheOriginMetadata {
    time_t origin_mtime = 0;
    off_t origin_size   = -1;
};

// Basic info returned by ListCacheContents - potentially less rich than coordinators view
struct CacheItemInfo {
    std::filesystem::path relative_path;
    struct stat attributes;
    std::optional<CacheOriginMetadata> origin_metadata;
};

// Interface for a Cache Storage Tier
class ICacheTier
{
    public:
    virtual ~ICacheTier() = default;

    // Configuration / Identification
    virtual int GetTier() const                          = 0;
    virtual Config::CacheTierStorageType GetType() const = 0;
    virtual const std::filesystem::path& GetPath() const = 0;

    // Capacity / Usage
    virtual StorageResult<std::uint64_t> GetCapacityBytes() const  = 0;
    virtual StorageResult<std::uint64_t> GetUsedBytes() const      = 0;
    virtual StorageResult<std::uint64_t> GetAvailableBytes() const = 0;

    // Core Cache Read/Write Operations
    // Read data from the cache tier
    virtual StorageResult<std::size_t> Read(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte> buffer
    ) = 0;
    // Write data into the cache tier
    virtual StorageResult<std::size_t> Write(
        const std::filesystem::path& relative_path, off_t offset, std::span<const std::byte> data
    ) = 0;
    // Remove an item from the cache tier (for invalidation or eviction)
    virtual StorageResult<void> Remove(const std::filesystem::path& relative_path) = 0;
    // Truncate a file within the cache tier (e.g., on origin truncate)
    virtual StorageResult<void> Truncate(
        const std::filesystem::path& relative_path, off_t size
    ) = 0;

    // Cache Metadata Management (Physical Tier level)
    /// Check if an item exists physically in this specific cache tier
    virtual StorageResult<bool> Probe(const std::filesystem::path& relative_path) const = 0;
    /// Get attributes of the cached item (stat call on cached file)
    virtual StorageResult<struct stat> GetAttributes(const std::filesystem::path& relative_path
    ) const = 0;
    /// Set the origin metadata (mtime, size) physically with the cached file
    virtual StorageResult<void> SetCacheMetadata(
        const std::filesystem::path& relative_path, const CacheOriginMetadata& metadata
    ) = 0;
    /// Get the origin metadata (mtime, size) physically stored with the cached file
    virtual StorageResult<CacheOriginMetadata> GetCacheMetadata(
        const std::filesystem::path& relative_path
    ) const = 0;

    // Initialization / Shutdown
    virtual StorageResult<void> Initialize() = 0;
    virtual StorageResult<void> Shutdown()   = 0;

    /// Helper to get full path within the cache tier
    virtual std::filesystem::path GetFullPath(const std::filesystem::path& relative_path) const = 0;

    /// List items currently stored in this cache tier along with their metadata
    virtual StorageResult<std::vector<CacheItemInfo>> ListCacheContents() const = 0;
};

template <typename T>
concept IsCacheTier = std::derived_from<T, ICacheTier>;

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_ICACHETIER_HPP_
