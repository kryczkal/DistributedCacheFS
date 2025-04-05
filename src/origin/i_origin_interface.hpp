#ifndef DISTRIBUTEDCACHEFS_SRC_ORIGIN_IORIGININTERFACE_HPP_
#define DISTRIBUTEDCACHEFS_SRC_ORIGIN_IORIGININTERFACE_HPP_

#include "cache/i_cache_tier.hpp"

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <filesystem>
#include <span>
#include <vector>

namespace DistributedCacheFS::Origin
{

// Interface for interacting with the origin filesystem
class IOriginInterface
{
    public:
    virtual ~IOriginInterface() = default;

    // Filesystem Read Operations
    virtual Storage::StorageResult<struct stat> GetAttributes(
        const std::filesystem::path& relative_path
    ) = 0;
    virtual Storage::StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const std::filesystem::path& relative_path
    ) = 0;
    virtual Storage::StorageResult<size_t> Read(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte> buffer
    ) = 0;

    // Filesystem Write/Modification Operations
    virtual Storage::StorageResult<size_t> Write(
        const std::filesystem::path& relative_path, off_t offset, std::span<const std::byte> data
    ) = 0;
    virtual Storage::StorageResult<void> CreateFile(
        const std::filesystem::path& relative_path, mode_t mode
    ) = 0;
    virtual Storage::StorageResult<void> CreateDirectory(
        const std::filesystem::path& relative_path, mode_t mode
    ) = 0;
    virtual Storage::StorageResult<void> Remove(const std::filesystem::path& relative_path
    ) = 0;  // Handles both files and dirs
    virtual Storage::StorageResult<void> Truncate(
        const std::filesystem::path& relative_path, off_t size
    ) = 0;
    virtual Storage::StorageResult<void> Move(
        const std::filesystem::path& from_relative_path,
        const std::filesystem::path& to_relative_path
    )                                                                   = 0;
    virtual Storage::StorageResult<struct statvfs> GetFilesystemStats() = 0;

    virtual Storage::StorageResult<void> Initialize() = 0;
    virtual Storage::StorageResult<void> Shutdown()   = 0;

    virtual std::filesystem::path GetFullPath(const std::filesystem::path& relative_path) const = 0;
};

}  // namespace DistributedCacheFS::Origin

#endif  // DISTRIBUTEDCACHEFS_SRC_ORIGIN_IORIGININTERFACE_HPP_
