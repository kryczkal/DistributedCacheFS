#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_I_STORAGE_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_I_STORAGE_HPP_

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

namespace DistributedCacheFS::Storage
{

// Interface for a Cache Storage Tier
class IStorage
{
    public:
    virtual ~IStorage() = default;

    // Configuration / Identification

    /// Get the tier type (e.g., Local, Shared)
    [[nodiscard]] virtual Config::StorageType GetType() const = 0;
    /// Get the path to the folder where the files are stored
    /// Assuming the fitting device/nfs etc. is mounted
    [[nodiscard]] virtual const std::filesystem::path& GetPath() const = 0;

    // Capacity / Usage
    [[nodiscard]] virtual StorageResult<std::size_t> GetCapacityBytes() const  = 0;
    [[nodiscard]] virtual StorageResult<std::size_t> GetUsedBytes() const      = 0;
    [[nodiscard]] virtual StorageResult<std::size_t> GetAvailableBytes() const = 0;

    // Core Read/Write Operations

    virtual StorageResult<std::size_t> Read(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& buffer
    ) = 0;

    virtual StorageResult<std::size_t> Write(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& data
    ) = 0;

    virtual StorageResult<void> Remove(const std::filesystem::path& relative_path) = 0;

    virtual StorageResult<void> Truncate(
        const std::filesystem::path& relative_path, off_t size
    ) = 0;

    virtual StorageResult<bool> CheckIfFileExists(const std::filesystem::path& relative_path
    ) const = 0;

    virtual StorageResult<struct stat> GetAttributes(const std::filesystem::path& relative_path
    ) const = 0;

    virtual StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const std::filesystem::path& relative_path
    ) = 0;

    virtual StorageResult<void> CreateFile(
        const std::filesystem::path& relative_path, mode_t mode
    ) = 0;

    virtual StorageResult<void> CreateDirectory(
        const std::filesystem::path& relative_path, mode_t mode
    ) = 0;

    virtual StorageResult<void> Move(
        const std::filesystem::path& from_relative_path,
        const std::filesystem::path& to_relative_path
    ) = 0;

    // Initialization / Shutdown
    virtual StorageResult<void> Initialize() = 0;
    virtual StorageResult<void> Shutdown()   = 0;

    virtual std::filesystem::path RelativeToAbsPath(const std::filesystem::path& relative_path
    ) const = 0;
};

template <typename T>
concept IsStorage = std::derived_from<T, IStorage>;

}  // namespace DistributedCacheFS::Storage

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_I_STORAGE_HPP_
