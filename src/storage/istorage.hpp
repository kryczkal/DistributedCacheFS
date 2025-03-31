#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_ISTORAGE_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_ISTORAGE_HPP_

#include "config/config_types.hpp"

#include <concepts>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <span>
#include <string_view>
#include <system_error>

namespace DistributedCacheFS::Storage
{

//------------------------------------------------------------------------------//
// Error Codes declared for Storage Operations
//------------------------------------------------------------------------------//

enum class StorageErrc {
    Success = 0,
    FileNotFound,
    PermissionDenied,
    IOError,
    NotSupported,
    OutOfSpace,
    InvalidOffset,
    AlreadyExists,
    UnknownError,
};

std::error_code make_error_code(StorageErrc e);

}  // namespace DistributedCacheFS::Storage

namespace std
{
template <>
struct is_error_code_enum<DistributedCacheFS::Storage::StorageErrc> : true_type {
};
}  // namespace std

namespace DistributedCacheFS::Storage
{

template <typename T>
using StorageResult = std::expected<T, std::error_code>;

//------------------------------------------------------------------------------//
// Interface for Storage Implementations
//------------------------------------------------------------------------------//

template <typename T>
concept IsStorage = requires(
    T storage, const T const_storage, const std::filesystem::path &p, off_t offset,
    std::size_t count
) {
    // Configuration / Identification
    { const_storage.get_tier() } -> std::same_as<int>;
    { const_storage.get_type() } -> std::same_as<Config::StorageType>;
    { const_storage.get_path() } -> std::same_as<const std::filesystem::path &>;

    // Capacity / Usage
    { const_storage.get_capacity_bytes() } -> std::same_as<StorageResult<std::uint64_t>>;
    { const_storage.get_used_bytes() } -> std::same_as<StorageResult<std::uint64_t>>;

    // Core I/O Operations (using std::span)
    {
        storage.read(p, offset, std::declval<std::span<std::byte>>())
    } -> std::same_as<StorageResult<std::size_t>>;
    {
        storage.write(p, offset, std::declval<std::span<const std::byte>>())
    } -> std::same_as<StorageResult<std::size_t>>;

    // File/Directory Management
    { storage.create_file(p) } -> std::same_as<StorageResult<void>>;
    { storage.create_directory(p) } -> std::same_as<StorageResult<void>>;
    { storage.remove(p) } -> std::same_as<StorageResult<void>>;
    { storage.truncate(p, offset) } -> std::same_as<StorageResult<void>>;

    // Initialization / Shutdown
    { storage.initialize() } -> std::same_as<StorageResult<void>>;
    { storage.shutdown() } -> std::same_as<StorageResult<void>>;
};

//------------------------------------------------------------------------------//
// Error Code Implementation
//------------------------------------------------------------------------------//

class StorageErrorCategory : public std::error_category
{
    public:
    const char *name() const noexcept override { return "DistributedCacheFS::Storage"; }
    std::string message(int ev) const override
    {
        switch (static_cast<StorageErrc>(ev)) {
            case StorageErrc::Success:
                return "Success";
            case StorageErrc::FileNotFound:
                return "File not found";
            case StorageErrc::PermissionDenied:
                return "Permission denied";
            case StorageErrc::IOError:
                return "Input/output error";
            case StorageErrc::NotSupported:
                return "Operation not supported";
            case StorageErrc::OutOfSpace:
                return "No space left on device";
            case StorageErrc::InvalidOffset:
                return "Invalid offset or size";
            case StorageErrc::AlreadyExists:
                return "File or directory already exists";
            case StorageErrc::UnknownError:
                return "Unknown storage error";
            default:
                return "Unrecognized error";
        }
    }
};

inline const StorageErrorCategory storage_error_category;

inline std::error_code make_error_code(StorageErrc e)
{
    return {static_cast<int>(e), storage_error_category};
}

}  // namespace DistributedCacheFS::Storage

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_ISTORAGE_HPP_
