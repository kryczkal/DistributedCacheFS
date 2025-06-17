#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_ERROR_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_ERROR_HPP_

#include <expected>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>

namespace DistributedCacheFS::Storage
{

//------------------------------------------------------------------------------//
// Error Codes declared for Storage/Cache Operations
//------------------------------------------------------------------------------//

// clang-format off
enum class StorageErrc {
    Success = 0,       // Not an error
    FileNotFound,      // Path does not exist (in cache or origin)
    PermissionDenied,  // Operation not permitted
    IOError,           // General I/O error during read/write/etc.
    NotSupported,      // Operation is not supported by this storage type/backend
    OutOfSpace,        // No space left on the storage medium (cache tier)
    InvalidOffset,     // Invalid offset or size for read/write/truncate
    AlreadyExists,     // Attempted to create something that already exists
    NotADirectory,     // Expected a directory, found a file
    IsADirectory,      // Expected a file, found a directory
    NotEmpty,          // Attempted to remove a non-empty directory
    InvalidPath,       // Path format or content is invalid for the storage
    CacheMiss,         // Item not found in cache (internal signal, may not map to errno)
    EvictionError,     // Failed to evict items to make space
    CoherencyError,    // Cache data is known to be stale or inconsistent
    OriginError,       // Error interacting with the origin filesystem
    MetadataNotFound,  // Required metadata (e.g., xattrs) not found for cache entry
    MetadataError,     // Error reading or writing metadata (e.g., xattrs)
    UnknownError,      // An unspecified error occurred
};
// clang-format on

std::error_code make_error_code(StorageErrc e);

inline StorageErrc ErrnoToStorageErrc(int err_no)
{
    switch (err_no) {
        case 0:
            return StorageErrc::Success;
        case ENOENT:
            return StorageErrc::FileNotFound;
        case EACCES:
        case EPERM:
            return StorageErrc::PermissionDenied;
        case EIO:
            return StorageErrc::IOError;
        case ENOSPC:
            return StorageErrc::OutOfSpace;
        case EINVAL:
            return StorageErrc::InvalidOffset;
        case EEXIST:
            return StorageErrc::AlreadyExists;
        case ENOTDIR:
            return StorageErrc::NotADirectory;
        case EISDIR:
            return StorageErrc::IsADirectory;
        case ENOTEMPTY:
            return StorageErrc::NotEmpty;
        case EOPNOTSUPP:
            return StorageErrc::NotSupported;

        default:
            return StorageErrc::UnknownError;
    }
}

//------------------------------------------------------------------------------//
// Error Category Definition (Private Implementation Detail)
//------------------------------------------------------------------------------//
namespace detail
{
class StorageErrorCategory : public std::error_category
{
    public:
    const char* name() const noexcept override { return "DistributedCacheFS::Storage"; }
    std::string message(int ev) const override
    {
        switch (static_cast<StorageErrc>(ev)) {
            case StorageErrc::Success:
                return "Success";
            case StorageErrc::FileNotFound:
                return "File or directory not found";
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
            case StorageErrc::NotADirectory:
                return "Path is not a directory";
            case StorageErrc::IsADirectory:
                return "Path is a directory";
            case StorageErrc::NotEmpty:
                return "Directory not empty";
            case StorageErrc::InvalidPath:
                return "Invalid path";
            case StorageErrc::CacheMiss:
                return "Item not found in cache";
            case StorageErrc::EvictionError:
                return "Cache eviction failed";
            case StorageErrc::CoherencyError:
                return "Cache coherency error";
            case StorageErrc::OriginError:
                return "Origin filesystem error";
            case StorageErrc::MetadataNotFound:
                return "Metadata not found for cache entry";
            case StorageErrc::MetadataError:
                return "Error reading or writing metadata";
            case StorageErrc::UnknownError:
                return "Unknown storage/cache error";
            default:
                return "Unrecognized error code";
        }
    }
};
}  // namespace detail

// Global instance of the category
inline const detail::StorageErrorCategory storage_error_category;

// Make the enum usable with std::error_code
inline std::error_code make_error_code(StorageErrc e)
{
    return {static_cast<int>(e), storage_error_category};
}

//------------------------------------------------------------------------------//
// Custom Exception Type
//------------------------------------------------------------------------------//
class StorageException : public std::runtime_error
{
    private:
    std::error_code ec_;

    public:
    explicit StorageException(std::error_code ec) : std::runtime_error(ec.message()), ec_(ec) {}

    const std::error_code& code() const noexcept { return ec_; }
};

//------------------------------------------------------------------------------//
// Result Type Alias
//------------------------------------------------------------------------------//
template <typename T>
using StorageResult = std::expected<T, std::error_code>;

//------------------------------------------------------------------------------//
// Helper Function to Convert StorageResult to FUSE errno
//------------------------------------------------------------------------------//

template <typename T>
int StorageResultToErrno(const StorageResult<T>& result)
{
    if (result.has_value()) {
        return 0;
    } else {
        const std::error_code& ec = result.error();
        if (ec.category() == std::generic_category() || ec.category() == std::system_category()) {
            return -ec.value();  // ensure negative errno
        }
        if (ec.category() == Storage::storage_error_category) {
            switch (static_cast<StorageErrc>(ec.value())) {
                case StorageErrc::Success:
                    return 0;  // Should not happen in error case
                case StorageErrc::FileNotFound:
                    return -ENOENT;
                case StorageErrc::PermissionDenied:
                    return -EACCES;  // Or EPERM
                case StorageErrc::IOError:
                    return -EIO;
                case StorageErrc::NotSupported:
                    return -ENOSYS;  // Or EOPNOTSUPP
                case StorageErrc::OutOfSpace:
                    return -ENOSPC;
                case StorageErrc::InvalidOffset:
                    return -EINVAL;
                case StorageErrc::AlreadyExists:
                    return -EEXIST;
                case StorageErrc::NotADirectory:
                    return -ENOTDIR;
                case StorageErrc::IsADirectory:
                    return -EISDIR;
                case StorageErrc::NotEmpty:
                    return -ENOTEMPTY;
                case StorageErrc::MetadataNotFound:
                    return -ENOENT;
                case StorageErrc::MetadataError:
                    return -EIO;  // Treat metadata error as I/O error
                case StorageErrc::InvalidPath:
                    return -EINVAL;  // Or ENOENT
                    // Internal/Cache specific errors might not map directly
                case StorageErrc::CacheMiss:
                    return -ENOENT;  // Treat miss as not found externally
                case StorageErrc::EvictionError:
                    return -EIO;  // Map eviction failure to IO error
                case StorageErrc::CoherencyError:
                    return -EIO;  // Treat coherency issues as IO error
                case StorageErrc::OriginError:
                    return -EIO;                 // Treat origin issues as IO error
                case StorageErrc::UnknownError:  // Fall through
                default:
                    return -EIO;  // Default to general I/O error
            }
        } else {
            // If it's a generic error code (e.g., from std::filesystem)
            return -EIO;  // Return negative errno heat
        }
    }
}

}  // namespace DistributedCacheFS::Storage

// Enable std::error_code implicit conversion for StorageErrc
namespace std
{
template <>
struct is_error_code_enum<DistributedCacheFS::Storage::StorageErrc> : true_type {
};
}  // namespace std

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_ERROR_HPP_
