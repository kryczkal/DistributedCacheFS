#include "storage/local_storage.hpp"

#include <fcntl.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <system_error>

namespace DistributedCacheFS::Storage
{

const char* LocalStorage::XATTR_ORIGIN_MTIME_KEY = "user.dcachefs.origin_mtime_sec";
const char* LocalStorage::XATTR_ORIGIN_SIZE_KEY  = "user.dcachefs.size";

namespace  // Anonymous namespace
{

// Helper to convert errno from xattr calls to StorageErrc
Storage::StorageErrc XattrErrnoToStorageErrc(int err_no)
{
    switch (err_no) {
        case 0:
            return Storage::StorageErrc::Success;
        case ENOENT:
            return Storage::StorageErrc::FileNotFound;  // Path not found
        case ENODATA:
            return Storage::StorageErrc::MetadataNotFound;  // Attribute not found
        case EPERM:
        case EACCES:
            return Storage::StorageErrc::PermissionDenied;
        case ENOSPC:
            return Storage::StorageErrc::OutOfSpace;
        case EOPNOTSUPP:
            return Storage::StorageErrc::NotSupported;  // FS doesn't support xattrs or operation
        case ERANGE:
            return Storage::StorageErrc::MetadataError;
        case EIO:
            return Storage::StorageErrc::IOError;

        default:
            return Storage::StorageErrc::MetadataError;  // Treat other errors as metadata errors
    }
}

Storage::StorageErrc ErrnoToStorageErrc(int err_no)
{
    switch (err_no) {
        case 0:
            return Storage::StorageErrc::Success;
        case ENOENT:
            return Storage::StorageErrc::FileNotFound;
        case EACCES:
        case EPERM:
            return Storage::StorageErrc::PermissionDenied;
        case EIO:
            return Storage::StorageErrc::IOError;
        case ENOSPC:
            return Storage::StorageErrc::OutOfSpace;
        case EINVAL:
            return Storage::StorageErrc::InvalidOffset;
        case EEXIST:
            return Storage::StorageErrc::AlreadyExists;
        case ENOTDIR:
            return Storage::StorageErrc::NotADirectory;
        case EISDIR:
            return Storage::StorageErrc::IsADirectory;
        case ENOTEMPTY:
            return Storage::StorageErrc::NotEmpty;
        case EOPNOTSUPP:
            return Storage::StorageErrc::NotSupported;

        default:
            return Storage::StorageErrc::UnknownError;
    }
}

// RAII for file descriptors
class FileDescriptorGuard
{
    private:
    int fd_;

    public:
    explicit FileDescriptorGuard(int fd = -1) noexcept : fd_(fd) {}
    ~FileDescriptorGuard()
    {
        if (fd_ >= 0) {
            if (::close(fd_) == -1) {
                spdlog::error(
                    "~FileDescriptorGuard: Failed to close fd {}: {}", fd_, std::strerror(errno)
                );
            }
        }
    }
    FileDescriptorGuard(const FileDescriptorGuard&)            = delete;
    FileDescriptorGuard& operator=(const FileDescriptorGuard&) = delete;
    FileDescriptorGuard(FileDescriptorGuard&& other) noexcept : fd_(other.release()) {}
    FileDescriptorGuard& operator=(FileDescriptorGuard&& other) noexcept
    {
        reset(other.release());
        return *this;
    }
    int get() const noexcept { return fd_; }
    int release() noexcept { return std::exchange(fd_, -1); }
    void reset(int new_fd = -1) noexcept
    {
        if (fd_ >= 0 && fd_ != new_fd) {
            if (::close(fd_) == -1) {
                spdlog::error(
                    "~FileDescriptorGuard.reset: Failed to close fd {}: {}", fd_,
                    std::strerror(errno)
                );
            }
        }
        fd_ = new_fd;
    }
    explicit operator bool() const noexcept { return fd_ >= 0; }
};

}  // anonymous namespace

StorageResult<void> LocalStorage::SetXattr(
    const std::filesystem::path& full_path, const char* key, const void* value, size_t size
)
{
    if (::setxattr(full_path.c_str(), key, value, size, 0) == -1) {
        int xattr_errno = errno;
        spdlog::warn(
            "LocalStorage::SetXattr failed for key '{}' on '{}': {}", key, full_path.string(),
            std::strerror(xattr_errno)
        );
        return std::unexpected(make_error_code(XattrErrnoToStorageErrc(xattr_errno)));
    }
    return {};
}

StorageResult<std::vector<char>> LocalStorage::GetXattr(
    const std::filesystem::path& full_path, const char* key
) const
{
    // First call to get size
    ssize_t size = ::getxattr(full_path.c_str(), key, nullptr, 0);
    if (size == -1) {
        int xattr_errno = errno;
        // Don't log error if attribute simply doesn't exist
        if (xattr_errno != ENODATA) {
            spdlog::trace(
                "LocalStorage::GetXattr size check failed for key '{}' on '{}': {}", key,
                full_path.string(), std::strerror(xattr_errno)
            );
        }
        return std::unexpected(make_error_code(XattrErrnoToStorageErrc(xattr_errno)));
    }
    if (size == 0) {
        return std::vector<char>();  // Empty attribute
    }

    // Allocate buffer and get heat
    std::vector<char> value(size);
    size = ::getxattr(full_path.c_str(), key, value.data(), value.size());
    if (size == -1) {
        int xattr_errno = errno;
        spdlog::warn(
            "LocalStorage::GetXattr read failed for key '{}' on '{}': {}", key, full_path.string(),
            std::strerror(xattr_errno)
        );
        return std::unexpected(make_error_code(XattrErrnoToStorageErrc(xattr_errno)));
    }
    // Should match the size from the first call
    value.resize(size);
    return value;
}

StorageResult<void> LocalStorage::RemoveXattr(
    const std::filesystem::path& full_path, const char* key
)
{
    if (::removexattr(full_path.c_str(), key) == -1) {
        int xattr_errno = errno;
        // Ignore error if attribute simply doesn't exist
        if (xattr_errno != ENODATA) {
            spdlog::warn(
                "LocalStorage::RemoveXattr failed for key '{}' on '{}': {}", key,
                full_path.string(), std::strerror(xattr_errno)
            );
            return std::unexpected(make_error_code(XattrErrnoToStorageErrc(xattr_errno)));
        }
        spdlog::trace(
            "LocalStorage::RemoveXattr: Attribute '{}' not found on '{}', ignoring.", key,
            full_path.string()
        );
    }
    return {};
}

std::filesystem::path LocalStorage::RelativeToAbsPath(const std::filesystem::path& relative_path
) const
{
    auto combined        = (base_path_ / relative_path).lexically_normal();
    std::string base_str = base_path_.string();
    if (base_str.back() != std::filesystem::path::preferred_separator) {
        base_str += std::filesystem::path::preferred_separator;
    }
    if (combined.string().rfind(base_str, 0) != 0 && combined != base_path_) {
        spdlog::warn(
            "LocalStorage: Potential path traversal: relative='{}', combined='{}', base='{}'",
            relative_path.string(), combined.string(), base_path_.string()
        );
        return {};
    }
    return combined;
}

std::filesystem::path LocalStorage::GetValidatedFullPath(const std::filesystem::path& relative_path
) const
{
    auto full_path = RelativeToAbsPath(relative_path);
    if (full_path.empty()) {
        return {};
    }
    return full_path;
}

std::error_code LocalStorage::MapFilesystemError(
    const std::error_code& ec, const std::string& operation
) const
{
    if (!ec)
        return {};
    Storage::StorageErrc storage_errc = Storage::StorageErrc::UnknownError;
    if (ec.category() == std::generic_category()) {
        storage_errc = ErrnoToStorageErrc(ec.value());
    } else if (ec.category() == std::system_category()) {
        storage_errc = ErrnoToStorageErrc(ec.value());  // Best guess
    }
    if (storage_errc == Storage::StorageErrc::UnknownError && ec.value() != 0) {
        spdlog::warn(
            "LocalStorage::MapFilesystemError: Unmapped error during '{}': code={}, category={}, "
            "message='{}'",
            operation.empty() ? "op" : operation, ec.value(), ec.category().name(), ec.message()
        );
    } else {
        spdlog::trace(
            "LocalStorage::MapFilesystemError: Mapped error during '{}': {} -> {}",
            operation.empty() ? "op" : operation, ec.message(), static_cast<int>(storage_errc)
        );
    }
    return Storage::make_error_code(storage_errc);
}

// IStorage Implementation

StorageResult<void> LocalStorage::Initialize()
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    std::error_code ec;

    if (!std::filesystem::exists(base_path_, ec)) {
        spdlog::info(
            "LocalStorage: Cache path '{}' does not exist, creating.", base_path_.string()
        );
        if (!std::filesystem::create_directories(base_path_, ec)) {
            if (ec) {
                spdlog::error(
                    "LocalStorage: Failed create cache dir '{}': {}", base_path_.string(),
                    ec.message()
                );
                return std::unexpected(MapFilesystemError(ec, "init_create_dir"));
            }
            // If no error, check again (race?)
            if (!std::filesystem::is_directory(base_path_, ec)) {
                spdlog::error(
                    "LocalStorage: Failed verify cache dir '{}' after creation.",
                    base_path_.string()
                );
                return std::unexpected(MapFilesystemError(
                    ec ? ec : std::make_error_code(std::errc::io_error), "init_verify_dir"
                ));
            }
        }
        if (ec) {
            spdlog::error(
                "LocalStorage: Failed create cache dir '{}': {}", base_path_.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "init_create_dir"));
        }
        spdlog::info("LocalStorage: Successfully created cache directory: {}", base_path_.string());
    } else if (ec) {
        spdlog::error(
            "LocalStorage: Error checking cache path '{}': {}", base_path_.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "init_check_exists"));
    } else if (!std::filesystem::is_directory(base_path_, ec)) {
        spdlog::error(
            "LocalStorage: Cache path '{}' exists but is not a directory.", base_path_.string()
        );
        return std::unexpected(make_error_code(StorageErrc::NotADirectory));
    } else if (ec) {
        spdlog::error(
            "LocalStorage: Error checking cache path type '{}': {}", base_path_.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "init_check_type"));
    } else {
        spdlog::info("LocalStorage initialized using existing directory: {}", base_path_.string());
    }

    // TODO: Scan existing cache contents to populate initial metadata (access_times_, used_bytes_)

    return {};
}

StorageResult<void> LocalStorage::Shutdown()
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("Shutting down LocalStorage for path: {}", base_path_.string());
    // No specific action currently needed on shutdown
    return {};
}

StorageResult<std::uint64_t> LocalStorage::GetCapacityBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    struct statvfs vfs_buf;
    if (::statvfs(base_path_.c_str(), &vfs_buf) == -1) {
        int stat_errno = errno;
        spdlog::error(
            "LocalStorage::GetCapacityBytes: statvfs failed for '{}': {}", base_path_.string(),
            std::strerror(stat_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }
    return static_cast<std::uint64_t>(vfs_buf.f_frsize) * vfs_buf.f_blocks;
}

StorageResult<std::uint64_t> LocalStorage::GetUsedBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    // TODO: Implement accurate tracking.
    // For now, estimate based on capacity - available.
    auto capacity_res = GetCapacityBytes();
    if (!capacity_res)
        return std::unexpected(capacity_res.error());
    auto available_res = GetAvailableBytes();
    if (!available_res)
        return std::unexpected(available_res.error());

    if (*capacity_res >= *available_res) {
        return *capacity_res - *available_res;
    } else {
        return 0;
    }
}

StorageResult<std::uint64_t> LocalStorage::GetAvailableBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    struct statvfs vfs_buf;
    if (::statvfs(base_path_.c_str(), &vfs_buf) == -1) {
        int stat_errno = errno;
        spdlog::error(
            "LocalStorage::GetAvailableBytes: statvfs failed for '{}': {}", base_path_.string(),
            std::strerror(stat_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }

    return static_cast<std::uint64_t>(vfs_buf.f_frsize) * vfs_buf.f_bavail;
}

StorageResult<std::size_t> LocalStorage::Read(
    const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& buffer
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (offset < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    int fd = ::open(full_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int open_errno = errno;
        spdlog::trace(
            "LocalStorage::Read open failed for '{}': {}", full_path.string(),
            std::strerror(open_errno)
        );
        if (open_errno == EISDIR)
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        if (open_errno == ENOENT)
            return std::unexpected(make_error_code(Storage::StorageErrc::FileNotFound)
            );  // Cache miss!
        return std::unexpected(make_error_code(ErrnoToStorageErrc(open_errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    ssize_t bytes_read = ::pread(fd, buffer.data(), buffer.size(), static_cast<off_t>(offset));

    if (bytes_read < 0) {
        int read_errno = errno;
        spdlog::error(
            "LocalStorage::Read pread failed for '{}': {}", full_path.string(),
            std::strerror(read_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(read_errno)));
    }

    return static_cast<size_t>(bytes_read);
}

StorageResult<std::size_t> LocalStorage::Write(
    const std::filesystem::path& relative_path, off_t offset, std::span<const std::byte>& data
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (offset < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    auto parent_path = full_path.parent_path();
    std::error_code ec;
    if (!std::filesystem::exists(parent_path, ec)) {
        if (!std::filesystem::create_directories(parent_path, ec)) {
            if (ec || !std::filesystem::exists(parent_path)) {
                spdlog::error(
                    "LocalStorage::Write: Failed create parent cache dir '{}': {}",
                    parent_path.string(), ec ? ec.message() : "Unknown"
                );
                return std::unexpected(MapFilesystemError(
                    ec ? ec : std::make_error_code(std::errc::io_error), "write_create_parent"
                ));
            }
        }
        if (ec) {
            spdlog::error(
                "LocalStorage::Write: Failed create parent cache dir '{}': {}",
                parent_path.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "write_create_parent"));
        }
    } else if (ec) {
        spdlog::error(
            "LocalStorage::Write: Failed check parent cache dir '{}': {}", parent_path.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "write_check_parent"));
    }

    mode_t default_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;  // 0644
    int fd              = ::open(full_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, default_mode);
    if (fd < 0) {
        int open_errno = errno;
        spdlog::error(
            "LocalStorage::Write open failed for '{}': {}", full_path.string(),
            std::strerror(open_errno)
        );
        if (open_errno == EISDIR)
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        return std::unexpected(make_error_code(ErrnoToStorageErrc(open_errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    ssize_t bytes_written = ::pwrite(fd, data.data(), data.size(), static_cast<off_t>(offset));

    if (bytes_written < 0) {
        int write_errno = errno;
        spdlog::error(
            "LocalStorage::Write pwrite failed for '{}': {}", full_path.string(),
            std::strerror(write_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(write_errno)));
    }

    return static_cast<size_t>(bytes_written);
}

StorageResult<void> LocalStorage::Remove(const std::filesystem::path& relative_path)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    spdlog::trace(
        "LocalStorage::Remove called for: {} (relative: {})", full_path.string(),
        relative_path.string()
    );

    auto rem_mtime_res = RemoveXattr(full_path, XATTR_ORIGIN_MTIME_KEY);
    if (!rem_mtime_res && rem_mtime_res.error() != make_error_code(StorageErrc::MetadataNotFound)) {
        spdlog::error(
            "LocalStorage::Remove: Failed to remove mtime xattr for '{}': {}", full_path.string(),
            rem_mtime_res.error().message()
        );
    }
    auto rem_size_res = RemoveXattr(full_path, XATTR_ORIGIN_SIZE_KEY);
    if (!rem_size_res && rem_size_res.error() != make_error_code(StorageErrc::MetadataNotFound)) {
        spdlog::error(
            "LocalStorage::Remove: Failed to remove size xattr for '{}': {}", full_path.string(),
            rem_size_res.error().message()
        );
    }

    std::string full_path_str = full_path.string();
    std::string base_path_str = base_path_.string();

    if (!full_path_str.empty() &&
        full_path_str.back() == std::filesystem::path::preferred_separator) {
        full_path_str.pop_back();
    }
    if (!base_path_str.empty() &&
        base_path_str.back() == std::filesystem::path::preferred_separator) {
        base_path_str.pop_back();
    }

    if (full_path_str == base_path_str) {
        spdlog::trace(
            "LocalStorage::Remove: Attempted to remove base path '{}' for relative path '{}'. "
            "Skipping deletion.",
            base_path_.string(), relative_path.string()
        );
        // TODO: Decide what invalidating '.' should mean. Maybe clear contents?
        return {};
    }

    std::error_code ec;

    if (!std::filesystem::remove(full_path, ec)) {
        if (ec) {
            if (ec != std::errc::no_such_file_or_directory) {
                spdlog::warn(
                    "LocalStorage::Remove failed for '{}': {}", full_path.string(), ec.message()
                );
                return std::unexpected(MapFilesystemError(ec, "remove"));
            }
        } else {
            spdlog::trace("LocalStorage::Remove: Path '{}' did not exist.", full_path.string());
        }
    }

    return {};
}

StorageResult<void> LocalStorage::Truncate(const std::filesystem::path& relative_path, off_t size)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (size < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    if (::truncate(full_path.c_str(), size) == -1) {
        int trunc_errno = errno;

        if (trunc_errno == ENOENT) {
            return std::unexpected(make_error_code(StorageErrc::FileNotFound));
        }
        if (trunc_errno == EISDIR) {
            return std::unexpected(make_error_code(StorageErrc::IsADirectory));
        }

        spdlog::error(
            "LocalStorage::Truncate failed for '{}': {}", full_path.string(),
            std::strerror(trunc_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(trunc_errno)));
    }

    return {};
}

StorageResult<bool> LocalStorage::CheckIfFileExists(const std::filesystem::path& relative_path
) const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    std::error_code ec;
    bool exists = std::filesystem::exists(full_path, ec);
    if (ec) {
        spdlog::warn(
            "LocalStorage::CheckIfFileExists: Error checking existence for '{}': {}",
            full_path.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "probe"));
    }
    return exists;
}

StorageResult<struct stat> LocalStorage::GetAttributes(const std::filesystem::path& relative_path
) const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    struct stat stbuf{};
    if (::stat(full_path.c_str(), &stbuf) == -1) {
        int stat_errno = errno;

        if (stat_errno == ENOENT) {
            return std::unexpected(make_error_code(StorageErrc::FileNotFound));
        }

        spdlog::warn(
            "LocalStorage::GetAttributes: stat failed for '{}': {}", full_path.string(),
            std::strerror(stat_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }
    // Note: This returns attributes of the cached copy.
    // Caller (CacheCoordinator) needs to compare with origin if needed.
    return stbuf;
}

LocalStorage::LocalStorage(const Config::StorageDefinition& definition)
{
    // TODO
}

}  // namespace DistributedCacheFS::Storage
