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

namespace fs = std::filesystem;

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
    spdlog::debug("LocalStorage::SetXattr({}, {}, value_ptr, {})", full_path.string(), key, size);
    if (::setxattr(full_path.c_str(), key, value, size, 0) == -1) {
        int xattr_errno = errno;
        spdlog::warn(
            "LocalStorage::SetXattr failed for key '{}' on '{}': {}", key, full_path.string(),
            std::strerror(xattr_errno)
        );
        return std::unexpected(make_error_code(XattrErrnoToStorageErrc(xattr_errno)));
    }
    spdlog::trace("LocalStorage::SetXattr -> Success");
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
    spdlog::debug("LocalStorage::RemoveXattr({}, {})", full_path.string(), key);
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
    spdlog::trace("LocalStorage::RemoveXattr -> Success");
    return {};
}

std::filesystem::path LocalStorage::RelativeToAbsPath(const std::filesystem::path& relative_path
) const
{
    std::error_code ec;
    auto full = fs::weakly_canonical(base_path_ / relative_path, ec);
    if (ec)
        return {};

    auto base_can = fs::weakly_canonical(base_path_, ec);
    if (ec)
        return {};

    const std::string full_str = full.string();
    const std::string base_str = base_can.string();

    if (full_str.rfind(base_str, 0) != 0) {
        spdlog::warn("LocalStorage: path traversal attempt: {}", relative_path.string());
        return {};
    }
    return full;
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
    spdlog::debug("LocalStorage::Initialize()");
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

    if (definition_.max_size_bytes.has_value()) {
        stats_.SetMaxSizeBytes(definition_.max_size_bytes.value());
        stats_.SetUsesSizeTracking(true);
    } else {
        stats_.SetUsesSizeTracking(false);
    }
    // Scan existing cache contents to populate initial metadata (stats_)
    for (const auto& entry : std::filesystem::recursive_directory_iterator(base_path_)) {
        if (entry.is_regular_file()) {
            std::error_code ec;
            uintmax_t file_size = entry.file_size(ec);
            if (ec) {
                spdlog::warn(
                    "LocalStorage: Failed to get file size for '{}' during initial scan: {}",
                    entry.path().string(), ec.message()
                );
                continue;
            }
            stats_.IncrementSizeBytes(file_size);
        }
    }

    spdlog::trace("LocalStorage::Initialize -> Success");
    return {};
}

StorageResult<void> LocalStorage::Shutdown()
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::Shutdown() for path: {}", base_path_.string());
    // No specific action currently needed on shutdown

    spdlog::trace("LocalStorage::Shutdown -> Success");
    return {};
}

StorageResult<std::uint64_t> LocalStorage::GetCapacityBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::trace("LocalStorage::GetCapacityBytes()");
    std::error_code ec;
    fs::space_info space = fs::space(base_path_, ec);
    if (ec) {
        spdlog::error(
            "LocalStorage::GetCapacityBytes: fs::space failed for '{}': {}", base_path_.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "get_capacity"));
    }
    auto capacity = space.capacity;
    if (stats_.UsesSizeTracking()) {
        capacity = std::min(capacity, stats_.GetMaxSizeBytes());
    }
    spdlog::trace("LocalStorage::GetCapacityBytes -> {}", capacity);
    return capacity;
}

StorageResult<std::uint64_t> LocalStorage::GetUsedBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::trace("LocalStorage::GetUsedBytes()");

    uint64_t actual_used = 0;
    if (stats_.UsesSizeTracking()) {
        actual_used = stats_.GetCurrentSizeBytes();
    } else {
        fs::space_info space_val = fs::space(base_path_);
        uint64_t actual_capacity = space_val.capacity;
        uint64_t actual_free     = space_val.free;
        actual_used = actual_capacity > actual_free ? actual_capacity - actual_free : 0;
    }
    spdlog::trace("LocalStorage::GetUsedBytes -> {}", actual_used);
    return actual_used;
}

StorageResult<std::uint64_t> LocalStorage::GetAvailableBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::trace("LocalStorage::GetAvailableBytes()");
    std::error_code ec;
    auto available = 0;
    if (stats_.UsesSizeTracking()) {
        if (stats_.GetCurrentSizeBytes() < stats_.GetMaxSizeBytes()) {
            available = stats_.GetMaxSizeBytes() - stats_.GetCurrentSizeBytes();
        } else {
            available = 0;
        }
    } else {
        fs::space_info space = fs::space(base_path_, ec);
        if (ec) {
            spdlog::error(
                "LocalStorage::GetAvailableBytes: fs::space failed for '{}': {}",
                base_path_.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "get_available"));
        }
        available = space.available;
    }
    spdlog::trace("LocalStorage::GetAvailableBytes -> {}", available);
    return available;
}

StorageResult<std::size_t> LocalStorage::Read(
    const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& buffer
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug(
        "LocalStorage::Read({}, {}, buffer_size={})", relative_path.string(), offset, buffer.size()
    );
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

    spdlog::trace("LocalStorage::Read -> {} bytes read", bytes_read);
    return static_cast<size_t>(bytes_read);
}

StorageResult<std::size_t> LocalStorage::Write(
    const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& data
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug(
        "LocalStorage::Write({}, {}, data_size={})", relative_path.string(), offset, data.size()
    );

    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (offset < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    // Determine file size before the write-operation
    off_t old_size = 0;
    if (stats_.UsesSizeTracking()) {
        struct stat st{};
        if (::lstat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
            old_size = st.st_size;
    }

    // Capacity guard – reject if the growth would exceed max_size_bytes_
    const off_t new_size  = std::max<off_t>(old_size, offset + static_cast<off_t>(data.size()));
    const uint64_t growth = (new_size > old_size) ? static_cast<uint64_t>(new_size - old_size) : 0;

    if (stats_.UsesSizeTracking() && growth > 0) {
        auto avail_res = GetAvailableBytes();
        if (!avail_res) {
            return std::unexpected(avail_res.error());
        }
        if (growth > *avail_res) {
            spdlog::warn(
                "LocalStorage::Write: Out of space – need {} bytes, only {} bytes left.", growth,
                *avail_res
            );
            return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
        }
    }

    // Ensure parent directory exists
    const auto parent_path = full_path.parent_path();
    std::error_code ec;
    if (!std::filesystem::exists(parent_path, ec)) {
        if (!std::filesystem::create_directories(parent_path, ec) ||
            (ec && !std::filesystem::exists(parent_path))) {
            spdlog::error(
                "LocalStorage::Write: Failed create parent cache dir '{}': {}",
                parent_path.string(), ec ? ec.message() : "Unknown"
            );
            return std::unexpected(MapFilesystemError(
                ec ? ec : std::make_error_code(std::errc::io_error), "write_create_parent"
            ));
        }
    } else if (ec) {
        spdlog::error(
            "LocalStorage::Write: Failed check parent cache dir '{}': {}", parent_path.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "write_check_parent"));
    }

    // Open/create file and perform the write
    constexpr mode_t default_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;  // 0644
    const int fd = ::open(full_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, default_mode);
    if (fd < 0) {
        const int open_errno = errno;
        spdlog::error(
            "LocalStorage::Write open failed for '{}': {}", full_path.string(),
            std::strerror(open_errno)
        );
        if (open_errno == EISDIR)
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        return std::unexpected(make_error_code(ErrnoToStorageErrc(open_errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    // Perform the write
    const ssize_t bytes_written =
        ::pwrite(fd, data.data(), data.size(), static_cast<off_t>(offset));
    if (bytes_written < 0) {
        const int write_errno = errno;
        spdlog::error(
            "LocalStorage::Write pwrite failed for '{}': {}", full_path.string(),
            std::strerror(write_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(write_errno)));
    }

    // Update used-bytes counter if enabled
    if (stats_.UsesSizeTracking()) {
        struct stat st_after{};
        if (::fstat(fd, &st_after) == 0 && S_ISREG(st_after.st_mode)) {
            const off_t new_size = st_after.st_size;
            if (new_size > old_size) {
                stats_.IncrementSizeBytes(static_cast<uint64_t>(new_size - old_size));
            } else if (new_size < old_size) {
                stats_.DecrementSizeBytes(static_cast<uint64_t>(old_size - new_size));
            }
        }
    }

    spdlog::trace("LocalStorage::Write -> {} bytes written", bytes_written);
    return static_cast<size_t>(bytes_written);
}

StorageResult<void> LocalStorage::Remove(const std::filesystem::path& relative_path)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::Remove({})", relative_path.string());

    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    // Capture size prior to removal (only for regular files & tracking)
    uint64_t size_to_remove = 0;
    if (stats_.UsesSizeTracking()) {
        struct stat st{};
        if (::lstat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
            size_to_remove = static_cast<uint64_t>(st.st_size);
    }

    // Remove extended attributes
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

    // Guard against accidental base-path deletion
    std::string full_path_str = full_path.string();
    std::string base_path_str = base_path_.string();
    if (!full_path_str.empty() && full_path_str.back() == fs::path::preferred_separator)
        full_path_str.pop_back();
    if (!base_path_str.empty() && base_path_str.back() == fs::path::preferred_separator)
        base_path_str.pop_back();
    if (full_path_str == base_path_str) {
        spdlog::trace(
            "LocalStorage::Remove: Attempt to remove base path '{}'. Skipping.", base_path_.string()
        );
        return {};
    }

    // Actual filesystem removal
    std::error_code ec;
    if (!std::filesystem::remove(full_path, ec)) {
        if (ec && ec != std::errc::no_such_file_or_directory) {
            spdlog::warn(
                "LocalStorage::Remove failed for '{}': {}", full_path.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "remove"));
        }
    } else if (stats_.UsesSizeTracking() && size_to_remove > 0) {
        stats_.DecrementSizeBytes(size_to_remove);
    }

    spdlog::trace("LocalStorage::Remove -> Success");
    return {};
}

StorageResult<void> LocalStorage::Truncate(const std::filesystem::path& relative_path, off_t size)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::Truncate({}, {})", relative_path.string(), size);

    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (size < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    // Obtain previous file size if we track
    off_t old_size = 0;
    if (stats_.UsesSizeTracking()) {
        struct stat st{};
        if (::lstat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
            old_size = st.st_size;
    }
    // Guard against quota overflow when growing the file
    if (stats_.UsesSizeTracking() && size > old_size) {
        uint64_t growth = static_cast<uint64_t>(size - old_size);
        auto avail_res  = GetAvailableBytes();
        if (!avail_res) {
            return std::unexpected(avail_res.error());
        }
        if (growth > *avail_res) {
            spdlog::warn(
                "LocalStorage::Truncate: Out of space – need {} bytes, only {} bytes left.", growth,
                *avail_res
            );
            return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
        }
    }

    // Perform truncate
    if (::truncate(full_path.c_str(), size) == -1) {
        const int trunc_errno = errno;
        if (trunc_errno == ENOENT)
            return std::unexpected(make_error_code(StorageErrc::FileNotFound));
        if (trunc_errno == EISDIR)
            return std::unexpected(make_error_code(StorageErrc::IsADirectory));

        spdlog::error(
            "LocalStorage::Truncate failed for '{}': {}", full_path.string(),
            std::strerror(trunc_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(trunc_errno)));
    }

    // Update stats delta
    if (stats_.UsesSizeTracking()) {
        if (size > old_size) {
            stats_.IncrementSizeBytes(static_cast<uint64_t>(size - old_size));
        } else if (size < old_size) {
            stats_.DecrementSizeBytes(static_cast<uint64_t>(old_size - size));
        }
    }

    spdlog::trace("LocalStorage::Truncate -> Success");
    return {};
}

StorageResult<bool> LocalStorage::CheckIfFileExists(const std::filesystem::path& relative_path
) const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::CheckIfFileExists({})", relative_path.string());
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        spdlog::trace("LocalStorage::CheckIfFileExists -> InvalidPath");
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
    spdlog::trace("LocalStorage::CheckIfFileExists -> {}", exists);
    return exists;
}
StorageResult<void> LocalStorage::CreateFile(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::CreateFile({}, {:o})", relative_path.string(), mode);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    // Create parent directories if missing
    std::error_code ec;
    std::filesystem::create_directories(full_path.parent_path(), ec);
    if (ec)
        return std::unexpected(MapFilesystemError(ec, "create_file_parent"));

    // Create & close empty file
    std::ofstream ofs(full_path, std::ios::binary | std::ios::trunc);
    if (!ofs)
        return std::unexpected(make_error_code(StorageErrc::IOError));
    ofs.close();

    // Apply permissions incl. execute bits
    std::filesystem::perms perms{};
    auto add = [&](mode_t m, std::filesystem::perms p) {
        if (mode & m)
            perms |= p;
    };
    add(S_IRUSR, std::filesystem::perms::owner_read);
    add(S_IWUSR, std::filesystem::perms::owner_write);
    add(S_IXUSR, std::filesystem::perms::owner_exec);
    add(S_IRGRP, std::filesystem::perms::group_read);
    add(S_IWGRP, std::filesystem::perms::group_write);
    add(S_IXGRP, std::filesystem::perms::group_exec);
    add(S_IROTH, std::filesystem::perms::others_read);
    add(S_IWOTH, std::filesystem::perms::others_write);
    add(S_IXOTH, std::filesystem::perms::others_exec);
    std::filesystem::permissions(full_path, perms, ec);
    if (ec)
        return std::unexpected(MapFilesystemError(ec, "create_file_perm"));

    // special bits
    if (mode & (S_ISUID | S_ISGID | S_ISVTX))
        if (::chmod(full_path.c_str(), mode) == -1)
            return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));

    spdlog::trace("LocalStorage::CreateFile -> Success");
    return {};
}

StorageResult<void> LocalStorage::CreateDirectory(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::CreateDirectory({}, {:o})", relative_path.string(), mode);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    std::error_code ec;
    if (!std::filesystem::create_directories(full_path, ec) && ec)
        return std::unexpected(MapFilesystemError(ec, "create_directory"));

    // Set directory permissions incl. execute/search bits
    std::filesystem::perms perms{};
    auto add = [&](mode_t m, std::filesystem::perms p) {
        if (mode & m)
            perms |= p;
    };
    add(S_IRUSR, std::filesystem::perms::owner_read);
    add(S_IWUSR, std::filesystem::perms::owner_write);
    add(S_IXUSR, std::filesystem::perms::owner_exec);
    add(S_IRGRP, std::filesystem::perms::group_read);
    add(S_IWGRP, std::filesystem::perms::group_write);
    add(S_IXGRP, std::filesystem::perms::group_exec);
    add(S_IROTH, std::filesystem::perms::others_read);
    add(S_IWOTH, std::filesystem::perms::others_write);
    add(S_IXOTH, std::filesystem::perms::others_exec);
    std::filesystem::permissions(full_path, perms, ec);
    if (ec)
        return std::unexpected(MapFilesystemError(ec, "create_directory_perm"));

    // sticky / setgid on directories
    if (mode & (S_ISGID | S_ISVTX))
        if (::chmod(full_path.c_str(), mode) == -1)
            return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));

    spdlog::trace("LocalStorage::CreateDirectory -> Success");
    return {};
}

StorageResult<void> LocalStorage::Move(
    const std::filesystem::path& from_relative_path, const std::filesystem::path& to_relative_path
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug(
        "LocalStorage::Move({}, {})", from_relative_path.string(), to_relative_path.string()
    );
    auto from_full = GetValidatedFullPath(from_relative_path);
    if (from_full.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    auto to_full = GetValidatedFullPath(to_relative_path);
    if (to_full.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    std::error_code ec;
    auto parent = to_full.parent_path();
    if (!parent.empty() && !fs::exists(parent, ec)) {
        fs::create_directories(parent, ec);
        if (ec)
            return std::unexpected(MapFilesystemError(ec, "move_create_parent"));
    } else if (ec) {
        return std::unexpected(MapFilesystemError(ec, "move_check_parent"));
    }

    // TODO: Properly handle quota in edge cases
    std::filesystem::rename(from_full, to_full, ec);
    if (ec)
        return std::unexpected(MapFilesystemError(ec, "move"));

    spdlog::trace("LocalStorage::Move -> Success");
    return {};
}

StorageResult<struct stat> LocalStorage::GetAttributes(const std::filesystem::path& relative_path
) const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::GetAttributes({})", relative_path.string());
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        spdlog::trace("LocalStorage::GetAttributes -> InvalidPath");
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    struct stat stbuf{};
    if (::lstat(full_path.c_str(), &stbuf) == -1) {
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
    spdlog::trace(
        "LocalStorage::GetAttributes -> Success (st_mode={:o}, st_size={})", stbuf.st_mode,
        stbuf.st_size
    );
    return stbuf;
}

LocalStorage::LocalStorage(const Config::StorageDefinition& definition)
    : definition_(definition), base_path_(definition.path)
{
}
StorageResult<std::vector<std::pair<std::string, struct stat>>> LocalStorage::ListDirectory(
    const std::filesystem::path& relative_path
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::ListDirectory({})", relative_path.string());
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        spdlog::trace("LocalStorage::ListDirectory -> InvalidPath");
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    if (!std::filesystem::is_directory(full_path)) {
        return std::unexpected(make_error_code(StorageErrc::NotADirectory));
    }

    std::vector<std::pair<std::string, struct stat>> entries;
    for (const auto& entry : std::filesystem::directory_iterator(full_path)) {
        struct stat stbuf{};
        if (::lstat(entry.path().c_str(), &stbuf) == -1) {
            int stat_errno = errno;
            spdlog::warn(
                "LocalStorage::ListDirectory: lstat failed for '{}': {}", entry.path().string(),
                std::strerror(stat_errno)
            );
            return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
        }
        entries.emplace_back(entry.path().filename().string(), stbuf);
    }
    spdlog::trace("LocalStorage::ListDirectory -> {} entries", entries.size());
    return entries;
}

StorageResult<void> LocalStorage::SetPermissions(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::SetPermissions({}, {:o})", relative_path.string(), mode);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    // Convert POSIX mode → std::filesystem::perms (incl. execute bits)
    std::filesystem::perms perms = std::filesystem::perms::none;
    auto add                     = [&](mode_t m, std::filesystem::perms p) {
        if (mode & m)
            perms |= p;
    };
    add(S_IRUSR, std::filesystem::perms::owner_read);
    add(S_IWUSR, std::filesystem::perms::owner_write);
    add(S_IXUSR, std::filesystem::perms::owner_exec);
    add(S_IRGRP, std::filesystem::perms::group_read);
    add(S_IWGRP, std::filesystem::perms::group_write);
    add(S_IXGRP, std::filesystem::perms::group_exec);
    add(S_IROTH, std::filesystem::perms::others_read);
    add(S_IWOTH, std::filesystem::perms::others_write);
    add(S_IXOTH, std::filesystem::perms::others_exec);

    std::error_code ec;
    std::filesystem::permissions(full_path, perms, ec);
    if (ec)
        return std::unexpected(MapFilesystemError(ec, "chmod"));

    /* Preserve special bits (set-uid, set-gid, sticky) via raw chmod */
    if (mode & (S_ISUID | S_ISGID | S_ISVTX)) {
        if (::chmod(full_path.c_str(), mode) == -1)
            return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }

    spdlog::trace("LocalStorage::SetPermissions -> Success for {}", full_path.string());
    return {};
}

StorageResult<void> LocalStorage::SetOwner(
    const std::filesystem::path& relative_path, uid_t uid, gid_t gid
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::SetOwner({}, {}, {})", relative_path.string(), uid, gid);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        spdlog::error("LocalStorage::SetOwner: Invalid path {}", relative_path.string());
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // -1 for uid or gid means don't change
    if (::chown(full_path.c_str(), uid, gid) == -1) {
        int chown_errno = errno;
        spdlog::error(
            "LocalStorage::SetOwner failed for path {}: {}", full_path.string(),
            std::strerror(chown_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(chown_errno)));
    }

    spdlog::trace("LocalStorage::SetOwner -> Success for {}", full_path.string());
    return {};
}

}  // namespace DistributedCacheFS::Storage
