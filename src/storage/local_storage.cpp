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

    // TODO: Scan existing cache contents to populate initial metadata (access_times_, used_bytes_)

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
    if (definition_.max_size_bytes.has_value()) {
        spdlog::trace(
            "LocalStorage::GetCapacityBytes -> {}",
            std::min(space.capacity, *definition_.max_size_bytes)
        );
        return std::min(space.capacity, *definition_.max_size_bytes);
    }
    spdlog::trace("LocalStorage::GetCapacityBytes -> {}", space.capacity);
    return space.capacity;
}

StorageResult<std::uint64_t> LocalStorage::GetUsedBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::trace("LocalStorage::GetUsedBytes()");

    // TODO: Implement accurate tracking of used bytes.
    // This currently estimates based on capacity - available from fs::space_info,
    // which is NOT accurate if definition_.max_size_bytes is set and it's different
    //
    // For accurate cache eviction, this MUST return the sum of sizes of all files
    // and directories managed by this LocalStorage instance within its base_path_.
    //
    // Suggested approach:
    // 1. Add a member: `mutable std::uint64_t current_managed_size_bytes_ = 0;`
    // 2. Add a member: `mutable bool has_scanned_initial_size_ = false;`
    // 3. In Initialize():
    //    - Scan base_path_ recursively.
    //    - Sum the sizes of all files.
    //    - Store in `current_managed_size_bytes_`.
    //    - Set `has_scanned_initial_size_ = true;`
    // 4. In Write(), CreateFile(), Truncate():
    //    - Atomically update `current_managed_size_bytes_` based on the change in file size.
    //    - Be careful with Truncate: it can increase or decrease size.
    //    - Ensure these operations correctly report the number of bytes *actually* written/changed.
    // 5. In Remove():
    //    - Atomically decrement `current_managed_size_bytes_` by the size of the removed file.
    // 6. GetUsedBytes() would then simply return `current_managed_size_bytes_`.
    //    (after ensuring initial scan has happened).
    //
    // For now, using a highly simplified and potentially INACCURATE estimation for placeholder:
    // This estimation will behave poorly if max_size_bytes is much smaller than actual disk space.
    fs::space_info space_val = fs::space(base_path_);
    uint64_t actual_capacity = space_val.capacity;
    uint64_t actual_free     = space_val.free;
    uint64_t actual_used     = actual_capacity > actual_free ? actual_capacity - actual_free : 0;

    if (definition_.max_size_bytes.has_value()) {
        uint64_t result = std::min(actual_used, *definition_.max_size_bytes);
        spdlog::trace("LocalStorage::GetUsedBytes -> {}", result);
        return result;
    }
    spdlog::trace("LocalStorage::GetUsedBytes -> {}", actual_used);
    return actual_used;
}

StorageResult<std::uint64_t> LocalStorage::GetAvailableBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::trace("LocalStorage::GetAvailableBytes()");
    std::error_code ec;
    fs::space_info space = fs::space(base_path_, ec);  // Actual free space on the physical device
    if (ec) {
        spdlog::error(
            "LocalStorage::GetAvailableBytes: fs::space failed for '{}': {}", base_path_.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "get_available"));
    }

    uint64_t actual_filesystem_free_space = space.available;
    uint64_t result;

    if (definition_.max_size_bytes.has_value()) {
        uint64_t defined_capacity = *definition_.max_size_bytes;

        // This relies on GetUsedBytes() being accurate.
        auto used_bytes_res = GetUsedBytes();
        if (!used_bytes_res) {
            spdlog::error(
                "LocalStorage::GetAvailableBytes: Failed to get used bytes: {}",
                used_bytes_res.error().message()
            );
            return std::unexpected(used_bytes_res.error());
        }
        uint64_t current_managed_used_bytes = used_bytes_res.value();

        uint64_t available_within_defined_limit;
        if (defined_capacity <= current_managed_used_bytes) {
            available_within_defined_limit = 0;
        } else {
            available_within_defined_limit = defined_capacity - current_managed_used_bytes;
        }
        spdlog::trace(
            "LocalStorage::GetAvailableBytes -> {} (defined limit) vs {} (actual)",
            available_within_defined_limit, actual_filesystem_free_space
        );
        result = std::min(available_within_defined_limit, actual_filesystem_free_space);
        return result;
    }
    result = actual_filesystem_free_space;
    spdlog::trace("LocalStorage::GetAvailableBytes -> {}", result);
    return result;
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

    spdlog::trace("LocalStorage::Write -> {} bytes written", bytes_written);
    return static_cast<size_t>(bytes_written);
}

StorageResult<void> LocalStorage::Remove(const std::filesystem::path& relative_path)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::Remove({})", relative_path.string());
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        spdlog::trace("LocalStorage::Remove -> InvalidPath");
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

    spdlog::trace("LocalStorage::Remove -> Success");
    return {};
}

StorageResult<void> LocalStorage::Truncate(const std::filesystem::path& relative_path, off_t size)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    spdlog::debug("LocalStorage::Truncate({}, {})", relative_path.string(), size);
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
    if (full_path.empty()) {
        spdlog::trace("LocalStorage::CreateFile -> InvalidPath");
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    auto parent = full_path.parent_path();
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        return std::unexpected(MapFilesystemError(ec, "create_file_parent"));
    }
    std::ofstream ofs(full_path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        return std::unexpected(make_error_code(StorageErrc::IOError));
    }
    ofs.close();
    std::filesystem::perms perms = static_cast<std::filesystem::perms>(0);
    if (mode & S_IRUSR)
        perms |= std::filesystem::perms::owner_read;
    if (mode & S_IWUSR)
        perms |= std::filesystem::perms::owner_write;
    if (mode & S_IRGRP)
        perms |= std::filesystem::perms::group_read;
    if (mode & S_IWGRP)
        perms |= std::filesystem::perms::group_write;
    if (mode & S_IROTH)
        perms |= std::filesystem::perms::others_read;
    if (mode & S_IWOTH)
        perms |= std::filesystem::perms::others_write;
    std::filesystem::permissions(full_path, perms, ec);
    if (ec) {
        return std::unexpected(MapFilesystemError(ec, "create_file_perm"));
    }
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
    if (full_path.empty()) {
        spdlog::trace("LocalStorage::CreateDirectory -> InvalidPath");
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    std::error_code ec;
    // Create directory and all parents
    if (!fs::create_directories(full_path, ec) && ec) {
        spdlog::error(
            "LocalStorage::CreateDirectory: Failed to create directory '{}': {}",
            full_path.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "create_directory"));
    }
    // Set permissions from mode
    std::filesystem::perms perms = static_cast<std::filesystem::perms>(0);
    if (mode & S_IRUSR)
        perms |= std::filesystem::perms::owner_read;
    if (mode & S_IWUSR)
        perms |= std::filesystem::perms::owner_write;
    if (mode & S_IRGRP)
        perms |= std::filesystem::perms::group_read;
    if (mode & S_IWGRP)
        perms |= std::filesystem::perms::group_write;
    if (mode & S_IROTH)
        perms |= std::filesystem::perms::others_read;
    if (mode & S_IWOTH)
        perms |= std::filesystem::perms::others_write;
    std::filesystem::permissions(full_path, perms, ec);
    if (ec) {
        spdlog::error(
            "LocalStorage::CreateDirectory: Failed to set permissions on '{}': {}",
            full_path.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "create_directory_perm"));
    }
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

}  // namespace DistributedCacheFS::Storage
