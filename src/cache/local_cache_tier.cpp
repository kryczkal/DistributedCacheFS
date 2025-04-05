#include "cache/local_cache_tier.hpp"
#include <fcntl.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <system_error>

namespace DistributedCacheFS::Cache
{

namespace  // Anonymous namespace
{

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
            return Storage::StorageErrc::InvalidOffset;  // Or InvalidPath etc.
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
        // Map more errors as needed
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

LocalCacheTier::LocalCacheTier(const Config::CacheTierDefinition& definition)
    : definition_(definition), base_path_(definition.path)
{
    if (base_path_.empty()) {
        throw std::invalid_argument("LocalCacheTier requires a non-empty path.");
    }
    base_path_ = std::filesystem::absolute(base_path_).lexically_normal();
    spdlog::debug("LocalCacheTier created for path: {}", base_path_.string());
}

std::filesystem::path LocalCacheTier::GetFullPath(const std::filesystem::path& relative_path) const
{
    auto combined        = (base_path_ / relative_path).lexically_normal();
    std::string base_str = base_path_.string();
    if (base_str.back() != std::filesystem::path::preferred_separator) {
        base_str += std::filesystem::path::preferred_separator;
    }
    if (combined.string().rfind(base_str, 0) != 0 && combined != base_path_) {
        spdlog::warn(
            "LocalCacheTier: Potential path traversal: relative='{}', combined='{}', base='{}'",
            relative_path.string(), combined.string(), base_path_.string()
        );
        return {};
    }
    return combined;
}

std::filesystem::path LocalCacheTier::GetValidatedFullPath(
    const std::filesystem::path& relative_path
) const
{
    auto full_path = GetFullPath(relative_path);
    if (full_path.empty()) {
        return {};
    }
    return full_path;
}

std::error_code LocalCacheTier::MapFilesystemError(
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
            "LocalCacheTier::MapFilesystemError: Unmapped error during '{}': code={}, category={}, "
            "message='{}'",
            operation.empty() ? "op" : operation, ec.value(), ec.category().name(), ec.message()
        );
    } else {
        spdlog::trace(
            "LocalCacheTier::MapFilesystemError: Mapped error during '{}': {} -> {}",
            operation.empty() ? "op" : operation, ec.message(), static_cast<int>(storage_errc)
        );
    }
    return Storage::make_error_code(storage_errc);
}

// ICacheTier Implementation

StorageResult<void> LocalCacheTier::Initialize()
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    std::error_code ec;

    if (!std::filesystem::exists(base_path_, ec)) {
        spdlog::info(
            "LocalCacheTier: Cache path '{}' does not exist, creating.", base_path_.string()
        );
        if (!std::filesystem::create_directories(base_path_, ec)) {
            if (ec) {
                spdlog::error(
                    "LocalCacheTier: Failed create cache dir '{}': {}", base_path_.string(),
                    ec.message()
                );
                return std::unexpected(MapFilesystemError(ec, "init_create_dir"));
            }
            // If no error, check again (race?)
            if (!std::filesystem::is_directory(base_path_, ec)) {
                spdlog::error(
                    "LocalCacheTier: Failed verify cache dir '{}' after creation.",
                    base_path_.string()
                );
                return std::unexpected(MapFilesystemError(
                    ec ? ec : std::make_error_code(std::errc::io_error), "init_verify_dir"
                ));
            }
        }
        if (ec) {
            spdlog::error(
                "LocalCacheTier: Failed create cache dir '{}': {}", base_path_.string(),
                ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "init_create_dir"));
        }
        spdlog::info(
            "LocalCacheTier: Successfully created cache directory: {}", base_path_.string()
        );
    } else if (ec) {
        spdlog::error(
            "LocalCacheTier: Error checking cache path '{}': {}", base_path_.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "init_check_exists"));
    } else if (!std::filesystem::is_directory(base_path_, ec)) {
        spdlog::error(
            "LocalCacheTier: Cache path '{}' exists but is not a directory.", base_path_.string()
        );
        return std::unexpected(make_error_code(StorageErrc::NotADirectory));
    } else if (ec) {
        spdlog::error(
            "LocalCacheTier: Error checking cache path type '{}': {}", base_path_.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "init_check_type"));
    } else {
        spdlog::info(
            "LocalCacheTier initialized using existing directory: {}", base_path_.string()
        );
    }

    // TODO: Scan existing cache contents to populate initial metadata (access_times_, used_bytes_)

    return {};
}

StorageResult<void> LocalCacheTier::Shutdown()
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    spdlog::debug("Shutting down LocalCacheTier for path: {}", base_path_.string());
    // TODO: Clear cache metadata, close any open file descriptors, etc.
    access_times_.clear();
    return {};
}

StorageResult<std::uint64_t> LocalCacheTier::GetCapacityBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    struct statvfs vfs_buf;
    if (::statvfs(base_path_.c_str(), &vfs_buf) == -1) {
        int stat_errno = errno;
        spdlog::error(
            "LocalCacheTier::GetCapacityBytes: statvfs failed for '{}': {}", base_path_.string(),
            std::strerror(stat_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }
    return static_cast<std::uint64_t>(vfs_buf.f_frsize) * vfs_buf.f_blocks;
}

StorageResult<std::uint64_t> LocalCacheTier::GetUsedBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
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

StorageResult<std::uint64_t> LocalCacheTier::GetAvailableBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    struct statvfs vfs_buf;
    if (::statvfs(base_path_.c_str(), &vfs_buf) == -1) {
        int stat_errno = errno;
        spdlog::error(
            "LocalCacheTier::GetAvailableBytes: statvfs failed for '{}': {}", base_path_.string(),
            std::strerror(stat_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }

    return static_cast<std::uint64_t>(vfs_buf.f_frsize) * vfs_buf.f_bavail;
}

StorageResult<std::size_t> LocalCacheTier::Read(
    const std::filesystem::path& relative_path, off_t offset, std::span<std::byte> buffer
)
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (offset < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    int fd = ::open(full_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int open_errno = errno;
        spdlog::trace(
            "LocalCacheTier::Read open failed for '{}': {}", full_path.string(),
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
            "LocalCacheTier::Read pread failed for '{}': {}", full_path.string(),
            std::strerror(read_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(read_errno)));
    }

    return static_cast<size_t>(bytes_read);
}

StorageResult<std::size_t> LocalCacheTier::Write(
    const std::filesystem::path& relative_path, off_t offset, std::span<const std::byte> data
)
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
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
                    "LocalCacheTier::Write: Failed create parent cache dir '{}': {}",
                    parent_path.string(), ec ? ec.message() : "Unknown"
                );
                return std::unexpected(MapFilesystemError(
                    ec ? ec : std::make_error_code(std::errc::io_error), "write_create_parent"
                ));
            }
        }
        if (ec) {
            spdlog::error(
                "LocalCacheTier::Write: Failed create parent cache dir '{}': {}",
                parent_path.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "write_create_parent"));
        }
    } else if (ec) {
        spdlog::error(
            "LocalCacheTier::Write: Failed check parent cache dir '{}': {}", parent_path.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "write_check_parent"));
    }

    mode_t default_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;  // 0644
    int fd              = ::open(full_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, default_mode);
    if (fd < 0) {
        int open_errno = errno;
        spdlog::error(
            "LocalCacheTier::Write open failed for '{}': {}", full_path.string(),
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
            "LocalCacheTier::Write pwrite failed for '{}': {}", full_path.string(),
            std::strerror(write_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(write_errno)));
    }

    UpdateMetaOnWrite(full_path);

    return static_cast<size_t>(bytes_written);
}

StorageResult<void> LocalCacheTier::Remove(const std::filesystem::path& relative_path)
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    spdlog::trace(
        "LocalCacheTier::Remove called for: {} (relative: {})", full_path.string(),
        relative_path.string()
    );

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
            "LocalCacheTier::Remove: Attempted to remove base path '{}' for relative path '{}'. "
            "Skipping deletion.",
            base_path_.string(), relative_path.string()
        );
        // TODO: Decide what invalidating '.' should mean. Maybe clear contents?
        RemoveMeta(full_path);
        return {};
    }

    std::error_code ec;

    if (!std::filesystem::remove(full_path, ec)) {
        if (ec) {
            if (ec != std::errc::no_such_file_or_directory) {
                spdlog::warn(
                    "LocalCacheTier::Remove failed for '{}': {}", full_path.string(), ec.message()
                );
                return std::unexpected(MapFilesystemError(ec, "remove"));
            }
        } else {
            spdlog::trace("LocalCacheTier::Remove: Path '{}' did not exist.", full_path.string());
        }
    }

    // Remove from internal tracking regardless of filesystem result
    RemoveMeta(full_path);

    return {};
}

StorageResult<void> LocalCacheTier::Truncate(const std::filesystem::path& relative_path, off_t size)
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
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
            "LocalCacheTier::Truncate failed for '{}': {}", full_path.string(),
            std::strerror(trunc_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(trunc_errno)));
    }

    // Update meta (size changed)
    UpdateMetaOnWrite(full_path);

    return {};
}

StorageResult<bool> LocalCacheTier::Probe(const std::filesystem::path& relative_path) const
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    std::error_code ec;
    bool exists = std::filesystem::exists(full_path, ec);
    if (ec) {
        spdlog::warn(
            "LocalCacheTier::Probe: Error checking existence for '{}': {}", full_path.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "probe"));
    }
    return exists;
}

StorageResult<struct stat> LocalCacheTier::GetAttributes(const std::filesystem::path& relative_path
) const
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
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
            "LocalCacheTier::GetAttributes: stat failed for '{}': {}", full_path.string(),
            std::strerror(stat_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }
    // Note: This returns attributes of the cached copy.
    // Caller (CacheCoordinator) needs to compare with origin if needed.
    return stbuf;
}

/// This function needs to be called after successful reads by the CacheCoordinator
StorageResult<void> LocalCacheTier::UpdateAccessMeta(const std::filesystem::path& relative_path)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    access_times_[full_path.string()] = std::time(nullptr);
    spdlog::trace("Updated access time for {}", full_path.string());
    return {};
}

// TODO: Implement this properly - needs directory iteration and stat
StorageResult<std::vector<CacheItemInfo>> LocalCacheTier::ListCacheContents() const
{
    std::vector<CacheItemInfo> contents;
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);

    std::error_code ec;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                 base_path_, std::filesystem::directory_options::skip_permission_denied, ec
             )) {
            if (ec) {
                spdlog::warn("ListCacheContents: Error iterating: {}", ec.message());
                continue;
            }
            if (entry.is_regular_file(ec) && !ec) {
                CacheItemInfo item;
                item.relative_path = std::filesystem::relative(entry.path(), base_path_);

                struct stat stbuf{};
                if (::stat(entry.path().c_str(), &stbuf) == 0) {
                    item.attributes = stbuf;
                } else {
                    spdlog::trace("ListCacheContents: stat failed for {}", entry.path().string());
                    continue;
                }

                auto it = access_times_.find(entry.path().string());
                if (it != access_times_.end()) {
                    item.last_accessed = it->second;
                } else {
                    item.last_accessed = stbuf.st_atime;
                }
                contents.push_back(std::move(item));

            } else if (ec) {
                spdlog::trace(
                    "ListCacheContents: is_regular_file check failed for {}: {}",
                    entry.path().string(), ec.message()
                );
                ec.clear();
            }
        }
        if (ec) {
            spdlog::error("ListCacheContents: Filesystem error after iteration: {}", ec.message());
            return std::unexpected(MapFilesystemError(ec, "listcontents_end"));
        }
    } catch (const std::exception& e) {
        spdlog::error("ListCacheContents: Exception: {}", e.what());
        return std::unexpected(make_error_code(StorageErrc::UnknownError));
    }

    return contents;
}

// Private Helpers

void LocalCacheTier::UpdateMetaOnWrite(const std::filesystem::path& full_path)
{
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    access_times_[full_path.string()] = std::time(nullptr);
    // TODO: Update current_used_bytes_ if tracking dynamically
    spdlog::trace("Updated write/access meta for {}", full_path.string());
}

void LocalCacheTier::RemoveMeta(const std::filesystem::path& full_path)
{
    // Called after Remove
    std::lock_guard<std::recursive_mutex> lock(tier_mutex_);
    auto it = access_times_.find(full_path.string());
    if (it != access_times_.end()) {
        access_times_.erase(it);
        spdlog::trace("Removed access meta for {}", full_path.string());
    }
    // TODO: Update current_used_bytes_ if tracking dynamically
}

}  // namespace DistributedCacheFS::Cache
