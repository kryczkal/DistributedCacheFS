#include "origin/local_origin.hpp"
#include <fcntl.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>

namespace DistributedCacheFS::Origin
{

namespace
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

LocalOrigin::LocalOrigin(const Config::OriginDefinition& definition)
    : definition_(definition), base_path_(definition.path)
{
    if (base_path_.empty()) {
        throw std::invalid_argument("LocalOrigin requires a non-empty path.");
    }

    base_path_ = std::filesystem::absolute(base_path_).lexically_normal();
    spdlog::debug("LocalOrigin created for path: {}", base_path_.string());
}

std::filesystem::path LocalOrigin::GetFullPath(const std::filesystem::path& relative_path) const
{
    auto combined = (base_path_ / relative_path).lexically_normal();

    std::string base_str = base_path_.string();
    if (base_str.back() != std::filesystem::path::preferred_separator) {
        base_str += std::filesystem::path::preferred_separator;
    }
    if (combined.string().rfind(base_str, 0) != 0 && combined != base_path_) {
        spdlog::warn(
            "LocalOrigin: Potential path traversal detected: relative='{}', combined='{}', "
            "base='{}'",
            relative_path.string(), combined.string(), base_path_.string()
        );

        return {};
    }
    return combined;
}

// Private helper to get path
std::filesystem::path LocalOrigin::GetValidatedFullPath(const std::filesystem::path& relative_path
) const
{
    auto full_path = GetFullPath(relative_path);
    if (full_path.empty()) {
        return {};
    }
    return full_path;
}

std::error_code LocalOrigin::MapFilesystemError(
    const std::error_code& ec, const std::string& operation
) const
{
    if (!ec)
        return {};

    Storage::StorageErrc storage_errc = Storage::StorageErrc::UnknownError;
    if (ec.category() == std::generic_category()) {
        storage_errc = ErrnoToStorageErrc(ec.value());
    } else if (ec.category() == std::system_category()) {
        storage_errc = ErrnoToStorageErrc(ec.value());
    }

    if (storage_errc == Storage::StorageErrc::UnknownError && ec.value() != 0) {
        spdlog::warn(
            "LocalOrigin::MapFilesystemError: Unmapped error during '{}': code={}, category={}, "
            "message='{}'",
            operation.empty() ? "operation" : operation, ec.value(), ec.category().name(),
            ec.message()
        );
    } else {
        spdlog::trace(
            "LocalOrigin::MapFilesystemError: Mapped error during '{}': code={}, category={}, "
            "message='{}' to StorageErrc {}",
            operation.empty() ? "operation" : operation, ec.value(), ec.category().name(),
            ec.message(), static_cast<int>(storage_errc)
        );
    }

    return Storage::make_error_code(storage_errc);
}

// IOriginInterface Implementation

Storage::StorageResult<void> LocalOrigin::Initialize()
{
    std::error_code ec;
    if (!std::filesystem::exists(base_path_, ec)) {
        spdlog::error(
            "LocalOrigin Initialize: Origin path '{}' does not exist.", base_path_.string()
        );
        return std::unexpected(MapFilesystemError(
            ec ? ec : std::make_error_code(std::errc::no_such_file_or_directory),
            "initialize_check_exists"
        ));
    }
    if (ec) {
        spdlog::error(
            "LocalOrigin Initialize: Error checking existence of origin path '{}': {}",
            base_path_.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "initialize_check_exists"));
    }
    if (!std::filesystem::is_directory(base_path_, ec)) {
        spdlog::error(
            "LocalOrigin Initialize: Origin path '{}' is not a directory.", base_path_.string()
        );
        return std::unexpected(MapFilesystemError(
            ec ? ec : std::make_error_code(std::errc::not_a_directory), "initialize_check_isdir"
        ));
    }
    if (ec) {
        spdlog::error(
            "LocalOrigin Initialize: Error checking type of origin path '{}': {}",
            base_path_.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "initialize_check_isdir"));
    }

    spdlog::info("LocalOrigin initialized using path: {}", base_path_.string());
    return {};
}

Storage::StorageResult<void> LocalOrigin::Shutdown()
{
    spdlog::debug("LocalOrigin shutting down for path: {}", base_path_.string());
    // No specific action needed for local directory origin
    return {};
}

Storage::StorageResult<struct stat> LocalOrigin::GetAttributes(
    const std::filesystem::path& relative_path
)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    struct stat stbuf{};

    if (::stat(full_path.c_str(), &stbuf) == -1) {
        spdlog::trace(
            "LocalOrigin::GetAttributes failed for '{}': {}", full_path.string(),
            std::strerror(errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }
    return stbuf;
}

Storage::StorageResult<std::vector<std::pair<std::string, struct stat>>> LocalOrigin::ListDirectory(
    const std::filesystem::path& relative_path
)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    std::vector<std::pair<std::string, struct stat>> entries;
    std::error_code ec;

    if (!std::filesystem::is_directory(full_path, ec)) {
        if (ec) {
            spdlog::error(
                "LocalOrigin::ListDirectory: Failed check for '{}': {}", full_path.string(),
                ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "listdir_check_isdir"));
        }
        spdlog::warn(
            "LocalOrigin::ListDirectory: Path '{}' is not a directory.", full_path.string()
        );
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::NotADirectory));
    }
    if (ec) {
        spdlog::error(
            "LocalOrigin::ListDirectory: Failed check for '{}': {}", full_path.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "listdir_check_isdir"));
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(
                 full_path, std::filesystem::directory_options::skip_permission_denied, ec
             )) {
            if (ec) {
                spdlog::warn(
                    "LocalOrigin::ListDirectory: Error iterating directory '{}': {}",
                    full_path.string(), ec.message()
                );
                return std::unexpected(MapFilesystemError(ec, "listdir_iterate"));
            }
            struct stat stbuf{};

            if (::lstat(entry.path().c_str(), &stbuf) == -1) {
                spdlog::warn(
                    "LocalOrigin::ListDirectory: Failed lstat for '{}': {}", entry.path().string(),
                    std::strerror(errno)
                );
                continue;
            }
            entries.emplace_back(entry.path().filename().string(), stbuf);
        }
        if (ec) {
            spdlog::warn(
                "LocalOrigin::ListDirectory: Filesystem error after iterating '{}': {}",
                full_path.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "listdir_iterate_end"));
        }

    } catch (const std::filesystem::filesystem_error& fs_err) {
        spdlog::error(
            "LocalOrigin::ListDirectory: Exception iterating directory '{}': {}",
            full_path.string(), fs_err.what()
        );
        return std::unexpected(MapFilesystemError(fs_err.code(), "listdir_exception"));
    }

    return entries;
}

Storage::StorageResult<size_t> LocalOrigin::Read(
    const std::filesystem::path& relative_path, off_t offset, std::span<std::byte> buffer
)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    if (offset < 0) {
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidOffset));
    }

    int fd = ::open(full_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int open_errno = errno;
        spdlog::trace(
            "LocalOrigin::Read open failed for '{}': {}", full_path.string(),
            std::strerror(open_errno)
        );

        if (open_errno == EISDIR) {
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        }
        return std::unexpected(make_error_code(ErrnoToStorageErrc(open_errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    ssize_t bytes_read = ::pread(fd, buffer.data(), buffer.size(), static_cast<off_t>(offset));

    if (bytes_read < 0) {
        int read_errno = errno;
        spdlog::error(
            "LocalOrigin::Read pread failed for '{}': {}", full_path.string(),
            std::strerror(read_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(read_errno)));
    }

    return static_cast<size_t>(bytes_read);
}

Storage::StorageResult<size_t> LocalOrigin::Write(
    const std::filesystem::path& relative_path, off_t offset, std::span<const std::byte> data
)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    if (offset < 0) {
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidOffset));
    }

    int fd = ::open(full_path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        int open_errno = errno;
        spdlog::trace(
            "LocalOrigin::Write open failed for '{}': {}", full_path.string(),
            std::strerror(open_errno)
        );
        // Handle EISDIR specifically
        if (open_errno == EISDIR) {
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        }
        if (open_errno == ENOENT) {
            return std::unexpected(make_error_code(Storage::StorageErrc::FileNotFound));
        }
        return std::unexpected(make_error_code(ErrnoToStorageErrc(open_errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    ssize_t bytes_written = ::pwrite(fd, data.data(), data.size(), static_cast<off_t>(offset));

    if (bytes_written < 0) {
        int write_errno = errno;
        spdlog::error(
            "LocalOrigin::Write pwrite failed for '{}': {}", full_path.string(),
            std::strerror(write_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(write_errno)));
    }

    return static_cast<size_t>(bytes_written);
}

Storage::StorageResult<void> LocalOrigin::CreateFile(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    // Ensure parent directory exists
    auto parent_path = full_path.parent_path();
    std::error_code ec;
    if (!std::filesystem::exists(parent_path, ec)) {
        if (ec) {
            spdlog::error(
                "LocalOrigin::CreateFile: Failed check parent dir '{}': {}", parent_path.string(),
                ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "createfile_check_parent"));
        }
        if (!std::filesystem::create_directories(parent_path, ec)) {
            // Check if creation failed or if it exists now (race condition)
            if (ec || !std::filesystem::exists(parent_path)) {
                spdlog::error(
                    "LocalOrigin::CreateFile: Failed create parent dir '{}': {}",
                    parent_path.string(), ec ? ec.message() : "Unknown reason"
                );
                return std::unexpected(MapFilesystemError(
                    ec ? ec : std::make_error_code(std::errc::io_error), "createfile_create_parent"
                ));
            }
        }
        if (ec) {
            spdlog::error(
                "LocalOrigin::CreateFile: Failed create parent dir '{}': {}", parent_path.string(),
                ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "createfile_create_parent"));
        }
    } else if (ec) {
        spdlog::error(
            "LocalOrigin::CreateFile: Failed check parent dir '{}': {}", parent_path.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "createfile_check_parent"));
    }

    int fd = ::open(full_path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, mode);
    if (fd < 0) {
        int create_errno = errno;
        spdlog::trace(
            "LocalOrigin::CreateFile failed for '{}': {}", full_path.string(),
            std::strerror(create_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(create_errno)));
    }

    if (::close(fd) == -1) {
        spdlog::warn(
            "LocalOrigin::CreateFile: Failed to close fd for newly created file '{}': {}",
            full_path.string(), std::strerror(errno)
        );
    }

    return {};
}

Storage::StorageResult<void> LocalOrigin::CreateDirectory(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    auto parent_path = full_path.parent_path();
    std::error_code ec;
    if (!std::filesystem::exists(parent_path, ec)) {
        if (ec) {
            spdlog::error(
                "LocalOrigin::CreateDirectory: Failed check parent dir '{}': {}",
                parent_path.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "createdir_check_parent"));
        }
        if (!std::filesystem::create_directories(parent_path, ec)) {
            if (ec || !std::filesystem::exists(parent_path)) {
                spdlog::error(
                    "LocalOrigin::CreateDirectory: Failed create parent dir '{}': {}",
                    parent_path.string(), ec ? ec.message() : "Unknown reason"
                );
                return std::unexpected(MapFilesystemError(
                    ec ? ec : std::make_error_code(std::errc::io_error), "createdir_create_parent"
                ));
            }
        }
        if (ec) {
            spdlog::error(
                "LocalOrigin::CreateDirectory: Failed create parent dir '{}': {}",
                parent_path.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "createdir_create_parent"));
        }
    } else if (ec) {
        spdlog::error(
            "LocalOrigin::CreateDirectory: Failed check parent dir '{}': {}", parent_path.string(),
            ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "createdir_check_parent"));
    }

    // Use POSIX mkdir to respect mode (std::filesystem::create_directory has limited mode control)
    if (::mkdir(full_path.c_str(), mode) == -1) {
        int mkdir_errno = errno;
        if (mkdir_errno == EEXIST) {
            struct stat stbuf;
            if (::stat(full_path.c_str(), &stbuf) == 0 && S_ISDIR(stbuf.st_mode)) {
                return std::unexpected(make_error_code(Storage::StorageErrc::AlreadyExists));
            }
        }
        spdlog::trace(
            "LocalOrigin::CreateDirectory mkdir failed for '{}': {}", full_path.string(),
            std::strerror(mkdir_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(mkdir_errno)));
    }

    return {};
}

Storage::StorageResult<void> LocalOrigin::Remove(const std::filesystem::path& relative_path)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    std::error_code ec;
    if (!std::filesystem::remove(full_path, ec)) {
        // If remove returns false, an error might have occurred OR the file didn't exist.
        if (ec) {
            spdlog::trace(
                "LocalOrigin::Remove failed for '{}': {}", full_path.string(), ec.message()
            );
            return std::unexpected(MapFilesystemError(ec, "remove"));
        }
        // If no error code, but remove returned false, it likely means the file/dir didn't exist.
        // Double-check existence to be sure (potential race condition).
        std::error_code exist_ec;
        if (!std::filesystem::exists(std::filesystem::symlink_status(full_path, exist_ec))) {
            if (!exist_ec) {
                return std::unexpected(make_error_code(Storage::StorageErrc::FileNotFound));
            }
        }

        spdlog::error(
            "LocalOrigin::Remove failed for '{}' without specific error code.", full_path.string()
        );
        return std::unexpected(make_error_code(Storage::StorageErrc::UnknownError));
    }

    return {};
}

Storage::StorageResult<void> LocalOrigin::Truncate(
    const std::filesystem::path& relative_path, off_t size
)
{
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    if (size < 0) {
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidOffset));
    }

    // Use POSIX truncate
    if (::truncate(full_path.c_str(), size) == -1) {
        int trunc_errno = errno;
        spdlog::trace(
            "LocalOrigin::Truncate failed for '{}': {}", full_path.string(),
            std::strerror(trunc_errno)
        );

        if (trunc_errno == EISDIR) {
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        }
        return std::unexpected(make_error_code(ErrnoToStorageErrc(trunc_errno)));
    }

    return {};
}

Storage::StorageResult<void> LocalOrigin::Move(
    const std::filesystem::path& from_relative_path, const std::filesystem::path& to_relative_path
)
{
    auto full_from_path = GetValidatedFullPath(from_relative_path);
    if (full_from_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    auto full_to_path = GetValidatedFullPath(to_relative_path);
    if (full_to_path.empty())
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::InvalidPath));

    std::error_code ec;
    std::filesystem::rename(full_from_path, full_to_path, ec);
    if (ec) {
        spdlog::trace(
            "LocalOrigin::Move failed for '{}' -> '{}': {}", full_from_path.string(),
            full_to_path.string(), ec.message()
        );
        return std::unexpected(MapFilesystemError(ec, "move"));
    }

    return {};
}

Storage::StorageResult<struct statvfs> LocalOrigin::GetFilesystemStats()
{
    struct statvfs stbuf{};
    if (::statvfs(base_path_.c_str(), &stbuf) == -1) {
        int stat_errno = errno;
        spdlog::error(
            "LocalOrigin::GetFilesystemStats failed for '{}': {}", base_path_.string(),
            std::strerror(stat_errno)
        );
        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }
    return stbuf;
}

}  // namespace DistributedCacheFS::Origin
