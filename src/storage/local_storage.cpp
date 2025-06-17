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
#include <utility>

namespace DistributedCacheFS::Storage
{

namespace fs = std::filesystem;

namespace
{

Storage::StorageErrc XattrErrnoToStorageErrc(int err_no)
{
    switch (err_no) {
        case 0:
            return Storage::StorageErrc::Success;
        case ENOENT:
            return Storage::StorageErrc::FileNotFound;
        case ENODATA:
            return Storage::StorageErrc::MetadataNotFound;
        case EPERM:
        case EACCES:
            return Storage::StorageErrc::PermissionDenied;
        case ENOSPC:
            return Storage::StorageErrc::OutOfSpace;
        case EOPNOTSUPP:
            return Storage::StorageErrc::NotSupported;
        case ERANGE:
            return Storage::StorageErrc::MetadataError;
        case EIO:
            return Storage::StorageErrc::IOError;

        default:
            return Storage::StorageErrc::MetadataError;
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
            }
        }
        fd_ = new_fd;
    }
    explicit operator bool() const noexcept { return fd_ >= 0; }
};

}  // namespace

LocalStorage::LocalStorage(const Config::StorageDefinition& definition)
    : definition_(definition), base_path_(definition.path)
{
}

Config::StorageType LocalStorage::GetType() const { return definition_.type; }

const std::filesystem::path& LocalStorage::GetPath() const { return base_path_; }

std::filesystem::path LocalStorage::RelativeToAbsPath(
    const std::filesystem::path& relative_path
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
        return {};
    }
    return full;
}
std::filesystem::path LocalStorage::GetValidatedFullPath(
    const std::filesystem::path& relative_path
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
        storage_errc = ErrnoToStorageErrc(ec.value());
    }
    return Storage::make_error_code(storage_errc);
}

StorageResult<void> LocalStorage::Initialize()
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    std::error_code ec;

    if (!std::filesystem::exists(base_path_, ec)) {
        if (!std::filesystem::create_directories(base_path_, ec)) {
            if (ec) {
                return std::unexpected(MapFilesystemError(ec, "init_create_dir"));
            }
            if (!std::filesystem::is_directory(base_path_, ec)) {
                return std::unexpected(MapFilesystemError(
                    ec ? ec : std::make_error_code(std::errc::io_error), "init_verify_dir"
                ));
            }
        }
        if (ec) {
            return std::unexpected(MapFilesystemError(ec, "init_create_dir"));
        }
    } else if (ec) {
        return std::unexpected(MapFilesystemError(ec, "init_check_exists"));
    } else if (!std::filesystem::is_directory(base_path_, ec)) {
        return std::unexpected(make_error_code(StorageErrc::NotADirectory));
    } else if (ec) {
        return std::unexpected(MapFilesystemError(ec, "init_check_type"));
    }

    if (definition_.max_size_bytes.has_value()) {
        stats_.SetMaxSizeBytes(definition_.max_size_bytes.value());
        stats_.SetUsesSizeTracking(true);
    } else {
        stats_.SetUsesSizeTracking(false);
    }
    for (const auto& entry : std::filesystem::recursive_directory_iterator(base_path_)) {
        if (entry.is_regular_file()) {
            std::error_code ec;
            uintmax_t file_size = entry.file_size(ec);
            if (ec) {
                continue;
            }
            stats_.IncrementSizeBytes(file_size);
        }
    }

    return {};
}

StorageResult<void> LocalStorage::Shutdown()
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    return {};
}

StorageResult<std::uint64_t> LocalStorage::GetCapacityBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    std::error_code ec;
    fs::space_info space = fs::space(base_path_, ec);
    if (ec) {
        return std::unexpected(MapFilesystemError(ec, "get_capacity"));
    }
    auto capacity = space.capacity;
    if (stats_.UsesSizeTracking()) {
        capacity = std::min(capacity, stats_.GetMaxSizeBytes());
    }
    return capacity;
}

StorageResult<std::uint64_t> LocalStorage::GetUsedBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    uint64_t actual_used = 0;
    if (stats_.UsesSizeTracking()) {
        actual_used = stats_.GetCurrentSizeBytes();
    } else {
        fs::space_info space_val = fs::space(base_path_);
        uint64_t actual_capacity = space_val.capacity;
        uint64_t actual_free     = space_val.free;
        actual_used = actual_capacity > actual_free ? actual_capacity - actual_free : 0;
    }
    return actual_used;
}

StorageResult<std::uint64_t> LocalStorage::GetAvailableBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    std::error_code ec;
    uint64_t available = 0;
    if (stats_.UsesSizeTracking()) {
        if (stats_.GetCurrentSizeBytes() < stats_.GetMaxSizeBytes()) {
            available = stats_.GetMaxSizeBytes() - stats_.GetCurrentSizeBytes();
        } else {
            available = 0;
        }
    } else {
        fs::space_info space = fs::space(base_path_, ec);
        if (ec) {
            return std::unexpected(MapFilesystemError(ec, "get_available"));
        }
        available = space.available;
    }
    return available;
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
        if (open_errno == EISDIR)
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        if (open_errno == ENOENT)
            return std::unexpected(make_error_code(Storage::StorageErrc::FileNotFound));
        return std::unexpected(make_error_code(ErrnoToStorageErrc(open_errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    ssize_t bytes_read = ::pread(fd, buffer.data(), buffer.size(), static_cast<off_t>(offset));

    if (bytes_read < 0) {
        int read_errno = errno;
        return std::unexpected(make_error_code(ErrnoToStorageErrc(read_errno)));
    }

    return static_cast<size_t>(bytes_read);
}

StorageResult<std::size_t> LocalStorage::Write(
    const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& data
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (offset < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    off_t old_size = 0;
    if (stats_.UsesSizeTracking()) {
        struct stat st{};
        if (::lstat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
            old_size = st.st_size;
    }

    const off_t new_size  = std::max<off_t>(old_size, offset + static_cast<off_t>(data.size()));
    const uint64_t growth = (new_size > old_size) ? static_cast<uint64_t>(new_size - old_size) : 0;

    if (stats_.UsesSizeTracking() && growth > 0) {
        auto avail_res = GetAvailableBytes();
        if (!avail_res) {
            return std::unexpected(avail_res.error());
        }
        if (growth > *avail_res) {
            return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
        }
    }

    const auto parent_path = full_path.parent_path();
    std::error_code ec;
    if (!std::filesystem::exists(parent_path, ec)) {
        if (!std::filesystem::create_directories(parent_path, ec) ||
            (ec && !std::filesystem::exists(parent_path))) {
            return std::unexpected(MapFilesystemError(
                ec ? ec : std::make_error_code(std::errc::io_error), "write_create_parent"
            ));
        }
    } else if (ec) {
        return std::unexpected(MapFilesystemError(ec, "write_check_parent"));
    }

    constexpr mode_t default_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    const int fd = ::open(full_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, default_mode);
    if (fd < 0) {
        const int open_errno = errno;
        if (open_errno == EISDIR)
            return std::unexpected(make_error_code(Storage::StorageErrc::IsADirectory));
        return std::unexpected(make_error_code(ErrnoToStorageErrc(open_errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    const ssize_t bytes_written =
        ::pwrite(fd, data.data(), data.size(), static_cast<off_t>(offset));
    if (bytes_written < 0) {
        const int write_errno = errno;
        return std::unexpected(make_error_code(ErrnoToStorageErrc(write_errno)));
    }

    if (stats_.UsesSizeTracking()) {
        struct stat st_after{};
        if (::fstat(fd, &st_after) == 0 && S_ISREG(st_after.st_mode)) {
            const off_t new_file_size = st_after.st_size;
            if (new_file_size > old_size) {
                stats_.IncrementSizeBytes(static_cast<uint64_t>(new_file_size - old_size));
            } else if (new_file_size < old_size) {
                stats_.DecrementSizeBytes(static_cast<uint64_t>(old_size - new_file_size));
            }
        }
    }

    return static_cast<size_t>(bytes_written);
}

StorageResult<void> LocalStorage::Remove(const std::filesystem::path& relative_path)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    uint64_t size_to_remove = 0;
    if (stats_.UsesSizeTracking()) {
        struct stat st{};
        if (::lstat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
            size_to_remove = static_cast<uint64_t>(st.st_size);
    }

    std::string full_path_str = full_path.string();
    std::string base_path_str = base_path_.string();
    if (!full_path_str.empty() && full_path_str.back() == fs::path::preferred_separator)
        full_path_str.pop_back();
    if (!base_path_str.empty() && base_path_str.back() == fs::path::preferred_separator)
        base_path_str.pop_back();
    if (full_path_str == base_path_str) {
        return {};
    }

    std::error_code ec;
    if (!std::filesystem::remove(full_path, ec)) {
        if (ec && ec != std::errc::no_such_file_or_directory) {
            return std::unexpected(MapFilesystemError(ec, "remove"));
        }
    } else if (stats_.UsesSizeTracking() && size_to_remove > 0) {
        stats_.DecrementSizeBytes(size_to_remove);
    }

    return {};
}

StorageResult<void> LocalStorage::Truncate(const std::filesystem::path& relative_path, off_t size)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    if (size < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));

    off_t old_size = 0;
    if (stats_.UsesSizeTracking()) {
        struct stat st{};
        if (::lstat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode))
            old_size = st.st_size;
    }
    if (stats_.UsesSizeTracking() && size > old_size) {
        uint64_t growth = static_cast<uint64_t>(size - old_size);
        auto avail_res  = GetAvailableBytes();
        if (!avail_res) {
            return std::unexpected(avail_res.error());
        }
        if (growth > *avail_res) {
            return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
        }
    }

    if (::truncate(full_path.c_str(), size) == -1) {
        const int trunc_errno = errno;
        if (trunc_errno == ENOENT)
            return std::unexpected(make_error_code(StorageErrc::FileNotFound));
        if (trunc_errno == EISDIR)
            return std::unexpected(make_error_code(StorageErrc::IsADirectory));

        return std::unexpected(make_error_code(ErrnoToStorageErrc(trunc_errno)));
    }

    if (stats_.UsesSizeTracking()) {
        if (size > old_size) {
            stats_.IncrementSizeBytes(static_cast<uint64_t>(size - old_size));
        } else if (size < old_size) {
            stats_.DecrementSizeBytes(static_cast<uint64_t>(old_size - size));
        }
    }

    return {};
}

StorageResult<void> LocalStorage::PunchHole(
    const std::filesystem::path& relative_path, off_t offset, size_t size
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    int fd = ::open(full_path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    if (::fallocate(
            fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, static_cast<off_t>(size)
        ) == -1) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }

    if (stats_.UsesSizeTracking()) {
        stats_.DecrementSizeBytes(size);
    }

    return {};
}

StorageResult<void> LocalStorage::Fsync(
    const std::filesystem::path& relative_path, bool is_data_sync
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    const auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    int fd = ::open(full_path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    int sync_result = is_data_sync ? ::fdatasync(fd) : ::fsync(fd);
    if (sync_result == -1) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }

    return {};
}

StorageResult<bool> LocalStorage::CheckIfFileExists(
    const std::filesystem::path& relative_path
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
        return std::unexpected(MapFilesystemError(ec, "probe"));
    }
    return exists;
}
StorageResult<void> LocalStorage::CreateFile(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    std::error_code ec;
    std::filesystem::create_directories(full_path.parent_path(), ec);
    if (ec)
        return std::unexpected(MapFilesystemError(ec, "create_file_parent"));

    // Use open() with O_CREAT to create if not exists, but not truncate.
    // The mode is applied on creation, respecting the process umask.
    int fd = ::open(full_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }
    FileDescriptorGuard fd_guard(fd);

    return {};
}

StorageResult<void> LocalStorage::CreateSpecialFile(
    const std::filesystem::path& relative_path, mode_t mode, dev_t rdev
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    std::error_code ec;
    std::filesystem::create_directories(full_path.parent_path(), ec);
    if (ec)
        return std::unexpected(MapFilesystemError(ec, "create_special_file_parent"));

    if (::mknod(full_path.c_str(), mode, rdev) == -1) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }

    return {};
}

StorageResult<void> LocalStorage::CreateDirectory(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    std::error_code ec;
    if (!std::filesystem::create_directories(full_path, ec) && ec)
        return std::unexpected(MapFilesystemError(ec, "create_directory"));

    if (::chmod(full_path.c_str(), mode) == -1)
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));

    return {};
}

StorageResult<void> LocalStorage::CreateHardLink(
    const std::filesystem::path& from_relative_path, const std::filesystem::path& to_relative_path
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
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
            return std::unexpected(MapFilesystemError(ec, "link_create_parent"));
    } else if (ec) {
        return std::unexpected(MapFilesystemError(ec, "link_check_parent"));
    }

    if (::link(from_full.c_str(), to_full.c_str()) == -1) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }

    return {};
}

StorageResult<void> LocalStorage::Move(
    const std::filesystem::path& from_relative_path, const std::filesystem::path& to_relative_path
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
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

    return {};
}

StorageResult<struct stat> LocalStorage::GetAttributes(
    const std::filesystem::path& relative_path
) const
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    struct stat stbuf{};
    if (::lstat(full_path.c_str(), &stbuf) == -1) {
        int stat_errno = errno;

        if (stat_errno == ENOENT) {
            return std::unexpected(make_error_code(StorageErrc::FileNotFound));
        }

        return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
    }
    return stbuf;
}

StorageResult<struct statvfs> LocalStorage::GetFilesystemStats(const std::string& path) const
{
    struct statvfs st = {};
    if (::statvfs(base_path_.c_str(), &st) == -1) {
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
    }
    return st;
}

StorageResult<void> LocalStorage::SetXattr(
    const fs::path& relative_path, const std::string& name, const char* value, size_t size,
    int flags
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    if (::setxattr(full_path.c_str(), name.c_str(), value, size, flags) == -1) {
        return std::unexpected(make_error_code(XattrErrnoToStorageErrc(errno)));
    }
    return {};
}

StorageResult<ssize_t> LocalStorage::GetXattr(
    const fs::path& relative_path, const std::string& name, char* value, size_t size
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    ssize_t res = ::getxattr(full_path.c_str(), name.c_str(), value, size);
    if (res == -1) {
        return std::unexpected(make_error_code(XattrErrnoToStorageErrc(errno)));
    }
    return res;
}

StorageResult<ssize_t> LocalStorage::ListXattr(
    const fs::path& relative_path, char* list, size_t size
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    ssize_t res = ::listxattr(full_path.c_str(), list, size);
    if (res == -1) {
        return std::unexpected(make_error_code(XattrErrnoToStorageErrc(errno)));
    }
    return res;
}

StorageResult<void> LocalStorage::RemoveXattr(
    const fs::path& relative_path, const std::string& name
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    if (::removexattr(full_path.c_str(), name.c_str()) == -1) {
        // ENODATA means the attribute didn't exist, which is not an error for a remove operation.
        if (errno != ENODATA) {
            return std::unexpected(make_error_code(XattrErrnoToStorageErrc(errno)));
        }
    }
    return {};
}

StorageResult<std::vector<std::pair<std::string, struct stat>>> LocalStorage::ListDirectory(
    const std::filesystem::path& relative_path
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);
    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
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
            return std::unexpected(make_error_code(ErrnoToStorageErrc(stat_errno)));
        }
        entries.emplace_back(entry.path().filename().string(), stbuf);
    }
    return entries;
}

StorageResult<void> LocalStorage::SetPermissions(
    const std::filesystem::path& relative_path, mode_t mode
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    if (::chmod(full_path.c_str(), mode) == -1)
        return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));

    return {};
}

StorageResult<void> LocalStorage::SetOwner(
    const std::filesystem::path& relative_path, uid_t uid, gid_t gid
)
{
    std::lock_guard<std::recursive_mutex> lock(storage_mutex_);

    auto full_path = GetValidatedFullPath(relative_path);
    if (full_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    if (::chown(full_path.c_str(), uid, gid) == -1) {
        int chown_errno = errno;
        return std::unexpected(make_error_code(ErrnoToStorageErrc(chown_errno)));
    }

    return {};
}

}  // namespace DistributedCacheFS::Storage
