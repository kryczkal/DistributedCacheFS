// clang-format off
#include "app_constants.hpp"
#include <fuse3/fuse.h>
#include "fuse_operations.hpp"
// clang-format on

#include "cache/cache_manager.hpp"
#include "config/config_types.hpp"
#include "storage/storage_error.hpp"

#include <spdlog/spdlog.h>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace DistributedCacheFS::FuseOps
{

namespace fs = std::filesystem;

// Helper to get coordinator
inline Cache::CacheManager *get_coordinator()
{
    FileSystemContext *ctx = get_context();
    if (!ctx || !ctx->cache_manager) {
        spdlog::critical("FUSE Ops: CacheCoordinator not found in context!");
        // Cannot return error easily here, fuse expects specific context setup
        // This indicates a programming error in main.cpp
        return nullptr;
    }
    return ctx->cache_manager.get();
}

// Helper to sanitize fuse path
inline void sanitize_fuse_path(std::filesystem::path &fuse_path)
{
    spdlog::trace("FUSE: sanitize_fuse_path({})", fuse_path.string());
    if (fuse_path.empty())
        return;
    if (fuse_path == "/")
        return;
    if (fuse_path.has_root_directory())  // strip leading '/'
        fuse_path = fuse_path.lexically_relative("/");
}

inline fs::path get_fuse_path(const char *path)
{
    spdlog::trace("FUSE: get_fuse_path({})", path);
    if (!path) {
        spdlog::error("FUSE: Invalid path provided");
        return {};
    }
    fs::path fuse_path = path;
    sanitize_fuse_path(fuse_path);
    return fuse_path;
}

// FUSE Operation Implementations

int getattr(const char *path, struct stat *stbuf, struct fuse_file_info * /*fi*/)
{
    spdlog::debug("FUSE: getattr({})", path);
    memset(stbuf, 0, sizeof(struct stat));

    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator) {
        return -EIO;
    }

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->GetAttributes(fuse_path);

    if (result.has_value()) {
        *stbuf          = result.value();
        stbuf->st_atime = time(nullptr);
        stbuf->st_ctime = stbuf->st_atime;
    } else {
        spdlog::warn("FUSE getattr failed for path {}: {}", path, result.error().message());
        return Storage::StorageResultToErrno(result);
    }

    return Storage::StorageResultToErrno(result);
}

int readdir(
    const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
    struct fuse_file_info * /*fi*/, enum fuse_readdir_flags /*flags*/
)
{
    spdlog::debug("FUSE: readdir({})", path);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto list_res  = coordinator->ListDirectory(fuse_path);

    if (!list_res) {
        return Storage::StorageResultToErrno(list_res);
    }

    // Fill buffer with directory entries from the result
    for (const auto &entry : list_res.value()) {
        // Pass name and stat buffer to filler
        if (filler(buf, entry.first.c_str(), &entry.second, 0, (fuse_fill_dir_flags)0) != 0) {
            spdlog::warn("FUSE readdir: filler buffer full for path {}", path);
            return -ENOMEM;  // Buffer full
        }
    }

    return 0;
}

int readlink(const char *path, char *linkbuf, size_t size)
{
    spdlog::debug("FUSE readlink called for {}, but not implemented.", path);
    return -ENOSYS;
}

int mknod(const char *path, mode_t mode, dev_t /*rdev*/)
{
    spdlog::trace("FUSE mknod called for path: {}, mode={:o}", path, mode);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    if (!S_ISREG(mode)) {
        spdlog::warn("FUSE mknod: unsupported file type {:o}", mode);
        return -EPERM;  // Operation not permitted for non-regular files
    }

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->CreateFile(fuse_path, mode);
    return Storage::StorageResultToErrno(result);
}

int mkdir(const char *path, mode_t mode)
{
    spdlog::debug("FUSE mkdir called for path: {}, mode={:o}", path, mode);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->CreateDirectory(fuse_path, mode);
    return Storage::StorageResultToErrno(result);
}

int unlink(const char *path)
{
    spdlog::debug("FUSE unlink called for path: {}", path);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    // Assuming unlink is for files
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->Remove(fuse_path);
    return Storage::StorageResultToErrno(result);
}

int rmdir(const char *path)
{
    spdlog::debug("FUSE rmdir called for path: {}", path);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->Remove(fuse_path);
    return Storage::StorageResultToErrno(result);
}

int symlink(const char *target, const char *linkpath)
{
    spdlog::debug(
        "FUSE symlink called for target {}, linkpath {}, but not implemented.", target, linkpath
    );
    return -ENOSYS;
}

int rename(const char *from_path, const char *to_path, unsigned int flags)
{
    spdlog::debug("FUSE rename called for: {} -> {}", from_path, to_path);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    // TODO: Check flags
    if (flags != 0) {
        spdlog::warn("FUSE rename flags ({}) ignored.", flags);
    }

    auto from_fuse_path = FuseOps::get_fuse_path(from_path);
    auto to_fuse_path   = FuseOps::get_fuse_path(to_path);
    auto result         = coordinator->Move(from_fuse_path, to_fuse_path);
    return Storage::StorageResultToErrno(result);
}

int link(const char *oldpath, const char *newpath)
{
    spdlog::debug("FUSE link called for old {}, new {}, but not implemented.", oldpath, newpath);
    return -ENOSYS;
}

int chmod(const char *path, mode_t mode, struct fuse_file_info * /*fi*/)
{
    spdlog::debug("FUSE chmod called for path: {}, mode={:o}", path, mode);
    // TODO: Implement in CacheCoordinator and Origin

    spdlog::warn("FUSE chmod called, but currently not implemented.");
    return -ENOSYS;
}

int chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info * /*fi*/)
{
    spdlog::debug("FUSE chown called for path: {}, uid={}, gid={}", path, uid, gid);
    // TODO: Implement in CacheCoordinator and Origin
    spdlog::warn("FUSE chown called, but currently not implemented.");
    return -ENOSYS;
}

int truncate(const char *path, off_t size, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE truncate called for path: {}, size={}", path, size);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->TruncateFile(fuse_path, size);
    return Storage::StorageResultToErrno(result);
}

int open(const char *path, struct fuse_file_info *fi)
{
    spdlog::trace("FUSE open called for path: {}", path);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator) {
        return -EIO;
    }

    int flags = fi->flags;

    auto fuse_path                = FuseOps::get_fuse_path(path);
    auto attr_res                 = coordinator->GetAttributes(fuse_path);
    int attr_errno                = Storage::StorageResultToErrno(attr_res);
    bool file_existed_before_open = (attr_errno == 0);

    if (!file_existed_before_open && (flags & O_CREAT)) {
        // File doesn't exist, and O_CREAT is set: Try to create it.
        if (attr_errno != -ENOENT) {
            spdlog::debug(
                "FUSE open: GetAttributes failed unexpectedly for non-existent path {}: {}", path,
                attr_errno
            );
            return attr_errno;
        }

        spdlog::trace("FUSE open: O_CREAT requested, path {} does not exist. Creating...", path);
        // Use default mode, FUSE/kernel usually handles umask.
        mode_t create_mode = 0644;
        auto create_res    = coordinator->CreateFile(fuse_path, create_mode);
        int create_errno   = Storage::StorageResultToErrno(create_res);

        if (create_errno != 0) {
            spdlog::error("FUSE open: O_CREAT failed to create file {}: {}", path, create_errno);
            return create_errno;
        }
        spdlog::trace("FUSE open: O_CREAT successfully created file {}", path);

    } else if (file_existed_before_open && (flags & O_CREAT) && (flags & O_EXCL)) {
        spdlog::debug("FUSE open: O_CREAT|O_EXCL failed, path {} already exists.", path);
        return -EEXIST;
    } else if (!file_existed_before_open && !(flags & O_CREAT)) {
        spdlog::debug("FUSE open: Path {} does not exist and O_CREAT not specified.", path);
        return -ENOENT;
    } else if (attr_errno != 0 && file_existed_before_open) {
        spdlog::error("FUSE open: GetAttributes failed for existing path {}: {}", path, attr_errno);
        return attr_errno;
    }
    const struct stat &stbuf = attr_res.value();

    // Check if opening a directory when not allowed (e.g., O_WRONLY)
    if (S_ISDIR(stbuf.st_mode) && (flags & O_ACCMODE) != O_RDONLY) {
        spdlog::debug("FUSE open: Attempt to open directory {} with write flags.", path);
        return -EISDIR;
    }

    // TODO: Implement permission checks based on flags and file mode

    if ((flags & O_TRUNC) && S_ISREG(stbuf.st_mode)) {
        // O_TRUNC: Truncate file to zero length if opening for writing
        if ((flags & O_ACCMODE) != O_RDONLY) {
            spdlog::trace("FUSE open: O_TRUNC requested for path {}.", path);
            auto trunc_res  = coordinator->TruncateFile(fuse_path, 0);
            int trunc_errno = Storage::StorageResultToErrno(trunc_res);
            if (trunc_errno != 0) {
                spdlog::warn("FUSE open: O_TRUNC failed for path {}: {}", path, trunc_errno);
                return trunc_errno;
            }
        } else {
            spdlog::warn("FUSE open: O_TRUNC requested but file not opened for writing.");
            return -EACCES;
        }
    }

    fi->keep_cache = 1;  // Keep cache for this file

    spdlog::trace("FUSE open successful for path: {}", path);
    return 0;
}

int read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE read called for path: {}, size={}, offset={}", path, size, offset);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    std::span<std::byte> buffer_span{reinterpret_cast<std::byte *>(buf), size};

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->ReadFile(fuse_path, offset, buffer_span);

    if (!result) {
        return Storage::StorageResultToErrno(result);
    }

    return static_cast<int>(result.value());
}

int write(
    const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info * /*fi*/
)
{
    spdlog::trace("FUSE write called for path: {}, size={}, offset={}", path, size, offset);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    std::span<std::byte> data_span{reinterpret_cast<std::byte *>(const_cast<char *>(buf)), size};

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->WriteFile(fuse_path, offset, data_span);

    if (!result) {
        return Storage::StorageResultToErrno(result);
    }

    return static_cast<int>(result.value());
}

int statfs(const char *path, struct statvfs *stbuf)
{
    spdlog::trace("FUSE statfs called for path: {}", path);
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;

    // Delegate primarily to the coordinator
    // Currently only supports "/", proxies to origin
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->GetFilesystemStats(fuse_path);
    if (!result) {
        return Storage::StorageResultToErrno(result);
    }

    *stbuf = result.value();
    return 0;
}

// TODO: Implement flush, release, fsync if needed for specific behaviors
int flush(const char *path, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE flush called for path: {}", path);
    // TODO: Implement logic to flush data to origin
    return 0;
}

int release(const char *path, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE release called for path: {}", path);
    return 0;
}

int fsync(const char *path, int isdatasync, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE fsync called for path: {}, isdatasync={}", path, isdatasync);
    // TODO: Propagate fsync to origin/cache tiers
    spdlog::warn("FUSE fsync called, but currently a no-op.");
    return 0;
}

// xattr operations - TODO: Not Implemented
int setxattr(const char *, const char *, const char *, size_t, int) { return -ENOSYS; }
int getxattr(const char *, const char *, char *, size_t) { return -ENOSYS; }
int listxattr(const char *, char *, size_t) { return -ENOSYS; }
int removexattr(const char *, const char *) { return -ENOSYS; }

// opendir/releasedir - Minimal Implementation
int opendir(const char *path, struct fuse_file_info *fi)
{
    spdlog::trace("FUSE opendir called for {}", path);
    // Check if directory exists using GetAttributes
    Cache::CacheManager *coordinator = FuseOps::get_coordinator();
    if (!coordinator)
        return -EIO;
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = coordinator->GetAttributes(fuse_path);
    int res_errno  = Storage::StorageResultToErrno(result);
    if (res_errno != 0)
        return res_errno;

    if (!S_ISDIR(result.value().st_mode)) {
        return -ENOTDIR;
    }
    // TODO: Permissions check could go here
    return 0;
}

int releasedir(const char *path, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE releasedir called for {}", path);
    return 0;
}

int fsyncdir(const char *path, int isdatasync, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE fsyncdir called for path: {}, isdatasync={}", path, isdatasync);
    spdlog::warn("FUSE fsyncdir called, but currently a no-op.");
    return 0;
}

// Function to populate the fuse_operations struct
fuse_operations get_fuse_operations()
{
    fuse_operations ops = {};

    ops.getattr     = DistributedCacheFS::FuseOps::getattr;
    ops.readdir     = DistributedCacheFS::FuseOps::readdir;
    ops.readlink    = DistributedCacheFS::FuseOps::readlink;
    ops.mknod       = DistributedCacheFS::FuseOps::mknod;
    ops.mkdir       = DistributedCacheFS::FuseOps::mkdir;
    ops.unlink      = DistributedCacheFS::FuseOps::unlink;
    ops.rmdir       = DistributedCacheFS::FuseOps::rmdir;
    ops.symlink     = DistributedCacheFS::FuseOps::symlink;
    ops.rename      = DistributedCacheFS::FuseOps::rename;
    ops.link        = DistributedCacheFS::FuseOps::link;
    ops.chmod       = DistributedCacheFS::FuseOps::chmod;
    ops.chown       = DistributedCacheFS::FuseOps::chown;
    ops.truncate    = DistributedCacheFS::FuseOps::truncate;
    ops.open        = DistributedCacheFS::FuseOps::open;
    ops.read        = DistributedCacheFS::FuseOps::read;
    ops.write       = DistributedCacheFS::FuseOps::write;
    ops.statfs      = DistributedCacheFS::FuseOps::statfs;
    ops.flush       = DistributedCacheFS::FuseOps::flush;
    ops.release     = DistributedCacheFS::FuseOps::release;
    ops.fsync       = DistributedCacheFS::FuseOps::fsync;
    ops.setxattr    = DistributedCacheFS::FuseOps::setxattr;
    ops.getxattr    = DistributedCacheFS::FuseOps::getxattr;
    ops.listxattr   = DistributedCacheFS::FuseOps::listxattr;
    ops.removexattr = DistributedCacheFS::FuseOps::removexattr;
    ops.opendir     = DistributedCacheFS::FuseOps::opendir;
    ops.releasedir  = DistributedCacheFS::FuseOps::releasedir;
    ops.fsyncdir    = DistributedCacheFS::FuseOps::fsyncdir;

    return ops;
}

}  // namespace DistributedCacheFS::FuseOps
