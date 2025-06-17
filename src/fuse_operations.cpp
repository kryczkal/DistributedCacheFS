// clang-format off
#include "app_constants.hpp"
#include <fuse3/fuse.h>
#include "fuse_operations.hpp"
// clang-format on

#include "cache/cache_manager.hpp"
#include "config/config_types.hpp"
#include "storage/storage_error.hpp"

#include <spdlog/spdlog.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace DistributedCacheFS::FuseOps
{

namespace fs = std::filesystem;

// Helper to get manager
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
        fuse_path = fs::path(".");
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

    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager) {
        return -EIO;
    }

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->GetAttributes(fuse_path);

    if (result.has_value()) {
        *stbuf          = result.value();
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
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto list_res  = manager->ListDirectory(fuse_path);

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

int mknod(const char *path, mode_t mode, dev_t rdev)
{
    spdlog::trace("FUSE mknod called for path: {}, mode={:o}", path, mode);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    if (S_ISREG(mode)) {
        auto result = manager->CreateFile(fuse_path, mode);
        return Storage::StorageResultToErrno(result);
    } else {
        auto result = manager->CreateSpecialFile(fuse_path, mode, rdev);
        return Storage::StorageResultToErrno(result);
    }
}

int mkdir(const char *path, mode_t mode)
{
    spdlog::debug("FUSE mkdir called for path: {}, mode={:o}", path, mode);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->CreateDirectory(fuse_path, mode);
    return Storage::StorageResultToErrno(result);
}

int unlink(const char *path)
{
    spdlog::debug("FUSE unlink called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    // Assuming unlink is for files
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->Remove(fuse_path);
    return Storage::StorageResultToErrno(result);
}

int rmdir(const char *path)
{
    spdlog::debug("FUSE rmdir called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->Remove(fuse_path);
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
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    if (flags != 0) {
        spdlog::warn("FUSE rename flags ({}) are not supported and will be ignored.", flags);
        // RENAME_EXCHANGE and RENAME_NOREPLACE would require more complex logic.
        // For now, we proceed as if flags=0.
    }

    auto from_fuse_path = FuseOps::get_fuse_path(from_path);
    auto to_fuse_path   = FuseOps::get_fuse_path(to_path);
    auto result         = manager->Move(from_fuse_path, to_fuse_path);
    return Storage::StorageResultToErrno(result);
}

int link(const char *oldpath, const char *newpath)
{
    spdlog::debug("FUSE link called for old {}, new {}", oldpath, newpath);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto from_fuse_path = FuseOps::get_fuse_path(oldpath);
    auto to_fuse_path   = FuseOps::get_fuse_path(newpath);
    auto result         = manager->CreateHardLink(from_fuse_path, to_fuse_path);
    return Storage::StorageResultToErrno(result);
}

int chmod(const char *path, mode_t mode, struct fuse_file_info * /*fi*/)
{
    spdlog::debug("FUSE chmod called for path: {}, mode={:o}", path, mode);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    // Keep only permission bits, not file type
    mode_t permission_mode = mode & (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX);

    auto result = manager->SetPermissions(fuse_path, permission_mode);
    return Storage::StorageResultToErrno(result);
}

int chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info * /*fi*/)
{
    spdlog::debug("FUSE chown called for path: {}, uid={}, gid={}", path, uid, gid);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    // FUSE passes -1 if uid/gid is not to be changed. chown syscall expects this.
    auto result = manager->SetOwner(fuse_path, uid, gid);
    return Storage::StorageResultToErrno(result);
}

int truncate(const char *path, off_t size, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE truncate called for path: {}, size={}", path, size);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->TruncateFile(fuse_path, size);
    return Storage::StorageResultToErrno(result);
}

int open(const char *path, struct fuse_file_info *fi)
{
    spdlog::trace("FUSE open called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path   = FuseOps::get_fuse_path(path);
    const int oflags = fi->flags;

    // Acquire a per-path lock to ensure atomic handling of create/check operations.
    auto file_mutex = manager->GetFileLock(fuse_path);
    std::lock_guard lock(*file_mutex);

    auto attr_res = manager->GetAttributes(fuse_path);

    // Case 1: Path exists.
    if (attr_res.has_value()) {
        if ((oflags & O_CREAT) && (oflags & O_EXCL)) {
            return -EEXIST;
        }
    }
    // Case 2: Path does not exist.
    else {
        // If the error is anything other than "not found", it's a real problem.
        if (attr_res.error() != make_error_code(Storage::StorageErrc::FileNotFound)) {
            return Storage::StorageResultToErrno(attr_res);
        }

        if (oflags & O_CREAT) {
            // It doesn't exist, so we are clear to create it.
            // A default mode for new files. FUSE doesn't provide one in open().
            mode_t create_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
            auto create_res = manager->CreateFile(fuse_path, create_mode);
            if (!create_res) {
                return Storage::StorageResultToErrno(create_res);
            }
            // Re-fetch attributes for subsequent checks.
            attr_res = manager->GetAttributes(fuse_path);
            if (!attr_res) {
                spdlog::error(
                    "FUSE open: created file '{}' but failed to stat it immediately.",
                    fuse_path.string()
                );
                return -EIO;
            }
        } else {
            // It doesn't exist, and we were not asked to create it.
            return -ENOENT;
        }
    }

    const struct stat &st = attr_res.value();

    // Permission checks
    int req = 0;
    switch (oflags & O_ACCMODE) {
        case O_RDONLY:
            req = R_OK;
            break;
        case O_WRONLY:
            req = W_OK;
            break;
        case O_RDWR:
            req = R_OK | W_OK;
            break;
    }

    struct fuse_context *ctx = fuse_get_context();
    if (!ctx) {
        spdlog::error("open: missing FUSE context");
        return -EIO;
    }

    auto perm_res = manager->CheckPermissions(fuse_path, req, ctx->uid, ctx->gid);
    if (!perm_res) {
        return Storage::StorageResultToErrno(perm_res);
    }

    // O_TRUNC for regular files
    if ((oflags & O_TRUNC) && S_ISREG(st.st_mode) && (oflags & O_ACCMODE) != O_RDONLY) {
        auto trunc_res = manager->TruncateFile(fuse_path, 0);
        if (!trunc_res)
            return Storage::StorageResultToErrno(trunc_res);
    }

    // Reject writing a directory (unless O_PATH)
    if (S_ISDIR(st.st_mode) && ((oflags & O_ACCMODE) != O_RDONLY) && !(oflags & O_PATH))
        return -EISDIR;

    fi->keep_cache = 1;
    return 0;
}

int read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE read called for path: {}, size={}, offset={}", path, size, offset);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    std::span<std::byte> buffer_span{reinterpret_cast<std::byte *>(buf), size};

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->ReadFile(fuse_path, offset, buffer_span);

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
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    std::span<std::byte> data_span{reinterpret_cast<std::byte *>(const_cast<char *>(buf)), size};

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->WriteFile(fuse_path, offset, data_span);

    if (!result) {
        return Storage::StorageResultToErrno(result);
    }

    return static_cast<int>(result.value());
}

int statfs(const char *path, struct statvfs *stbuf)
{
    spdlog::trace("FUSE statfs called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->GetFilesystemStats(fuse_path);
    if (!result) {
        return Storage::StorageResultToErrno(result);
    }

    *stbuf = result.value();
    return 0;
}

int flush(const char *path, struct fuse_file_info * /*fi*/)
{
    spdlog::trace("FUSE flush called for path: {}", path);
    // This is typically a no-op unless you're implementing write-back caching
    // and need to flush internal buffers. Our current model is write-through
    // for modifications, so this is not strictly necessary.
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
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;

    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->Fsync(fuse_path, isdatasync != 0);
    return Storage::StorageResultToErrno(result);
}

int setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    spdlog::trace("FUSE setxattr called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->SetXattr(fuse_path, name, value, size, flags);
    return Storage::StorageResultToErrno(result);
}

int getxattr(const char *path, const char *name, char *value, size_t size)
{
    spdlog::trace("FUSE getxattr called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->GetXattr(fuse_path, name, value, size);
    if (!result) {
        return Storage::StorageResultToErrno(result);
    }
    return static_cast<int>(result.value());
}

int listxattr(const char *path, char *list, size_t size)
{
    spdlog::trace("FUSE listxattr called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->ListXattr(fuse_path, list, size);
    if (!result) {
        return Storage::StorageResultToErrno(result);
    }
    return static_cast<int>(result.value());
}

int removexattr(const char *path, const char *name)
{
    spdlog::trace("FUSE removexattr called for path: {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->RemoveXattr(fuse_path, name);
    return Storage::StorageResultToErrno(result);
}

int opendir(const char *path, struct fuse_file_info *fi)
{
    spdlog::trace("FUSE opendir called for {}", path);
    Cache::CacheManager *manager = FuseOps::get_coordinator();
    if (!manager)
        return -EIO;
    auto fuse_path = FuseOps::get_fuse_path(path);
    auto result    = manager->GetAttributes(fuse_path);
    int res_errno  = Storage::StorageResultToErrno(result);
    if (res_errno != 0)
        return res_errno;

    if (!S_ISDIR(result.value().st_mode)) {
        return -ENOTDIR;
    }
    
    struct fuse_context *ctx = fuse_get_context();
    if (!ctx) {
        spdlog::error("opendir: missing FUSE context");
        return -EIO;
    }

    auto perm_res = manager->CheckPermissions(fuse_path, R_OK | X_OK, ctx->uid, ctx->gid);
    if (!perm_res) {
        spdlog::debug(
            "FUSE opendir: Permission denied for path {}, mode {:#o}", path, result.value().st_mode
        );
        return Storage::StorageResultToErrno(perm_res);
    }
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
