#define FUSE_USE_VERSION 31

#include "fuse_operations.hpp"
#include <spdlog/spdlog.h>
#include "config/config_types.hpp"

#include <fuse3/fuse.h>
#include <cerrno>
#include <cstring>
#include <string>

namespace DistributedCacheFS::FuseOps
{

// Helper function
int not_implemented(const char *func_name)
{
    spdlog::debug("FUSE operation '{}' called, but not implemented.", func_name);
    return -ENOSYS;
}

// --- Minimal FUSE Operation Implementations ---

int getattr(const char *path, struct stat *stbuf, struct fuse_file_info * /*fi*/)
{
    spdlog::debug("getattr called for path: {}", path);
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        spdlog::trace("getattr returning directory attributes for '/'");
        return 0;
    }
    // --- TODO: Implement actual getattr logic ---

    spdlog::warn("getattr: Path '{}' not found (or logic not implemented)", path);
    return -ENOENT;
}

int readdir(
    const char *path, void *buf, fuse_fill_dir_t filler, off_t /*offset*/,
    struct fuse_file_info * /*fi*/, enum fuse_readdir_flags /*flags*/
)
{
    spdlog::debug("readdir called for path: {}", path);

    if (strcmp(path, "/") != 0) {
        spdlog::warn("readdir: Only '/' is currently supported.");
        return -ENOENT;
    }

    spdlog::trace("readdir filling '.' and '..'");
    filler(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);

    // --- TODO: Implement actual readdir logic ---

    spdlog::trace("readdir for '/' completed.");
    return 0;
}

// --- Stubs for other operations ---
int readlink(const char *, char *, size_t) { return not_implemented(__func__); }
int mknod(const char *, mode_t, dev_t) { return not_implemented(__func__); }
int mkdir(const char *, mode_t) { return not_implemented(__func__); }
int unlink(const char *) { return not_implemented(__func__); }
int rmdir(const char *) { return not_implemented(__func__); }
int symlink(const char *, const char *) { return not_implemented(__func__); }
int rename(const char *, const char *, unsigned int) { return not_implemented(__func__); }
int link(const char *, const char *) { return not_implemented(__func__); }
int chmod(const char *, mode_t, fuse_file_info *) { return not_implemented(__func__); }
int chown(const char *, uid_t, gid_t, fuse_file_info *) { return not_implemented(__func__); }
int truncate(const char *, off_t, fuse_file_info *) { return not_implemented(__func__); }
int open(const char *, fuse_file_info *) { return not_implemented(__func__); }
int read(const char *, char *, size_t, off_t, fuse_file_info *)
{
    return not_implemented(__func__);
}
int write(const char *, const char *, size_t, off_t, fuse_file_info *)
{
    return not_implemented(__func__);
}
int statfs(const char *, struct statvfs *) { return not_implemented(__func__); }
int flush(const char *, fuse_file_info *) { return not_implemented(__func__); }
int release(const char *, fuse_file_info *) { return not_implemented(__func__); }
int fsync(const char *, int, fuse_file_info *) { return not_implemented(__func__); }
int setxattr(const char *, const char *, const char *, size_t, int)
{
    return not_implemented(__func__);
}
int getxattr(const char *, const char *, char *, size_t) { return not_implemented(__func__); }
int listxattr(const char *, char *, size_t) { return not_implemented(__func__); }
int removexattr(const char *, const char *) { return not_implemented(__func__); }
int opendir(const char *p, fuse_file_info *)
{
    spdlog::trace("opendir called for {}", p);
    return 0;
}  // Use spdlog::trace
int releasedir(const char *p, fuse_file_info *)
{
    spdlog::trace("releasedir called for {}", p);
    return 0;
}  // Use spdlog::trace
int fsyncdir(const char *, int, fuse_file_info *) { return not_implemented(__func__); }

fuse_operations get_fuse_operations()
{
    fuse_operations ops = {};
    ops.getattr         = DistributedCacheFS::FuseOps::getattr;
    ops.readdir         = DistributedCacheFS::FuseOps::readdir;
    ops.opendir         = DistributedCacheFS::FuseOps::opendir;
    ops.releasedir      = DistributedCacheFS::FuseOps::releasedir;
    ops.readlink        = DistributedCacheFS::FuseOps::readlink;
    ops.mknod           = DistributedCacheFS::FuseOps::mknod;
    ops.mkdir           = DistributedCacheFS::FuseOps::mkdir;
    ops.unlink          = DistributedCacheFS::FuseOps::unlink;
    ops.rmdir           = DistributedCacheFS::FuseOps::rmdir;
    ops.symlink         = DistributedCacheFS::FuseOps::symlink;
    ops.rename          = DistributedCacheFS::FuseOps::rename;
    ops.link            = DistributedCacheFS::FuseOps::link;
    ops.chmod           = DistributedCacheFS::FuseOps::chmod;
    ops.chown           = DistributedCacheFS::FuseOps::chown;
    ops.truncate        = DistributedCacheFS::FuseOps::truncate;
    ops.open            = DistributedCacheFS::FuseOps::open;
    ops.read            = DistributedCacheFS::FuseOps::read;
    ops.write           = DistributedCacheFS::FuseOps::write;
    ops.statfs          = DistributedCacheFS::FuseOps::statfs;
    ops.flush           = DistributedCacheFS::FuseOps::flush;
    ops.release         = DistributedCacheFS::FuseOps::release;
    ops.fsync           = DistributedCacheFS::FuseOps::fsync;
    ops.setxattr        = DistributedCacheFS::FuseOps::setxattr;
    ops.getxattr        = DistributedCacheFS::FuseOps::getxattr;
    ops.listxattr       = DistributedCacheFS::FuseOps::listxattr;
    ops.removexattr     = DistributedCacheFS::FuseOps::removexattr;
    ops.fsyncdir        = DistributedCacheFS::FuseOps::fsyncdir;
    return ops;
}

}  // namespace DistributedCacheFS::FuseOps
