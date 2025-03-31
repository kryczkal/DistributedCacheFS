#ifndef DISTRIBUTEDCACHEFS_SRC_FUSE_OPERATIONS_HPP_
#define DISTRIBUTEDCACHEFS_SRC_FUSE_OPERATIONS_HPP_

#include <fuse3/fuse.h>
#include "config/config_types.hpp"

namespace DistributedCacheFS
{

struct FileSystemContext {
    Config::NodeConfig config;
    // TODO: pointers to storage managers etc. here later
    // Storage::StorageManager* storage_manager = nullptr;
};

namespace FuseOps
{

inline FileSystemContext *get_context()
{
    return static_cast<FileSystemContext *>(fuse_get_context()->private_data);
}

// Declarations
int getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int readdir(
    const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi,
    enum fuse_readdir_flags flags
);
int readlink(const char *, char *, size_t);
int mknod(const char *, mode_t, dev_t);
int mkdir(const char *, mode_t);
int unlink(const char *);
int rmdir(const char *);
int symlink(const char *, const char *);
int rename(const char *, const char *, unsigned int);
int link(const char *, const char *);
int chmod(const char *, mode_t, fuse_file_info *);
int chown(const char *, uid_t, gid_t, fuse_file_info *);
int truncate(const char *, off_t, fuse_file_info *);
int open(const char *, fuse_file_info *);
int read(const char *, char *, size_t, off_t, fuse_file_info *);
int write(const char *, const char *, size_t, off_t, fuse_file_info *);
int statfs(const char *, struct statvfs *);
int flush(const char *, fuse_file_info *);
int release(const char *, fuse_file_info *);
int fsync(const char *, int, fuse_file_info *);
int setxattr(const char *, const char *, const char *, size_t, int);
int getxattr(const char *, const char *, char *, size_t);
int listxattr(const char *, char *, size_t);
int removexattr(const char *, const char *);
int opendir(const char *, fuse_file_info *);
int releasedir(const char *, fuse_file_info *);
int fsyncdir(const char *, int, fuse_file_info *);

// Get the initialized operations struct
fuse_operations get_fuse_operations();

}  // namespace FuseOps
}  // namespace DistributedCacheFS

#endif  // DISTRIBUTEDCACHEFS_SRC_FUSE_OPERATIONS_HPP_
