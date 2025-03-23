#define FUSE_USE_VERSION 30
#include <cstdint>
#include <cstdlib>
#include <fuse3/fuse.h>

static struct fuse_operations operations = {
    .getattr = nullptr,
    .readlink = nullptr,
    .mknod = nullptr,
    .mkdir = nullptr,
    .unlink = nullptr,
    .rmdir = nullptr,
    .symlink = nullptr,
    .rename = nullptr,
    .link = nullptr,
    .chmod = nullptr,
    .chown = nullptr,
    .truncate = nullptr,
    .open = nullptr,
    .read = nullptr,
    .write = nullptr,
    .statfs = nullptr,
    .flush = nullptr,
    .release = nullptr,
    .fsync = nullptr,
    .setxattr = nullptr,
    .getxattr = nullptr,
    .listxattr = nullptr,
    .removexattr = nullptr,
    .opendir = nullptr,
    .readdir = nullptr,
    .releasedir = nullptr,
};

int main (int argc, char* argv[]) {
  return fuse_main(
      argc, argv, &operations, nullptr);
}