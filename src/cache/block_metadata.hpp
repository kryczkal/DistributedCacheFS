#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_METADATA_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_METADATA_HPP_

#include <boost/container_hash/hash.hpp>
#include <sys/types.h>
#include <ctime>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

namespace DistributedCacheFS::Cache
{

class CacheTier;

namespace fs = std::filesystem;

using TierToCacheMap = std::map<size_t, std::vector<std::shared_ptr<CacheTier>>>;
using Region         = std::pair<off_t, size_t>;
using RegionList     = std::vector<Region>;

struct CoherencyMetadata {
    time_t last_modified_time;
    off_t size_bytes;
};

struct FileId {
    dev_t st_dev;
    ino_t st_ino;

    bool operator==(const FileId& other) const
    {
        return st_dev == other.st_dev && st_ino == other.st_ino;
    }

    bool operator<(const FileId& other) const
    {
        if (st_dev != other.st_dev) {
            return st_dev < other.st_dev;
        }
        return st_ino < other.st_ino;
    }
};

inline std::size_t hash_value(const FileId& id)
{
    std::size_t seed = 0;
    boost::hash_combine(seed, id.st_dev);
    boost::hash_combine(seed, id.st_ino);
    return seed;
}

struct BlockMetadata {
    off_t offset;
    size_t size;
    time_t last_access_time;
    double heat;

    bool operator<(const BlockMetadata& other) const { return offset < other.offset; }
};

struct EvictionCandidate {
    FileId file_id;
    fs::path path_for_storage;  // The path to use for I/O in the backing store
    off_t offset;
    double heat;
    size_t size;

    struct ByHeat {
    };
    struct ByFileIdAndOffset {
    };
    struct ByFileId {
    };
};

struct FileCacheState {
    CoherencyMetadata coherency_metadata;
    std::set<std::shared_ptr<CacheTier>> resident_tiers;
};

}  // namespace DistributedCacheFS::Cache

namespace std
{
template <>
struct hash<DistributedCacheFS::Cache::FileId> {
    size_t operator()(const DistributedCacheFS::Cache::FileId& id) const noexcept
    {
        size_t seed = 0;
        seed ^= std::hash<dev_t>{}(id.st_dev) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= std::hash<ino_t>{}(id.st_ino) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
};
}  // namespace std

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_METADATA_HPP_
