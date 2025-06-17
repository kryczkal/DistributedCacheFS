#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_METADATA_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_METADATA_HPP_

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

using Region = std::pair<off_t, size_t>;
using RegionList = std::vector<Region>;

struct CoherencyMetadata
{
    time_t last_modified_time;
    off_t size_bytes;
};

struct BlockMetadata
{
    off_t offset;
    size_t size;
    time_t last_access_time;
    double heat;

    bool operator<(const BlockMetadata& other) const
    {
        return offset < other.offset;
    }
};

struct EvictionCandidate
{
    fs::path path;
    off_t offset;
    double heat;
    size_t size;

    struct ByHeat
    {
    };
    struct ByPathAndOffset
    {
    };
};

struct FileCacheState
{
    CoherencyMetadata coherency_metadata;
    std::set<std::shared_ptr<CacheTier>> resident_tiers;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_METADATA_HPP_
