#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_

#include <atomic>
#include <cstdint>

namespace DistributedCacheFS::Cache
{

class CacheStats
{
    public:
    // TODO: Add other statistics methods here

    private:
    // Future stats members:
    // std::atomic<uint64_t> hits_;
    // std::atomic<uint64_t> misses_;
    // std::atomic<uint64_t> items_added_;
    // std::atomic<uint64_t> items_removed_;
    // std::atomic<uint64_t> items_evicted_;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_
