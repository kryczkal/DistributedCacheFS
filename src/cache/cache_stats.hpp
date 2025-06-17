#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_

#include <atomic>
#include <cstdint>

namespace DistributedCacheFS::Cache
{

class CacheStats
{
    public:
    CacheStats() = default;

    void IncrementHits() { hits_++; }
    uint64_t GetHits() const { return hits_.load(); }

    void IncrementMisses() { misses_++; }
    uint64_t GetMisses() const { return misses_.load(); }

    void AddItemsEvicted(uint64_t count) { items_evicted_ += count; }
    uint64_t GetItemsEvicted() const { return items_evicted_.load(); }

    void IncrementPromotions() { promotions_++; }
    uint64_t GetPromotions() const { return promotions_.load(); }

    private:
    std::atomic<uint64_t> hits_{0};
    std::atomic<uint64_t> misses_{0};
    std::atomic<uint64_t> items_evicted_{0};
    std::atomic<uint64_t> promotions_{0};
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_
