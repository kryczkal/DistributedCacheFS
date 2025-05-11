#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_

#include <atomic>
#include <cstdint>

namespace DistributedCacheFS::Cache
{

class CacheStats
{
public:
    CacheStats() : current_size_bytes_(0), max_size_bytes_(0) {}

    void SetMaxSizeBytes(uint64_t max_size) { max_size_bytes_ = max_size; }
    uint64_t GetMaxSizeBytes() const { return max_size_bytes_; }

    uint64_t GetCurrentSizeBytes() const { return current_size_bytes_.load(std::memory_order_relaxed); }

    void IncrementSizeBytes(uint64_t size_to_add) { current_size_bytes_.fetch_add(size_to_add, std::memory_order_relaxed); }
    void DecrementSizeBytes(uint64_t size_to_remove) { current_size_bytes_.fetch_sub(size_to_remove, std::memory_order_relaxed); }

    bool UsesSizeTracking() const { return uses_size_tracking_; }
    void SetUsesSizeTracking(bool uses_size_tracking) { uses_size_tracking_ = uses_size_tracking; }
    
    // TODO: Add other statistics methods here

private:
    std::atomic<uint64_t> current_size_bytes_;
    bool uses_size_tracking_ = false;
    uint64_t max_size_bytes_;

    // Future stats members:
    // std::atomic<uint64_t> hits_;
    // std::atomic<uint64_t> misses_;
    // std::atomic<uint64_t> items_added_;
    // std::atomic<uint64_t> items_removed_;
    // std::atomic<uint64_t> items_evicted_;
};

} // namespace DistributedCacheFS::Cache

#endif // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_STATS_HPP_ 