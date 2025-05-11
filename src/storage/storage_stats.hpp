#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_STATS_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_STATS_HPP_

#include <atomic>
#include <cstdint>
#include <limits>

namespace DistributedCacheFS::Storage
{

class StorageStats
{
    public:
    StorageStats() : current_size_bytes_(0), max_size_bytes_(0) {}

    void SetMaxSizeBytes(uint64_t max_size) { max_size_bytes_ = max_size; }
    uint64_t GetMaxSizeBytes() const { return max_size_bytes_; }

    uint64_t GetCurrentSizeBytes() const { return current_size_bytes_.load(); }

    void IncrementSizeBytes(uint64_t size_to_add)
    {
        auto old_size = current_size_bytes_.load();
        current_size_bytes_.store(
            old_size < std::numeric_limits<uint64_t>::max() - size_to_add
                ? old_size + size_to_add
                : std::numeric_limits<uint64_t>::max()
        );
    }
    void DecrementSizeBytes(uint64_t size_to_remove)
    {
        auto old_size = current_size_bytes_.load();
        current_size_bytes_.store(old_size < size_to_remove ? 0 : old_size - size_to_remove);
    }
    void SetCurrentSizeBytes(uint64_t size) { current_size_bytes_.store(size); }

    bool UsesSizeTracking() const { return uses_size_tracking_; }
    void SetUsesSizeTracking(bool uses_size_tracking) { uses_size_tracking_ = uses_size_tracking; }

    private:
    std::atomic<uint64_t> current_size_bytes_;
    std::atomic<bool> uses_size_tracking_ = false;
    uint64_t max_size_bytes_;
};

}  // namespace DistributedCacheFS::Storage

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_STATS_HPP_
