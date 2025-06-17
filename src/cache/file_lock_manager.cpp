#include "cache/file_lock_manager.hpp"

#include <utility>

namespace DistributedCacheFS::Cache
{

void FileLockManager::CleanupExpiredLocks_()
{
    // This function is called from within a lock_guard in GetFileLock,
    // so we don't need to lock the mutex again here.
    for (auto it = locks_.begin(); it != locks_.end();) {
        if (it->second.expired()) {
            it = locks_.erase(it);
        } else {
            ++it;
        }
    }
}

std::shared_ptr<std::recursive_mutex> FileLockManager::GetFileLock(const fs::path& path)
{
    // Atomically increment the counter and get the value *before* increment.
    // A relaxed memory order is sufficient as this is just a counter.
    size_t old_count = access_count_.fetch_add(1, std::memory_order_relaxed);

    std::lock_guard lock(map_mutex_);

    // If the interval is reached, run the cleanup.
    // Check old_count > 0 to avoid running on the very first access.
    if (old_count > 0 && (old_count % kCleanupInterval == 0)) {
        CleanupExpiredLocks_();
    }

    // Check if a lock for the path already exists and is active.
    auto it = locks_.find(path);
    if (it != locks_.end()) {
        if (auto sp = it->second.lock()) {
            // Found an active mutex, return it.
            return sp;
        }
    }

    // No active mutex found (either didn't exist or has expired).
    // Create a new one.
    auto new_mutex = std::make_shared<std::recursive_mutex>();
    locks_[path]   = new_mutex;  // Insert/update the map with the new weak_ptr.
    return new_mutex;
}

}  // namespace DistributedCacheFS::Cache
