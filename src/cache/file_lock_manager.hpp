#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_FILE_LOCK_MANAGER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_FILE_LOCK_MANAGER_HPP_

#include <atomic>
#include <filesystem>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace DistributedCacheFS::Cache
{

namespace fs = std::filesystem;

/**
 * @brief Manages the creation, lifecycle, and acquisition of per-file mutexes.
 *
 * This class ensures that for any given file path, only one mutex exists.
 * It uses a map of weak pointers to allow mutexes to be automatically
 * deallocated when they are no longer in use by any thread, preventing
 * a memory leak of mutex objects for files that are no longer being accessed.
 * This class is thread-safe.
 */
class FileLockManager
{
    public:
    FileLockManager()  = default;
    ~FileLockManager() = default;

    FileLockManager(const FileLockManager&)            = delete;
    FileLockManager& operator=(const FileLockManager&) = delete;
    FileLockManager(FileLockManager&&)                 = delete;
    FileLockManager& operator=(FileLockManager&&)      = delete;

    /**
     * @brief Acquires a shared pointer to the mutex associated with a given path.
     *
     * If a mutex for the path already exists and is active, a pointer to it is
     * returned. If one does not exist or has expired, a new mutex is created,
     * stored, and a pointer to it is returned.
     *
     * The caller is expected to use the returned shared_ptr to instantiate a
     * lock guard (e.g., std::lock_guard or std::scoped_lock). The shared_ptr
     * ensures the mutex remains alive for the duration of the lock.
     *
     * @param path The filesystem path to lock.
     * @return A std::shared_ptr<std::recursive_mutex> for the given path.
     */
    std::shared_ptr<std::recursive_mutex> GetFileLock(const fs::path& path);

    private:
    void CleanupExpiredLocks_();

    std::mutex map_mutex_;
    std::unordered_map<fs::path, std::weak_ptr<std::recursive_mutex>> locks_;

    std::atomic<size_t> access_count_{0};
    static constexpr size_t kCleanupInterval = 1000;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_FILE_LOCK_MANAGER_HPP_
