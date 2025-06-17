#ifndef DISTRIBUTEDCACHEFS_SRC_ASYNC_IO_MANAGER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_ASYNC_IO_MANAGER_HPP_

#include "storage/i_storage.hpp"

#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace DistributedCacheFS
{

class AsyncIoManager
{
    public:
    explicit AsyncIoManager(size_t num_threads = std::thread::hardware_concurrency());
    ~AsyncIoManager();

    AsyncIoManager(const AsyncIoManager&)            = delete;
    AsyncIoManager& operator=(const AsyncIoManager&) = delete;

    using ReadResult = Storage::StorageResult<size_t>;

    std::future<ReadResult> SubmitRead(
        std::shared_ptr<Storage::IStorage> storage, std::filesystem::path path, off_t offset,
        std::span<std::byte> buffer
    );

    private:
    void WorkerThread();

    std::vector<std::thread> workers_;
    std::deque<std::packaged_task<ReadResult()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool stop_ = false;
};

}  // namespace DistributedCacheFS

#endif  // DISTRIBUTEDCACHEFS_SRC_ASYNC_IO_MANAGER_HPP_
