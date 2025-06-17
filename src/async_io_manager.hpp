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

    using ReadResult = Storage::StorageResult<std::vector<std::byte>>;

    std::future<ReadResult> SubmitRead(
        std::shared_ptr<Storage::IStorage> storage, std::filesystem::path path, off_t offset,
        size_t bytes_to_read
    );

    void SubmitTask(std::function<void()>&& task);

    private:
    void WorkerThread();

    std::vector<std::thread> workers_;
    std::deque<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool stop_ = false;
};

}  // namespace DistributedCacheFS

#endif  // DISTRIBUTEDCACHEFS_SRC_ASYNC_IO_MANAGER_HPP_
