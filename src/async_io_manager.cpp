#include "async_io_manager.hpp"

#include <spdlog/spdlog.h>

namespace DistributedCacheFS
{

AsyncIoManager::AsyncIoManager(size_t num_threads)
{
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this] { this->WorkerThread(); });
    }
}

AsyncIoManager::~AsyncIoManager()
{
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    condition_.notify_all();
    for (std::thread& worker : workers_) {
        worker.join();
    }
}

void AsyncIoManager::WorkerThread()
{
    while (true) {
        std::packaged_task<ReadResult()> task;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            condition_.wait(lock, [this] { return this->stop_ || !this->tasks_.empty(); });
            if (this->stop_ && this->tasks_.empty()) {
                return;
            }
            task = std::move(tasks_.front());
            tasks_.pop_front();
        }

        task();
    }
}

std::future<AsyncIoManager::ReadResult> AsyncIoManager::SubmitRead(
    std::shared_ptr<Storage::IStorage> storage, std::filesystem::path path, off_t offset,
    std::span<std::byte> buffer
)
{
    std::packaged_task<ReadResult()> task(
        [storage, path, offset, buffer]() mutable { return storage->Read(path, offset, buffer); }
    );

    std::future<ReadResult> future = task.get_future();
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) {
            throw std::runtime_error("AsyncIoManager is shutting down");
        }
        tasks_.emplace_back(std::move(task));
    }
    condition_.notify_one();
    return future;
}

}  // namespace DistributedCacheFS
