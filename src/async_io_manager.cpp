#include "async_io_manager.hpp"

#include <spdlog/spdlog.h>

namespace DistributedCacheFS
{

AsyncIoManager::AsyncIoManager(size_t num_threads)
{
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this] {
            this->WorkerThread();
        });
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
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            condition_.wait(lock, [this] {
                return this->stop_ || !this->tasks_.empty();
            });
            if (this->stop_ && this->tasks_.empty()) {
                return;
            }
            task = std::move(tasks_.front());
            tasks_.pop_front();
        }

        task();
    }
}

void AsyncIoManager::SubmitTask(std::function<void()>&& task)
{
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) {
            throw std::runtime_error("AsyncIoManager is shutting down");
        }
        tasks_.emplace_back(std::move(task));
    }
    condition_.notify_one();
}

std::future<AsyncIoManager::ReadResult> AsyncIoManager::SubmitRead(
    std::shared_ptr<Storage::IStorage> storage, std::filesystem::path path, off_t offset,
    size_t bytes_to_read
)
{
    auto task_ptr =
        std::make_shared<std::packaged_task<ReadResult()>>([storage, path, offset,
                                                            bytes_to_read]() mutable {
            std::vector<std::byte> data_buffer(bytes_to_read);
            std::span<std::byte> buffer_span{data_buffer};

            Storage::StorageResult<size_t> read_res = storage->Read(path, offset, buffer_span);

            if (!read_res) {
                return std::unexpected(read_res.error());
            }

            data_buffer.resize(*read_res);
            return data_buffer;
        });

    std::future<ReadResult> future = task_ptr->get_future();

    SubmitTask([task_ptr]() {
        (*task_ptr)();
    });

    return future;
}

}  // namespace DistributedCacheFS
