#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_

#include "config/config_types.hpp"
#include "storage/i_storage.hpp"
#include "storage/storage_stats.hpp"

#include <filesystem>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

namespace DistributedCacheFS::Storage
{

class LocalStorage final : public IStorage
{
    public:
    explicit LocalStorage(const Config::StorageDefinition& definition);
    ~LocalStorage() override = default;

    Config::StorageType GetType() const override;
    const std::filesystem::path& GetPath() const override;
    StorageResult<std::size_t> GetCapacityBytes() const override;
    StorageResult<std::size_t> GetUsedBytes() const override;
    StorageResult<std::size_t> GetAvailableBytes() const override;
    StorageResult<std::size_t> Read(
        const fs::path& relative_path, off_t offset, std::span<std::byte>& buffer
    ) override;
    StorageResult<std::size_t> Write(
        const fs::path& relative_path, off_t offset, std::span<std::byte>& data
    ) override;
    StorageResult<void> Remove(const fs::path& relative_path) override;
    StorageResult<void> Truncate(const fs::path& relative_path, off_t size) override;
    StorageResult<void> PunchHole(
        const fs::path& relative_path, off_t offset, size_t size
    ) override;
    StorageResult<void> Fsync(const fs::path& relative_path, bool is_data_sync) override;
    StorageResult<bool> CheckIfFileExists(const fs::path& relative_path) const override;
    StorageResult<struct stat> GetAttributes(const fs::path& relative_path) const override;
    StorageResult<struct statvfs> GetFilesystemStats(const std::string& path) const override;
    StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const fs::path& relative_path
    ) override;
    StorageResult<void> CreateFile(const fs::path& relative_path, mode_t mode) override;
    StorageResult<void> CreateSpecialFile(
        const fs::path& relative_path, mode_t mode, dev_t rdev
    ) override;
    StorageResult<void> CreateDirectory(const fs::path& relative_path, mode_t mode) override;
    StorageResult<void> CreateHardLink(
        const fs::path& from_relative_path, const fs::path& to_relative_path
    ) override;
    StorageResult<void> Move(
        const fs::path& from_relative_path, const fs::path& to_relative_path
    ) override;
    StorageResult<void> SetPermissions(const fs::path& relative_path, mode_t mode) override;
    StorageResult<void> SetOwner(const fs::path& relative_path, uid_t uid, gid_t gid) override;
    StorageResult<void> SetXattr(
        const fs::path& relative_path, const std::string& name, const char* value, size_t size,
        int flags
    ) override;
    StorageResult<ssize_t> GetXattr(
        const fs::path& relative_path, const std::string& name, char* value, size_t size
    ) override;
    StorageResult<ssize_t> ListXattr(
        const fs::path& relative_path, char* list, size_t size
    ) override;
    StorageResult<void> RemoveXattr(
        const fs::path& relative_path, const std::string& name
    ) override;
    StorageResult<void> Initialize() override;
    StorageResult<void> Shutdown() override;
    fs::path RelativeToAbsPath(const fs::path& relative_path) const override;

    private:
    fs::path GetValidatedFullPath(const fs::path& relative_path) const;
    std::error_code MapFilesystemError(
        const std::error_code& ec, const std::string& operation
    ) const;

    const Config::StorageDefinition definition_;
    const fs::path base_path_;
    mutable std::recursive_mutex storage_mutex_;
    StorageStats stats_;
};

}  // namespace DistributedCacheFS::Storage

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_
