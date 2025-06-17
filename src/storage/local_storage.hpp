#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_

#include "config/config_types.hpp"
#include "storage/i_storage.hpp"
#include "storage/storage_stats.hpp"

#include <filesystem>
#include <mutex>
#include <string>
#include <system_error>

namespace DistributedCacheFS::Storage
{

namespace fs = std::filesystem;

class LocalStorage : public IStorage
{
    public:
    explicit LocalStorage(const Config::StorageDefinition& definition);
    ~LocalStorage() override = default;

    LocalStorage(const LocalStorage&)            = delete;
    LocalStorage& operator=(const LocalStorage&) = delete;
    LocalStorage(LocalStorage&&)                 = delete;
    LocalStorage& operator=(LocalStorage&&)      = delete;

    Config::StorageType GetType() const override { return definition_.type; }
    const std::filesystem::path& GetPath() const override { return base_path_; }

    StorageResult<std::uint64_t> GetCapacityBytes() const override;
    StorageResult<std::uint64_t> GetUsedBytes() const override;
    StorageResult<std::uint64_t> GetAvailableBytes() const override;

    StorageResult<std::size_t> Read(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& buffer
    ) override;
    StorageResult<std::size_t> Write(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte>& data
    ) override;
    StorageResult<void> Remove(const std::filesystem::path& relative_path) override;
    StorageResult<void> Truncate(const std::filesystem::path& relative_path, off_t size) override;
    StorageResult<void> PunchHole(
        const std::filesystem::path& relative_path, off_t offset, size_t size
    ) override;

    StorageResult<bool> CheckIfFileExists(const std::filesystem::path& relative_path
    ) const override;
    StorageResult<struct stat> GetAttributes(const std::filesystem::path& relative_path
    ) const override;
    StorageResult<struct statvfs> GetFilesystemStats(const std::string& path) const override;
    StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const std::filesystem::path& relative_path
    ) override;

    StorageResult<void> CreateFile(const std::filesystem::path& relative_path, mode_t mode)
        override;
    StorageResult<void> CreateSpecialFile(
        const std::filesystem::path& relative_path, mode_t mode, dev_t rdev
    ) override;

    StorageResult<void> CreateDirectory(const std::filesystem::path& relative_path, mode_t mode)
        override;

    StorageResult<void> Move(
        const std::filesystem::path& from_relative_path,
        const std::filesystem::path& to_relative_path
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

    std::filesystem::path RelativeToAbsPath(const std::filesystem::path& relative_path
    ) const override;

    private:
    std::filesystem::path GetValidatedFullPath(const std::filesystem::path& relative_path) const;
    std::error_code MapFilesystemError(const std::error_code& ec, const std::string& operation = "")
        const;

    const Config::StorageDefinition definition_;
    fs::path base_path_;
    StorageStats stats_;
    mutable std::recursive_mutex storage_mutex_;
};

}  // namespace DistributedCacheFS::Storage

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_
