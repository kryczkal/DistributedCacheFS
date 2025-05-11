#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_

#include "config/config_types.hpp"
#include "storage/i_storage.hpp"

#include <filesystem>
#include <mutex>
#include <system_error>

namespace DistributedCacheFS::Storage
{

class LocalStorage : public IStorage
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    explicit LocalStorage(const Config::StorageDefinition& definition);
    ~LocalStorage() override = default;

    LocalStorage(const LocalStorage&)            = delete;
    LocalStorage& operator=(const LocalStorage&) = delete;
    LocalStorage(LocalStorage&&)                 = delete;
    LocalStorage& operator=(LocalStorage&&)      = delete;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    // IStorage Implementation

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

    StorageResult<bool> CheckIfFileExists(const std::filesystem::path& relative_path
    ) const override;
    StorageResult<struct stat> GetAttributes(const std::filesystem::path& relative_path
    ) const override;
    StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const std::filesystem::path& relative_path
    ) override;

    StorageResult<void> CreateFile(const std::filesystem::path& relative_path, mode_t mode)
        override;

    StorageResult<void> CreateDirectory(const std::filesystem::path& relative_path, mode_t mode)
        override;

    StorageResult<void> Move(
        const std::filesystem::path& from_relative_path,
        const std::filesystem::path& to_relative_path
    ) override;

    StorageResult<void> Initialize() override;
    StorageResult<void> Shutdown() override;

    std::filesystem::path RelativeToAbsPath(const std::filesystem::path& relative_path
    ) const override;

    //------------------------------------------------------------------------------//
    // Public Fields
    //------------------------------------------------------------------------------//

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//

    std::filesystem::path GetValidatedFullPath(const std::filesystem::path& relative_path) const;
    std::error_code MapFilesystemError(const std::error_code& ec, const std::string& operation = "")
        const;
    StorageResult<void> SetXattr(
        const std::filesystem::path& full_path, const char* key, const void* value, size_t size
    );
    StorageResult<std::vector<char>> GetXattr(
        const std::filesystem::path& full_path, const char* key
    ) const;
    StorageResult<void> RemoveXattr(const std::filesystem::path& full_path, const char* key);

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//
    static const char* XATTR_ORIGIN_MTIME_KEY;
    static const char* XATTR_ORIGIN_SIZE_KEY;

    const Config::StorageDefinition definition_;
    std::filesystem::path base_path_;
    mutable std::recursive_mutex storage_mutex_;

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Storage

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_LOCAL_STORAGE_HPP_
