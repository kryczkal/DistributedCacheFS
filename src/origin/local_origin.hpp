// === src/origin/LocalOrigin.hpp ===
#ifndef DISTRIBUTEDCACHEFS_SRC_ORIGIN_LOCALORIGIN_HPP_
#define DISTRIBUTEDCACHEFS_SRC_ORIGIN_LOCALORIGIN_HPP_

#include "config/config_types.hpp"
#include "origin/i_origin_interface.hpp"

#include <filesystem>
#include <mutex>

namespace DistributedCacheFS::Origin
{

class LocalOrigin : public IOriginInterface
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    explicit LocalOrigin(const Config::OriginDefinition& definition);
    ~LocalOrigin() override = default;

    LocalOrigin(const LocalOrigin&)            = delete;
    LocalOrigin& operator=(const LocalOrigin&) = delete;
    LocalOrigin(LocalOrigin&&)                 = delete;
    LocalOrigin& operator=(LocalOrigin&&)      = delete;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    // IOriginInterface Implementation
    Storage::StorageResult<struct stat> GetAttributes(const std::filesystem::path& relative_path
    ) override;
    Storage::StorageResult<std::vector<std::pair<std::string, struct stat>>> ListDirectory(
        const std::filesystem::path& relative_path
    ) override;
    Storage::StorageResult<size_t> Read(
        const std::filesystem::path& relative_path, off_t offset, std::span<std::byte> buffer
    ) override;
    Storage::StorageResult<size_t> Write(
        const std::filesystem::path& relative_path, off_t offset, std::span<const std::byte> data
    ) override;
    Storage::StorageResult<void> CreateFile(const std::filesystem::path& relative_path, mode_t mode)
        override;
    Storage::StorageResult<void> CreateDirectory(
        const std::filesystem::path& relative_path, mode_t mode
    ) override;
    Storage::StorageResult<void> Remove(const std::filesystem::path& relative_path) override;
    Storage::StorageResult<void> Truncate(const std::filesystem::path& relative_path, off_t size)
        override;
    Storage::StorageResult<void> Move(
        const std::filesystem::path& from_relative_path,
        const std::filesystem::path& to_relative_path
    ) override;
    Storage::StorageResult<struct statvfs> GetFilesystemStats() override;

    Storage::StorageResult<void> Initialize() override;
    Storage::StorageResult<void> Shutdown() override;

    std::filesystem::path GetFullPath(const std::filesystem::path& relative_path) const override;

    //------------------------------------------------------------------------------//
    // Public Fields
    //------------------------------------------------------------------------------//

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//
    std::filesystem::path GetValidatedFullPath(const std::filesystem::path& relative_path) const;
    std::error_code MapFilesystemError(const std::error_code& ec, const std::string& operation = "")
        const;  // Helper for error mapping

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//

    const Config::OriginDefinition definition_;
    std::filesystem::path base_path_;

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Origin

#endif  // DISTRIBUTEDCACHEFS_SRC_ORIGIN_LOCALORIGIN_HPP_
