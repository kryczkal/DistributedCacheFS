#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_TIER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_TIER_HPP_

#include "config/config_types.hpp"
#include "storage/i_storage.hpp"

#include "boost/multi_index/hashed_index.hpp"
#include "boost/multi_index/indexed_by.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"

#include <filesystem>

namespace DistributedCacheFS::Cache
{

namespace fs  = std::filesystem;
namespace bmi = boost::multi_index;

class CacheTier : Storage::IStorage
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    using IStorage = Storage::IStorage;

    template <typename T>
    using StorageResult = Storage::StorageResult<T>;

    struct HeatMetadata {
        double heat;
        double fetch_cost;
        time_t last_access_time;  ///< Last accessed time
    };

    struct CoherencyMetadata {
        time_t last_modified_time;
        off_t size_bytes;
    };

    struct ItemMetadata {
        fs::path path;
        HeatMetadata heat_metadata;
        CoherencyMetadata coherency_metadata;
    };

    // Cache index tags
    struct by_path {
    };
    struct by_heat {
    };

    struct HeatValueExtractor {
        using result_type   = double;
        using argument_type = ItemMetadata const&;
        result_type operator()(argument_type im) const noexcept { return im.heat_metadata.heat; }
    };

    using ItemMetadataContainer = bmi::multi_index_container<
        ItemMetadata,
        bmi::indexed_by<
            bmi::hashed_unique<
                bmi::tag<by_path>, bmi::member<ItemMetadata, fs::path, &ItemMetadata::path>>,
            bmi::ordered_non_unique<bmi::tag<by_heat>, HeatValueExtractor>>>;

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    explicit CacheTier(Config::CacheDefinition cache_definition);
    ~CacheTier() = default;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    // IStorage Implementation - Proxy to storage_instance_

    size_t GetTier() const { return cache_definition_.tier; }
    Config::StorageType GetType() const override { return storage_instance_->GetType(); }
    const std::filesystem::path& GetPath() const override { return storage_instance_->GetPath(); }

    StorageResult<std::uint64_t> GetCapacityBytes() const override;
    StorageResult<std::uint64_t> GetUsedBytes() const override;
    StorageResult<std::uint64_t> GetAvailableBytes() const override;

    StorageResult<std::size_t> Read(
        const std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& buffer
    ) override;
    StorageResult<std::size_t> Write(
        const std::filesystem::path& fuse_path, off_t offset, std::span<const std::byte>& data
    ) override;
    StorageResult<void> Remove(const std::filesystem::path& fuse_path) override;
    StorageResult<void> Truncate(const std::filesystem::path& fuse_path, off_t size) override;

    StorageResult<bool> CheckIfFileExists(const std::filesystem::path& fuse_path) const override;
    StorageResult<struct stat> GetAttributes(const std::filesystem::path& fuse_path) const override;

    StorageResult<void> Initialize() override;
    StorageResult<void> Shutdown() override;

    std::filesystem::path RelativeToAbsPath(const std::filesystem::path& fuse_path) const override;

    //------------------------------------------------------------------------------//
    // Public Fields
    //------------------------------------------------------------------------------//

    StorageResult<void> InvalidateAndRemoveEntry(const fs::path& fuse_path);

    StorageResult<bool> CacheIfWorthIt(
        const std::filesystem::path& fuse_path, off_t offset, std::span<const std::byte>& data,
        const ItemMetadata& item_metadata
    );

    StorageResult<void> CacheForcibly(
        const fs::path& fuse_path, off_t offset, std::span<const std::byte>& data,
        const ItemMetadata& item_metadata
    );

    StorageResult<bool> IsCacheValid(
        const fs::path& fuse_path, const CoherencyMetadata& current_origin_metadata
    ) const;

    StorageResult<bool> IsItemWorthInserting(const ItemMetadata& item_metadata) const;

    StorageResult<void> FreeUpSpace(size_t required_space);

    double CalculateHeat(
        const fs::path& fuse_path, ItemMetadata& item_metadata, time_t current_time
    ) const;

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//
    const Config::CacheDefinition cache_definition_;       ///< Cache definition
    std::unique_ptr<Storage::IStorage> storage_instance_;  ///< Storage instance
    ItemMetadataContainer item_metadatas_;
    mutable std::recursive_mutex cache_mutex_;  ///< Mutex for cache operations

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_TIER_HPP_
