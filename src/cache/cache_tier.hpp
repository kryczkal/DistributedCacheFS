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
#include <shared_mutex>

#include "cache_stats.hpp"

namespace DistributedCacheFS::Cache
{

namespace fs  = std::filesystem;
namespace bmi = boost::multi_index;

struct HeatMetadata {
    double heat;
    double fetch_cost_ms;
    time_t last_access_time;
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

class CacheTier : public std::enable_shared_from_this<CacheTier>
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    using IStorage = Storage::IStorage;
    template <typename T>
    using StorageResult = Storage::StorageResult<T>;

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
    explicit CacheTier(const Config::CacheDefinition& cache_definition);
    ~CacheTier() = default;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    StorageResult<void> Initialize();
    StorageResult<void> Shutdown();
    StorageResult<std::uint64_t> GetCapacityBytes() const;
    StorageResult<std::uint64_t> GetUsedBytes() const;
    StorageResult<std::uint64_t> GetAvailableBytes() const;

    size_t GetTier() const { return cache_definition_.tier; }
    Storage::IStorage* GetStorage() { return storage_instance_.get(); }

    void SetMappingCallback(
        std::function<void(const fs::path&,
                           const std::shared_ptr<CacheTier>&,
                           bool /*add?*/)> cb)
    {
        mapping_cb_ = std::move(cb);
    }

    StorageResult<std::pair<bool, size_t>> ReadItemIfCacheValid(
        const fs::path& fuse_path, off_t offset, std::span<std::byte>& buffer,
        const CoherencyMetadata& origin_metadata
    );

    StorageResult<bool> CacheItemIfWorthIt(
        const fs::path& fuse_path, off_t offset, std::span<std::byte>& data,
        const ItemMetadata& item_metadata
    );

    StorageResult<void> CacheItemForcibly(
        const fs::path& fuse_path, off_t offset, std::span<std::byte>& data,
        const ItemMetadata& item_metadata
    );

    StorageResult<bool> IsCacheItemValid(
        const fs::path& fuse_path, const CoherencyMetadata& origin_metadata
    ) const;

    StorageResult<bool> IsItemWorthInserting(const ItemMetadata& item_metadata);

    StorageResult<void> FreeUpSpace(size_t required_space);

    void ReheatItem(const fs::path& fuse_path);
    void UpdateItemHeat(const fs::path& fuse_path);
    void RefreshRandomHeats();

    StorageResult<void> InvalidateAndRemoveItem(const fs::path& fuse_path);
    StorageResult<const ItemMetadata> GetItemMetadata(const fs::path& fuse_path);
    StorageResult<void> InsertItemMetadata(const ItemMetadata& item_metadata);

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//

    StorageResult<void> FreeUpSpace_impl(size_t required_space);
    void ReheatItem_impl(const fs::path& fuse_path);
    void RefreshRandomHeats_impl();
    void UpdateItemHeat_impl(const fs::path& fuse_path);
    StorageResult<void> InvalidateAndRemoveItem_impl(const fs::path& fuse_path);

    double CalculateItemHeat(
        const fs::path& fuse_path, const ItemMetadata& item_metadata, time_t current_time
    ) const;

    static double CalculateInitialItemHeat(
        const fs::path& fuse_path, const ItemMetadata& item_metadata
    );

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//
    const Config::CacheDefinition cache_definition_;
    std::unique_ptr<Storage::IStorage> storage_instance_;
    ItemMetadataContainer item_metadatas_;
    mutable std::shared_mutex tier_op_mutex_;
    CacheStats stats_;

    std::function<void(const fs::path&,
                       const std::shared_ptr<CacheTier>&,
                       bool)> mapping_cb_;

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//

    inline bool InvalidFusePath(const fs::path& p)
    {
        return p.empty() || p == "." || p == ".." || p == "/";
    }
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_TIER_HPP_
