#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_TIER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_TIER_HPP_

#include "block_metadata.hpp"
#include "cache_stats.hpp"
#include "config/config_types.hpp"
#include "storage/i_storage.hpp"

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include <filesystem>
#include <map>
#include <shared_mutex>
#include <vector>

namespace DistributedCacheFS::Cache
{

namespace fs  = std::filesystem;
namespace bmi = boost::multi_index;

struct ItemMetadata
{
    fs::path path;
    CoherencyMetadata coherency_metadata;
    std::map<off_t, BlockMetadata> blocks;
    double base_fetch_cost_ms = 1.0;
};

class CacheTier
{
    private:
    using IStorage = Storage::IStorage;
    template <typename T>
    using StorageResult = Storage::StorageResult<T>;

    struct by_path
    {
    };
    using ItemMetadataContainer = bmi::multi_index_container<
        ItemMetadata,
        bmi::indexed_by<
            bmi::hashed_unique<bmi::tag<by_path>, bmi::member<ItemMetadata, fs::path, &ItemMetadata::path>>>>;

    using EvictionQueue = bmi::multi_index_container<
        EvictionCandidate,
        bmi::indexed_by<
            bmi::ordered_non_unique<
                bmi::tag<EvictionCandidate::ByHeat>,
                bmi::member<EvictionCandidate, double, &EvictionCandidate::heat>>,
            bmi::hashed_unique<
                bmi::tag<EvictionCandidate::ByPathAndOffset>,
                bmi::composite_key<
                    EvictionCandidate,
                    bmi::member<EvictionCandidate, fs::path, &EvictionCandidate::path>,
                    bmi::member<EvictionCandidate, off_t, &EvictionCandidate::offset>>>>>;

    public:
    explicit CacheTier(const Config::CacheDefinition& cache_definition);
    ~CacheTier() = default;

    StorageResult<void> Initialize();
    StorageResult<void> Shutdown();
    StorageResult<std::uint64_t> GetCapacityBytes() const;
    StorageResult<std::uint64_t> GetUsedBytes() const;
    StorageResult<std::uint64_t> GetAvailableBytes() const;

    size_t GetTier() const { return cache_definition_.tier; }
    Storage::IStorage* GetStorage() { return storage_instance_.get(); }
    const Config::CacheSettings& GetSettings() const { return cache_definition_.cache_settings; }

    StorageResult<std::pair<RegionList, RegionList>> GetCachedRegions(
        const fs::path& fuse_path, off_t offset, size_t size, const CoherencyMetadata& origin_metadata
    );

    StorageResult<void> CacheRegion(
        const fs::path& fuse_path, off_t offset, std::span<std::byte> data,
        const ItemMetadata& item_metadata
    );

    StorageResult<bool> IsRegionWorthInserting(double new_region_heat, size_t new_region_size);

    StorageResult<void> FreeUpSpace(size_t required_space);

    StorageResult<void> InvalidateAndRemoveItem(const fs::path& fuse_path);
    StorageResult<void> InvalidateRegion(const fs::path& fuse_path, off_t offset, size_t size);

    StorageResult<ItemMetadata> GetItemMetadata(const fs::path& fuse_path);

    double CalculateInitialRegionHeat(double fetch_cost_ms, size_t region_size) const;
    double CalculateRegionHeat(
        double base_heat, time_t last_access_time, time_t current_time
    ) const;

    private:
    StorageResult<void> FreeUpSpace_impl(size_t required_space);
    void RefreshRandomHeats_impl();

    const Config::CacheDefinition cache_definition_;
    std::unique_ptr<Storage::IStorage> storage_instance_;
    ItemMetadataContainer item_metadatas_;
    EvictionQueue eviction_queue_;
    mutable std::shared_mutex metadata_mutex_;
    CacheStats stats_;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_CACHE_TIER_HPP_
