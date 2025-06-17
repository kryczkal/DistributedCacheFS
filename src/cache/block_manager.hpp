#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_MANAGER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_MANAGER_HPP_

#include "cache/block_metadata.hpp"

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
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

class BlockManager
{
    private:
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
    BlockManager();
    ~BlockManager() = default;

    BlockManager(const BlockManager&)            = delete;
    BlockManager& operator=(const BlockManager&) = delete;
    BlockManager(BlockManager&&)                 = delete;
    BlockManager& operator=(BlockManager&&)      = delete;

    std::pair<RegionList, RegionList> GetCachedRegionsAndUpdateHeat(
        const fs::path& fuse_path, off_t offset, size_t size, const CoherencyMetadata& origin_metadata,
        std::function<double(const BlockMetadata&, double)> heat_updater,
        std::function<void(const fs::path&)> on_stale_item
    );

    void CacheRegion(
        const fs::path& fuse_path, off_t offset, size_t size, double initial_heat,
        double base_fetch_cost_ms, const CoherencyMetadata& coherency_metadata
    );

    std::vector<BlockMetadata> InvalidateRegion(const fs::path& fuse_path, off_t offset, size_t size);

    void InvalidateAndRemoveItem(const fs::path& fuse_path);

    std::optional<ItemMetadata> GetItemMetadata(const fs::path& fuse_path);

    bool IsRegionWorthInserting(
        double new_region_heat, size_t new_region_size, uint64_t available_space,
        std::function<double(const BlockMetadata&, double)> heat_updater
    );

    std::vector<EvictionCandidate> GetVictimsForEviction(size_t required_space);

    void RemoveEvictionVictims(const std::vector<EvictionCandidate>& victims);

    private:
    void RefreshRandomHeats_impl(std::function<double(const BlockMetadata&, double)> heat_updater);

    ItemMetadataContainer item_metadatas_;
    EvictionQueue eviction_queue_;
    mutable std::shared_mutex metadata_mutex_;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_MANAGER_HPP_
