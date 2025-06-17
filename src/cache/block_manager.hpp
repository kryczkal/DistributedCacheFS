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
#include <set>
#include <shared_mutex>
#include <vector>

namespace DistributedCacheFS::Cache
{

namespace fs  = std::filesystem;
namespace bmi = boost::multi_index;

struct ItemMetadata {
    FileId file_id;
    std::set<fs::path> known_paths;
    CoherencyMetadata coherency_metadata;
    std::map<off_t, BlockMetadata> blocks;
    double base_fetch_cost_ms = 1.0;
};

class BlockManager
{
    private:
    struct by_file_id {
    };
    using ItemMetadataContainer = bmi::multi_index_container<
        ItemMetadata,
        bmi::indexed_by<bmi::hashed_unique<
            bmi::tag<by_file_id>, bmi::member<ItemMetadata, FileId, &ItemMetadata::file_id>>>>;

    using EvictionQueue = bmi::multi_index_container<
        EvictionCandidate,
        bmi::indexed_by<
            bmi::ordered_non_unique<
                bmi::tag<EvictionCandidate::ByHeat>,
                bmi::member<EvictionCandidate, double, &EvictionCandidate::heat>>,
            bmi::hashed_unique<
                bmi::tag<EvictionCandidate::ByFileIdAndOffset>,
                bmi::composite_key<
                    EvictionCandidate,
                    bmi::member<EvictionCandidate, FileId, &EvictionCandidate::file_id>,
                    bmi::member<EvictionCandidate, off_t, &EvictionCandidate::offset>>>,
            bmi::hashed_non_unique<
                bmi::tag<EvictionCandidate::ByFileId>,
                bmi::member<EvictionCandidate, FileId, &EvictionCandidate::file_id>>>>;

    public:
    BlockManager();
    ~BlockManager() = default;

    BlockManager(const BlockManager&)            = delete;
    BlockManager& operator=(const BlockManager&) = delete;
    BlockManager(BlockManager&&)                 = delete;
    BlockManager& operator=(BlockManager&&)      = delete;

    std::pair<RegionList, RegionList> GetCachedRegionsAndUpdateHeat(
        const FileId& file_id, const fs::path& access_path, off_t offset, size_t size,
        const CoherencyMetadata& origin_metadata,
        std::function<double(const BlockMetadata&, double)> heat_updater,
        std::function<void(const FileId&)> on_stale_item
    );

    void CacheRegion(
        const FileId& file_id, const fs::path& access_path, off_t offset, size_t size,
        double initial_heat, double base_fetch_cost_ms, const CoherencyMetadata& coherency_metadata
    );

    std::vector<BlockMetadata> InvalidateRegion(const FileId& file_id, off_t offset, size_t size);

    std::vector<BlockMetadata> InvalidateAndRemoveItem(const FileId& file_id);

    std::optional<ItemMetadata> GetItemMetadata(const FileId& file_id);

    bool IsRegionWorthInserting(
        double new_region_heat, size_t new_region_size, uint64_t available_space,
        std::function<double(const BlockMetadata&, double)> heat_updater
    );

    std::vector<EvictionCandidate> GetVictimsForEviction(size_t required_space);

    void RemoveEvictionVictims(const std::vector<EvictionCandidate>& victims);

    void RefreshRandomHeats(std::function<double(const BlockMetadata&, double)> heat_updater);

    void AddLink(const FileId& file_id, const fs::path& new_path);
    bool RemoveLink(const FileId& file_id, const fs::path& path_to_remove);
    void RenameLink(const FileId& file_id, const fs::path& from, const fs::path& to);

    private:
    ItemMetadataContainer item_metadatas_;
    EvictionQueue eviction_queue_;
    mutable std::shared_mutex metadata_mutex_;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_BLOCK_MANAGER_HPP_
