#include "cache/block_manager.hpp"

#include "app_constants.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <iterator>
#include <random>
#include <vector>

namespace DistributedCacheFS::Cache
{

BlockManager::BlockManager()
{
}

std::pair<RegionList, RegionList> BlockManager::GetCachedRegionsAndUpdateHeat(
    const fs::path& fuse_path, off_t offset, size_t size, const CoherencyMetadata& origin_metadata,
    std::function<double(const BlockMetadata&, double)> heat_updater,
    std::function<void(const fs::path&)> on_stale_item
)
{
    std::unique_lock lock(metadata_mutex_);

    RegionList cached_regions;
    RegionList missing_regions;

    auto& item_index = item_metadatas_.get<by_path>();
    auto item_it     = item_index.find(fuse_path);

    if (item_it == item_index.end()) {
        missing_regions.push_back({offset, size});
        return {cached_regions, missing_regions};
    }

    if (item_it->coherency_metadata.last_modified_time != origin_metadata.last_modified_time ||
        item_it->coherency_metadata.size_bytes != origin_metadata.size_bytes) {
        on_stale_item(fuse_path);
        missing_regions.push_back({offset, size});
        return {cached_regions, missing_regions};
    }

    auto& blocks = item_it->blocks;
    if (blocks.empty()) {
        missing_regions.push_back({offset, size});
        return {cached_regions, missing_regions};
    }

    off_t request_end = offset + size;
    off_t current_pos = offset;

    auto it = blocks.upper_bound(offset);
    if (it != blocks.begin()) {
        --it;
    }

    while (current_pos < request_end && it != blocks.end()) {
        const auto& [block_offset, block] = *it;
        off_t block_end                   = block_offset + block.size;

        if (block_end <= current_pos) {
            ++it;
            continue;
        }

        if (block_offset > current_pos) {
            missing_regions.push_back({current_pos, block_offset - current_pos});
        }

        off_t overlap_start = std::max(current_pos, block_offset);
        off_t overlap_end   = std::min(request_end, block_end);

        if (overlap_start < overlap_end) {
            cached_regions.push_back({overlap_start, (size_t)(overlap_end - overlap_start)});

            auto& heat_index         = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();
            auto eviction_it         = heat_index.find(std::make_tuple(fuse_path, block_offset));
            const auto& current_block = it->second;

            if (eviction_it != heat_index.end()) {
                double new_heat = heat_updater(current_block, eviction_it->heat);
                heat_index.modify(eviction_it, [&](EvictionCandidate& c) { c.heat = new_heat; });
            }

            item_index.modify(item_it, [&](ItemMetadata& item) {
                item.blocks[block_offset].last_access_time = time(nullptr);
            });
        }

        current_pos = overlap_end;
        ++it;
    }

    if (current_pos < request_end) {
        missing_regions.push_back({current_pos, (size_t)(request_end - current_pos)});
    }

    return {cached_regions, missing_regions};
}

void BlockManager::CacheRegion(
    const fs::path& fuse_path, off_t offset, size_t size, double initial_heat,
    double base_fetch_cost_ms, const CoherencyMetadata& coherency_metadata
)
{
    std::unique_lock lock(metadata_mutex_);

    auto& item_index = item_metadatas_.get<by_path>();
    auto item_it     = item_index.find(fuse_path);

    if (item_it == item_index.end()) {
        item_it =
            item_index
                .emplace(ItemMetadata{
                    fuse_path, coherency_metadata, {}, base_fetch_cost_ms
                })
                .first;
    } else {
        if (item_it->coherency_metadata.last_modified_time != coherency_metadata.last_modified_time ||
            item_it->coherency_metadata.size_bytes != coherency_metadata.size_bytes) {
            item_index.modify(item_it, [&](ItemMetadata& item) {
                item.blocks.clear();
                item.coherency_metadata = coherency_metadata;
                eviction_queue_.get<EvictionCandidate::ByPathAndOffset>().erase(fuse_path);
            });
        }
    }

    BlockMetadata new_block{offset, size, time(nullptr), initial_heat};
    item_index.modify(
        item_it, [&](ItemMetadata& item) { item.blocks[offset] = new_block; }
    );

    auto& heat_index  = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();
    auto eviction_it = heat_index.find(std::make_tuple(fuse_path, offset));
    if (eviction_it != heat_index.end()) {
        heat_index.modify(eviction_it, [&](EvictionCandidate& c) {
            c.heat = initial_heat;
            c.size = size;
        });
    } else {
        eviction_queue_.emplace(EvictionCandidate{fuse_path, offset, initial_heat, size});
    }
}

std::vector<BlockMetadata> BlockManager::InvalidateRegion(
    const fs::path& fuse_path, off_t offset, size_t size
)
{
    std::unique_lock lock(metadata_mutex_);
    std::vector<BlockMetadata> invalidated_blocks;

    auto& item_index = item_metadatas_.get<by_path>();
    auto item_it     = item_index.find(fuse_path);
    if (item_it == item_index.end()) {
        return invalidated_blocks;
    }

    off_t invalidation_end = offset + size;
    auto& blocks           = item_it->blocks;
    auto& heat_index       = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();

    for (auto it = blocks.begin(); it != blocks.end();) {
        off_t block_start = it->first;
        off_t block_end   = block_start + it->second.size;

        if (block_start < invalidation_end && block_end > offset) {
            invalidated_blocks.push_back(it->second);
            heat_index.erase(std::make_tuple(fuse_path, it->first));
            it = blocks.erase(it);
        } else {
            ++it;
        }
    }
    return invalidated_blocks;
}

void BlockManager::InvalidateAndRemoveItem(const fs::path& fuse_path)
{
    std::unique_lock lock(metadata_mutex_);
    auto& item_index = item_metadatas_.get<by_path>();
    item_index.erase(fuse_path);

    auto& heat_index = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();
    heat_index.erase(fuse_path);
}

std::optional<ItemMetadata> BlockManager::GetItemMetadata(const fs::path& fuse_path)
{
    std::shared_lock lock(metadata_mutex_);
    auto& item_index = item_metadatas_.get<by_path>();
    auto it          = item_index.find(fuse_path);
    if (it != item_index.end()) {
        return *it;
    }
    return std::nullopt;
}

bool BlockManager::IsRegionWorthInserting(
    double new_region_heat, size_t new_region_size, uint64_t available_space,
    std::function<double(const BlockMetadata&, double)> heat_updater
)
{
    std::unique_lock lock(metadata_mutex_);
    if (available_space >= new_region_size) {
        return true;
    }

    size_t space_to_free = new_region_size - available_space;
    size_t potential_free_space = 0;
    auto& heat_index             = eviction_queue_.get<EvictionCandidate::ByHeat>();

    for (const auto& candidate : heat_index) {
        if (candidate.heat >= new_region_heat) {
            return false;
        }
        potential_free_space += candidate.size;
        if (potential_free_space >= space_to_free) {
            return true;
        }
    }

    return false;
}

std::vector<EvictionCandidate> BlockManager::GetVictimsForEviction(size_t required_space)
{
    std::unique_lock lock(metadata_mutex_);
    std::vector<EvictionCandidate> victims;
    size_t freed_space = 0;
    auto& heat_index   = eviction_queue_.get<EvictionCandidate::ByHeat>();

    for (const auto& candidate : heat_index) {
        if (freed_space >= required_space) {
            break;
        }
        victims.push_back(candidate);
        freed_space += candidate.size;
    }

    return victims;
}

void BlockManager::RemoveEvictionVictims(const std::vector<EvictionCandidate>& victims)
{
    std::unique_lock lock(metadata_mutex_);
    auto& path_offset_index = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();
    auto& item_index        = item_metadatas_.get<by_path>();

    for (const auto& victim : victims) {
        path_offset_index.erase(std::make_tuple(victim.path, victim.offset));

        auto item_it = item_index.find(victim.path);
        if (item_it != item_index.end()) {
            item_index.modify(item_it, [&](ItemMetadata& item) {
                item.blocks.erase(victim.offset);
                if (item.blocks.empty()) {
                    // This will be erased by the iterator below
                }
            });
        }
    }

    for (auto it = item_index.begin(); it != item_index.end();) {
        if (it->blocks.empty()) {
            it = item_index.erase(it);
        } else {
            ++it;
        }
    }
}

void BlockManager::RefreshRandomHeats(
    std::function<double(const BlockMetadata&, double)> heat_updater
)
{
    std::unique_lock lock(metadata_mutex_);

    static std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<> dist(0.0, 1.0);

    auto& heat_idx   = eviction_queue_.get<EvictionCandidate::ByHeat>();
    auto& item_index = item_metadatas_.get<by_path>();

    std::vector<EvictionCandidate> to_update;
    for (const auto& candidate : heat_idx) {
        if (dist(rng) < Constants::HEAT_REFRESH_PROBABILITY) {
            to_update.push_back(candidate);
        }
    }

    for (const auto& candidate : to_update) {
        auto item_it = item_index.find(candidate.path);
        if (item_it == item_index.end())
            continue;
        auto block_it = item_it->blocks.find(candidate.offset);
        if (block_it == item_it->blocks.end())
            continue;

        double new_heat    = heat_updater(block_it->second, candidate.heat);
        auto eviction_it = heat_idx.find(candidate);
        if (eviction_it != heat_idx.end()) {
            heat_idx.modify(eviction_it, [&](EvictionCandidate& c) { c.heat = new_heat; });
        }
    }
}

}  // namespace DistributedCacheFS::Cache
