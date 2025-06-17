#include "cache/block_manager.hpp"

#include "app_constants.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <iterator>
#include <random>
#include <vector>

namespace DistributedCacheFS::Cache
{

BlockManager::BlockManager() {}

std::pair<RegionList, RegionList> BlockManager::GetCachedRegionsAndUpdateHeat(
    const FileId& file_id, const fs::path& access_path, off_t offset, size_t size,
    const CoherencyMetadata& origin_metadata,
    std::function<double(const BlockMetadata&, double)> heat_updater,
    std::function<void(const FileId&)> on_stale_item
)
{
    std::unique_lock lock(metadata_mutex_);

    RegionList cached_regions;
    RegionList missing_regions;

    auto& item_index = item_metadatas_.get<by_file_id>();
    auto item_it     = item_index.find(file_id);

    if (item_it == item_index.end()) {
        missing_regions.push_back({offset, size});
        return {cached_regions, missing_regions};
    }

    if (item_it->coherency_metadata.last_modified_time != origin_metadata.last_modified_time ||
        item_it->coherency_metadata.size_bytes != origin_metadata.size_bytes) {
        on_stale_item(file_id);
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

            auto& heat_index          = eviction_queue_.get<EvictionCandidate::ByFileIdAndOffset>();
            auto eviction_it          = heat_index.find(std::make_tuple(file_id, block_offset));
            const auto& current_block = it->second;

            if (eviction_it != heat_index.end()) {
                double new_heat = heat_updater(current_block, eviction_it->heat);
                heat_index.modify(eviction_it, [&](EvictionCandidate& c) {
                    c.heat = new_heat;
                });
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
    const FileId& file_id, const fs::path& access_path, off_t offset, size_t size,
    double initial_heat, double base_fetch_cost_ms, const CoherencyMetadata& coherency_metadata
)
{
    std::unique_lock lock(metadata_mutex_);

    auto& item_index = item_metadatas_.get<by_file_id>();
    auto item_it     = item_index.find(file_id);

    if (item_it == item_index.end()) {
        item_it =
            item_index
                .emplace(
                    ItemMetadata{file_id, {access_path}, coherency_metadata, {}, base_fetch_cost_ms}
                )
                .first;
    } else {
        item_index.modify(item_it, [&](ItemMetadata& item) {
            item.known_paths.insert(access_path);
        });

        if (item_it->coherency_metadata.last_modified_time !=
                coherency_metadata.last_modified_time ||
            item_it->coherency_metadata.size_bytes != coherency_metadata.size_bytes) {
            item_index.modify(item_it, [&](ItemMetadata& item) {
                item.blocks.clear();
                item.coherency_metadata = coherency_metadata;
                eviction_queue_.get<EvictionCandidate::ByFileId>().erase(file_id);
            });
        }
    }

    BlockMetadata new_block{offset, size, time(nullptr), initial_heat};
    item_index.modify(item_it, [&](ItemMetadata& item) {
        item.blocks[offset] = new_block;
    });

    auto& heat_index = eviction_queue_.get<EvictionCandidate::ByFileIdAndOffset>();
    auto eviction_it = heat_index.find(std::make_tuple(file_id, offset));
    if (eviction_it != heat_index.end()) {
        heat_index.modify(eviction_it, [&](EvictionCandidate& c) {
            c.heat             = initial_heat;
            c.size             = size;
            c.path_for_storage = access_path;
        });
    } else {
        eviction_queue_.emplace(
            EvictionCandidate{file_id, access_path, offset, initial_heat, size}
        );
    }
}

std::vector<BlockMetadata> BlockManager::InvalidateRegion(
    const FileId& file_id, off_t offset, size_t size
)
{
    std::unique_lock lock(metadata_mutex_);
    std::vector<BlockMetadata> invalidated_blocks;

    auto& item_index = item_metadatas_.get<by_file_id>();
    auto item_it     = item_index.find(file_id);
    if (item_it == item_index.end()) {
        return invalidated_blocks;
    }

    auto& heat_index = eviction_queue_.get<EvictionCandidate::ByFileIdAndOffset>();

    item_index.modify(item_it, [&](ItemMetadata& item) {
        off_t invalidation_end = offset + size;
        auto& blocks           = item.blocks;

        for (auto it = blocks.begin(); it != blocks.end();) {
            off_t block_start = it->first;
            off_t block_end   = block_start + it->second.size;

            if (block_start < invalidation_end && block_end > offset) {
                invalidated_blocks.push_back(it->second);
                auto eviction_it = heat_index.find(std::make_tuple(file_id, it->first));
                if (eviction_it != heat_index.end()) {
                    heat_index.erase(eviction_it);
                }
                it = blocks.erase(it);
            } else {
                ++it;
            }
        }
    });
    return invalidated_blocks;
}

std::vector<BlockMetadata> BlockManager::InvalidateAndRemoveItem(const FileId& file_id)
{
    std::unique_lock lock(metadata_mutex_);
    auto& item_index = item_metadatas_.get<by_file_id>();
    auto item_it     = item_index.find(file_id);
    if (item_it == item_index.end()) {
        return {};
    }

    std::vector<BlockMetadata> invalidated_blocks;
    invalidated_blocks.reserve(item_it->blocks.size());
    for (const auto& [offset, block] : item_it->blocks) {
        invalidated_blocks.push_back(block);
    }

    item_index.erase(item_it);

    eviction_queue_.get<EvictionCandidate::ByFileId>().erase(file_id);

    return invalidated_blocks;
}

std::optional<ItemMetadata> BlockManager::GetItemMetadata(const FileId& file_id)
{
    std::shared_lock lock(metadata_mutex_);
    auto& item_index = item_metadatas_.get<by_file_id>();
    auto it          = item_index.find(file_id);
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

    size_t space_to_free        = new_region_size - available_space;
    size_t potential_free_space = 0;
    auto& heat_index            = eviction_queue_.get<EvictionCandidate::ByHeat>();

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
    auto& path_offset_index = eviction_queue_.get<EvictionCandidate::ByFileIdAndOffset>();
    auto& item_index        = item_metadatas_.get<by_file_id>();

    for (const auto& victim : victims) {
        auto eviction_it = path_offset_index.find(std::make_tuple(victim.file_id, victim.offset));
        if (eviction_it != path_offset_index.end()) {
            path_offset_index.erase(eviction_it);
        }

        auto item_it = item_index.find(victim.file_id);
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
    auto& item_index = item_metadatas_.get<by_file_id>();

    std::vector<EvictionCandidate> to_update;
    for (const auto& candidate : heat_idx) {
        if (dist(rng) < Constants::HEAT_REFRESH_PROBABILITY) {
            to_update.push_back(candidate);
        }
    }

    auto& fido_idx = eviction_queue_.get<EvictionCandidate::ByFileIdAndOffset>();
    for (const auto& candidate : to_update) {
        auto item_it = item_index.find(candidate.file_id);
        if (item_it == item_index.end())
            continue;
        auto block_it = item_it->blocks.find(candidate.offset);
        if (block_it == item_it->blocks.end())
            continue;

        double new_heat = heat_updater(block_it->second, candidate.heat);

        auto eviction_it = fido_idx.find(std::make_tuple(candidate.file_id, candidate.offset));
        if (eviction_it != fido_idx.end()) {
            // We can use any index's modify, as long as we use an iterator valid for that
            // index. Since we have an iterator from fido_idx, we use that. The
            // container will ensure all other indices are updated correctly.
            fido_idx.modify(eviction_it, [&](EvictionCandidate& c) {
                c.heat = new_heat;
            });
        }
    }
}

void BlockManager::AddLink(const FileId& file_id, const fs::path& new_path)
{
    std::unique_lock lock(metadata_mutex_);
    auto& item_index = item_metadatas_.get<by_file_id>();
    auto item_it     = item_index.find(file_id);
    if (item_it != item_index.end()) {
        item_index.modify(item_it, [&](ItemMetadata& item) {
            item.known_paths.insert(new_path);
        });
    }
}

bool BlockManager::RemoveLink(const FileId& file_id, const fs::path& path_to_remove)
{
    std::unique_lock lock(metadata_mutex_);
    auto& item_index = item_metadatas_.get<by_file_id>();
    auto item_it     = item_index.find(file_id);
    if (item_it != item_index.end()) {
        bool was_empty = false;
        item_index.modify(item_it, [&](ItemMetadata& item) {
            item.known_paths.erase(path_to_remove);
            was_empty = item.known_paths.empty();
        });
        return was_empty;
    }
    return true;  // Not tracked, so effectively has 0 links
}

void BlockManager::RenameLink(const FileId& file_id, const fs::path& from, const fs::path& to)
{
    std::unique_lock lock(metadata_mutex_);
    auto& item_index = item_metadatas_.get<by_file_id>();
    auto item_it     = item_index.find(file_id);
    if (item_it != item_index.end()) {
        item_index.modify(item_it, [&](ItemMetadata& item) {
            item.known_paths.erase(from);
            item.known_paths.insert(to);
        });
    }

    auto& heat_index              = eviction_queue_.get<EvictionCandidate::ByFileId>();
    auto [range_begin, range_end] = heat_index.equal_range(file_id);
    for (auto it = range_begin; it != range_end; ++it) {
        if (it->path_for_storage == from) {
            heat_index.modify(it, [&](EvictionCandidate& c) {
                c.path_for_storage = to;
            });
        }
    }
}

}  // namespace DistributedCacheFS::Cache
