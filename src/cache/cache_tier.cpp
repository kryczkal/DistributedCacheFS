#include "cache_tier.hpp"
#include "app_constants.hpp"
#include "storage/local_storage.hpp"
#include "storage/storage_factory.hpp"

#include <filesystem>
#include <numeric>
#include <random>
#include <system_error>

namespace DistributedCacheFS::Cache
{
using namespace Storage;

CacheTier::CacheTier(const Config::CacheDefinition& cache_definition)
    : cache_definition_(cache_definition)
{
    auto res = StorageFactory::Create(cache_definition_.storage_definition);
    if (!res) {
        throw std::runtime_error(
            "Failed to create storage instance for cache tier: " + res.error().message()
        );
    }
    storage_instance_ = std::move(res.value());
}

StorageResult<void> CacheTier::Initialize()
{
    return storage_instance_->Initialize();
}

StorageResult<void> CacheTier::Shutdown()
{
    return storage_instance_->Shutdown();
}

StorageResult<std::uint64_t> CacheTier::GetCapacityBytes() const
{
    return storage_instance_->GetCapacityBytes();
}

StorageResult<std::uint64_t> CacheTier::GetUsedBytes() const
{
    return storage_instance_->GetUsedBytes();
}

StorageResult<std::uint64_t> CacheTier::GetAvailableBytes() const
{
    return storage_instance_->GetAvailableBytes();
}

StorageResult<std::pair<RegionList, RegionList>> CacheTier::GetCachedRegions(
    const fs::path& fuse_path, off_t offset, size_t size, const CoherencyMetadata& origin_metadata
)
{
    std::unique_lock lock(metadata_mutex_);

    auto& by_path_index = item_metadatas_.get<by_path>();
    auto file_it        = by_path_index.find(fuse_path);

    if (file_it == item_metadatas_.end()) {
        return std::make_pair(RegionList{}, RegionList{{{offset, size}}});
    }

    if (file_it->coherency_metadata.last_modified_time != origin_metadata.last_modified_time ||
        file_it->coherency_metadata.size_bytes != origin_metadata.size_bytes) {
        lock.unlock();
        InvalidateAndRemoveItem(fuse_path);
        return std::make_pair(RegionList{}, RegionList{{{offset, size}}});
    }

    RegionList cached_regions;
    RegionList missing_regions;
    off_t current_pos = offset;
    const off_t end_pos   = offset + static_cast<off_t>(size);

    auto& block_map = file_it->blocks;
    auto it         = block_map.upper_bound(offset);
    if (it != block_map.begin()) {
        --it;
    }

    const time_t now = std::time(nullptr);
    auto& eviction_by_path_offset = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();

    while (current_pos < end_pos) {
        bool found_overlap = false;
        for (; it != block_map.end(); ++it) {
            const off_t block_start = it->first;
            const off_t block_end   = block_start + static_cast<off_t>(it->second.size);

            if (block_end <= current_pos) continue;
            if (block_start >= end_pos) break;

            found_overlap = true;
            if (block_start > current_pos) {
                missing_regions.emplace_back(current_pos, block_start - current_pos);
            }

            off_t intersect_start = std::max(current_pos, block_start);
            off_t intersect_end   = std::min(end_pos, block_end);
            cached_regions.emplace_back(intersect_start, intersect_end - intersect_start);

            auto evict_it = eviction_by_path_offset.find(std::make_tuple(fuse_path, block_start));
            if (evict_it != eviction_by_path_offset.end()) {
                double base_heat = evict_it->heat;
                eviction_by_path_offset.modify(evict_it, [&](EvictionCandidate& c) {
                    c.heat = CalculateRegionHeat(base_heat, it->second.last_access_time, now);
                });
            }

            current_pos = intersect_end;
            if (current_pos >= end_pos) break;
        }

        if (!found_overlap || current_pos < end_pos) {
            missing_regions.emplace_back(current_pos, end_pos - current_pos);
            break;
        }
    }

    return std::make_pair(cached_regions, missing_regions);
}

StorageResult<void> CacheTier::CacheRegion(
    const fs::path& fuse_path, off_t offset, std::span<std::byte> data,
    const ItemMetadata& item_metadata
)
{
    std::unique_lock lock(metadata_mutex_);

    if (auto res = FreeUpSpace_impl(data.size()); !res) {
        return std::unexpected(res.error());
    }

    auto write_res = storage_instance_->Write(fuse_path, offset, data);
    if (!write_res) return std::unexpected(write_res.error());

    auto& by_path_index = item_metadatas_.get<by_path>();
    auto file_it        = by_path_index.find(fuse_path);

    if (file_it == by_path_index.end()) {
        auto [new_it, success] = item_metadatas_.emplace(
            ItemMetadata{fuse_path, item_metadata.coherency_metadata, {}, item_metadata.base_fetch_cost_ms}
        );
        file_it = new_it;
    }

    auto& eviction_by_path_offset = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();
    BlockMetadata new_block_meta{offset, data.size(), std::time(nullptr), 0.0};
    new_block_meta.heat = CalculateInitialRegionHeat(file_it->base_fetch_cost_ms, data.size());

    // --- Block Merging Logic ---
    // Check for block before
    auto prev_it = file_it->blocks.find(offset - 1);
    if (prev_it != file_it->blocks.end() && (prev_it->first + prev_it->second.size) == offset) {
        auto evict_it = eviction_by_path_offset.find(std::make_tuple(fuse_path, prev_it->first));
        if (evict_it != eviction_by_path_offset.end()) {
            new_block_meta.offset = prev_it->first;
            new_block_meta.size += prev_it->second.size;
            eviction_by_path_offset.erase(evict_it);
            file_it = by_path_index.modify(file_it, [&](ItemMetadata& m){ m.blocks.erase(prev_it); });
        }
    }

    // Check for block after
    auto next_it = file_it->blocks.find(offset + data.size());
    if (next_it != file_it->blocks.end()) {
        auto evict_it = eviction_by_path_offset.find(std::make_tuple(fuse_path, next_it->first));
        if (evict_it != eviction_by_path_offset.end()) {
            new_block_meta.size += next_it->second.size;
            eviction_by_path_offset.erase(evict_it);
            file_it = by_path_index.modify(file_it, [&](ItemMetadata& m){ m.blocks.erase(next_it); });
        }
    }
    // --- End Block Merging Logic ---

    by_path_index.modify(file_it, [&](ItemMetadata& m) {
        m.blocks[new_block_meta.offset] = new_block_meta;
    });

    eviction_queue_.emplace(EvictionCandidate{fuse_path, new_block_meta.offset, new_block_meta.heat, new_block_meta.size});

    return {};
}

StorageResult<bool> CacheTier::IsRegionWorthInserting(double new_region_heat, size_t new_region_size)
{
    std::shared_lock lock(metadata_mutex_);
    RefreshRandomHeats_impl();

    auto avail_res = GetAvailableBytes();
    if (!avail_res) return std::unexpected(avail_res.error());
    if (new_region_size <= *avail_res) return true;

    size_t would_free  = 0;
    double heat_tally = 0.0;
    const auto& by_heat = eviction_queue_.get<EvictionCandidate::ByHeat>();

    for (const auto& candidate : by_heat) {
        if (would_free >= new_region_size) break;
        would_free += candidate.size;
        heat_tally += candidate.heat;
        if (heat_tally > new_region_heat) return false;
    }

    return (would_free >= new_region_size);
}

StorageResult<void> CacheTier::FreeUpSpace(size_t required_space)
{
    std::unique_lock lock(metadata_mutex_);
    return FreeUpSpace_impl(required_space);
}

StorageResult<void> CacheTier::FreeUpSpace_impl(size_t required_space)
{
    auto avail_res = GetAvailableBytes();
    if (!avail_res) return std::unexpected(avail_res.error());
    size_t space_to_free = (*avail_res >= required_space) ? 0 : required_space - *avail_res;
    if (space_to_free == 0) return {};

    size_t reclaimed = 0;
    auto& by_heat_idx = eviction_queue_.get<EvictionCandidate::ByHeat>();
    auto& by_path_idx = item_metadatas_.get<by_path>();

    std::vector<EvictionCandidate> victims;
    for (const auto& candidate : by_heat_idx) {
        if (reclaimed >= space_to_free) break;
        victims.push_back(candidate);
        reclaimed += candidate.size;
    }
    
    if (reclaimed < space_to_free) {
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
    }

    for (const auto& victim : victims) {
        auto punch_res = storage_instance_->PunchHole(victim.path, victim.offset, victim.size);
        if (!punch_res) {
            return std::unexpected(punch_res.error());
        }

        by_heat_idx.erase(by_heat_idx.begin());

        auto file_it = by_path_idx.find(victim.path);
        if (file_it != by_path_idx.end()) {
            by_path_idx.modify(file_it, [&](ItemMetadata& m) {
                m.blocks.erase(victim.offset);
                if (m.blocks.empty()) {
                    storage_instance_->Remove(victim.path);
                    item_metadatas_.erase(file_it);
                }
            });
        }
    }

    return {};
}

StorageResult<void> CacheTier::InvalidateAndRemoveItem(const fs::path& fuse_path)
{
    std::unique_lock lock(metadata_mutex_);

    auto& by_path_idx = item_metadatas_.get<by_path>();
    auto file_it      = by_path_idx.find(fuse_path);
    if (file_it == by_path_idx.end()) {
        return {};
    }

    auto& by_path_offset_idx = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();
    for (const auto& [offset, block] : file_it->blocks) {
        auto evict_it = by_path_offset_idx.find(std::make_tuple(fuse_path, offset));
        if (evict_it != by_path_offset_idx.end()) {
            by_path_offset_idx.erase(evict_it);
        }
    }

    by_path_idx.erase(file_it);
    auto remove_res = storage_instance_->Remove(fuse_path);
    if (!remove_res && remove_res.error() != make_error_code(StorageErrc::FileNotFound)) {
        return std::unexpected(remove_res.error());
    }

    return {};
}

StorageResult<void> CacheTier::InvalidateRegion(const fs::path& fuse_path, off_t offset, size_t size)
{
    std::unique_lock lock(metadata_mutex_);
    
    auto& by_path_index = item_metadatas_.get<by_path>();
    auto file_it = by_path_index.find(fuse_path);
    if (file_it == by_path_index.end()) {
        return {};
    }

    const off_t invalid_end = offset + static_cast<off_t>(size);
    auto& block_map = file_it->blocks;
    auto& eviction_by_path_offset = eviction_queue_.get<EvictionCandidate::ByPathAndOffset>();

    std::vector<off_t> blocks_to_remove;
    std::vector<BlockMetadata> blocks_to_add;

    for (auto it = block_map.lower_bound(offset); it != block_map.end(); ++it) {
        const off_t block_start = it->first;
        const off_t block_end = block_start + static_cast<off_t>(it->second.size);
        if (block_start >= invalid_end) break;

        blocks_to_remove.push_back(block_start);
        storage_instance_->PunchHole(fuse_path, block_start, it->second.size);

        // Case 1: Overlap splits the block
        if (offset > block_start && invalid_end < block_end) {
            blocks_to_add.push_back({block_start, (size_t)(offset - block_start), it->second.last_access_time, it->second.heat});
            blocks_to_add.push_back({invalid_end, (size_t)(block_end - invalid_end), it->second.last_access_time, it->second.heat});
        }
        // Case 2: Overlap covers the start
        else if (invalid_end < block_end) {
            blocks_to_add.push_back({invalid_end, (size_t)(block_end - invalid_end), it->second.last_access_time, it->second.heat});
        }
        // Case 3: Overlap covers the end
        else if (offset > block_start) {
            blocks_to_add.push_back({block_start, (size_t)(offset - block_start), it->second.last_access_time, it->second.heat});
        }
    }

    by_path_index.modify(file_it, [&](ItemMetadata& m) {
        for (off_t off : blocks_to_remove) {
            m.blocks.erase(off);
            eviction_by_path_offset.erase(std::make_tuple(fuse_path, off));
        }
        for (const auto& b : blocks_to_add) {
            m.blocks[b.offset] = b;
            eviction_queue_.emplace(EvictionCandidate{fuse_path, b.offset, b.heat, b.size});
        }
    });

    return {};
}

StorageResult<ItemMetadata> CacheTier::GetItemMetadata(const fs::path& fuse_path)
{
    std::shared_lock lock(metadata_mutex_);

    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        return std::unexpected(make_error_code(StorageErrc::MetadataNotFound));
    }
    return *it;
}

double CacheTier::CalculateInitialRegionHeat(double fetch_cost_ms, size_t region_size) const
{
    if (region_size == 0) return 0.0;
    return fetch_cost_ms / static_cast<double>(region_size);
}

double CacheTier::CalculateRegionHeat(
    double base_heat, time_t last_access_time, time_t current_time
) const
{
    const auto& decay_constant = cache_definition_.cache_settings.decay_constant;
    double time_diff_secs      = std::difftime(current_time, last_access_time);
    double decay_factor        = 1.0 / (1.0 + decay_constant * time_diff_secs);
    return base_heat * decay_factor;
}

void CacheTier::RefreshRandomHeats_impl()
{
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_real_distribution<double> dice(0.0, 1.0);
    const time_t now = std::time(nullptr);

    auto& by_heat_idx = eviction_queue_.get<EvictionCandidate::ByHeat>();

    for (auto it = by_heat_idx.begin(); it != by_heat_idx.end();) {
        if (dice(rng) < Constants::HEAT_REFRESH_PROBABILITY) {
            it = by_heat_idx.modify(it, [&](EvictionCandidate& c) {
                c.heat = CalculateRegionHeat(c.heat, now, now);
            });
        } else {
            ++it;
        }
    }
}

}  // namespace DistributedCacheFS::Cache
