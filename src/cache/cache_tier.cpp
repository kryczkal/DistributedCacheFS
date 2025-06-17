#include "cache_tier.hpp"
#include "app_constants.hpp"
#include "block_manager.hpp"
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
    : cache_definition_(cache_definition), block_manager_(std::make_unique<BlockManager>())
{
    auto res = StorageFactory::Create(cache_definition_.storage_definition);
    if (!res) {
        throw std::runtime_error(
            "Failed to create storage instance for cache tier: " + res.error().message()
        );
    }
    storage_instance_ = std::move(res.value());
}

CacheTier::~CacheTier() = default;

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
    const FileId& file_id, const fs::path& access_path, off_t offset, size_t size,
    const CoherencyMetadata& origin_metadata
)
{
    auto heat_updater = [this](const BlockMetadata& block, double current_heat) {
        return this->CalculateRegionHeat(current_heat, block.last_access_time, std::time(nullptr));
    };

    auto on_stale_item = [this](const FileId& id) { this->InvalidateAndPurgeItem(id); };

    auto result = block_manager_->GetCachedRegionsAndUpdateHeat(
        file_id, access_path, offset, size, origin_metadata, heat_updater, on_stale_item
    );

    if (result && !result->first.empty()) {
        size_t prev_hits = read_hit_counter_.fetch_add(1, std::memory_order_relaxed);
        if (prev_hits + 1 >= Constants::HEAT_REFRESH_PERIOD) {
            read_hit_counter_.store(0, std::memory_order_relaxed);
            block_manager_->RefreshRandomHeats(heat_updater);
        }
    }

    return result;
}

StorageResult<void> CacheTier::CacheRegion(
    const FileId& file_id, const fs::path& access_path, off_t offset,
    std::span<std::byte> data, const CoherencyMetadata& coherency_metadata,
    double base_fetch_cost_ms
)
{
    if (auto res = FreeUpSpace(data.size()); !res) {
        return std::unexpected(res.error());
    }

    auto write_res = storage_instance_->Write(access_path, offset, data);
    if (!write_res)
        return std::unexpected(write_res.error());

    double initial_heat = CalculateInitialRegionHeat(base_fetch_cost_ms, data.size());

    block_manager_->CacheRegion(
        file_id, access_path, offset, data.size(), initial_heat, base_fetch_cost_ms,
        coherency_metadata
    );

    return {};
}

StorageResult<bool> CacheTier::IsRegionWorthInserting(double new_region_heat, size_t new_region_size)
{
    auto avail_res = GetAvailableBytes();
    if (!avail_res)
        return std::unexpected(avail_res.error());

    auto heat_updater = [this](const BlockMetadata& block, double current_heat) {
        return this->CalculateRegionHeat(current_heat, block.last_access_time, std::time(nullptr));
    };

    return block_manager_->IsRegionWorthInserting(
        new_region_heat, new_region_size, *avail_res, heat_updater
    );
}

StorageResult<void> CacheTier::FreeUpSpace(size_t required_space)
{
    auto avail_res = GetAvailableBytes();
    if (!avail_res)
        return std::unexpected(avail_res.error());
    size_t space_to_free = (*avail_res >= required_space) ? 0 : required_space - *avail_res;
    if (space_to_free == 0)
        return {};

    auto victims = block_manager_->GetVictimsForEviction(space_to_free);
    if (victims.empty() && space_to_free > 0) {
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
    }

    size_t reclaimed = 0;
    for (const auto& victim : victims) {
        reclaimed += victim.size;
    }
    if (reclaimed < space_to_free) {
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
    }

    stats_.AddItemsEvicted(victims.size());

    for (const auto& victim : victims) {
        auto punch_res =
            storage_instance_->PunchHole(victim.path_for_storage, victim.offset, victim.size);
        if (!punch_res) {
            return std::unexpected(punch_res.error());
        }
    }

    block_manager_->RemoveEvictionVictims(victims);

    return {};
}

StorageResult<void> CacheTier::InvalidateAndPurgeItem(const FileId& file_id)
{
    auto item_meta_res = block_manager_->GetItemMetadata(file_id);

    auto blocks_to_punch = block_manager_->InvalidateAndRemoveItem(file_id);

    if (item_meta_res.has_value() && !item_meta_res->known_paths.empty()) {
        const fs::path& representative_path = *item_meta_res->known_paths.begin();

        for (const auto& block : blocks_to_punch) {
            storage_instance_->PunchHole(representative_path, block.offset, block.size);
        }
        storage_instance_->Remove(representative_path);
    }

    return {};
}

StorageResult<void> CacheTier::InvalidateRegion(
    const FileId& file_id, const fs::path& access_path, off_t offset, size_t size
)
{
    auto blocks_to_punch = block_manager_->InvalidateRegion(file_id, offset, size);

    for (const auto& block : blocks_to_punch) {
        storage_instance_->PunchHole(access_path, block.offset, block.size);
    }
    return {};
}

StorageResult<ItemMetadata> CacheTier::GetItemMetadata(const FileId& file_id)
{
    auto res = block_manager_->GetItemMetadata(file_id);
    if (!res.has_value()) {
        return std::unexpected(make_error_code(StorageErrc::MetadataNotFound));
    }
    return res.value();
}

void CacheTier::AddLink(const FileId& file_id, const fs::path& new_path)
{
    block_manager_->AddLink(file_id, new_path);
}

bool CacheTier::RemoveLink(const FileId& file_id, const fs::path& path_to_remove)
{
    return block_manager_->RemoveLink(file_id, path_to_remove);
}

void CacheTier::RenameLink(const FileId& file_id, const fs::path& from, const fs::path& to)
{
    auto move_res = storage_instance_->Move(from, to);
    if (move_res) {
        block_manager_->RenameLink(file_id, from, to);
    }
}

double CacheTier::CalculateInitialRegionHeat(double fetch_cost_ms, size_t region_size) const
{
    if (region_size == 0)
        return 0.0;
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

}  // namespace DistributedCacheFS::Cache
