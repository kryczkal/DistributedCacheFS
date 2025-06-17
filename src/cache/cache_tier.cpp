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
    const fs::path& fuse_path, off_t offset, size_t size, const CoherencyMetadata& origin_metadata
)
{
    auto heat_updater = [this](const BlockMetadata& block, double current_heat) {
        return this->CalculateRegionHeat(current_heat, block.last_access_time, std::time(nullptr));
    };

    auto on_stale_item = [this](const fs::path& p) { this->InvalidateAndRemoveItem(p); };

    return block_manager_->GetCachedRegionsAndUpdateHeat(
        fuse_path, offset, size, origin_metadata, heat_updater, on_stale_item
    );
}

StorageResult<void> CacheTier::CacheRegion(
    const fs::path& fuse_path, off_t offset, std::span<std::byte> data,
    const CoherencyMetadata& coherency_metadata, double base_fetch_cost_ms
)
{
    if (auto res = FreeUpSpace(data.size()); !res) {
        return std::unexpected(res.error());
    }

    auto write_res = storage_instance_->Write(fuse_path, offset, data);
    if (!write_res) return std::unexpected(write_res.error());

    double initial_heat = CalculateInitialRegionHeat(base_fetch_cost_ms, data.size());

    block_manager_->CacheRegion(
        fuse_path, offset, data.size(), initial_heat, base_fetch_cost_ms, coherency_metadata
    );

    return {};
}

StorageResult<bool> CacheTier::IsRegionWorthInserting(double new_region_heat, size_t new_region_size)
{
    auto avail_res = GetAvailableBytes();
    if (!avail_res) return std::unexpected(avail_res.error());

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
    if (!avail_res) return std::unexpected(avail_res.error());
    size_t space_to_free = (*avail_res >= required_space) ? 0 : required_space - *avail_res;
    if (space_to_free == 0) return {};

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

    for (const auto& victim : victims) {
        auto punch_res = storage_instance_->PunchHole(victim.path, victim.offset, victim.size);
        if (!punch_res) {
            return std::unexpected(punch_res.error());
        }
    }

    block_manager_->RemoveEvictionVictims(victims);

    return {};
}

StorageResult<void> CacheTier::InvalidateAndRemoveItem(const fs::path& fuse_path)
{
    block_manager_->InvalidateAndRemoveItem(fuse_path);

    auto remove_res = storage_instance_->Remove(fuse_path);
    if (!remove_res && remove_res.error() != make_error_code(StorageErrc::FileNotFound)) {
        return std::unexpected(remove_res.error());
    }

    return {};
}

StorageResult<void> CacheTier::InvalidateRegion(const fs::path& fuse_path, off_t offset, size_t size)
{
    auto blocks_to_punch = block_manager_->InvalidateRegion(fuse_path, offset, size);

    for (const auto& block : blocks_to_punch) {
        storage_instance_->PunchHole(fuse_path, block.offset, block.size);
    }
    return {};
}

StorageResult<ItemMetadata> CacheTier::GetItemMetadata(const fs::path& fuse_path)
{
    auto res = block_manager_->GetItemMetadata(fuse_path);
    if (!res.has_value()) {
        return std::unexpected(make_error_code(StorageErrc::MetadataNotFound));
    }
    return res.value();
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

}  // namespace DistributedCacheFS::Cache
