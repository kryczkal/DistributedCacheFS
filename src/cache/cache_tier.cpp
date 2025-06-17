#include "cache_tier.hpp"
#include "storage/local_storage.hpp"
#include "storage/storage_factory.hpp"
#include "app_constants.hpp"

#include <filesystem>
#include <numeric>
#include <random>
#include <system_error>

namespace DistributedCacheFS::Cache
{
using namespace Storage;

CacheTier::CacheTier(const Config::CacheDefinition &cache_definition)
    : cache_definition_(cache_definition)
{
    spdlog::debug(
        "CacheTier::CacheTier(tier={}, path={})", cache_definition.tier,
        cache_definition.storage_definition.path.c_str()
    );
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
    std::unique_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::Initialize(tier={})", cache_definition_.tier);
    return storage_instance_->Initialize();
}

StorageResult<void> CacheTier::Shutdown()
{
    std::unique_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::Shutdown(tier={})", cache_definition_.tier);
    return storage_instance_->Shutdown();
}

StorageResult<std::uint64_t> CacheTier::GetCapacityBytes() const
{
    std::shared_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::GetCapacityBytes(tier={})", cache_definition_.tier);
    return storage_instance_->GetCapacityBytes();
}

StorageResult<std::uint64_t> CacheTier::GetUsedBytes() const
{
    std::shared_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::GetUsedBytes(tier={})", cache_definition_.tier);
    return storage_instance_->GetUsedBytes();
}

StorageResult<std::uint64_t> CacheTier::GetAvailableBytes() const
{
    std::shared_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::GetAvailableBytes(tier={})", cache_definition_.tier);
    return storage_instance_->GetAvailableBytes();
}

StorageResult<std::pair<bool, size_t>> CacheTier::ReadItemIfCacheValid(
    const fs::path &fuse_path, off_t offset, std::span<std::byte> &buffer,
    const CoherencyMetadata &origin_metadata
)
{
    std::unique_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::ReadItemIfCacheValid({})", fuse_path.string());

    auto validate_item_res = IsCacheItemValid(fuse_path, origin_metadata);
    if (!validate_item_res) {
        return std::unexpected(validate_item_res.error());
    }

    if (!validate_item_res.value()) {
        auto invalidate_item_res = InvalidateAndRemoveItem_impl(fuse_path);
        if (!invalidate_item_res) {
            return std::unexpected(invalidate_item_res.error());
        }
        return std::make_pair(false, 0);
    }

    auto res = storage_instance_->Read(fuse_path, offset, buffer);
    if (!res) {
        return std::unexpected(res.error());
    }

    ReheatItem_impl(fuse_path);
    return std::make_pair(true, res.value());
}

StorageResult<bool> CacheTier::CacheItemIfWorthIt(
    const fs::path &fuse_path, off_t offset, std::span<std::byte> &data,
    const ItemMetadata &item_metadata
)
{
    std::unique_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::CacheItemIfWorthIt(tier={})", cache_definition_.tier);

    auto res = IsItemWorthInserting(item_metadata);
    if (!res) {
        return std::unexpected(res.error());
    }
    if (!*res) {
        return false;
    }

    auto forcibly_res = CacheItemForcibly(fuse_path, offset, data, item_metadata);
    if (!forcibly_res) {
        return std::unexpected(forcibly_res.error());
    }
    return true;
}

StorageResult<void> CacheTier::CacheItemForcibly(
    const fs::path &fuse_path, off_t offset, std::span<std::byte> &data,
    const ItemMetadata &item_metadata
)
{
    std::unique_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::CacheItemForcibly(tier={})", cache_definition_.tier);

    auto res = FreeUpSpace_impl(item_metadata.coherency_metadata.size_bytes);
    if (!res) {
        return std::unexpected(res.error());
    }

    auto write_res = storage_instance_->Write(fuse_path, offset, data);
    if (!write_res) {
        return std::unexpected(write_res.error());
    }

    item_metadatas_.insert(item_metadata);

    if (mapping_cb_) {
        mapping_cb_(fuse_path, shared_from_this(), true);
    }
    return {};
}

StorageResult<bool> CacheTier::IsCacheItemValid(
    const fs::path &fuse_path, const CoherencyMetadata &origin_metadata
) const
{
    std::shared_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::IsCacheValid({})", fuse_path.string());

    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        return false;
    }

    const auto &item_metadata = *it;
    bool last_modified_time_match =
        (item_metadata.coherency_metadata.last_modified_time == origin_metadata.last_modified_time);
    bool size_match = (item_metadata.coherency_metadata.size_bytes == origin_metadata.size_bytes);

    return (last_modified_time_match && size_match);
}

StorageResult<bool> CacheTier::IsItemWorthInserting(const ItemMetadata &item)
{
    std::shared_lock lock(tier_op_mutex_);
    RefreshRandomHeats_impl();

    auto avail_res = GetAvailableBytes();
    if (!avail_res) return std::unexpected(avail_res.error());

    if (item.coherency_metadata.size_bytes <= static_cast<off_t>(*avail_res)) return true;

    size_t would_free = 0;
    double heat_tally = 0.0;
    const auto &by_heat = item_metadatas_.get<CacheTier::by_heat>();
    for (auto it = by_heat.begin(); it != by_heat.end() && would_free < (size_t)item.coherency_metadata.size_bytes; ++it) {
        would_free += it->coherency_metadata.size_bytes;
        heat_tally += it->heat_metadata.heat;
        if (heat_tally > item.heat_metadata.heat) return false;
    }

    return (would_free >= (size_t)item.coherency_metadata.size_bytes);
}

StorageResult<void> CacheTier::FreeUpSpace(size_t required_space)
{
    std::unique_lock lock(tier_op_mutex_);
    return FreeUpSpace_impl(required_space);
}

StorageResult<void> CacheTier::FreeUpSpace_impl(size_t required_space)
{
    spdlog::debug("CacheTier::FreeUpSpace_impl({})", required_space);

    auto avail_res = GetAvailableBytes();
    if (!avail_res) return std::unexpected(avail_res.error());
    if (*avail_res >= required_space) return {};

    auto &by_heat = item_metadatas_.get<CacheTier::by_heat>();

    size_t reclaimed = 0;
    for (auto it = by_heat.begin(); it != by_heat.end() && reclaimed < required_space;) {
        const fs::path victim = it->path;
        const size_t vsize = it->coherency_metadata.size_bytes;
        it = by_heat.erase(it);

        auto rm_res = storage_instance_->Remove(victim);
        if (!rm_res) return std::unexpected(rm_res.error());
        reclaimed += vsize;
    }

    auto new_avail_res = GetAvailableBytes();
    if (!new_avail_res || *new_avail_res < required_space)
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));

    return {};
}

void CacheTier::ReheatItem(const fs::path &fuse_path)
{
    std::unique_lock lock(tier_op_mutex_);
    ReheatItem_impl(fuse_path);
}

void CacheTier::ReheatItem_impl(const fs::path &fuse_path)
{
    spdlog::trace("CacheTier::ReheatItem_impl({})", fuse_path.string());
    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) return;

    const time_t now = std::time(nullptr);
    item_metadatas_.modify(it, [&](ItemMetadata &m) {
        m.heat_metadata.last_access_time = now;
        m.heat_metadata.heat = CalculateItemHeat(fuse_path, m, now);
    });

    static std::atomic<std::uint64_t> global_hits{0};
    if ((++global_hits % Constants::HEAT_REFRESH_PERIOD) == 0) {
        RefreshRandomHeats_impl();
    }
}

void CacheTier::UpdateItemHeat(const fs::path &fuse_path)
{
    std::unique_lock lock(tier_op_mutex_);
    UpdateItemHeat_impl(fuse_path);
}

void CacheTier::UpdateItemHeat_impl(const fs::path &fuse_path)
{
    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) return;
    const time_t now = std::time(nullptr);
    item_metadatas_.modify(it, [&](ItemMetadata &m) {
        m.heat_metadata.heat = CalculateItemHeat(fuse_path, m, now);
    });
}

void CacheTier::RefreshRandomHeats()
{
    std::unique_lock lock(tier_op_mutex_);
    RefreshRandomHeats_impl();
}

void CacheTier::RefreshRandomHeats_impl()
{
    spdlog::debug("CacheTier::RefreshRandomHeats_impl() entered");

    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_real_distribution<double> dice(0.0, 1.0);

    std::vector<fs::path> paths_to_update;
    if (item_metadatas_.empty()) return;

    paths_to_update.reserve(
        static_cast<size_t>(item_metadatas_.size() * Constants::HEAT_REFRESH_PROBABILITY) + 1
    );

    for (const auto& metadata_item : item_metadatas_) {
        if (dice(rng) < Constants::HEAT_REFRESH_PROBABILITY) {
            paths_to_update.push_back(metadata_item.path);
        }
    }
    
    for (const auto& p : paths_to_update) {
        UpdateItemHeat_impl(p);
    }
}

StorageResult<void> CacheTier::InvalidateAndRemoveItem(const fs::path &fuse_path)
{
    std::unique_lock lock(tier_op_mutex_);
    return InvalidateAndRemoveItem_impl(fuse_path);
}

StorageResult<void> CacheTier::InvalidateAndRemoveItem_impl(const fs::path &fuse_path)
{
    spdlog::debug("CacheTier::InvalidateAndRemoveItem_impl(tier={}, {})", cache_definition_.tier, fuse_path.string());

    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        auto remove_res = storage_instance_->Remove(fuse_path);
        if (!remove_res && remove_res.error() != make_error_code(StorageErrc::FileNotFound)) {
            return std::unexpected(remove_res.error());
        }
        return {};
    }

    item_metadatas_.erase(it);
    auto remove_res = storage_instance_->Remove(fuse_path);
    if (!remove_res) {
        return std::unexpected(remove_res.error());
    }

    if (mapping_cb_) {
        mapping_cb_(fuse_path, shared_from_this(), false);
    }
    return {};
}

StorageResult<const ItemMetadata> CacheTier::GetItemMetadata(const fs::path &fuse_path)
{
    std::shared_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::GetItemMetadata(tier={}, {})", cache_definition_.tier, fuse_path.string());

    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        return std::unexpected(make_error_code(StorageErrc::MetadataNotFound));
    }
    return *it;
}

StorageResult<void> CacheTier::InsertItemMetadata(const ItemMetadata &item_metadata)
{
    std::unique_lock lock(tier_op_mutex_);
    spdlog::debug("CacheTier::InsertItemMetadata(tier={})", cache_definition_.tier);

    auto [it, inserted] = item_metadatas_.insert(item_metadata);
    if (!inserted) {
        return std::unexpected(make_error_code(StorageErrc::AlreadyExists));
    }
    return {};
}

double CacheTier::CalculateItemHeat(
    const fs::path &fuse_path, const ItemMetadata &item_metadata, time_t current_time
) const
{
    if (item_metadata.coherency_metadata.size_bytes < 0) return 0.0;
    const auto &decay_constant = cache_definition_.cache_settings.decay_constant;
    const auto &fetch_cost = item_metadata.heat_metadata.fetch_cost_ms;
    const auto &size_bytes = item_metadata.coherency_metadata.size_bytes;
    const auto &last_access_time = item_metadata.heat_metadata.last_access_time;
    double time_diff_secs = std::difftime(current_time, last_access_time);
    double decay_factor = 1.0 / (1.0 + decay_constant * time_diff_secs);
    double base_value = (size_bytes >= 0) ? (fetch_cost / (static_cast<double>(size_bytes) + 1.0)) : 0.0;
    return base_value * decay_factor;
}

double CacheTier::CalculateInitialItemHeat(
    const fs::path &fuse_path, const ItemMetadata &item_metadata
)
{
    if (item_metadata.coherency_metadata.size_bytes < 0) return 0.0;
    const auto &fetch_cost = item_metadata.heat_metadata.fetch_cost_ms;
    const auto &size_bytes = item_metadata.coherency_metadata.size_bytes;
    return (size_bytes >= 0) ? (fetch_cost / (static_cast<double>(size_bytes) + 1.0)) : 0.0;
}

}  // namespace DistributedCacheFS::Cache
