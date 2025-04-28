#include "cache_tier.hpp"
#include "storage/local_storage.hpp"
#include "storage/storage_factory.hpp"

#include <filesystem>

namespace DistributedCacheFS::Cache
{
using namespace Storage;

CacheTier::CacheTier(Config::CacheDefinition cache_definition)
    : cache_definition_(std::move(cache_definition))
{
    {
        auto res = StorageFactory::Create(cache_definition.storage_definition);
        if (!res) {
            throw std::runtime_error(
                "Failed to create storage instance for cache tier: " + res.error().message()
            );
        }
        storage_instance_ = std::move(res.value());
    }
}

StorageResult<std::uint64_t> CacheTier::GetCapacityBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->GetCapacityBytes();
}
StorageResult<std::uint64_t> CacheTier::GetUsedBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->GetUsedBytes();
}
StorageResult<std::uint64_t> CacheTier::GetAvailableBytes() const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->GetAvailableBytes();
}
StorageResult<std::size_t> CacheTier::Read(
    const std::filesystem::path &fuse_path, off_t offset, std::span<std::byte> &buffer
)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->Read(fuse_path, offset, buffer);
}
StorageResult<std::size_t> CacheTier::Write(
    const std::filesystem::path &fuse_path, off_t offset, std::span<const std::byte> &data
)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->Write(fuse_path, offset, data);
}
StorageResult<void> CacheTier::Remove(const std::filesystem::path &fuse_path)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->Remove(fuse_path);
}
StorageResult<void> CacheTier::Truncate(const std::filesystem::path &fuse_path, off_t size)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->Truncate(fuse_path, size);
}
StorageResult<bool> CacheTier::CheckIfFileExists(const std::filesystem::path &fuse_path) const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->CheckIfFileExists(fuse_path);
}
StorageResult<struct stat> CacheTier::GetAttributes(const std::filesystem::path &fuse_path) const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->GetAttributes(fuse_path);
}
StorageResult<void> CacheTier::Initialize()
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->Initialize();
}
StorageResult<void> CacheTier::Shutdown()
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->Shutdown();
}
std::filesystem::path CacheTier::RelativeToAbsPath(const std::filesystem::path &fuse_path) const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    return storage_instance_->RelativeToAbsPath(fuse_path);
}
StorageResult<void> CacheTier::InvalidateAndRemoveEntry(const fs::path &fuse_path)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug("CacheTier::InvalidateAndRemoveEntry({})", fuse_path.string());
    auto it = item_metadatas_.find(fuse_path);
    if (it != item_metadatas_.end()) {
        item_metadatas_.erase(it);
        spdlog::trace(
            "CacheTier::InvalidateAndRemoveEntry: Invalidated cache entry for {}",
            fuse_path.string()
        );
    } else {
        spdlog::warn(
            "CacheTier::InvalidateAndRemoveEntry: Cache entry for {} not found. Nothing to "
            "invalidate.",
            fuse_path.string()
        );
    }

    auto res = storage_instance_->Remove(fuse_path);
    if (!res) {
        spdlog::error(
            "CacheTier::InvalidateAndRemoveEntry: Failed to remove cache entry for {}: {}",
            fuse_path.string(), res.error().message()
        );
        return std::unexpected(res.error());
    }
    spdlog::trace(
        "CacheTier::InvalidateAndRemoveEntry: Successfully removed cache entry for {}",
        fuse_path.string()
    );

    return {};
}
StorageResult<bool> CacheTier::CacheIfWorthIt(
    const std::filesystem::path &fuse_path, off_t offset, std::span<const std::byte> &data,
    const ItemMetadata &item_metadata
)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug("CacheTier::InsertIfWorth({}, {}, {})", fuse_path.string(), offset, data.size());
    {
        auto res = IsItemWorthInserting(item_metadata);
        if (!res) {
            spdlog::error(
                "CacheTier::InsertIfWorth: Failed to check if item is worth inserting: {}",
                res.error().message()
            );
            return std::unexpected(res.error());
        }
        if (!*res) {
            spdlog::trace(
                "CacheTier::InsertIfWorth: Item {} is not worth inserting. Skipping.",
                item_metadata.path.string()
            );
            return false;
        }
    }
    {
        auto res = CacheForcibly(fuse_path, offset, data, item_metadata);
        if (!res) {
            spdlog::error(
                "CacheTier::InsertIfWorth: Failed to force cache item: {}", res.error().message()
            );
            return std::unexpected(res.error());
        }
    }
    return true;
}
StorageResult<void> CacheTier::CacheForcibly(
    const fs::path &fuse_path, off_t offset, std::span<const std::byte> &data,
    const ItemMetadata &item_metadata
)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug("CacheTier::ForceCache({}, {}, {})", fuse_path.string(), offset, data.size());
    {
        auto res = FreeUpSpace(item_metadata.coherency_metadata.size_bytes);
        if (!res) {
            spdlog::error(
                "CacheTier::InsertIfWorth: Failed to free up space: {}", res.error().message()
            );
            return std::unexpected(res.error());
        }
    }
    {
        auto res = Write(fuse_path, 0, data);
        if (!res) {
            spdlog::error(
                "CacheTier::InsertIfWorth: Failed to write data to cache: {}", res.error().message()
            );
            return std::unexpected(res.error());
        }
    }
    return {};
}
StorageResult<bool> CacheTier::IsCacheValid(
    const fs::path &fuse_path, const CacheTier::CoherencyMetadata &current_origin_metadata
) const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug(
        "CacheTier::IsCacheValid({}, {})", fuse_path.string(),
        current_origin_metadata.last_modified_time
    );
    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        spdlog::warn(
            "CacheTier::IsCacheValid: Item '{}' not found in metadata. Nothing to invalidate.",
            fuse_path.string()
        );
        return false;
    }

    const auto &item_metadata = *it;
    bool last_modified_time_match =
        (item_metadata.coherency_metadata.last_modified_time ==
         current_origin_metadata.last_modified_time);
    bool size_match =
        (item_metadata.coherency_metadata.size_bytes == current_origin_metadata.size_bytes);

    if (last_modified_time_match && size_match) {
        spdlog::trace(
            "CacheTier::IsCacheValid: Cache VALID for {}. Origin mtime ({}) and size ({}) match "
            "stored "
            "metadata.",
            fuse_path.string(), current_origin_metadata.last_modified_time,
            current_origin_metadata.size_bytes
        );
        return true;
    } else {
        spdlog::trace(
            "CacheTier::IsCacheValid: Cache STALE for {}. Origin mtime: {}, size: {}. Stored "
            "mtime: {}, size: "
            "{}",
            fuse_path.string(), current_origin_metadata.last_modified_time,
            current_origin_metadata.size_bytes, item_metadata.coherency_metadata.last_modified_time,
            item_metadata.coherency_metadata.size_bytes
        );
        return false;
    }
}
StorageResult<bool> CacheTier::IsItemWorthInserting(const CacheTier::ItemMetadata &item_metadata
) const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug("CacheTier::IsItemWorthInserting({})", item_metadata.path.string());
    // Check if deleting elements to make item fit
    // is worth it

    const auto &proposed_value = item_metadata.heat_metadata.heat;
    const auto &required_size  = item_metadata.coherency_metadata.size_bytes;

    size_t freed_size    = 0;
    size_t deleted_value = 0;
    auto res             = storage_instance_->GetAvailableBytes();
    if (!res) {
        return std::unexpected(res.error());
    }
    size_t available_size = *res;
    freed_size            = available_size;

    const auto &view_by_heat = item_metadatas_.get<by_heat>();

    auto it = view_by_heat.begin();
    while (it != view_by_heat.end() && proposed_value > deleted_value && required_size > freed_size
    ) {
        deleted_value += it->heat_metadata.heat;
        freed_size += it->coherency_metadata.size_bytes;
        ++it;
    }

    if (freed_size >= required_size && deleted_value < proposed_value) {
        spdlog::trace(
            "CacheTier::IsItemWorthInserting: Item {} is worth inserting. Freed size: {}, "
            "Deleted value: {}",
            item_metadata.path.string(), freed_size, deleted_value
        );
        return true;
    } else {
        spdlog::trace(
            "CacheTier::IsItemWorthInserting: Item {} is NOT worth inserting. Freed size: {}, "
            "Deleted value: {}",
            item_metadata.path.string(), freed_size, deleted_value
        );
        return false;
    }
}
StorageResult<void> CacheTier::FreeUpSpace(const size_t required_space)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);

    const auto &view_by_heat = item_metadatas_.get<by_heat>();
    size_t freed_size        = 0;
    auto res                 = storage_instance_->GetAvailableBytes();
    if (!res) {
        return std::unexpected(res.error());
    }
    const auto available_size = *res;
    if (available_size < required_space) {
        spdlog::warn(
            "CacheTier::FreeUpSpace: Not enough space available. Required: {}, Available: {}",
            required_space, storage_instance_->GetAvailableBytes().value_or(0)
        );
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
    }

    auto it = view_by_heat.begin();
    while (it != view_by_heat.end() && freed_size < required_space) {
        freed_size += it->coherency_metadata.size_bytes;
        InvalidateAndRemoveEntry(it->path);
    }
}
double CacheTier::CalculateHeat(
    const fs::path &fuse_path, CacheTier::ItemMetadata &item_metadata, time_t current_time
) const
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug("CacheTier::CalculateHeat({}, {})", fuse_path.string(), current_time);
    if (item_metadata.coherency_metadata.size_bytes < 0) {
        return 0.0;
    }

    const auto &decay_constant = cache_settings_.decay_constant;
    const auto &fetch_cost     = item_metadata.heat_metadata.fetch_cost;
    const auto &size_bytes     = item_metadata.coherency_metadata.size_bytes;

    double time_diff_secs =
        std::difftime(current_time, item_metadata.heat_metadata.last_access_time);
    double decay_factor = 1.0 / (1.0 + decay_constant * time_diff_secs);

    double base_value =
        (size_bytes >= 0) ? (fetch_cost / (static_cast<double>(size_bytes) + 1.0)) : 0.0;
    double heat = base_value * decay_factor;
    spdlog::trace(
        "CacheTier::CalculateHeat: Heat for {}: {} (base_value: {}, decay_factor: {})",
        fuse_path.string(), heat, base_value, decay_factor
    );
    return heat;
}
}  // namespace DistributedCacheFS::Cache
