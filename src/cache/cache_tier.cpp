#include "cache_tier.hpp"
#include "storage/local_storage.hpp"
#include "storage/storage_factory.hpp"

#include "boost/multi_index/hashed_index.hpp"
#include "boost/multi_index/indexed_by.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"

#include <filesystem>

namespace DistributedCacheFS::Cache
{
using namespace Storage;

CacheTier::CacheTier(const Config::CacheDefinition &cache_definition)
    : cache_definition_(cache_definition)
{
    {
        auto res = StorageFactory::Create(cache_definition_.storage_definition);
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
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->GetCapacityBytes();
}
StorageResult<std::uint64_t> CacheTier::GetUsedBytes() const
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->GetUsedBytes();
}
StorageResult<std::uint64_t> CacheTier::GetAvailableBytes() const
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->GetAvailableBytes();
}
StorageResult<std::pair<bool, size_t>> CacheTier::ReadItemIfCacheValid(
    const fs::path &fuse_path, off_t offset, std::span<std::byte> &buffer,
    const CoherencyMetadata &origin_metadata
)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::ReadIfCacheValid");
    {
        auto validate_item_res = IsCacheItemValid(fuse_path, origin_metadata);
        if (!validate_item_res) {
            spdlog::error(
                "CacheTier::ReadIfCacheValid: Failed to check if cache item is valid: {}",
                validate_item_res.error().message()
            );
            return std::unexpected(validate_item_res.error());
        }
        if (!validate_item_res.value()) {
            spdlog::trace("CacheTier::ReadIfCacheValid: Cache item is not valid. Returning false.");
            {
                auto invalidate_item_res = InvalidateAndRemoveItem(fuse_path);
                if (!invalidate_item_res) {
                    spdlog::error(
                        "CacheTier::ReadIfCacheValid: Failed to invalidate cache item: {}",
                        invalidate_item_res.error().message()
                    );
                    return std::unexpected(invalidate_item_res.error());
                }
            }
            return std::make_pair(false, 0);
        }
    }
    size_t bytes_read = 0;
    {
        auto res = Read(fuse_path, offset, buffer);
        if (!res) {
            spdlog::error(
                "CacheTier::ReadIfCacheValid: Failed to read cache item: {}", res.error().message()
            );
            return std::unexpected(res.error());
        }
        auto bytes_read = res.value();
        if (bytes_read == 0) {
            spdlog::error(
                "CacheTier::ReadIfCacheValid: Read zero bytes from cache item: {}",
                fuse_path.string()
            );
            return std::make_pair(false, 0);
        }
    }
    ReheatItem(fuse_path);
    return std::make_pair(true, bytes_read);
}

//------------------------------------------------------------------------------//
//                              Proxies to storage                              //
//------------------------------------------------------------------------------//

StorageResult<std::size_t> CacheTier::Read(
    const std::filesystem::path &fuse_path, off_t offset, std::span<std::byte> &buffer
)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::Read({}, {}, {})", fuse_path.string(), offset, buffer.size());
    return storage_instance_->Read(fuse_path, offset, buffer);
}
StorageResult<std::size_t> CacheTier::Write(
    const std::filesystem::path &fuse_path, off_t offset, std::span<const std::byte> &data
)
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->Write(fuse_path, offset, data);
}
StorageResult<void> CacheTier::Remove(const std::filesystem::path &fuse_path)
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->Remove(fuse_path);
}
StorageResult<void> CacheTier::Truncate(const std::filesystem::path &fuse_path, off_t size)
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->Truncate(fuse_path, size);
}
StorageResult<bool> CacheTier::CheckIfFileExists(const std::filesystem::path &fuse_path) const
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->CheckIfFileExists(fuse_path);
}
StorageResult<struct stat> CacheTier::GetAttributes(const std::filesystem::path &fuse_path) const
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->GetAttributes(fuse_path);
}
StorageResult<void> CacheTier::Initialize()
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->Initialize();
}
StorageResult<void> CacheTier::Shutdown()
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->Shutdown();
}
std::filesystem::path CacheTier::RelativeToAbsPath(const std::filesystem::path &fuse_path) const
{
    std::lock_guard lock(cache_mutex_);
    return storage_instance_->RelativeToAbsPath(fuse_path);
}

StorageResult<void> CacheTier::InvalidateAndRemoveItem(const fs::path &fuse_path)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::InvalidateAndRemoveEntry({})", fuse_path.string());

    // Remove backing file first – only drop metadata once that succeeds
    auto rm_res = storage_instance_->Remove(fuse_path);
    if (!rm_res) {
        return std::unexpected(rm_res.error());
    }

    item_metadatas_.erase(fuse_path);
    return {};
}
StorageResult<const ItemMetadata &> CacheTier::GetItemMetadata(const fs::path &fuse_path)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::GetItemMetadata({})", fuse_path.string());
    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        spdlog::error(
            "CacheTier::GetItemMetadata: Item {} not found in metadata.", fuse_path.string()
        );
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    return *it;
}
StorageResult<bool> CacheTier::CacheItemIfWorthIt(
    const std::filesystem::path &fuse_path, off_t offset, std::span<const std::byte> &data,
    const ItemMetadata &item_metadata
)
{
    std::lock_guard lock(cache_mutex_);
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
        auto res = CacheItemForcibly(fuse_path, offset, data, item_metadata);
        if (!res) {
            spdlog::error(
                "CacheTier::InsertIfWorth: Failed to force cache item: {}", res.error().message()
            );
            return std::unexpected(res.error());
        }
    }
    return true;
}
StorageResult<void> CacheTier::CacheItemForcibly(
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
    item_metadatas_.insert(item_metadata);
    return {};
}
StorageResult<bool> CacheTier::IsCacheItemValid(
    const fs::path &fuse_path, const CoherencyMetadata &origin_metadata
) const
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::IsCacheValid({})", fuse_path.string());

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
        (item_metadata.coherency_metadata.last_modified_time == origin_metadata.last_modified_time);
    bool size_match = (item_metadata.coherency_metadata.size_bytes == origin_metadata.size_bytes);

    if (last_modified_time_match && size_match) {
        spdlog::trace(
            "CacheTier::IsCacheValid: Cache VALID for {}. Origin mtime ({}) and size ({}) match "
            "stored "
            "metadata.",
            fuse_path.string(), origin_metadata.last_modified_time, origin_metadata.size_bytes
        );
        return true;
    } else {
        spdlog::trace(
            "CacheTier::IsCacheValid: Cache STALE for {}. Origin mtime: {}, size: {}. Stored "
            "mtime: {}, size: "
            "{}",
            fuse_path.string(), origin_metadata.last_modified_time, origin_metadata.size_bytes,
            item_metadata.coherency_metadata.last_modified_time,
            item_metadata.coherency_metadata.size_bytes
        );
        return false;
    }
}
StorageResult<bool> CacheTier::IsItemWorthInserting(const ItemMetadata &item) const
{
    std::lock_guard lock(cache_mutex_);

    auto avail_res = storage_instance_->GetAvailableBytes();
    if (!avail_res)
        return std::unexpected(avail_res.error());
    size_t avail = *avail_res;

    // Quick accept if it already fits without eviction
    if (item.coherency_metadata.size_bytes <= static_cast<off_t>(avail))
        return true;

    // Simulate eviction of coldest items until either we have enough space
    // or the cumulative heat of evicted items exceeds the candidate’s heat.
    size_t would_free   = 0;
    double heat_tally   = 0.0;
    const auto &by_heat = item_metadatas_.get<by_heat>();
    for (auto it = by_heat.begin();
         it != by_heat.end() && would_free < item.coherency_metadata.size_bytes; ++it) {
        would_free += it->coherency_metadata.size_bytes;
        heat_tally += it->heat_metadata.heat;
        if (heat_tally > item.heat_metadata.heat) {
            return false;  // too expensive to evict
        }
    }
    return true;
}
StorageResult<void> CacheTier::FreeUpSpace(const size_t required_space)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::FreeUpSpace({})", required_space);

    auto avail_res = storage_instance_->GetAvailableBytes();
    if (!avail_res) {
        return std::unexpected(avail_res.error());
    }

    size_t freed = avail_res.value();
    if (freed >= required_space) {
        return {};
    }

    const auto &by_heat = item_metadatas_.get<by_heat>();
    for (auto it = by_heat.begin(); it != by_heat.end() && freed < required_space;) {
        auto victim_path         = it->path;
        const size_t victim_size = it->coherency_metadata.size_bytes;
        // advance iterator before erasing to avoid invalidation
        it           = std::next(it);
        auto inv_res = InvalidateAndRemoveItem(victim_path);
        if (!inv_res) {
            return std::unexpected(inv_res.error());
        }
        freed += victim_size;
    }

    if (freed < required_space) {
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
    }
    return {};
}
double CacheTier::CalculateItemHeat(
    const fs::path &fuse_path, const ItemMetadata &item_metadata, time_t current_time
) const
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::CalculateHeat({}, {})", fuse_path.string(), current_time);
    if (item_metadata.coherency_metadata.size_bytes < 0) {
        return 0.0;
    }

    const auto &decay_constant   = cache_definition_.cache_settings.decay_constant;
    const auto &fetch_cost       = item_metadata.heat_metadata.fetch_cost_ms;
    const auto &size_bytes       = item_metadata.coherency_metadata.size_bytes;
    const auto &last_access_time = item_metadata.heat_metadata.last_access_time;

    double time_diff_secs = std::difftime(current_time, last_access_time);  // Convert to seconds
    double decay_factor   = 1.0 / (1.0 + decay_constant * time_diff_secs);

    double base_value =
        (size_bytes >= 0) ? (fetch_cost / (static_cast<double>(size_bytes) + 1.0)) : 0.0;
    double heat = base_value * decay_factor;
    spdlog::trace(
        "CacheTier::CalculateHeat: Heat for {}: {} (base_value: {}, decay_factor: {})",
        fuse_path.string(), heat, base_value, decay_factor
    );
    return heat;
}
void CacheTier::ReheatItem(const fs::path &fuse_path)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::TouchItem({})", fuse_path.string());
    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        return;
    }

    const auto now = std::time(nullptr);
    item_metadatas_.modify(it, [&](ItemMetadata &m) {
        m.heat_metadata.last_access_time = now;
        m.heat_metadata.heat             = CalculateItemHeat(fuse_path, m, now);
    });
}
}  // namespace DistributedCacheFS::Cache
