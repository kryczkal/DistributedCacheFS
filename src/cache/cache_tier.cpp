#include "cache_tier.hpp"
#include "storage/local_storage.hpp"
#include "storage/storage_factory.hpp"

#include "boost/multi_index/hashed_index.hpp"
#include "boost/multi_index/indexed_by.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"

#include <filesystem>
#include <random>

namespace DistributedCacheFS::Cache
{
using namespace Storage;

CacheTier::CacheTier(const Config::CacheDefinition &cache_definition)
    : cache_definition_(cache_definition)
{
    spdlog::debug("CacheTier::CacheTier(tier={}, path={})", cache_definition.tier, cache_definition.storage_definition.path);
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
    spdlog::debug("CacheTier::GetCapacityBytes(tier={})", cache_definition_.tier);
    auto result = storage_instance_->GetCapacityBytes();
    if (result)
        spdlog::trace("CacheTier::GetCapacityBytes(tier={}) -> {}", cache_definition_.tier, *result);
    else
        spdlog::trace("CacheTier::GetCapacityBytes(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<std::uint64_t> CacheTier::GetUsedBytes() const
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::GetUsedBytes(tier={})", cache_definition_.tier);
    auto result = storage_instance_->GetUsedBytes();
    if (result)
        spdlog::trace("CacheTier::GetUsedBytes(tier={}) -> {}", cache_definition_.tier, *result);
    else
        spdlog::trace("CacheTier::GetUsedBytes(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<std::uint64_t> CacheTier::GetAvailableBytes() const
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::GetAvailableBytes(tier={})", cache_definition_.tier);
    auto result = storage_instance_->GetAvailableBytes();
    if (result)
        spdlog::trace("CacheTier::GetAvailableBytes(tier={}) -> {}", cache_definition_.tier, *result);
    else
        spdlog::trace("CacheTier::GetAvailableBytes(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<std::pair<bool, size_t>> CacheTier::ReadItemIfCacheValid(
    const fs::path &fuse_path, off_t offset, std::span<std::byte> &buffer,
    const CoherencyMetadata &origin_metadata
)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::ReadItemIfCacheValid({})", fuse_path.string());
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
        bytes_read = res.value();
        if (bytes_read == 0) {
            spdlog::error(
                "CacheTier::ReadIfCacheValid: Read zero bytes from cache item: {}",
                fuse_path.string()
            );
            return std::make_pair(false, 0);
        }
    }
    ReheatItem(fuse_path);
    spdlog::trace("CacheTier::ReadItemIfCacheValid(tier={}) -> Valid: true, Bytes Read: {}", cache_definition_.tier, bytes_read);
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
    spdlog::debug("CacheTier::Read(tier={}, {}, {}, buffer_size={})", cache_definition_.tier, fuse_path.string(), offset, buffer.size());
    auto result = storage_instance_->Read(fuse_path, offset, buffer);
    if (result)
        spdlog::trace("CacheTier::Read(tier={}) -> {} bytes read", cache_definition_.tier, *result);
    else
        spdlog::trace("CacheTier::Read(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<std::size_t> CacheTier::Write(
    const std::filesystem::path &fuse_path, off_t offset, std::span<std::byte> &data
)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::Write(tier={}, {}, {}, data_size={})", cache_definition_.tier, fuse_path.string(), offset, data.size());
    auto result = storage_instance_->Write(fuse_path, offset, data);
    if (result)
        spdlog::trace("CacheTier::Write(tier={}) -> {} bytes written", cache_definition_.tier, *result);
    else
        spdlog::trace("CacheTier::Write(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<void> CacheTier::Remove(const std::filesystem::path &fuse_path)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::Remove(tier={}, {})", cache_definition_.tier, fuse_path.string());
    auto result = storage_instance_->Remove(fuse_path);
    if (result)
        spdlog::trace("CacheTier::Remove(tier={}) -> Success");
    else
        spdlog::trace("CacheTier::Remove(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<void> CacheTier::Truncate(const std::filesystem::path &fuse_path, off_t size)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::Truncate(tier={}, {}, {})", cache_definition_.tier, fuse_path.string(), size);
    auto result = storage_instance_->Truncate(fuse_path, size);
    if (result)
        spdlog::trace("CacheTier::Truncate(tier={}) -> Success");
    else
        spdlog::trace("CacheTier::Truncate(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<void> CacheTier::CreateFile(const std::filesystem::path &fuse_path, mode_t mode)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::CreateFile(tier={}, {}, {:o})", cache_definition_.tier, fuse_path.string(), mode);
    auto result = storage_instance_->CreateFile(fuse_path, mode);
    if (result)
        spdlog::trace("CacheTier::CreateFile(tier={}) -> Success");
    else
        spdlog::trace("CacheTier::CreateFile(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<void> CacheTier::CreateDirectory(const std::filesystem::path &fuse_path, mode_t mode)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::CreateDirectory(tier={}, {}, {:o})", cache_definition_.tier, fuse_path.string(), mode);
    auto result = storage_instance_->CreateDirectory(fuse_path, mode);
    if (result)
        spdlog::trace("CacheTier::CreateDirectory(tier={}) -> Success");
    else
        spdlog::trace("CacheTier::CreateDirectory(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<void> CacheTier::Move(
    const std::filesystem::path &from_fuse_path, const std::filesystem::path &to_fuse_path
)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::Move(tier={}, {}, {})", cache_definition_.tier, from_fuse_path.string(), to_fuse_path.string());
    auto result = storage_instance_->Move(from_fuse_path, to_fuse_path);
    if (result)
        spdlog::trace("CacheTier::Move(tier={}) -> Success");
    else
        spdlog::trace("CacheTier::Move(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<std::vector<std::pair<std::string, struct stat>>> CacheTier::ListDirectory(
    const std::filesystem::path &fuse_path
)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::ListDirectory(tier={}, {})", cache_definition_.tier, fuse_path.string());
    auto result = storage_instance_->ListDirectory(fuse_path);
    if (result)
        spdlog::trace("CacheTier::ListDirectory(tier={}) -> {} entries", cache_definition_.tier, result.value().size());
    else
        spdlog::trace("CacheTier::ListDirectory(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<bool> CacheTier::CheckIfFileExists(const std::filesystem::path &fuse_path) const
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::CheckIfFileExists(tier={}, {})", cache_definition_.tier, fuse_path.string());
    auto result = storage_instance_->CheckIfFileExists(fuse_path);
    if (result)
        spdlog::trace("CacheTier::CheckIfFileExists(tier={}) -> {}", cache_definition_.tier, *result);
    else
        spdlog::trace("CacheTier::CheckIfFileExists(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<struct stat> CacheTier::GetAttributes(const std::filesystem::path &fuse_path) const
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::GetAttributes(tier={}, {})", cache_definition_.tier, fuse_path.string());
    auto result = storage_instance_->GetAttributes(fuse_path);
    if (result)
        spdlog::trace("CacheTier::GetAttributes(tier={}) -> Success (st_mode={:o}, st_size={})", cache_definition_.tier, result.value().st_mode, result.value().st_size);
    else
        spdlog::trace("CacheTier::GetAttributes(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<void> CacheTier::Initialize()
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::Initialize(tier={})", cache_definition_.tier);
    // TODO: Load existing metadata from disk
    auto result = storage_instance_->Initialize();
    if (result)
        spdlog::trace("CacheTier::Initialize(tier={}) -> Success");
    else
        spdlog::trace("CacheTier::Initialize(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
StorageResult<void> CacheTier::Shutdown()
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::Shutdown(tier={})", cache_definition_.tier);
    auto result = storage_instance_->Shutdown();
    if (result)
        spdlog::trace("CacheTier::Shutdown(tier={}) -> Success");
    else
        spdlog::trace("CacheTier::Shutdown(tier={}) -> Error: {}", cache_definition_.tier, result.error().message());
    return result;
}
std::filesystem::path CacheTier::RelativeToAbsPath(const std::filesystem::path &fuse_path) const
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::RelativeToAbsPath(tier={}, {})", cache_definition_.tier, fuse_path.string());
    auto result = storage_instance_->RelativeToAbsPath(fuse_path);
    spdlog::trace("CacheTier::RelativeToAbsPath(tier={}) -> {}", cache_definition_.tier, result.string());
    return result;
}

StorageResult<void> CacheTier::InvalidateAndRemoveItem(const fs::path &fuse_path)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::InvalidateAndRemoveItem(tier={}, {})", cache_definition_.tier, fuse_path.string());

    // Remove backing file first – only drop metadata once that succeeds
    auto rm_res = storage_instance_->Remove(fuse_path);
    if (!rm_res) {
        spdlog::trace("CacheTier::InvalidateAndRemoveItem(tier={}) -> Error removing backing file: {}", cache_definition_.tier, rm_res.error().message());
        return std::unexpected(rm_res.error());
    }

    item_metadatas_.erase(fuse_path);
    spdlog::trace("CacheTier::InvalidateAndRemoveItem(tier={}) -> Success");
    return {};
}
StorageResult<const ItemMetadata> CacheTier::GetItemMetadata(const fs::path &fuse_path)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::GetItemMetadata(tier={}, {})", cache_definition_.tier, fuse_path.string());
    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end()) {
        spdlog::error(
            "CacheTier::GetItemMetadata: Item {} not found in metadata.", fuse_path.string()
        );
        spdlog::trace("CacheTier::GetItemMetadata(tier={}) -> Error: InvalidPath", cache_definition_.tier);
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    spdlog::trace("CacheTier::GetItemMetadata(tier={}) -> Success (path={}, size={})", cache_definition_.tier, it->path.string(), it->coherency_metadata.size_bytes);
    return *it;
}
StorageResult<void> CacheTier::InsertItemMetadata(const ItemMetadata &item_metadata)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug(
        "CacheTier::InsertItemMetadata(tier={}, {}, size_bytes={})", cache_definition_.tier, item_metadata.path.string(),
        item_metadata.coherency_metadata.size_bytes
    );
    auto [it, inserted] = item_metadatas_.insert(item_metadata);
    if (!inserted) {
        spdlog::error(
            "CacheTier::InsertItemMetadata: Item {} already exists in metadata.",
            item_metadata.path.string()
        );
        spdlog::trace("CacheTier::InsertItemMetadata(tier={}) -> Error: InvalidPath (already exists)", cache_definition_.tier);
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    spdlog::trace("CacheTier::InsertItemMetadata(tier={}) -> Success");
    return {};
}
StorageResult<bool> CacheTier::CacheItemIfWorthIt(
    const std::filesystem::path &fuse_path, off_t offset, std::span<std::byte> &data,
    const ItemMetadata &item_metadata
)
{
    std::lock_guard lock(cache_mutex_);
    spdlog::debug("CacheTier::CacheItemIfWorthIt(tier={}, {}, {}, data_size={}, item_path={})", cache_definition_.tier, fuse_path.string(), offset, data.size(), item_metadata.path.string());
    {
        auto res = IsItemWorthInserting(item_metadata);
        if (!res) {
            spdlog::error(
                "CacheTier::InsertIfWorth: Failed to check if item is worth inserting: {}",
                res.error().message()
            );
            spdlog::trace("CacheTier::CacheItemIfWorthIt(tier={}) -> Error: {}", cache_definition_.tier, res.error().message());
            return false;
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
                "CacheTier::InsertIfWorth: Failed to forcibly cache item: {}",
                res.error().message()
            );
            spdlog::trace("CacheTier::CacheItemIfWorthIt(tier={}) -> Error: {}", cache_definition_.tier, res.error().message());
            return std::unexpected(res.error());
        }
    }
    spdlog::trace("CacheTier::CacheItemIfWorthIt(tier={}) -> Success (cached)", cache_definition_.tier);
    return true;
}
StorageResult<void> CacheTier::CacheItemForcibly(
    const fs::path &fuse_path, off_t offset, std::span<std::byte> &data,
    const ItemMetadata &item_metadata
)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug(
        "CacheTier::CacheItemForcibly(tier={}, {}, {}, data_size={}, item_path={}, item_size={})",
        cache_definition_.tier, fuse_path.string(), offset, data.size(), item_metadata.path.string(), item_metadata.coherency_metadata.size_bytes
    );

    // Make space if needed
    {
        auto res = FreeUpSpace(item_metadata.coherency_metadata.size_bytes);
        if (!res) {
            spdlog::error(
                "CacheTier::CacheItemForcibly: Failed to free up space for item '{}': {}", 
                fuse_path.string(), res.error().message()
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
    spdlog::trace("CacheTier::CacheItemForcibly(tier={}) -> Success", cache_definition_.tier);
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
    spdlog::trace(
        "CacheTier::IsItemWorthInserting({}, {})", item.path.string(),
        item.coherency_metadata.size_bytes
    );

    auto avail_res = storage_instance_->GetAvailableBytes();
    if (!avail_res)
        return std::unexpected(avail_res.error());
    size_t avail = *avail_res;

    // Quick accept if it already fits without eviction
    if (item.coherency_metadata.size_bytes <= static_cast<off_t>(avail))
        return true;

    // Simulate eviction of coldest items until either we have enough space
    // or the cumulative heat of evicted items exceeds the candidate's heat.
    size_t would_free   = 0;
    double heat_tally   = 0.0;
    const auto &by_heat = item_metadatas_.get<CacheTier::by_heat>();
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
StorageResult<void> CacheTier::FreeUpSpace(size_t required_space)
{
    spdlog::debug("CacheTier::FreeUpSpace({})", required_space);
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);

    auto avail_res = storage_instance_->GetAvailableBytes();
    if (!avail_res)
        return std::unexpected(avail_res.error());
    if (*avail_res >= required_space)
        return {};

    auto &by_heat = item_metadatas_.get<CacheTier::by_heat>();

    size_t reclaimed = 0;
    for (auto it = by_heat.begin(); it != by_heat.end() && reclaimed < required_space;) {
        const fs::path victim = it->path;  // iterator may be invalidated
        const size_t vsize    = it->coherency_metadata.size_bytes;

        // erase metadata first (iterator safe with modifier)
        it = by_heat.erase(it);

        // remove backing file (still under lock → no one else touches it)
        auto rm_res = storage_instance_->Remove(victim);
        if (!rm_res)
            return std::unexpected(rm_res.error());

        reclaimed += vsize;
    }

    auto new_avail_res = storage_instance_->GetAvailableBytes();
    if (!new_avail_res || *new_avail_res < required_space)
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));

    return {};
}

double CacheTier::CalculateItemHeat(
    const fs::path &fuse_path, const ItemMetadata &item_metadata, time_t current_time
) const
{
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
double CacheTier::CalculateInitialItemHeat(
    const fs::path &fuse_path, const ItemMetadata &item_metadata
)
{
    spdlog::debug(
        "CacheTier::CalculateInitialHeat({}, {})", fuse_path.string(), item_metadata.path.string()
    );
    if (item_metadata.coherency_metadata.size_bytes < 0) {
        return 0.0;
    }

    const auto &fetch_cost = item_metadata.heat_metadata.fetch_cost_ms;
    const auto &size_bytes = item_metadata.coherency_metadata.size_bytes;

    double base_value =
        (size_bytes >= 0) ? (fetch_cost / (static_cast<double>(size_bytes) + 1.0)) : 0.0;
    double heat = base_value;
    spdlog::trace(
        "CacheTier::CalculateInitialHeat: Heat for {}: {} (base_value: {})", fuse_path.string(),
        heat, base_value
    );
    return heat;
}
void CacheTier::ReheatItem(const fs::path &fuse_path)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::trace("CacheTier::ReheatItem({})", fuse_path.string());

    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end())
        return;

    const time_t now = std::time(nullptr);
    item_metadatas_.modify(it, [&](ItemMetadata &m) {
        m.heat_metadata.last_access_time = now;
        m.heat_metadata.heat             = CalculateItemHeat(fuse_path, m, now);
    });

    static std::atomic<std::uint64_t> global_hits{0};
    if ((++global_hits % Constants::HEAT_REFRESH_PERIOD) == 0) {
        RefreshRandomHeats();
    }
}
void CacheTier::UpdateItemHeat(const fs::path &fuse_path)
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    auto it = item_metadatas_.find(fuse_path);
    if (it == item_metadatas_.end())
        return;
    const time_t now = std::time(nullptr);
    item_metadatas_.modify(it, [&](ItemMetadata &m) {
        m.heat_metadata.heat = CalculateItemHeat(fuse_path, m, now);
    });
}
void CacheTier::RefreshRandomHeats()
{
    std::lock_guard<std::recursive_mutex> lock(cache_mutex_);
    spdlog::debug("CacheTier::RefreshRandomHeats()");

    if (item_metadatas_.empty())
        return;

    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_real_distribution<double> dice(0.0, 1.0);

    auto it = item_metadatas_.begin();
    while (it != item_metadatas_.end()) {
        if (dice(rng) < Constants::HEAT_REFRESH_PROBABILITY) {
            const fs::path p = it->path;
            // iterator might be invalidated by modify; copy path first
            ++it;  // advance before modify
            UpdateItemHeat(p);
        } else {
            ++it;
        }
    }
}
}  // namespace DistributedCacheFS::Cache
