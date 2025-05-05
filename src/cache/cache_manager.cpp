#include "cache/cache_manager.hpp"
#include "storage/i_storage.hpp"
#include "storage/local_storage.hpp"
#include "storage/storage_error.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <functional>
#include <memory>
#include <numeric>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace DistributedCacheFS::Cache
{

using namespace Storage;
using namespace Config;

CacheManager::CacheManager(Config::NodeConfig& config, std::shared_ptr<IStorage> origin)
    : config_(config), origin_(std::move(origin))
{
    spdlog::debug("CacheManager::CacheManager()");
    spdlog::info("Creating CacheManager...");
    if (!origin_) {
        throw std::runtime_error("Origin storage instance is null");
    }
}
CacheManager::~CacheManager()
{
    spdlog::debug("CacheManager::~CacheManager()");
    spdlog::info("Destroying CacheManager...");
    {
        if (auto res = ShutdownAll(); !res) {
            spdlog::error("CacheManager destructor: Shutdown failed: {}", res.error().message());
        }
    }
    tier_to_cache_.clear();
}

StorageResult<void> CacheManager::InitializeAll()
{
    spdlog::debug("CacheManager::InitializeAll()");
    spdlog::info("Initializing CacheManager...");

    if (auto res = origin_->Initialize(); !res)
        return std::unexpected(res.error());

    {
        std::unique_lock lock_tiers(tier_mutex_);
        tier_to_cache_.clear();
        file_to_cache_.clear();

        for (const auto& cache_definition : config_.cache_definitions) {
            auto cache_instance = std::make_shared<CacheTier>(cache_definition);
            if (auto res = cache_instance->Initialize(); !res)
                return std::unexpected(res.error());

            tier_to_cache_[cache_definition.tier].push_back(std::move(cache_instance));
        }
    }
    return {};
}

StorageResult<void> CacheManager::ShutdownAll()
{
    std::unique_lock lock(metadata_mutex_);
    spdlog::debug("CacheManager::ShutdownAll()");
    spdlog::info("Shutting down CacheManager ...");
    std::error_code first_error;

    // Shutdown Cache Tiers
    for (auto& [tier, cache_tiers] : tier_to_cache_) {
        for (const auto& cache_tier : cache_tiers) {
            spdlog::info("Shutting down cache tier {}...", tier);
            if (auto res = cache_tier->Shutdown(); !res) {
                spdlog::error("Failed to shut down cache tier {}: {}", tier, res.error().message());
                if (!first_error) {
                    first_error = res.error();
                }
            } else {
                spdlog::info("Cache tier {} shut down successfully.", tier);
            }
        }
    }

    tier_to_cache_.clear();
    file_to_cache_.clear();

    // Shutdown Origin
    spdlog::info("Shutting down origin...");
    {
        if (auto res = origin_->Shutdown(); !res) {
            spdlog::error("Failed to shut down origin: {}", res.error().message());
            if (!first_error) {
                first_error = res.error();
            }
        }
    }

    if (first_error) {
        spdlog::error(
            "Cache Coordinator shutdown completed with errors: {}", first_error.message()
        );
        return std::unexpected(first_error);
    }

    return {};
}

// Core FUSE Operation Implementations

StorageResult<struct stat> CacheManager::GetAttributes(std::filesystem::path& fuse_path)
{
    spdlog::debug("CacheManager::GetAttributes({})", fuse_path.string());
    if (fuse_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    auto origin_stat_res = origin_->GetAttributes(fuse_path);
    if (!origin_stat_res)
        return std::unexpected(origin_stat_res.error());
    struct stat origin_stat = origin_stat_res.value();

    // validate (or evict) existing cache entry
    std::shared_ptr<CacheTier> cache_tier;
    {
        std::shared_lock meta_rlock(metadata_mutex_);
        auto it = file_to_cache_.find(fuse_path);
        if (it != file_to_cache_.end())
            cache_tier = it->second;
    }

    if (cache_tier) {
        CoherencyMetadata origin_meta{origin_stat.st_mtime, origin_stat.st_size};
        auto valid_res = cache_tier->IsCacheItemValid(fuse_path, origin_meta);
        if (!valid_res || !valid_res.value()) {
            RemoveMetadataInvalidateCache(fuse_path, cache_tier);  // ignore error, best‑effort
        }
    }

    return origin_stat;
}
StorageResult<std::vector<std::pair<std::string, struct stat>>> CacheManager::ListDirectory(
    const std::filesystem::path& fuse_path
)
{
    spdlog::debug("CacheManager::ListDirectory({})", fuse_path.string());
    if (fuse_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Always fetch from origin
    return origin_->ListDirectory(fuse_path);
}

StorageResult<size_t> CacheManager::ReadFile(
    std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& buffer
)
{
    spdlog::debug("CacheManager::ReadFile({}, {}, {})", fuse_path.string(), offset, buffer.size());
    if (fuse_path.empty() || fuse_path == "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    // fast path : cached hit
    std::shared_ptr<CacheTier> cache_tier;
    {
        std::shared_lock meta_rlock(metadata_mutex_);
        auto it = file_to_cache_.find(fuse_path);
        if (it != file_to_cache_.end())
            cache_tier = it->second;
    }

    if (cache_tier) {
        auto meta_res = GetOriginCoherencyMetadata(fuse_path);
        if (!meta_res)
            return std::unexpected(meta_res.error());

        auto hit = cache_tier->ReadItemIfCacheValid(fuse_path, offset, buffer, meta_res.value());
        if (!hit)
            return std::unexpected(hit.error());
        if (hit->first) {               // cache hit
            TryPromoteItem(fuse_path);  // background promotion
            return hit->second;
        }
    }

    // miss → fetch & (maybe) cache
    return FetchAndTryCache(fuse_path, offset, buffer);
}

StorageResult<size_t> CacheManager::WriteFile(
    fs::path& fuse_path, off_t offset, std::span<std::byte>& data
)
{
    spdlog::debug("CacheManager::WriteFile({}, {}, {})", fuse_path.string(), offset, data.size());
    if (fuse_path.empty() || fuse_path == "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy;

    spdlog::trace("CacheManager::WriteFile: Writing to origin for {}", fuse_path.string());
    size_t bytes_written = 0;
    {
        auto res = origin_->Write(fuse_path, offset, data);
        if (!res) {
            spdlog::error(
                "CacheManager::WriteFile: Origin write failed for {}: {}", fuse_path.string(),
                res.error().message()
            );
            return std::unexpected(res.error());
        }
        bytes_written = res.value();
    }

    // Check if cache exists then invalidate it
    auto cache_tier_it = file_to_cache_.find(fuse_path);
    if (cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto res         = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!res) {
            spdlog::error(
                "CacheManager::WriteFile: Failed to invalidate cache entry for {}: {}",
                fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    return bytes_written;
}

StorageResult<void> CacheManager::CreateFile(std::filesystem::path& fuse_path, mode_t mode)
{
    spdlog::debug("CacheManager::CreateFile({}, {:o})", fuse_path.string(), mode);
    if (fuse_path.empty() || fuse_path == "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    {
        auto res = origin_->CreateFile(fuse_path, mode);
        if (!res) {
            spdlog::error(
                "CacheManager::CreateFile: Origin create failed for {}: {}", fuse_path.string(),
                res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    if (auto cache_tier_it = file_to_cache_.find(fuse_path);
        cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto res         = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!res) {
            spdlog::error(
                "CacheManager::CreateFile: Failed to invalidate cache entry for {}: {}",
                fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    return {};
}

StorageResult<void> CacheManager::CreateDirectory(std::filesystem::path& fuse_path, mode_t mode)
{
    spdlog::debug("CacheManager::CreateDirectory({}, {:o})", fuse_path.string(), mode);
    if (fuse_path.empty() || fuse_path == "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    {
        auto res = origin_->CreateDirectory(fuse_path, mode);
        if (!res) {
            spdlog::error(
                "CacheManager::CreateDirectory: Origin create failed for {}: {}",
                fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    if (auto cache_tier_it = file_to_cache_.find(fuse_path);
        cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto res         = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!res) {
            spdlog::error(
                "CacheManager::CreateDirectory: Failed to invalidate cache entry for {}: {}",
                fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    return {};
}

StorageResult<void> CacheManager::Remove(std::filesystem::path& fuse_path)
{
    spdlog::debug("CacheManager::Remove({})", fuse_path.string());
    if (fuse_path.empty() || fuse_path == "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    {
        auto res = origin_->Remove(fuse_path);
        if (!res) {
            spdlog::error(
                "CacheManager::Remove: Origin remove failed for {}: {}", fuse_path.string(),
                res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    // Origin remove succeeded, remove from all cache tiers.
    if (auto cache_tier_it = file_to_cache_.find(fuse_path);
        cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto res         = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!res) {
            spdlog::error(
                "CacheManager::Remove: Failed to invalidate cache entry for {}: {}",
                fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    return {};
}

StorageResult<void> CacheManager::TruncateFile(std::filesystem::path& fuse_path, off_t size)
{
    spdlog::debug("CacheManager::TruncateFile({}, {})", fuse_path.string(), size);
    if (fuse_path.empty() || fuse_path == "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    if (size < 0) {
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));
    }

    // Write-Through Policy
    {
        auto res = origin_->Truncate(fuse_path, size);
        if (!res) {
            spdlog::error(
                "CacheManager::TruncateFile: Origin truncate failed for {}: {}", fuse_path.string(),
                res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    if (auto cache_tier_it = file_to_cache_.find(fuse_path);
        cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto res         = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!res) {
            spdlog::error(
                "CacheManager::TruncateFile: Failed to invalidate cache entry for {}: {}",
                fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    return {};
}

StorageResult<void> CacheManager::Move(
    std::filesystem::path& from_fuse_path, std::filesystem::path& to_fuse_path
)
{
    spdlog::debug("CacheManager::Move({}, {})", from_fuse_path.string(), to_fuse_path.string());
    if (from_fuse_path.empty() || to_fuse_path.empty() || from_fuse_path == "/" ||
        to_fuse_path == "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    {
        auto res = origin_->Move(from_fuse_path, to_fuse_path);
        if (!res) {
            spdlog::error(
                "CacheManager::Move: Origin move failed for {} to {}: {}", from_fuse_path.string(),
                to_fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    if (auto cache_tier_it = file_to_cache_.find(from_fuse_path);
        cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto res         = RemoveMetadataInvalidateCache(from_fuse_path, cache_tier);
        if (!res) {
            spdlog::error(
                "CacheManager::Move: Failed to invalidate cache entry for {}: {}",
                from_fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    if (auto cache_tier_it = file_to_cache_.find(to_fuse_path);
        cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto res         = RemoveMetadataInvalidateCache(to_fuse_path, cache_tier);
        if (!res) {
            spdlog::error(
                "CacheManager::Move: Failed to invalidate cache entry for {}: {}",
                to_fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
    }

    return {};
}

StorageResult<struct statvfs> CacheManager::GetFilesystemStats(fs::path& fuse_path)
{
    spdlog::debug("CacheManager::GetFilesystemStats({})", fuse_path.string());
    if (fuse_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    spdlog::warn("CacheManager::GetFilesystemStats not implemented", fuse_path.string());
    // Do statvfs on the origin path
    struct statvfs origin_statvfs = {};
    return origin_statvfs;
}

// Private Cache Logic Helper Implementations

StorageResult<size_t> CacheManager::FetchAndTryCache(
    fs::path& fuse_path, off_t offset, std::span<std::byte>& buffer
)
{
    spdlog::debug(
        "CacheManager::FetchAndTryCache({}, {}, {})", fuse_path.string(), offset, buffer.size()
    );
    if (offset < 0)
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));
    if (fuse_path.empty() || fuse_path == "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    auto origin_attr = origin_->GetAttributes(fuse_path);
    if (!origin_attr)
        return std::unexpected(origin_attr.error());
    const size_t origin_size = static_cast<size_t>(origin_attr->st_size);

    // Satisfy caller first (single read)
    auto now      = std::chrono::system_clock::now();
    auto read_res = origin_->Read(fuse_path, offset, buffer);
    auto elapsed  = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now() - now
    );
    if (!read_res)
        return std::unexpected(read_res.error());
    const size_t bytes_for_caller = *read_res;

    // Pick tier; if none, we are done

    const auto fetch_cost_ms = static_cast<double>(elapsed.count());
    ItemMetadata meta{
        fuse_path,
        {0.0, fetch_cost_ms, std::time(nullptr)},
        {origin_attr->st_mtime, origin_attr->st_size}
    };
    meta.heat_metadata.heat = CacheTier::CalculateInitialItemHeat(fuse_path, meta);
    auto tier_res           = SelectCacheTierForWrite(meta);
    if (!tier_res)
        return std::unexpected(tier_res.error());
    auto tier = tier_res.value();
    if (!tier)
        return bytes_for_caller;

    // Stream from origin to tier in 1‑MiB blocks to avoid giant vec
    constexpr std::size_t kBlk = 1 << 20;
    std::vector<std::byte> blk(kBlk);
    std::span<std::byte> blk_span{blk};
    size_t total_read = 0;
    while (total_read < origin_size) {
        const size_t want = std::min(kBlk, origin_size - total_read);
        blk_span          = {blk.data(), want};
        auto r            = origin_->Read(fuse_path, static_cast<off_t>(total_read), blk_span);
        if (!r)
            return std::unexpected(r.error());
        if (*r == 0)
            break;
        std::span<std::byte> cblk{blk.data(), *r};
        auto w = tier->Write(fuse_path, static_cast<off_t>(total_read), cblk);
        if (!w || *w != *r)
            return std::unexpected(make_error_code(StorageErrc::IOError));
        total_read += *r;
    }
    tier->ReheatItem(fuse_path);
    {
        std::unique_lock w_lock(metadata_mutex_);
        file_to_cache_[fuse_path] = tier;
    }
    return bytes_for_caller;
}
StorageResult<std::shared_ptr<CacheTier>> CacheManager::SelectCacheTierForWrite(
    const ItemMetadata& item_metadata
)
{
    std::shared_lock tiers_rlock(tier_mutex_);  // hierarchy: tier_mutex_ before metadata_mutex_
    spdlog::debug("CacheManager::SelectCacheTierForWrite({})", item_metadata.path.string());
    if (tier_to_cache_.empty())
        return nullptr;  // no cache at all

    for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {  // slowest first
        for (const auto& tier : it->second) {
            auto worth = tier->IsItemWorthInserting(item_metadata);
            if (!worth)
                return std::unexpected(worth.error());
            if (*worth) {
                spdlog::trace(
                    "CacheManager::SelectCacheTierForWrite: Found cache tier {} for {}",
                    tier->GetTier(), item_metadata.path.string()
                );
                return tier;  // first slow tier that accepts
            }
        }
    }
    spdlog::trace(
        "CacheManager::SelectCacheTierForWrite: No cache tier found for {}",
        item_metadata.path.string()
    );
    return nullptr;  // nothing suitable
}

StorageResult<void> CacheManager::RemoveMetadataInvalidateCache(
    const fs::path& fuse_path, const std::shared_ptr<CacheTier>& cache_tier
)
{
    spdlog::debug(
        "CacheManager::RemoveMetadataInvalidateCache({}, {})", fuse_path.string(),
        cache_tier->GetTier()
    );
    if (!cache_tier) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    auto res = cache_tier->InvalidateAndRemoveItem(fuse_path);
    if (!res) {
        return std::unexpected(res.error());
    }
    std::unique_lock lock(metadata_mutex_);
    file_to_cache_.erase(fuse_path);
    return {};
}

StorageResult<void> CacheManager::TryPromoteItem(fs::path& fuse_path)
{
    spdlog::debug("CacheManager::TryPromoteItem({})", fuse_path.string());
    if (fuse_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    // snapshot current tier under metadata lock
    std::shared_ptr<CacheTier> current_tier;
    {
        std::shared_lock meta_rlock(metadata_mutex_);
        auto it = file_to_cache_.find(fuse_path);
        if (it == file_to_cache_.end())
            return {};
        current_tier = it->second;
    }
    const size_t current_level = current_tier->GetTier();
    if (current_level == 0)  // already hottest tier
        return {};

    // collect faster tiers (lower tier index)
    std::vector<std::shared_ptr<CacheTier>> faster_tiers;
    {
        std::shared_lock tiers_rlock(tier_mutex_);
        for (const auto& [lvl, vec] : tier_to_cache_) {
            if (lvl < current_level)
                faster_tiers.insert(faster_tiers.end(), vec.begin(), vec.end());
        }
    }
    if (faster_tiers.empty())
        return {};

    // fetch metadata & data once from current tier (under tier lock)
    auto meta_res = current_tier->GetItemMetadata(fuse_path);
    if (!meta_res)
        return std::unexpected(meta_res.error());
    const ItemMetadata meta = meta_res.value();

    std::vector<std::byte> buf(meta.coherency_metadata.size_bytes);
    std::span<std::byte> span{buf};
    auto read_res = current_tier->Read(fuse_path, 0, span);
    if (!read_res || *read_res != span.size())
        return std::unexpected(read_res ? make_error_code(StorageErrc::IOError) : read_res.error());

    // attempt promotion into the first tier that accepts it
    for (const auto& faster : faster_tiers) {
        auto worth = faster->IsItemWorthInserting(meta);
        if (!worth)
            return std::unexpected(worth.error());
        if (!*worth)
            continue;

        faster->CacheItemForcibly(fuse_path, 0, span, meta);
        {
            std::unique_lock meta_wlock(metadata_mutex_);
            file_to_cache_[fuse_path] = faster;
        }
        current_tier->InvalidateAndRemoveItem(fuse_path);  // best‑effort
        break;
    }
    return {};
}
StorageResult<CoherencyMetadata> CacheManager::GetOriginCoherencyMetadata(const fs::path& fuse_path
) const
{
    spdlog::debug("CacheManager::GetOriginMetadata({})", fuse_path.string());
    auto res = origin_->GetAttributes(fuse_path);
    if (!res) {
        spdlog::error(
            "CacheManager::GetOriginMetadata: Failed to get origin metadata for {}: {}",
            fuse_path.string(), res.error().message()
        );
        return std::unexpected(res.error());
    }
    return CoherencyMetadata{res.value().st_mtime, res.value().st_size};
}

}  // namespace DistributedCacheFS::Cache
;
