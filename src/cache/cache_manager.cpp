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

    {
        if (auto res = origin_->Initialize(); !res) {
            spdlog::error("Failed to initialize origin: {}", res.error().message());
            return std::unexpected(res.error());
        }
    }

    tier_to_cache_.clear();
    file_to_cache_.clear();

    for (const auto& cache_definition : config_.cache_definitions) {
        auto cache_instance = std::make_shared<CacheTier>(cache_definition);

        {
            if (auto res = cache_instance->Initialize(); !res) {
                spdlog::error(
                    "CacheManager::InitializeAll: Failed to initialize cache tier {} at path "
                    "'{}': "
                    "{}",
                    cache_definition.tier, cache_definition.storage_definition.path.string(),
                    res.error().message()
                );
                return std::unexpected(res.error());
            }
        }

        tier_to_cache_[cache_definition.tier].push_back(cache_instance);
    }

    if (tier_to_cache_.empty()) {
        spdlog::warn("CacheManager::InitializeAll: No cache tiers defined.");
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
    if (fuse_path.empty() || fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    struct stat origin_stat = {};
    {
        auto res = origin_->GetAttributes(fuse_path);
        if (!res) {
            spdlog::error(
                "CacheManager::GetAttributes failed for {}: Origin lookup error {}",
                fuse_path.string(), res.error().message()
            );
            return std::unexpected(res.error());
        }
        origin_stat = res.value();
    }

    {
        auto it = file_to_cache_.find(fuse_path);
        if (it == file_to_cache_.end()) {
            spdlog::trace("CacheManager::GetAttributes: Cache miss for {}", fuse_path.string());
            return origin_stat;
        }
        auto& cache_tier                  = it->second;
        CoherencyMetadata origin_metadata = {origin_stat.st_mtime, origin_stat.st_size};

        if (const auto res = cache_tier->IsCacheItemValid(fuse_path, origin_metadata);
            !res || !res.value()) {
            if (auto invalidate_res = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
                !invalidate_res) {
                spdlog::error(
                    "CacheManager::GetAttributes: Failed to invalidate cache entry for {}: {}",
                    fuse_path.string(), invalidate_res.error().message()
                );
            }
        }
    }

    spdlog::trace("CacheManager::GetAttributes: Cache miss for {}", fuse_path.string());
    return origin_stat;
}

StorageResult<std::vector<std::pair<std::string, struct stat>>> CacheManager::ListDirectory(
    const std::filesystem::path& fuse_path
)
{
    spdlog::debug("CacheManager::ListDirectory({})", fuse_path.string());
    if (fuse_path.empty() || fuse_path != "/") {
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
    if (fuse_path.empty() || fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    {
        auto cache_tier_it = file_to_cache_.find(fuse_path);
        if (cache_tier_it != file_to_cache_.end()) {
            const auto& cache_tier   = cache_tier_it->second;
            auto origin_metadata_res = GetOriginCoherencyMetadata(fuse_path);
            if (!origin_metadata_res) {
                spdlog::error(
                    "CacheManager::ReadFile: Failed to get origin metadata for {}: {}",
                    fuse_path.string(), origin_metadata_res.error().message()
                );
                return std::unexpected(origin_metadata_res.error());
            }

            {
                auto res = cache_tier->ReadItemIfCacheValid(
                    fuse_path, offset, buffer, origin_metadata_res.value()
                );
                if (!res) {
                    spdlog::error(
                        "CacheManager::ReadFile: Cache read failed for {}: {}", fuse_path.string(),
                        res.error().message()
                    );
                    return std::unexpected(res.error());
                }
                if (res.value().first) {
                    spdlog::trace(
                        "CacheManager::ReadFile: Cache hit for {}. Read {} bytes.",
                        fuse_path.string(), res.value().second
                    );
                    TryPromoteItem(fuse_path);
                    const auto& bytes_read = res.value().second;
                    return bytes_read;
                }
            }
        }
    }
    spdlog::trace(
        "CacheManager::ReadFile: Cache miss for {}. Fetching from origin.", fuse_path.string()
    );

    return FetchAndTryCache(fuse_path, offset, buffer);
}

StorageResult<size_t> CacheManager::WriteFile(
    fs::path& fuse_path, off_t offset, std::span<const std::byte>& data
)
{
    spdlog::debug("CacheManager::WriteFile({}, {}, {})", fuse_path.string(), offset, data.size());
    if (fuse_path.empty() || fuse_path != "/") {
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
    if (fuse_path.empty() || fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    {
        auto res = origin_->CreateFile(fuse_path, mode);
        if (!res) {
            spdlog::error(
                "CacheManager::CreateFile: Origin create failed for {}: {}", res.error().message()
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
    if (fuse_path.empty() || fuse_path != "/") {
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
    if (fuse_path.empty() || fuse_path != "/") {
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
    if (fuse_path.empty() || fuse_path != "/") {
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
    if (from_fuse_path.empty() || to_fuse_path.empty()) {
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
    if (fuse_path.empty() || fuse_path != "/") {
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

    if (offset < 0) {
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));
    }

    size_t bytes_read_from_origin = 0;
    {
        auto read_res = origin_->Read(fuse_path, offset, buffer);
        if (!read_res) {
            return std::unexpected(read_res.error());
        }
        bytes_read_from_origin = read_res.value();
    }

    struct stat origin_stat = {};
    {
        auto attr_res = origin_->GetAttributes(fuse_path);
        if (!attr_res) {
            return std::unexpected(attr_res.error());
        }
        origin_stat = attr_res.value();
    }

    const auto start_t     = std::chrono::steady_clock::now();
    const auto origin_size = static_cast<size_t>(origin_stat.st_size);

    ItemMetadata item_metadata{
        .path = fuse_path,
        .heat_metadata =
            {.heat = 0.0, .fetch_cost_ms = 0.0, .last_access_time = std::time(nullptr)},
        .coherency_metadata =
            {.last_modified_time = origin_stat.st_mtime,
                            .size_bytes         = static_cast<off_t>(origin_size)}
    };

    auto tier_res = SelectCacheTierForWrite(item_metadata);
    if (!tier_res) {
        return std::unexpected(tier_res.error());
    }
    auto cache_tier = tier_res.value();
    if (!cache_tier) {
        return bytes_read_from_origin;
    }

    // Read full file for caching
    std::vector<std::byte> staging(origin_size);
    std::span<std::byte> staging_span{staging};
    {
        auto full_res = origin_->Read(fuse_path, 0, staging_span);
        if (!full_res) {
            return std::unexpected(full_res.error());
        }
        if (full_res.value() != origin_size) {
            return std::unexpected(make_error_code(StorageErrc::IOError));
        }
    }
    const auto elapsed_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start_t)
            .count();

    item_metadata.heat_metadata.fetch_cost_ms = elapsed_ms;
    item_metadata.heat_metadata.heat          = 1.0;

    auto cache_res = cache_tier->CacheItemIfWorthIt(fuse_path, 0, staging_span, item_metadata);
    if (!cache_res) {
        return std::unexpected(cache_res.error());
    }
    if (cache_res.value()) {
        file_to_cache_[fuse_path] = cache_tier;
    }

    return bytes_read_from_origin;
}

StorageResult<std::shared_ptr<CacheTier>> CacheManager::SelectCacheTierForWrite(
    const ItemMetadata& item_metadata
)
{
    spdlog::debug("CacheManager::SelectCacheTierForWrite({})", item_metadata.path.string());
    if (tier_to_cache_.empty()) {
        return nullptr;  // caching disabled – not an error
    }

    for (auto& [tier_num, tier_vec] : tier_to_cache_) {
        for (const auto& tier : tier_vec) {
            auto worth_res = tier->IsItemWorthInserting(item_metadata);
            if (!worth_res) {
                return std::unexpected(worth_res.error());
            }
            if (worth_res.value()) {
                return tier;  // first acceptable tier wins
            }
        }
    }
    return nullptr;
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
    if (fuse_path.empty() || fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    const auto it = file_to_cache_.find(fuse_path);
    if (it == file_to_cache_.end()) {
        return {};
    }
    const auto& current_tier = it->second;

    // Find all tiers strictly lower number (higher speed) than current
    const auto current_level = current_tier->GetTier();
    auto next_it             = tier_to_cache_.find(current_level - 1);
    if (next_it == tier_to_cache_.end()) {
        return {};
    }

    // Retrieve metadata
    auto meta_res = current_tier->GetItemMetadata(fuse_path);
    if (!meta_res)
        return std::unexpected(meta_res.error());
    const ItemMetadata item_meta = meta_res.value();

    // Attempt promotion to any candidate tier at the faster level
    for (const auto& faster_tier : next_it->second) {
        auto worth_res = faster_tier->IsItemWorthInserting(item_meta);
        if (!worth_res) {
            return std::unexpected(worth_res.error());
        }
        if (!worth_res.value()) {
            continue;
        }

        // read from origin to avoid propagating corrupted data
        const auto size_bytes = item_meta.coherency_metadata.size_bytes;
        std::vector<std::byte> buf(size_bytes);
        std::span<std::byte> span{buf};
        auto read_res = origin_->Read(fuse_path, 0, span);
        if (!read_res) {
            return std::unexpected(read_res.error());
        }
        // write into faster tier
        auto cache_res = faster_tier->CacheItemForcibly(fuse_path, 0, span, item_meta);
        if (!cache_res) {
            return std::unexpected(cache_res.error());
        }

        // demote from slower tier
        auto invalidate_res = current_tier->InvalidateAndRemoveItem(fuse_path);
        std::unique_lock lock(metadata_mutex_);
        file_to_cache_[fuse_path] = faster_tier;
        if (!invalidate_res) {
            return std::unexpected(invalidate_res.error());
        }
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
