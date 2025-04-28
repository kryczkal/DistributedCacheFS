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
        auto res = ShutdownAll();
        if (!res) {
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
        auto res = origin_->Initialize();
        if (!res) {
            spdlog::error("Failed to initialize origin: {}", res.error().message());
            return std::unexpected(res.error());
        }
    }

    tier_to_cache_.clear();
    file_to_cache_.clear();

    for (const auto& cache_definition : config_.cache_definitions) {
        auto cache_instance = std::make_shared<CacheTier>(cache_definition);

        {
            auto res = cache_instance->Initialize();
            if (!res) {
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
        for (auto& cache_tier : cache_tiers) {
            spdlog::info("Shutting down cache tier {}...", tier);
            auto res = cache_tier->Shutdown();
            if (!res) {
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
        auto res = origin_->Shutdown();
        if (!res) {
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

// Path Sanitization
std::filesystem::path CacheManager::SanitizeFusePath(const std::filesystem::path& fuse_path) const
{
    spdlog::debug("CacheManager::SanitizeFusePath({})", fuse_path.string());
    if (!fuse_path.has_root_path() || fuse_path.root_path() != "/") {
        spdlog::warn(
            "CacheManager::SanitizeFusePath: Non-absolute path received: {}", fuse_path.string()
        );
        // Return empty path to signify error - caller must check.
        return {};
    }
    if (fuse_path == "/") {
        // Represent root relative to base path using "."
        return ".";
    }
    // Remove leading slash to get relative path
    return fuse_path.relative_path();
}

// Core FUSE Operation Implementations

StorageResult<struct stat> CacheManager::GetAttributes(const std::filesystem::path& fuse_path)
{
    spdlog::debug("CacheManager::GetAttributes({})", fuse_path.string());
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Fetch Origin Attributes
    auto origin_attr_res = origin_manager_->GetOrigin()->GetAttributes(relative_path);
    if (!origin_attr_res) {
        spdlog::error(
            "CacheManager::GetAttributes failed for {}: Origin lookup error {}",
            relative_path.string(), origin_attr_res.error().message()
        );
        return std::unexpected(origin_attr_res.error());
    }
    const struct stat& origin_stat = origin_attr_res.heat();

    // Check the central metadata store (Read Lock)
    {
        std::shared_lock lock(metadata_mutex_);
        auto it = item_metadata_.find(relative_path);
        if (it != item_metadata_.end()) {
            // Cache Hit (Metadata exists)
            const auto& item_info = it->second;
            spdlog::trace(
                "CacheManager::GetAttributes: Cache metadata hit for {}: tier {}",
                relative_path.string(), item_info.current_tier->GetTier()
            );

            auto valid_res = IsCacheValid(item_info, origin_stat);
            if (valid_res && valid_res.value()) {
                // No need to update access time here - let ReadFile handle that
                return origin_stat;
            } else {
                // Cache is stale or check failed - need exclusive lock to invalidate
                lock.unlock();
                InvalidateCacheEntry(relative_path);
            }
        }
    }

    spdlog::trace("CacheManager::GetAttributes: Cache miss for {}", relative_path.string());
    return origin_stat;
}

StorageResult<std::vector<std::pair<std::string, struct stat>>> CacheManager::ListDirectory(
    const std::filesystem::path& fuse_path
)
{
    spdlog::debug("CacheManager::ListDirectory({})", fuse_path.string());
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Strategy: Always fetch from Origin for consistency.
    // TODO: Implement directory entry caching later if performance demands it.

    auto origin_list_res = origin_manager_->GetOrigin()->ListDirectory(relative_path);

    if (!origin_list_res) {
        spdlog::error(
            "CacheManager::ListDirectory failed for {}: Origin lookup error {}",
            relative_path.string(), origin_list_res.error().message()
        );
    } else {
        // TODO: Update cache access meta for the directory itself?
    }

    return origin_list_res;
}

StorageResult<size_t> CacheManager::ReadFile(
    const std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& buffer
)
{
    spdlog::debug("CacheManager::ReadFile({}, {}, {})", fuse_path.string(), offset, buffer.size());
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    RichCacheItemInfo item_info_copy;
    bool was_hit       = false;
    int hit_tier_level = -1;

    // Check Metadata Cache (Read Lock)
    {
        std::shared_lock lock(metadata_mutex_);
        auto it = item_metadata_.find(relative_path);
        if (it != item_metadata_.end()) {
            item_info_copy = it->second;
            was_hit        = true;
            hit_tier_level = item_info_copy.current_tier->GetTier();
            spdlog::trace(
                "CacheManager::ReadFile: Cache metadata hit for {}: tier {}",
                relative_path.string(), hit_tier_level
            );
        }
    }

    if (was_hit) {
        // Check Origin Attributes for Validity (No lock needed for origin)
        auto origin_attr_res = origin_manager_->GetOrigin()->GetAttributes(relative_path);
        if (!origin_attr_res) {
            spdlog::error(
                "CacheManager::ReadFile: Origin lookup failed for {}: {}. Invalidating cache.",
                relative_path.string(), origin_attr_res.error().message()
            );
            InvalidateCacheEntry(relative_path);  // Requires exclusive lock internally
            return std::unexpected(make_error_code(StorageErrc::OriginError));
        }

        // Perform Coherency Check
        auto valid_res = IsCacheValid(item_info_copy, origin_attr_res.heat());

        if (valid_res && valid_res.value()) {
            spdlog::trace(
                "CacheManager::ReadFile: Cache valid for {}. Reading from cache.",
                relative_path.string()
            );
            auto read_res = item_info_copy.current_tier->Read(relative_path, offset, buffer);

            if (read_res) {
                // Read successful: Update metadata (Write Lock)
                auto now        = std::time(nullptr);
                double new_heat = 0.0;
                {
                    std::unique_lock lock(metadata_mutex_);
                    auto it = item_metadata_.find(relative_path);
                    if (it !=
                        item_metadata_.end()) {  // Check again in case invalidated between locks
                        it->second.last_accessed = now;
                        new_heat                 = CalculateHeat(it->second, now);
                        UpdateHeapEntry(relative_path, new_heat, hit_tier_level);
                        spdlog::trace(
                            "CacheManager::ReadFile: Updated heat for {}: {}",
                            relative_path.string(), new_heat
                        );
                    } else {
                        spdlog::warn(
                            "CacheManager::ReadFile: Item {} disappeared from metadata during "
                            "update.",
                            relative_path.string()
                        );
                        // Proceed with returning data, but something is odd.
                    }
                }

                // Trigger Promotion (Outside lock)
                if (item_info_copy.current_tier) {
                    PromoteItem(relative_path, item_info_copy.current_tier);
                }

                spdlog::trace(
                    "ReadFile read {} bytes from cache for {}", *read_res, relative_path.string()
                );
                return read_res.heat();

            } else if (read_res.error() == make_error_code(StorageErrc::FileNotFound)) {
                spdlog::warn(
                    "CacheManager::ReadFile cache read failed for {}: {}. Invalidating.",
                    relative_path.string(), read_res.error().message()
                );
                InvalidateCacheEntry(relative_path);  // Requires exclusive lock internally
            } else {
                spdlog::error(
                    "CacheManager::ReadFile cache read error for {}: {}", relative_path.string(),
                    read_res.error().message()
                );
                return std::unexpected(read_res.error());
            }
        } else {
            // Cache Invalid: Invalidate and fall through
            spdlog::trace(
                "Cache stale/invalid for ReadFile: {}. Invalidating and fetching from origin.",
                relative_path.string()
            );
            InvalidateCacheEntry(relative_path);
        }
    }

    // Cache Miss or Invalidated: Fetch from Origin
    spdlog::trace(
        "ReadFile cache miss or invalid for: {}. Fetching from origin.", relative_path.string()
    );
    return FetchAndCache(relative_path, offset, buffer);
}

StorageResult<size_t> CacheManager::WriteFile(
    const std::filesystem::path& fuse_path, off_t offset, std::span<const std::byte>& data
)
{
    spdlog::debug("CacheManager::WriteFile({}, {}, {})", fuse_path.string(), offset, data.size());
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy

    spdlog::trace("CacheManager::WriteFile: Writing to origin for {}", relative_path.string());
    auto origin_write_res = origin_manager_->GetOrigin()->Write(relative_path, offset, data);
    if (!origin_write_res) {
        spdlog::error(
            "WriteFile origin write failed for {}: {}", relative_path.string(),
            origin_write_res.error().message()
        );
        return std::unexpected(origin_write_res.error());
    }
    spdlog::trace(
        "WriteFile: Origin write successful for {}, {} bytes", relative_path.string(),
        origin_write_res.heat()
    );

    spdlog::trace("WriteFile: Invalidating cache for {}", relative_path.string());
    InvalidateCacheEntry(relative_path);  // Requires exclusive lock internally

    return origin_write_res.heat();
}

StorageResult<void> CacheManager::CreateFile(const std::filesystem::path& fuse_path, mode_t mode)
{
    spdlog::debug("CacheManager::CreateFile({}, {:o})", fuse_path.string(), mode);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    auto origin_res = origin_manager_->GetOrigin()->CreateFile(relative_path, mode);
    if (!origin_res) {
        // Don't invalidate cache here, file creation failed at origin
        spdlog::error(
            "CreateFile origin failed for {}: {}", relative_path.string(),
            origin_res.error().message()
        );
        return std::unexpected(origin_res.error());
    }

    // Invalidate any potentially conflicting cache entry (e.g., if a directory existed there)
    InvalidateCacheEntry(relative_path);

    // TODO: Pre-cache the empty file's metadata?

    spdlog::trace("CreateFile successful in origin for {}", relative_path.string());
    return {};
}

StorageResult<void> CacheManager::CreateDirectory(
    const std::filesystem::path& fuse_path, mode_t mode
)
{
    spdlog::debug("CacheManager::CreateDirectory({}, {:o})", fuse_path.string(), mode);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    auto origin_res = origin_manager_->GetOrigin()->CreateDirectory(relative_path, mode);
    if (!origin_res) {
        spdlog::error(
            "CreateDirectory origin failed for {}: {}", relative_path.string(),
            origin_res.error().message()
        );
        return std::unexpected(origin_res.error());
    }

    // Invalidate any potentially conflicting cache entry (e.g., if a file existed there)
    InvalidateCacheEntry(relative_path);

    // TODO: Cache directory metadata? Less common than file caching.

    spdlog::trace("CreateDirectory successful in origin for {}", relative_path.string());
    return {};
}

StorageResult<void> CacheManager::Remove(const std::filesystem::path& fuse_path)
{
    spdlog::debug("CacheManager::Remove({})", fuse_path.string());
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    auto origin_res = origin_manager_->GetOrigin()->Remove(relative_path);
    if (!origin_res) {
        // If origin remove fails (e.g., dir not empty, permissions), don't touch cache.
        spdlog::error(
            "CacheManager::Remove origin failed for {}: {}", relative_path.string(),
            origin_res.error().message()
        );
        return std::unexpected(origin_res.error());
    }

    // Origin remove succeeded, remove from all cache tiers.
    spdlog::trace(
        "CacheManager::Remove: Origin remove successful for {}. Invalidating cache.",
        relative_path.string()
    );
    InvalidateCacheEntry(relative_path);

    return {};
}

StorageResult<void> CacheManager::TruncateFile(const std::filesystem::path& fuse_path, off_t size)
{
    spdlog::debug("CacheManager::TruncateFile({}, {})", fuse_path.string(), size);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    if (size < 0) {
        return std::unexpected(make_error_code(StorageErrc::InvalidOffset));
    }

    // Write-Through Policy
    auto origin_res = origin_manager_->GetOrigin()->Truncate(relative_path, size);
    if (!origin_res) {
        spdlog::error(
            "CacheManager::TruncateFile origin failed for {}: {}", relative_path.string(),
            origin_res.error().message()
        );
        InvalidateCacheEntry(relative_path);
        return std::unexpected(origin_res.error());
    }

    spdlog::trace(
        "CacheManager::TruncateFile: Origin truncate successful for {}. Invalidating cache.",
        relative_path.string()
    );
    InvalidateCacheEntry(relative_path);
    // TODO: update the cache entry instead of invalidating.

    return {};
}

StorageResult<void> CacheManager::Move(
    const std::filesystem::path& from_fuse_path, const std::filesystem::path& to_fuse_path
)
{
    spdlog::debug("CacheManager::Move({}, {})", from_fuse_path.string(), to_fuse_path.string());
    auto from_relative = SanitizeFusePath(from_fuse_path);
    auto to_relative   = SanitizeFusePath(to_fuse_path);
    if (from_relative.empty() || to_relative.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    auto origin_res = origin_manager_->GetOrigin()->Move(from_relative, to_relative);
    if (!origin_res) {
        spdlog::error(
            "CacheManager::Move origin failed for {} -> {}: {}", from_relative.string(),
            to_relative.string(), origin_res.error().message()
        );
        return std::unexpected(origin_res.error());
    }

    spdlog::trace(
        "CacheManager::Move: Origin move successful for {} -> {}. Invalidating cache.",
        from_relative.string(), to_relative.string()
    );
    InvalidateCacheEntry(from_relative);
    InvalidateCacheEntry(to_relative);

    return {};
}

StorageResult<struct statvfs> CacheManager::GetFilesystemStats(
    const std::filesystem::path& fuse_path
)
{
    spdlog::debug("CacheManager::GetFilesystemStats({})", fuse_path.string());
    // Do statvfs on the origin path
    auto origin_res = origin_->GetPath();
}

// Private Cache Logic Helper Implementations

StorageResult<size_t> CacheManager::FetchAndCache(
    const fs::path& relative_path, off_t offset, std::span<std::byte>& buffer
)
{
    spdlog::debug(
        "CacheManager::FetchAndCache({}, {}, {})", relative_path.string(), offset, buffer.size()
    );
}

StorageResult<IStorage*> CacheManager::SelectCacheTierForWrite(
    const fs::path& relative_path, size_t required_space
)
{
}

void CacheManager::PromoteItem(const fs::path& relative_path, IStorage* current_tier) {
}  // End PromoteItem

}  // namespace DistributedCacheFS::Cache
