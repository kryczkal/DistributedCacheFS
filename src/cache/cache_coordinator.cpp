#include "cache/cache_coordinator.hpp"
#include "cache/local_cache_tier.hpp"
#include "origin/i_origin_interface.hpp"
#include "storage/storage_error.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <numeric>
#include <set>
#include <thread>

namespace DistributedCacheFS::Cache
{

CacheCoordinator::CacheCoordinator(
    const Config::NodeConfig& config, Origin::OriginManager* origin_manager
)
    : config_(config), origin_manager_(origin_manager)
{
    if (!origin_manager_ || !origin_manager_->GetOrigin()) {
        throw std::runtime_error("CacheCoordinator requires a valid OriginManager.");
    }
    for (const auto& tier_def : config_.cache_tiers) {
        tier_eviction_heaps_[tier_def.tier];  // Creates an empty heap for each tier level
    }
    spdlog::debug(
        "CacheCoordinator created for origin path '{}'",
        origin_manager_->GetOrigin()->GetFullPath(".").string()
    );
}

CacheCoordinator::~CacheCoordinator()
{
    spdlog::debug("CacheCoordinator shutting down...");
    ShutdownAll();
    // unique_ptrs in cache_tier_map_ handle tier destruction
    spdlog::debug(
        "CacheCoordinator shutdown sequence potentially complete (ensure ShutdownAll was called)."
    );
}

StorageResult<void> CacheCoordinator::InitializeAll()
{
    // TODO: Initial scan of metadata/heaps?
    spdlog::info("Initializing cache coordinator...");

    // Initialize Origin
    auto origin_init_res = origin_manager_->Initialize();
    if (!origin_init_res) {
        spdlog::critical("Failed to initialize origin: {}", origin_init_res.error().message());
        return std::unexpected(origin_init_res.error());
    }
    spdlog::info("Origin initialized successfully.");

    // Initialize Cache Tiers
    cache_tier_map_.clear();
    tier_eviction_heaps_.clear();
    bool has_local_tier = false;

    spdlog::info("Initializing {} configured cache tiers...", config_.cache_tiers.size());
    for (const auto& tier_def : config_.cache_tiers) {
        std::unique_ptr<ICacheTier> tier_instance;
        if (tier_def.type == Config::CacheTierStorageType::Local) {
            spdlog::info(
                "Initializing local cache tier {} at path: {}", tier_def.tier,
                tier_def.path.string()
            );
            tier_instance  = std::make_unique<LocalCacheTier>(tier_def);
            has_local_tier = true;

        } else if (tier_def.type == Config::CacheTierStorageType::Shared) {
            std::string policy_str =
                tier_def.policy ? Config::SharedCachePolicyToString(*tier_def.policy) : "N/A";
            std::string group_str = tier_def.share_group ? *tier_def.share_group : "N/A";
            spdlog::warn(
                "Shared cache tier type '{}' for path '{}' (group '{}', tier {}) is defined but "
                "not yet implemented. This tier will be unavailable.",
                policy_str, tier_def.path.string(), group_str, tier_def.tier
            );
            // TODO: Implement SharedCacheTier and initialize here
        }

        auto init_result = tier_instance->Initialize();
        if (!init_result) {
            spdlog::error(
                "Failed to initialize cache tier {} at '{}': {}", tier_def.tier,
                tier_def.path.string(), init_result.error().message()
            );
            return std::unexpected(init_result.error());
        }

        // Add to tier map and initialize heap
        cache_tier_map_[tier_def.tier].push_back(std::move(tier_instance));
        tier_eviction_heaps_[tier_def.tier];
        spdlog::info("Successfully initialized cache tier {}.", tier_def.tier);
    }

    if (cache_tier_map_.empty()) {
        spdlog::warn("No cache tiers were successfully initialized or configured.");
    }

    spdlog::info("Cache Coordinator initialized successfully.");
    return {};
}

StorageResult<void> CacheCoordinator::ShutdownAll()
{
    std::unique_lock lock(metadata_heap_mutex_);
    spdlog::info("Shutting down Cache Coordinator...");
    std::error_code first_error;

    // Shutdown Cache Tiers
    spdlog::info("Shutting down cache tiers...");
    for (auto& [tier_level, tiers_vec] : cache_tier_map_) {
        for (auto& tier_ptr : tiers_vec) {
            if (tier_ptr) {
                auto shutdown_result = tier_ptr->Shutdown();
                if (!shutdown_result) {
                    spdlog::error(
                        "Failed to shut down cache tier {} (Path: '{}'): {}", tier_ptr->GetTier(),
                        tier_ptr->GetPath().string(), shutdown_result.error().message()
                    );
                    if (!first_error) {
                        first_error = shutdown_result.error();
                    }
                } else {
                    spdlog::info("Cache tier {} shut down successfully.", tier_ptr->GetTier());
                }
            }
        }
    }

    cache_tier_map_.clear();
    item_metadata_.clear();
    tier_eviction_heaps_.clear();

    // Shutdown Origin
    spdlog::info("Shutting down origin...");
    auto origin_shutdown_res = origin_manager_->Shutdown();
    if (!origin_shutdown_res) {
        spdlog::error("Failed to shut down origin: {}", origin_shutdown_res.error().message());
        if (!first_error) {
            first_error = origin_shutdown_res.error();
        }
    } else {
        spdlog::info("Origin shut down successfully.");
    }

    if (first_error) {
        spdlog::error(
            "Cache Coordinator shutdown completed with errors: {}", first_error.message()
        );
        return std::unexpected(first_error);
    }

    spdlog::info("Cache Coordinator shut down successfully.");
    return {};
}

// Path Sanitization
std::filesystem::path CacheCoordinator::SanitizeFusePath(const std::filesystem::path& fuse_path
) const
{
    if (!fuse_path.has_root_path() || fuse_path.root_path() != "/") {
        spdlog::warn("Received non-absolute FUSE path: {}", fuse_path.string());
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

StorageResult<struct stat> CacheCoordinator::GetAttributes(const std::filesystem::path& fuse_path)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "GetAttributes called for: {} (relative: {})", fuse_path.string(), relative_path.string()
    );
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Fetch Origin Attributes
    auto origin_attr_res = origin_manager_->GetOrigin()->GetAttributes(relative_path);
    if (!origin_attr_res) {
        spdlog::error(
            "GetAttributes failed for {}: Origin lookup error {}", relative_path.string(),
            origin_attr_res.error().message()
        );
        return std::unexpected(origin_attr_res.error());
    }
    const struct stat& origin_stat = origin_attr_res.value();

    // Check the central metadata store (Read Lock)
    {
        std::shared_lock lock(metadata_heap_mutex_);
        auto it = item_metadata_.find(relative_path);
        if (it != item_metadata_.end()) {
            // Cache Hit (Metadata exists)
            const auto& item_info = it->second;
            spdlog::trace(
                "Cache metadata hit for GetAttributes: tier {}", item_info.current_tier->GetTier()
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

    spdlog::trace(
        "Cache miss or invalid for GetAttributes: {}. Returning origin stat.",
        relative_path.string()
    );
    return origin_stat;
}

StorageResult<std::vector<std::pair<std::string, struct stat>>> CacheCoordinator::ListDirectory(
    const std::filesystem::path& fuse_path
)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "ListDirectory called for: {} (relative: {})", fuse_path.string(), relative_path.string()
    );
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Strategy: Always fetch from Origin for consistency.
    // TODO: Implement directory entry caching later if performance demands it.

    auto origin_list_res = origin_manager_->GetOrigin()->ListDirectory(relative_path);

    if (!origin_list_res) {
        spdlog::error(
            "ListDirectory failed for {}: Origin lookup error {}", relative_path.string(),
            origin_list_res.error().message()
        );
    } else {
        // TODO: Update cache access meta for the directory itself?
    }

    return origin_list_res;
}

StorageResult<size_t> CacheCoordinator::ReadFile(
    const std::filesystem::path& fuse_path, off_t offset, std::span<std::byte> buffer
)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "ReadFile called for: {} (relative: {}), offset: {}, size: {}", fuse_path.string(),
        relative_path.string(), offset, buffer.size()
    );
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    RichCacheItemInfo item_info_copy;
    bool was_hit       = false;
    int hit_tier_level = -1;

    // Check Metadata Cache (Read Lock)
    {
        std::shared_lock lock(metadata_heap_mutex_);
        auto it = item_metadata_.find(relative_path);
        if (it != item_metadata_.end()) {
            item_info_copy = it->second;
            was_hit        = true;
            hit_tier_level = item_info_copy.current_tier->GetTier();
            spdlog::trace("ReadFile metadata cache hit: tier {}", hit_tier_level);
        }
    }

    if (was_hit) {
        // Check Origin Attributes for Validity (No lock needed for origin)
        auto origin_attr_res = origin_manager_->GetOrigin()->GetAttributes(relative_path);
        if (!origin_attr_res) {
            spdlog::error(
                "ReadFile cache hit but origin GetAttributes failed for {}: {}. Invalidating.",
                relative_path.string(), origin_attr_res.error().message()
            );
            InvalidateCacheEntry(relative_path);  // Requires exclusive lock internally
            return std::unexpected(make_error_code(StorageErrc::OriginError));
        }

        // Perform Coherency Check
        auto valid_res = IsCacheValid(item_info_copy, origin_attr_res.value());

        if (valid_res && valid_res.value()) {
            // Cache Valid: Read from physical tier
            spdlog::trace(
                "ReadFile cache valid for {}. Reading from cache tier {}.", relative_path.string(),
                hit_tier_level
            );
            auto read_res = item_info_copy.current_tier->Read(relative_path, offset, buffer);

            if (read_res) {
                // Read successful: Update metadata (Write Lock)
                auto now        = std::time(nullptr);
                double new_heat = 0.0;
                {
                    std::unique_lock lock(metadata_heap_mutex_);
                    auto it = item_metadata_.find(relative_path);
                    if (it !=
                        item_metadata_.end()) {  // Check again in case invalidated between locks
                        it->second.last_accessed = now;
                        new_heat                 = CalculateHeat(it->second, now);
                        UpdateHeapEntry(relative_path, new_heat, hit_tier_level);
                        spdlog::trace(
                            "Updated access time and heat ({}) for {}", new_heat,
                            relative_path.string()
                        );
                    } else {
                        spdlog::warn(
                            "ReadFile: Item {} disappeared from metadata during update.",
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
                return read_res.value();

            } else if (read_res.error() == make_error_code(StorageErrc::FileNotFound)) {
                spdlog::warn(
                    "ReadFile cache inconsistency: Metadata hit but physical read failed ENOENT "
                    "for {}. Invalidating.",
                    relative_path.string()
                );
                InvalidateCacheEntry(relative_path);  // Requires exclusive lock internally
            } else {
                spdlog::error(
                    "ReadFile cache read error for {}: {}", relative_path.string(),
                    read_res.error().message()
                );
                return std::unexpected(read_res.error());
            }
        } else {
            // Cache Invalid: Invalidate and fall through
            spdlog::info(
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

StorageResult<size_t> CacheCoordinator::WriteFile(
    const std::filesystem::path& fuse_path, off_t offset, std::span<const std::byte> data
)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "WriteFile called for: {} (relative: {}), offset: {}, size: {}", fuse_path.string(),
        relative_path.string(), offset, data.size()
    );
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy

    spdlog::trace("WriteFile: Writing to origin for {}", relative_path.string());
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
        origin_write_res.value()
    );

    spdlog::trace("WriteFile: Invalidating cache for {}", relative_path.string());
    InvalidateCacheEntry(relative_path);  // Requires exclusive lock internally

    return origin_write_res.value();
}

StorageResult<void> CacheCoordinator::CreateFile(
    const std::filesystem::path& fuse_path, mode_t mode
)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "CreateFile called for: {} (relative: {}), mode={:o}", fuse_path.string(),
        relative_path.string(), mode
    );
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

StorageResult<void> CacheCoordinator::CreateDirectory(
    const std::filesystem::path& fuse_path, mode_t mode
)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "CreateDirectory called for: {} (relative: {}), mode={:o}", fuse_path.string(),
        relative_path.string(), mode
    );
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

StorageResult<void> CacheCoordinator::Remove(const std::filesystem::path& fuse_path)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "Remove called for: {} (relative: {})", fuse_path.string(), relative_path.string()
    );
    if (relative_path.empty() && fuse_path != "/") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    auto origin_res = origin_manager_->GetOrigin()->Remove(relative_path);
    if (!origin_res) {
        // If origin remove fails (e.g., dir not empty, permissions), don't touch cache.
        spdlog::error(
            "Remove origin failed for {}: {}", relative_path.string(), origin_res.error().message()
        );
        return std::unexpected(origin_res.error());
    }

    // Origin remove succeeded, remove from all cache tiers.
    spdlog::trace("Remove successful in origin, invalidating cache for {}", relative_path.string());
    InvalidateCacheEntry(relative_path);

    return {};
}

StorageResult<void> CacheCoordinator::TruncateFile(
    const std::filesystem::path& fuse_path, off_t size
)
{
    auto relative_path = SanitizeFusePath(fuse_path);
    spdlog::trace(
        "TruncateFile called for: {} (relative: {}), size={}", fuse_path.string(),
        relative_path.string(), size
    );
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
            "TruncateFile origin failed for {}: {}", relative_path.string(),
            origin_res.error().message()
        );
        InvalidateCacheEntry(relative_path);
        return std::unexpected(origin_res.error());
    }

    spdlog::trace(
        "TruncateFile successful in origin, invalidating cache for {}", relative_path.string()
    );
    InvalidateCacheEntry(relative_path);
    // TODO: update the cache entry instead of invalidating.

    return {};
}

StorageResult<void> CacheCoordinator::Move(
    const std::filesystem::path& from_fuse_path, const std::filesystem::path& to_fuse_path
)
{
    auto from_relative = SanitizeFusePath(from_fuse_path);
    auto to_relative   = SanitizeFusePath(to_fuse_path);
    spdlog::trace("Move called for: {} -> {}", from_fuse_path.string(), to_fuse_path.string());
    if (from_relative.empty() || to_relative.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    // Write-Through Policy
    auto origin_res = origin_manager_->GetOrigin()->Move(from_relative, to_relative);
    if (!origin_res) {
        spdlog::error(
            "Move origin failed for {} -> {}: {}", from_relative.string(), to_relative.string(),
            origin_res.error().message()
        );
        return std::unexpected(origin_res.error());
    }

    spdlog::trace(
        "Move successful in origin, invalidating cache for {} and {}", from_relative.string(),
        to_relative.string()
    );
    InvalidateCacheEntry(from_relative);
    InvalidateCacheEntry(to_relative);

    return {};
}

StorageResult<struct statvfs> CacheCoordinator::GetFilesystemStats(
    const std::filesystem::path& fuse_path
)
{
    spdlog::trace("GetFilesystemStats called for: {}", fuse_path.string());
    // TODO: What should this report?
    spdlog::warn("GetFilesystemStats not fully implemented. Returning ENOSYS.");
    return std::unexpected(make_error_code(StorageErrc::NotSupported));
}

// Private Cache Logic Helper Implementations

StorageResult<CacheLocation> CacheCoordinator::FindInCachePhysical(const fs::path& relative_path)
{
    // No locking needed here - tier->Probe handles its own locking
    // Iterate tiers from lowest number (highest priority) to highest
    for (auto const& [tier_level, tiers_vec] : cache_tier_map_) {
        for (const auto& tier_ptr : tiers_vec) {
            if (tier_ptr) {
                auto probe_res = tier_ptr->Probe(relative_path);
                if (probe_res && probe_res.value()) {
                    spdlog::trace(
                        "FindInCachePhysical: Found '{}' in tier {}", relative_path.string(),
                        tier_level
                    );
                    return CacheLocation{tier_ptr.get(), relative_path, tier_level};
                } else if (!probe_res &&
                           probe_res.error() != make_error_code(StorageErrc::FileNotFound)) {
                    spdlog::warn(
                        "FindInCachePhysical: Error probing tier {} for '{}': {}", tier_level,
                        relative_path.string(), probe_res.error().message()
                    );
                }
            }
        }
    }

    spdlog::trace(
        "FindInCachePhysical: Path '{}' not found in any cache tier.", relative_path.string()
    );
    return std::unexpected(make_error_code(StorageErrc::CacheMiss));  // Use CacheMiss internally
}

StorageResult<size_t> CacheCoordinator::FetchAndCache(
    const fs::path& relative_path, off_t offset, std::span<std::byte> buffer
)
{
    spdlog::trace("FetchAndCache: Fetching origin data for {}", relative_path.string());

    auto origin_attr_res = origin_manager_->GetOrigin()->GetAttributes(relative_path);
    if (!origin_attr_res) {
        spdlog::error(
            "FetchAndCache: Origin GetAttributes failed for {}: {}", relative_path.string(),
            origin_attr_res.error().message()
        );
        return std::unexpected(origin_attr_res.error());
    }
    const struct stat& origin_stat = origin_attr_res.value();
    const off_t origin_file_size   = origin_stat.st_size;

    // Measure Cost
    auto start_time = std::chrono::steady_clock::now();

    // Fetch the requested chunk directly into the user's buffer
    auto origin_read_res = origin_manager_->GetOrigin()->Read(relative_path, offset, buffer);

    auto end_time        = std::chrono::steady_clock::now();
    double fetch_cost_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

    if (!origin_read_res) {
        spdlog::error(
            "FetchAndCache: Origin read failed for {}: {}", relative_path.string(),
            origin_read_res.error().message()
        );
        return std::unexpected(origin_read_res.error());
    }
    size_t bytes_read_from_origin = origin_read_res.value();
    spdlog::trace(
        "FetchAndCache: Read {} bytes from origin for {} (cost: {:.2f} ms)", bytes_read_from_origin,
        relative_path.string(), fetch_cost_ms
    );

    if (bytes_read_from_origin == 0 && offset >= origin_file_size) {
        spdlog::trace(
            "FetchAndCache: Read 0 bytes (EOF) from origin for {}. Not caching.",
            relative_path.string()
        );
        return 0;
    }
    // If read less than buffer size but not necessarily EOF for the whole file (partial read)
    // we still cache what was read.

    // Select Cache Tier - Use origin file size to check needed space
    // NOTE: We might cache only the first chunk if the origin read was partial.
    // This policy assumes we cache the intent to store the file, requiring its full size.

    size_t required_space = static_cast<size_t>(origin_file_size);
    if (required_space == 0 && bytes_read_from_origin > 0) {
        // Handle case where origin stat might be slightly delayed vs read, use read size
        required_space = bytes_read_from_origin;
    }

    auto target_tier_res = SelectCacheTierForWrite(relative_path, required_space);
    if (!target_tier_res) {
        spdlog::warn(
            "FetchAndCache: No suitable cache tier found (need {} bytes) to store {}. Serving from "
            "origin only.",
            required_space, relative_path.string()
        );
        return bytes_read_from_origin;  // Return data read from origin, but don't cache
    }
    ICacheTier* target_tier = target_tier_res.value();
    spdlog::trace(
        "FetchAndCache: Selected tier {} for caching {}", target_tier->GetTier(),
        relative_path.string()
    );

    // Evict if Needed

    auto evict_res = EvictIfNeeded(target_tier, required_space);
    if (!evict_res) {
        spdlog::error(
            "FetchAndCache: Eviction failed or insufficient space in tier {}. Cannot cache {}.",
            target_tier->GetTier(), relative_path.string()
        );
        return bytes_read_from_origin;
    }

    // Write to Cache Tier
    // Write only the data actually read from the origin in this operation
    spdlog::trace(
        "FetchAndCache: Writing {} bytes (offset {}) to cache tier {} for {}",
        bytes_read_from_origin, offset, target_tier->GetTier(), relative_path.string()
    );
    std::span<const std::byte> data_to_cache(buffer.data(), bytes_read_from_origin);
    auto cache_write_res = target_tier->Write(relative_path, offset, data_to_cache);

    if (!cache_write_res) {
        spdlog::error(
            "FetchAndCache: Failed to write to cache tier {} for {}: {}", target_tier->GetTier(),
            relative_path.string(), cache_write_res.error().message()
        );
        // TODO: Attempt cleanup / remove partially written file?
    } else {
        spdlog::trace(
            "FetchAndCache: Successfully wrote {} bytes to cache tier {} for {}",
            cache_write_res.value(), target_tier->GetTier(), relative_path.string()
        );

        // Set Origin Metadata
        CacheOriginMetadata origin_meta_for_tier;
        origin_meta_for_tier.origin_mtime = origin_stat.st_mtime;
        origin_meta_for_tier.origin_size  = origin_stat.st_size;
        auto meta_set_res = target_tier->SetCacheMetadata(relative_path, origin_meta_for_tier);
        if (!meta_set_res) {
            spdlog::error(
                "FetchAndCache: Failed to set origin metadata on tier {} for {}: {}",
                target_tier->GetTier(), relative_path.string(), meta_set_res.error().message()
            );
            // Invalidate the entry if setting metadata failed after write
            InvalidateCacheEntry(relative_path);  // Requires lock
        } else {
            // Add to Central Metadata and Heap (Exclusive Lock)
            auto now = std::time(nullptr);
            {
                std::unique_lock lock(metadata_heap_mutex_);

                RichCacheItemInfo new_info;
                new_info.relative_path = relative_path;
                new_info.cost          = fetch_cost_ms;
                new_info.size          = origin_file_size;
                new_info.last_accessed = now;
                new_info.origin_mtime  = origin_stat.st_mtime;
                new_info.origin_size   = origin_stat.st_size;
                new_info.current_tier  = target_tier;

                double initial_heat = CalculateHeat(new_info, now);

                // Use insert_or_assign to handle potential races if entry exists briefly
                item_metadata_.insert_or_assign(relative_path, std::move(new_info));

                // Add to heap
                try {
                    tier_eviction_heaps_.at(target_tier->GetTier())
                        .push({initial_heat, relative_path});
                    spdlog::trace(
                        "FetchAndCache: Added/Updated metadata and heap entry for {} (Heat: {})",
                        relative_path.string(), initial_heat
                    );
                } catch (const std::out_of_range& oor) {
                    spdlog::error(
                        "FetchAndCache: Heap not initialized for tier {}!", target_tier->GetTier()
                    );
                    // If heap doesn't exist, metadata entry is orphaned, remove it
                    item_metadata_.erase(relative_path);
                    target_tier->Remove(relative_path);  // Attempt cleanup
                }
            }
        }
    }
    // Return the number of bytes read from origin (which are now in user buffer)
    return bytes_read_from_origin;
}

StorageResult<ICacheTier*> CacheCoordinator::SelectCacheTierForWrite(
    const fs::path& relative_path, size_t required_space
)
{
    // Simple strategy: Iterate lowest tier first, pick first that reports enough space.
    // Note: Available space check might be inaccurate, EvictIfNeeded does the real work.
    for (auto const& [tier_level, tiers_vec] : cache_tier_map_) {
        for (const auto& tier_ptr : tiers_vec) {
            if (tier_ptr) {
                auto available_res = tier_ptr->GetAvailableBytes();
                if (available_res) {
                    auto capacity_res = tier_ptr->GetCapacityBytes();
                    bool has_capacity = capacity_res && (*capacity_res >= required_space);

                    if (has_capacity && (*available_res >= required_space)) {
                        spdlog::trace(
                            "SelectCacheTierForWrite: Found suitable tier {} for {} ({} bytes "
                            "needed, {} available)",
                            tier_level, relative_path.string(), required_space,
                            available_res.value()
                        );
                        return tier_ptr.get();
                    } else if (has_capacity) {
                        spdlog::trace(
                            "SelectCacheTierForWrite: Tentatively selecting tier {} for {} ({} "
                            "needed, {} avail, {} capacity). Eviction likely required.",
                            tier_level, relative_path.string(), required_space,
                            available_res.value(), capacity_res.value()
                        );
                        return tier_ptr.get();
                    }
                    // else: Not enough total capacity, skip tier.

                } else {
                    spdlog::warn(
                        "SelectCacheTierForWrite: Could not get available space for tier {} (Path: "
                        "'{}'): {}",
                        tier_level, tier_ptr->GetPath().string(), available_res.error().message()
                    );
                }
            }
        }
    }
    spdlog::warn(
        "SelectCacheTierForWrite: No cache tier found with enough capacity ({} bytes) for {}",
        required_space, relative_path.string()
    );
    return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
}

StorageResult<void> CacheCoordinator::EvictIfNeeded(ICacheTier* target_tier, size_t required_space)
{
    std::unique_lock lock(metadata_heap_mutex_
    );  // Exclusive lock needed for heap & metadata modification

    int tier_level = target_tier->GetTier();
    spdlog::trace(
        "EvictIfNeeded: Checking tier {} for {} bytes required.", tier_level, required_space
    );

    auto available_res = target_tier->GetAvailableBytes();
    if (!available_res) {
        spdlog::error(
            "EvictIfNeeded: Failed to get available space for tier {}: {}", tier_level,
            available_res.error().message()
        );
        return std::unexpected(make_error_code(StorageErrc::EvictionError));
    }

    uint64_t current_available = available_res.value();
    int64_t space_to_free =
        static_cast<int64_t>(required_space) - static_cast<int64_t>(current_available);

    if (space_to_free <= 0) {
        spdlog::trace(
            "EvictIfNeeded: Tier {} has enough space ({} available >= {} required).", tier_level,
            current_available, required_space
        );
        return {};
    }

    spdlog::info(
        "EvictIfNeeded: Tier {} needs eviction ({} required, {} available). Need to free {} bytes.",
        tier_level, required_space, current_available, space_to_free
    );

    EvictionHeap* heap_ptr = nullptr;
    try {
        heap_ptr = &tier_eviction_heaps_.at(tier_level);
    } catch (const std::out_of_range& oor) {
        spdlog::error("EvictIfNeeded: Heap not found for tier {}!", tier_level);
        return std::unexpected(make_error_code(StorageErrc::EvictionError));
    }
    auto& heap = *heap_ptr;

    size_t freed_space_total = 0;
    int eviction_count       = 0;

    while (space_to_free > 0 && !heap.empty()) {
        HeatEntry entry_to_evict = heap.top();
        heap.pop();

        double evicted_heat          = entry_to_evict.first;
        const fs::path& evicted_path = entry_to_evict.second;

        auto it = item_metadata_.find(evicted_path);
        if (it == item_metadata_.end()) {
            spdlog::trace(
                "EvictIfNeeded: Item '{}' from heap not found in metadata (already evicted?), "
                "skipping.",
                evicted_path.string()
            );
            continue;  // Item already gone from metadata, skip physical removal
        }

        if (it->second.current_tier != target_tier) {
            spdlog::warn(
                "EvictIfNeeded: Heap inconsistency! Item '{}' (Heat {}) supposed to be in tier {}, "
                "but metadata says tier {}. Skipping eviction.",
                evicted_path.string(), evicted_heat, tier_level,
                it->second.current_tier ? it->second.current_tier->GetTier() : -99
            );
            // Don't remove from metadata, as it belongs to another tier's heap presumably.
            // TODO: This indicates a need for better heap update logic.
            continue;
        }

        size_t evicted_size = it->second.size;
        spdlog::trace(
            "EvictIfNeeded: Evicting '{}' (Size: {}, Heat: {}) from tier {}", evicted_path.string(),
            evicted_size, evicted_heat, tier_level
        );

        // Remove from physical tier first
        auto remove_res = target_tier->Remove(evicted_path);
        if (!remove_res && remove_res.error() != make_error_code(StorageErrc::FileNotFound)) {
            spdlog::error(
                "EvictIfNeeded: Failed to remove '{}' from tier {}: {}. Stopping eviction.",
                evicted_path.string(), tier_level, remove_res.error().message()
            );
            item_metadata_.erase(it);
            return std::unexpected(make_error_code(StorageErrc::EvictionError));
        }

        // Remove from central metadata
        item_metadata_.erase(it);

        space_to_free -= evicted_size;
        freed_space_total += evicted_size;
        eviction_count++;
    }

    if (space_to_free > 0) {
        spdlog::error(
            "EvictIfNeeded: Could not free enough space in tier {}. Needed {}, freed {}. Heap "
            "empty? {}",
            tier_level, required_space - current_available, freed_space_total, heap.empty()
        );
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
    }

    spdlog::info(
        "EvictIfNeeded: Successfully freed {} bytes by evicting {} items from tier {}.",
        freed_space_total, eviction_count, tier_level
    );
    return {};
}
void CacheCoordinator::InvalidateCacheEntry(const fs::path& relative_path)
{
    spdlog::trace("Invalidating cache entry for: {}", relative_path.string());
    bool removed_physically = false;

    // Remove from Central Metadata and Heaps (Exclusive Lock)
    RemoveItemFromMetadataAndHeap(relative_path);

    // Remove from all physical tiers where it might exist (Best Effort)
    for (auto& [tier_level, tiers_vec] : cache_tier_map_) {
        for (auto& tier_ptr : tiers_vec) {
            if (tier_ptr) {
                auto remove_res = tier_ptr->Remove(relative_path);
                if (remove_res) {
                    spdlog::trace(
                        "InvalidateCacheEntry: Physically removed '{}' from tier {}",
                        relative_path.string(), tier_level
                    );
                    removed_physically = true;
                } else if (remove_res.error() != make_error_code(StorageErrc::FileNotFound)) {
                    spdlog::warn(
                        "InvalidateCacheEntry: Error physically removing '{}' from tier {}: {}",
                        relative_path.string(), tier_level, remove_res.error().message()
                    );
                }
            }
        }
    }
    if (!removed_physically) {
        spdlog::trace(
            "InvalidateCacheEntry: '{}' was not found in any physical cache tier during "
            "invalidation.",
            relative_path.string()
        );
    }
}
StorageResult<bool> CacheCoordinator::IsCacheValid(
    const RichCacheItemInfo& item_info, const struct stat& current_origin_stat
)
{
    spdlog::trace("IsCacheValid checking for: {}", item_info.relative_path.string());

    // Compare metadata stored centrally with current origin metadata
    bool mtime_match = (current_origin_stat.st_mtime == item_info.origin_mtime);
    bool size_match  = (current_origin_stat.st_size == item_info.origin_size);

    // item_info.origin_mtime != 0 implicitly checks if metadata was ever stored.
    if (item_info.origin_mtime == 0 && item_info.origin_size == -1) {
        spdlog::warn(
            "IsCacheValid: Missing origin metadata in central store for cached item '{}'. Treating "
            "as STALE.",
            item_info.relative_path.string()
        );
        return false;
    }

    if (mtime_match && size_match) {
        spdlog::trace(
            "IsCacheValid: Cache VALID for {}. Origin mtime ({}) and size ({}) match stored "
            "metadata.",
            item_info.relative_path.string(), current_origin_stat.st_mtime,
            current_origin_stat.st_size
        );
        return true;
    } else {
        spdlog::info(
            "IsCacheValid: Cache STALE for {}. Origin mtime: {}, size: {}. Stored mtime: {}, size: "
            "{}",
            item_info.relative_path.string(), current_origin_stat.st_mtime,
            current_origin_stat.st_size, item_info.origin_mtime, item_info.origin_size
        );
        return false;
    }
}
// TODO: Add more sophisticated checks if needed (checksums?)}

double CacheCoordinator::CalculateHeat(const RichCacheItemInfo& info, std::time_t current_time)
    const
{
    if (info.size < 0) {
        return 0.0;
    }

    double time_diff_secs = std::max(0.0, std::difftime(current_time, info.last_accessed));

    double decay_factor = 1.0 / (1.0 + config_.cache_settings.decay_constant * time_diff_secs);

    // Base Value (Cost / Size)
    double base_value =
        (info.size >= 0) ? (info.cost / (static_cast<double>(info.size) + 1.0)) : 0.0;

    double heat = base_value * decay_factor;
    spdlog::trace(
        "CalculateHeat for {}: Cost={:.2f}, Size={}, TimeDiff={:.0f}s, Decay={:.4f} -> Heat={:.6f}",
        info.relative_path.string(), info.cost, info.size, time_diff_secs, decay_factor, heat
    );
    return heat;
}

// Simplistic heap update: just re-insert. EvictIfNeeded needs to handle duplicates.
void CacheCoordinator::UpdateHeapEntry(
    const fs::path& relative_path, double new_heat, int tier_level
)
{
    // Assumes caller holds the unique lock on metadata_heap_mutex_
    try {
        tier_eviction_heaps_.at(tier_level).push({new_heat, relative_path});
        spdlog::trace(
            "UpdateHeapEntry: Re-inserted {} into heap for tier {} with heat {}",
            relative_path.string(), tier_level, new_heat
        );
    } catch (const std::out_of_range& oor) {
        spdlog::error("UpdateHeapEntry: Heap not found for tier {}!", tier_level);
    }
    // TODO: Implement a more robust heap update using boost::heap or tracking invalidated entries
}

void CacheCoordinator::RemoveItemFromMetadataAndHeap(const fs::path& relative_path)
{
    std::unique_lock lock(metadata_heap_mutex_);
    auto it = item_metadata_.find(relative_path);
    if (it != item_metadata_.end()) {
        int tier_level = it->second.current_tier ? it->second.current_tier->GetTier() : -1;
        item_metadata_.erase(it);
        spdlog::trace(
            "RemoveItemFromMetadataAndHeap: Removed '{}' from metadata.", relative_path.string()
        );

        // TODO: Removing from std::priority_queue is inefficient.
        // For now, we only remove from metadata map. The heap entry becomes stale.
        if (tier_level != -1) {
            spdlog::trace(
                "RemoveItemFromMetadataAndHeap: Corresponding entry in heap for tier {} for '{}' "
                "becomes stale.",
                tier_level, relative_path.string()
            );
        }

    } else {
        spdlog::trace(
            "RemoveItemFromMetadataAndHeap: '{}' not found in metadata.", relative_path.string()
        );
    }
}

ICacheTier* CacheCoordinator::FindNextFasterTier(int current_tier_level)
{
    // Iterate through tiers in ascending order (map is sorted by key)
    ICacheTier* faster_tier = nullptr;
    int fastest_found       = current_tier_level;

    for (const auto& [level, tiers_vec] : cache_tier_map_) {
        if (!tiers_vec.empty() && level < fastest_found) {
            // TODO: !!! For now, just pick the first tier in the vector !!!
            faster_tier   = tiers_vec[0].get();
            fastest_found = level;
        }
    }
    if (faster_tier && faster_tier->GetTier() < current_tier_level) {
        return faster_tier;
    }
    return nullptr;  // No faster tier found
}

void CacheCoordinator::PromoteItem(const fs::path& relative_path, ICacheTier* current_tier)
{
    if (!current_tier)
        return;

    int current_tier_level  = current_tier->GetTier();
    ICacheTier* target_tier = FindNextFasterTier(current_tier_level);

    if (!target_tier) {
        spdlog::trace(
            "PromoteItem: No faster tier found for item '{}' in tier {}.", relative_path.string(),
            current_tier_level
        );
        return;
    }

    int target_tier_level = target_tier->GetTier();
    spdlog::trace(
        "PromoteItem: Considering promotion of '{}' from tier {} to tier {}.",
        relative_path.string(), current_tier_level, target_tier_level
    );

    double item_heat = 0.0;
    size_t item_size = 0;
    bool item_exists = false;

    {
        std::shared_lock lock(metadata_heap_mutex_);
        auto it = item_metadata_.find(relative_path);
        if (it != item_metadata_.end() && it->second.current_tier == current_tier) {
            item_size   = it->second.size;
            item_heat   = CalculateHeat(it->second, std::time(nullptr));
            item_exists = true;
        } else {
            spdlog::warn(
                "PromoteItem: Item '{}' not found in metadata or not in expected tier {} during "
                "check.",
                relative_path.string(), current_tier_level
            );
            return;
        }
    }

    if (!item_exists || item_size == 0) {
        spdlog::trace(
            "PromoteItem: Item '{}' has size 0 or doesn't exist, skipping promotion.",
            relative_path.string()
        );
        return;
    }

    // Evaluation Phase
    double evicted_heat_sum = 0.0;
    size_t evicted_size_sum = 0;
    std::vector<HeatEntry> candidates_to_evict;  // Store candidates temporarily

    // Need exclusive lock to potentially modify target heap
    std::unique_lock lock(metadata_heap_mutex_);

    EvictionHeap* target_heap_ptr = nullptr;
    try {
        target_heap_ptr = &tier_eviction_heaps_.at(target_tier_level);
    } catch (const std::out_of_range& oor) {
        spdlog::error("PromoteItem: Heap not found for target tier {}!", target_tier_level);
        return;
    }
    auto& target_heap = *target_heap_ptr;

    // Check target tier capacity
    auto target_capacity_res = target_tier->GetCapacityBytes();
    if (!target_capacity_res || *target_capacity_res < item_size) {
        spdlog::warn(
            "PromoteItem: Target tier {} lacks total capacity ({}) for item size {}.",
            target_tier_level, target_capacity_res.value_or(0), item_size
        );
        return;
    }

    // Create a temporary copy of the heap top to check without permanently popping #TODO
    EvictionHeap temp_heap = target_heap;
    while (evicted_size_sum < item_size && !temp_heap.empty()) {
        HeatEntry candidate = temp_heap.top();
        temp_heap.pop();

        // Check if candidate is valid in metadata (might be stale entry in heap)
        auto cand_it = item_metadata_.find(candidate.second);
        if (cand_it != item_metadata_.end() && cand_it->second.current_tier == target_tier) {
            candidates_to_evict.push_back(candidate);
            evicted_heat_sum += candidate.first;
            evicted_size_sum += cand_it->second.size;
        } else {
            spdlog::trace(
                "PromoteItem: Skipping stale candidate '{}' during evaluation.",
                candidate.second.string()
            );
        }
    }

    if (evicted_size_sum < item_size) {
        spdlog::info(
            "PromoteItem: Could not find enough candidates (found {} bytes) in tier {} to make "
            "space for '{}' ({} bytes).",
            evicted_size_sum, target_tier_level, relative_path.string(), item_size
        );
        return;
    }

    // Promotion Condition
    if (item_heat > evicted_heat_sum) {
        spdlog::info(
            "PromoteItem: Promoting '{}' (Heat {:.4f}) from tier {} to {}. Evicting {} items "
            "(Total Heat {:.4f}, Size {}).",
            relative_path.string(), item_heat, current_tier_level, target_tier_level,
            candidates_to_evict.size(), evicted_heat_sum, evicted_size_sum
        );

        // Perform Eviction from Target Tier
        for (const auto& entry_to_evict : candidates_to_evict) {
            const fs::path& evicted_path = entry_to_evict.second;
            auto it                      = item_metadata_.find(evicted_path);
            if (it != item_metadata_.end() && it->second.current_tier == target_tier) {
                spdlog::trace(
                    "PromoteItem: Evicting candidate '{}' from tier {}.", evicted_path.string(),
                    target_tier_level
                );
                auto remove_res = target_tier->Remove(evicted_path);  // Physical removal
                if (!remove_res &&
                    remove_res.error() != make_error_code(StorageErrc::FileNotFound)) {
                    spdlog::error(
                        "PromoteItem: Failed to physically remove eviction candidate '{}': {}. "
                        "Aborting promotion.",
                        evicted_path.string(), remove_res.error().message()
                    );
                    // TODO: Need robust rollback - how to restore evicted items?
                    return;
                }
                item_metadata_.erase(it);
            }
            // TODO: Improve heap cleanup after confirming eviction candidate removal
        }
        // Need to rebuild or clean target_heap realistically here.

        // Perform Move
        // This is a simplification: Assumes reading whole file, writing whole file.
        std::vector<std::byte> temp_buffer(item_size);
        StorageResult<size_t> read_res = current_tier->Read(relative_path, 0, temp_buffer);
        if (!read_res || read_res.value() != item_size) {
            spdlog::error(
                "PromoteItem: Failed to read full item '{}' from tier {}: {}",
                relative_path.string(), current_tier_level, read_res.error().message()
            );
            InvalidateCacheEntry(relative_path);
            return;
        }

        StorageResult<size_t> write_res = target_tier->Write(relative_path, 0, temp_buffer);
        if (!write_res || write_res.value() != item_size) {
            spdlog::error(
                "PromoteItem: Failed to write full item '{}' to tier {}: {}",
                relative_path.string(), target_tier_level, write_res.error().message()
            );
            InvalidateCacheEntry(relative_path);
            return;
        }

        // Read/Write successful, remove from original tier
        auto remove_orig_res = current_tier->Remove(relative_path);
        if (!remove_orig_res &&
            remove_orig_res.error() != make_error_code(StorageErrc::FileNotFound)) {
            spdlog::warn(
                "PromoteItem: Failed to remove original item '{}' from tier {} after move: {}",
                relative_path.string(), current_tier_level, remove_orig_res.error().message()
            );
            // Continue metadata update anyway
        }

        // Update Metadata and Heaps
        auto it_meta = item_metadata_.find(relative_path);
        if (it_meta != item_metadata_.end()) {
            it_meta->second.current_tier = target_tier;
            UpdateHeapEntry(relative_path, item_heat, target_tier_level);
            spdlog::trace(
                "PromoteItem: Updated metadata for '{}' to tier {}.", relative_path.string(),
                target_tier_level
            );
        } else {
            spdlog::error(
                "PromoteItem: Metadata for '{}' disappeared during move!", relative_path.string()
            );
            target_tier->Remove(relative_path);
        }

    } else {
        spdlog::trace(
            "PromoteItem: Promotion of '{}' (Heat {:.4f}) not worth it compared to eviction "
            "candidates' heat ({:.4f}).",
            relative_path.string(), item_heat, evicted_heat_sum
        );
    }

}  // End PromoteItem

}  // namespace DistributedCacheFS::Cache
