#include "cache/cache_coordinator.hpp"
#include "cache/local_cache_tier.hpp"
#include "origin/i_origin_interface.hpp"
#include "storage/storage_error.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <cerrno>
#include <numeric>
#include <set>

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
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
    bool has_local_tier = false;

    spdlog::info("Initializing {} configured cache tiers...", config_.cache_tiers.size());
    for (const auto& tier_def : config_.cache_tiers) {
        if (tier_def.type == Config::CacheTierStorageType::Local) {
            spdlog::info(
                "Initializing local cache tier {} at path: {}", tier_def.tier,
                tier_def.path.string()
            );
            auto local_tier  = std::make_unique<LocalCacheTier>(tier_def);
            auto init_result = local_tier->Initialize();
            if (!init_result) {
                spdlog::error(
                    "Failed to initialize local cache tier at '{}': {}", tier_def.path.string(),
                    init_result.error().message()
                );

                return std::unexpected(init_result.error());
            }
            cache_tier_map_[tier_def.tier].push_back(std::move(local_tier));
            has_local_tier = true;
            spdlog::info("Successfully initialized local cache tier {}.", tier_def.tier);

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
    }

    if (cache_tier_map_.empty()) {
        spdlog::warn("No cache tiers were successfully initialized or configured.");
    }

    spdlog::info("Cache Coordinator initialized successfully.");
    return {};
}

StorageResult<void> CacheCoordinator::ShutdownAll()
{
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
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
    cache_tier_map_.clear();  // Clear the map after shutting down

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "GetAttributes called for: {} (relative: {})", fuse_path.string(), relative_path.string()
    );

    // Check Cache
    auto cache_loc_res = FindInCache(relative_path);

    // Fetch Origin Attributes (always needed for coherency check or if missed)
    auto origin_attr_res = origin_manager_->GetOrigin()->GetAttributes(relative_path);

    if (cache_loc_res) {
        // Cache Hit
        const auto& location = cache_loc_res.value();
        spdlog::trace("Cache hit for GetAttributes: tier {}", location.tier_level);

        if (!origin_attr_res) {
            spdlog::warn(
                "GetAttributes Cache Hit: Origin lookup failed for {}: {}. Returning potentially "
                "stale cache attrs.",
                relative_path.string(), origin_attr_res.error().message()
            );
            // Decide: return stale cache attrs or report origin error? Let's return stale for now.
            auto cached_attr_res = location.cache_tier->GetAttributes(relative_path);
            if (cached_attr_res) {
                location.cache_tier->UpdateAccessMeta(relative_path);  // Update LRU
                return cached_attr_res.value();
            } else {
                // Cache entry exists but can't get attrs? Inconsistent state.
                InvalidateCacheEntry(relative_path);
                return std::unexpected(make_error_code(StorageErrc::IOError));
            }
        }

        // Basic Coherency Check
        auto valid_res = IsCacheValid(location, origin_attr_res.value());
        if (valid_res && valid_res.value()) {
            location.cache_tier->UpdateAccessMeta(relative_path);  // Update LRU
            return origin_attr_res.value();
        } else {
            // Cache is stale or check failed
            spdlog::info(
                "Cache stale/invalid for GetAttributes: {}. Invalidating.", relative_path.string()
            );
            InvalidateCacheEntry(relative_path);
            // Fall through to return fresh origin attributes (if origin lookup succeeded)
        }

    } else {
        // Cache Miss
        spdlog::trace("Cache miss for GetAttributes: {}", relative_path.string());
        // Fall through to return origin attributes (if origin lookup succeeded)
    }

    // Return Origin Attributes if lookup succeeded (either cache miss or stale cache)
    if (origin_attr_res) {
        return origin_attr_res.value();
    } else {
        // Origin lookup failed, and either cache miss or stale cache invalidated
        spdlog::error(
            "GetAttributes failed for {}: Origin lookup error {}", relative_path.string(),
            origin_attr_res.error().message()
        );
        return std::unexpected(origin_attr_res.error());  // Propagate origin error
    }
}

StorageResult<std::vector<std::pair<std::string, struct stat>>> CacheCoordinator::ListDirectory(
    const std::filesystem::path& fuse_path
)
{
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "ListDirectory called for: {} (relative: {})", fuse_path.string(), relative_path.string()
    );

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "ReadFile called for: {} (relative: {}), offset: {}, size: {}", fuse_path.string(),
        relative_path.string(), offset, buffer.size()
    );

    // Check Cache
    auto cache_loc_res = FindInCache(relative_path);

    if (cache_loc_res) {
        const auto& location = cache_loc_res.value();
        spdlog::trace("Cache hit for ReadFile: tier {}", location.tier_level);

        bool use_cache       = false;
        auto origin_attr_res = origin_manager_->GetOrigin()->GetAttributes(relative_path);

        if (!origin_attr_res) {
            // Fail the read
            spdlog::error(
                "ReadFile cache hit but origin GetAttributes failed for {}: {}. Failing read.",
                relative_path.string(), origin_attr_res.error().message()
            );
            return std::unexpected(make_error_code(StorageErrc::OriginError));

        } else {
            // Origin lookup succeeded, check coherency
            auto valid_res = IsCacheValid(location, origin_attr_res.value());
            if (valid_res && valid_res.value()) {
                spdlog::trace(
                    "ReadFile cache valid for {}. Reading from cache.", relative_path.string()
                );
                use_cache = true;
            } else {
                spdlog::info(
                    "Cache stale/invalid for ReadFile: {}. Invalidating and fetching from origin.",
                    relative_path.string()
                );
                InvalidateCacheEntry(relative_path);
                use_cache = false;
            }
        }

        if (use_cache) {
            auto read_res = location.cache_tier->Read(relative_path, offset, buffer);
            if (read_res) {
                location.cache_tier->UpdateAccessMeta(relative_path);  // Update LRU
                if (*read_res == 0 && buffer.size() > 0) {             // Read 0 bytes (EOF)
                    spdlog::trace(
                        "ReadFile read 0 bytes (EOF) from cache for {}", relative_path.string()
                    );
                } else {
                    spdlog::trace(
                        "ReadFile read {} bytes from cache for {}", *read_res,
                        relative_path.string()
                    );
                }
                return read_res.value();
            } else if (read_res.error() == make_error_code(StorageErrc::FileNotFound)) {
                spdlog::warn(
                    "ReadFile cache inconsistency: Found meta but read failed ENOENT for {}. "
                    "Invalidating.",
                    relative_path.string()
                );
                InvalidateCacheEntry(relative_path);
                // Fall through to cache miss logic below
            } else {
                spdlog::error(
                    "ReadFile cache read error for {}: {}", relative_path.string(),
                    read_res.error().message()
                );
                return std::unexpected(read_res.error());
            }
        }
    }

    spdlog::trace("Cache miss/stale for ReadFile: {}", relative_path.string());
    return FetchAndCache(relative_path, offset, buffer);
}

StorageResult<size_t> CacheCoordinator::WriteFile(
    const std::filesystem::path& fuse_path, off_t offset, std::span<const std::byte> data
)
{
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "WriteFile called for: {} (relative: {}), offset: {}, size: {}", fuse_path.string(),
        relative_path.string(), offset, data.size()
    );

    // Write-Through Policy

    spdlog::trace("WriteFile: Writing to origin for {}", relative_path.string());
    auto origin_write_res = origin_manager_->GetOrigin()->Write(relative_path, offset, data);
    if (!origin_write_res) {
        spdlog::error(
            "WriteFile origin write failed for {}: {}", relative_path.string(),
            origin_write_res.error().message()
        );
        InvalidateCacheEntry(relative_path);
        return std::unexpected(origin_write_res.error());
    }
    spdlog::trace(
        "WriteFile: Origin write successful for {}, {} bytes", relative_path.string(),
        origin_write_res.value()
    );

    // Update/Invalidate Cache
    // Simple strategy: Invalidate the entry in all cache tiers.
    // TODO: More complex strategy: Update the cached data if present.
    spdlog::trace("WriteFile: Invalidating cache for {}", relative_path.string());
    InvalidateCacheEntry(relative_path);

    return origin_write_res.value();
}

StorageResult<void> CacheCoordinator::CreateFile(
    const std::filesystem::path& fuse_path, mode_t mode
)
{
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "CreateFile called for: {} (relative: {}), mode={:o}", fuse_path.string(),
        relative_path.string(), mode
    );

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "CreateDirectory called for: {} (relative: {}), mode={:o}", fuse_path.string(),
        relative_path.string(), mode
    );

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "Remove called for: {} (relative: {})", fuse_path.string(), relative_path.string()
    );

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto relative_path = SanitizeFusePath(fuse_path);
    if (relative_path.empty() && fuse_path != "/")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace(
        "TruncateFile called for: {} (relative: {}), size={}", fuse_path.string(),
        relative_path.string(), size
    );

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    auto from_relative = SanitizeFusePath(from_fuse_path);
    auto to_relative   = SanitizeFusePath(to_fuse_path);
    if (from_relative.empty() || to_relative.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    spdlog::trace("Move called for: {} -> {}", from_fuse_path.string(), to_fuse_path.string());

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
    std::lock_guard<std::recursive_mutex> lock(coordinator_mutex_);
    spdlog::trace("GetFilesystemStats called for: {}", fuse_path.string());
    // TODO: What should this report?
    spdlog::warn("GetFilesystemStats not fully implemented. Returning ENOSYS.");
    return std::unexpected(make_error_code(StorageErrc::NotSupported));
}

// Private Cache Logic Helper Implementations

StorageResult<CacheLocation> CacheCoordinator::FindInCache(
    const std::filesystem::path& relative_path
)
{
    // Iterate tiers from lowest number (highest priority) to highest
    for (auto const& [tier_level, tiers_vec] : cache_tier_map_) {
        for (const auto& tier_ptr : tiers_vec) {
            if (tier_ptr) {
                auto probe_res = tier_ptr->Probe(relative_path);
                if (probe_res && probe_res.value()) {
                    spdlog::trace(
                        "FindInCache: Found '{}' in tier {}", relative_path.string(), tier_level
                    );
                    return CacheLocation{tier_ptr.get(), relative_path, tier_level};
                } else if (!probe_res &&
                           probe_res.error() != make_error_code(StorageErrc::FileNotFound)) {
                    spdlog::warn(
                        "FindInCache: Error probing tier {} for '{}': {}", tier_level,
                        relative_path.string(), probe_res.error().message()
                    );
                }
            }
        }
    }

    spdlog::trace("FindInCache: Path '{}' not found in any cache tier.", relative_path.string());
    return std::unexpected(make_error_code(StorageErrc::CacheMiss));
}

StorageResult<size_t> CacheCoordinator::FetchAndCache(
    const std::filesystem::path& relative_path, off_t offset, std::span<std::byte> buffer
)
{
    spdlog::trace("FetchAndCache: Fetching origin data for {}", relative_path.string());

    // Fetch from Origin (TODO: Fetch strategy - whole file or just requested chunk?)
    // Fetch the requested chunk directly into the user's buffer
    auto origin_read_res = origin_manager_->GetOrigin()->Read(relative_path, offset, buffer);
    if (!origin_read_res) {
        spdlog::error(
            "FetchAndCache: Origin read failed for {}: {}", relative_path.string(),
            origin_read_res.error().message()
        );
        // TODO: OriginError wrapper?
        return std::unexpected(origin_read_res.error());
    }
    size_t bytes_read_from_origin = origin_read_res.value();
    spdlog::trace(
        "FetchAndCache: Read {} bytes from origin for {}", bytes_read_from_origin,
        relative_path.string()
    );

    // If 0 bytes read (EOF), don't cache.
    if (bytes_read_from_origin == 0) {
        return 0;
    }

    // Select Cache Tier
    // TODO: Improve selection
    // For now, pick the highest priority (lowest number) tier.
    auto target_tier_res = SelectCacheTierForWrite(relative_path, bytes_read_from_origin);
    if (!target_tier_res) {
        spdlog::warn(
            "FetchAndCache: No suitable cache tier found to store {}. Serving from origin only.",
            relative_path.string()
        );
        return bytes_read_from_origin;  // Return data read from origin, but don't cache
    }
    ICacheTier* target_tier = target_tier_res.value();
    spdlog::trace(
        "FetchAndCache: Selected tier {} for caching {}", target_tier->GetTier(),
        relative_path.string()
    );

    // Evict if Needed (Basic Check - TODO: Implement real eviction)
    auto evict_res = EvictIfNeeded(target_tier, bytes_read_from_origin);
    if (!evict_res) {
        spdlog::error(
            "FetchAndCache: Eviction failed for tier {}. Cannot cache {}.", target_tier->GetTier(),
            relative_path.string()
        );
        return bytes_read_from_origin;
    }

    spdlog::trace(
        "FetchAndCache: Writing {} bytes to cache tier {} for {}", bytes_read_from_origin,
        target_tier->GetTier(), relative_path.string()
    );
    // Create a const span from the buffer part that was filled
    std::span<const std::byte> data_to_cache(buffer.data(), bytes_read_from_origin);
    auto cache_write_res = target_tier->Write(relative_path, offset, data_to_cache);

    if (!cache_write_res) {
        spdlog::error(
            "FetchAndCache: Failed to write to cache tier {} for {}: {}", target_tier->GetTier(),
            relative_path.string(), cache_write_res.error().message()
        );
        // Cache write failed, but we already served from origin. Log error and continue.
    } else {
        spdlog::trace(
            "FetchAndCache: Successfully wrote {} bytes to cache tier {} for {}",
            cache_write_res.value(), target_tier->GetTier(), relative_path.string()
        );
        auto meta_update_res = target_tier->UpdateAccessMeta(relative_path);
        if (!meta_update_res) {
            spdlog::trace(
                "FetchAndCache: Failed to update access meta for {}: {}", relative_path.string(),
                meta_update_res.error().message()
            );
        }
    }

    // Return the number of bytes read from origin (which are now in user buffer)
    return bytes_read_from_origin;
}

StorageResult<ICacheTier*> CacheCoordinator::SelectCacheTierForWrite(
    const std::filesystem::path& relative_path, size_t required_space
)
{
    // Simple strategy: Iterate lowest tier first, pick first with enough space.
    for (auto const& [tier_level, tiers_vec] : cache_tier_map_) {
        for (const auto& tier_ptr : tiers_vec) {
            if (tier_ptr) {
                auto available_res = tier_ptr->GetAvailableBytes();
                if (available_res && available_res.value() >= required_space) {
                    spdlog::trace(
                        "SelectCacheTierForWrite: Found suitable tier {} for {} ({} bytes needed, "
                        "{} available)",
                        tier_level, relative_path.string(), required_space, available_res.value()
                    );
                    return tier_ptr.get();
                } else if (!available_res) {
                    spdlog::warn(
                        "SelectCacheTierForWrite: Could not get available space for tier {} (Path: "
                        "'{}'): {}",
                        tier_level, tier_ptr->GetPath().string(), available_res.error().message()
                    );
                } else {
                    spdlog::trace(
                        "SelectCacheTierForWrite: Tier {} (Path: '{}') insufficient space ({} "
                        "bytes needed, {} available)",
                        tier_level, tier_ptr->GetPath().string(), required_space,
                        available_res.value()
                    );
                }
            }
        }
    }
    spdlog::warn(
        "SelectCacheTierForWrite: No cache tier found with enough space ({} bytes) for {}",
        required_space, relative_path.string()
    );
    return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
}

StorageResult<void> CacheCoordinator::EvictIfNeeded(ICacheTier* target_tier, size_t required_space)
{
    // TODO: Implement actual eviction logic (e.g., LRU)
    auto available_res = target_tier->GetAvailableBytes();
    if (!available_res) {
        spdlog::error(
            "EvictIfNeeded: Failed to get available space for tier {}: {}", target_tier->GetTier(),
            available_res.error().message()
        );
        return std::unexpected(make_error_code(StorageErrc::EvictionError)
        );  // Cannot determine if eviction needed
    }

    if (available_res.value() < required_space) {
        spdlog::warn(
            "EvictIfNeeded: Tier {} needs eviction ({} required, {} available). Eviction logic NOT "
            "IMPLEMENTED.",
            target_tier->GetTier(), required_space, available_res.value()
        );
        // TODO: Implement eviction logic here
        return std::unexpected(make_error_code(StorageErrc::OutOfSpace));
    }

    return {};
}

void CacheCoordinator::InvalidateCacheEntry(const std::filesystem::path& relative_path)
{
    spdlog::trace("Invalidating cache entry for: {}", relative_path.string());
    bool removed_from_any = false;
    // Remove from all tiers where it might exist
    for (auto& [tier_level, tiers_vec] : cache_tier_map_) {
        for (auto& tier_ptr : tiers_vec) {
            if (tier_ptr) {
                auto remove_res = tier_ptr->Remove(relative_path);
                if (remove_res) {
                    spdlog::trace(
                        "InvalidateCacheEntry: Removed '{}' from tier {}", relative_path.string(),
                        tier_level
                    );
                    removed_from_any = true;
                } else if (remove_res.error() != make_error_code(StorageErrc::FileNotFound)) {
                    spdlog::warn(
                        "InvalidateCacheEntry: Error removing '{}' from tier {}: {}",
                        relative_path.string(), tier_level, remove_res.error().message()
                    );
                }
            }
        }
    }
    if (!removed_from_any) {
        spdlog::trace(
            "InvalidateCacheEntry: '{}' was not found in any cache tier during invalidation.",
            relative_path.string()
        );
    }
}

StorageResult<bool> CacheCoordinator::IsCacheValid(
    const CacheLocation& location, const struct stat& origin_stat
)
{
    spdlog::trace("IsCacheValid checking for: {}", location.relative_path.string());

    auto cached_attr_res = location.cache_tier->GetAttributes(location.relative_path);
    if (!cached_attr_res) {
        spdlog::warn(
            "IsCacheValid: Failed to get attributes for cached item '{}' in tier {}: {}",
            location.relative_path.string(), location.tier_level, cached_attr_res.error().message()
        );
        return std::unexpected(make_error_code(StorageErrc::CoherencyError));
    }
    const struct stat& cached_stat = cached_attr_res.value();

    // Basic coherency check: Modification time and Size
    if (cached_stat.st_mtime == origin_stat.st_mtime &&
        cached_stat.st_size == origin_stat.st_size) {
        spdlog::trace(
            "IsCacheValid: Cache mtime ({}) and size ({}) match origin for {}. Valid.",
            cached_stat.st_mtime, cached_stat.st_size, location.relative_path.string()
        );
        return true;
    } else {
        spdlog::info(
            "IsCacheValid: Cache STALE for {}. Origin mtime: {}, size: {}. Cache mtime: {}, size: "
            "{}",
            location.relative_path.string(), origin_stat.st_mtime, origin_stat.st_size,
            cached_stat.st_mtime, cached_stat.st_size
        );
        return false;
    }
    // TODO: Add more sophisticated checks if needed (checksums?)
}

}  // namespace DistributedCacheFS::Cache
