#include "cache/cache_manager.hpp"
#include "cache/tier_selector.hpp"

#include <spdlog/spdlog.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <numeric>
#include <set>
#include <thread>
#include <utility>
#include <vector>

namespace DistributedCacheFS::Cache
{

using namespace Storage;
using namespace Config;

CacheManager::CacheManager(const Config::NodeConfig& config, std::shared_ptr<IStorage> origin)
    : config_(config),
      origin_(std::move(origin)),
      io_manager_(std::make_unique<AsyncIoManager>()),
      file_lock_manager_(std::make_unique<FileLockManager>()),
      tier_selector_(std::make_unique<DefaultTierSelector>())
{
    if (!origin_) {
        throw std::runtime_error("Origin storage instance is null");
    }
}

CacheManager::~CacheManager()
{
    if (auto res = ShutdownAll(); !res) {
    }
}

StorageResult<void> CacheManager::InitializeAll()
{
    if (auto res = origin_->Initialize(); !res) {
        return std::unexpected(res.error());
    }

    tier_to_cache_.clear();

    for (const auto& cache_definition : config_.cache_definitions) {
        auto cache_instance = std::make_shared<CacheTier>(cache_definition);
        if (auto res = cache_instance->Initialize(); !res) {
            return std::unexpected(res.error());
        }
        tier_to_cache_[cache_definition.tier].push_back(std::move(cache_instance));
    }
    return {};
}

StorageResult<void> CacheManager::ShutdownAll()
{
    io_manager_.reset();
    std::error_code first_error;

    for (auto& [tier, cache_tiers] : tier_to_cache_) {
        for (const auto& cache_tier : cache_tiers) {
            if (auto res = cache_tier->Shutdown(); !res) {
                if (!first_error) {
                    first_error = res.error();
                }
            }
        }
    }

    if (auto res = origin_->Shutdown(); !res) {
        if (!first_error)
            first_error = res.error();
    }

    if (first_error)
        return std::unexpected(first_error);
    return {};
}

StorageResult<struct stat> CacheManager::GetAttributes(std::filesystem::path& fuse_path)
{
    auto file_mutex = file_lock_manager_->GetFileLock(fuse_path);
    std::lock_guard file_lock(*file_mutex);
    return origin_->GetAttributes(fuse_path);
}

StorageResult<std::vector<std::pair<std::string, struct stat>>> CacheManager::ListDirectory(
    const std::filesystem::path& fuse_path
)
{
    return origin_->ListDirectory(fuse_path);
}

StorageResult<size_t> CacheManager::ReadFile(
    std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& buffer
)
{
    auto file_mutex = file_lock_manager_->GetFileLock(fuse_path);
    std::lock_guard file_lock(*file_mutex);

    auto origin_meta_res = GetOriginCoherencyMetadata(fuse_path);
    if (!origin_meta_res)
        return std::unexpected(origin_meta_res.error());
    CoherencyMetadata origin_meta = origin_meta_res.value();
    auto attr_res = origin_->GetAttributes(fuse_path);
    if (!attr_res)
        return std::unexpected(attr_res.error());
    FileId file_id{attr_res->st_dev, attr_res->st_ino};

    if (offset >= origin_meta.size_bytes)
        return 0;
    size_t size_to_read = std::min(buffer.size(), (size_t)(origin_meta.size_bytes - offset));
    if (size_to_read == 0)
        return 0;

    RegionList missing_regions = {{offset, size_to_read}};
    size_t bytes_from_cache    = 0;

    std::vector<std::shared_ptr<CacheTier>> tiers_with_data;
    for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
        for (const auto& tier : it->second) {
            if (tier->GetItemMetadata(file_id)) {
                tiers_with_data.push_back(tier);
            }
        }
    }

    for (const auto& tier : tiers_with_data) {
        if (missing_regions.empty())
            break;
        RegionList current_tier_missing;
        for (const auto& missing_region : missing_regions) {
            auto regions_res = tier->GetCachedRegions(
                file_id, fuse_path, missing_region.first, missing_region.second, origin_meta
            );
            if (regions_res) {
                auto& [cached, missing] = *regions_res;
                if (!cached.empty()) {
                    tier->GetStats().IncrementHits();
                }
                for (const auto& r : cached) {
                    off_t buffer_start_at        = r.first - offset;
                    std::span<std::byte> sub_buffer{buffer.data() + buffer_start_at, r.second};
                    auto read_res = tier->GetStorage()->Read(fuse_path, r.first, sub_buffer);
                    if (read_res)
                        bytes_from_cache += *read_res;
                    TryPromoteBlock(file_id, fuse_path, r.first, r.second, tier);
                }
                current_tier_missing.insert(current_tier_missing.end(), missing.begin(), missing.end());
            } else {
                current_tier_missing.push_back(missing_region);
            }
        }
        missing_regions = std::move(current_tier_missing);
    }

    size_t bytes_from_origin = 0;
    if (!missing_regions.empty()) {
        if (!tier_to_cache_.empty() && !tier_to_cache_.rbegin()->second.empty()) {
            tier_to_cache_.rbegin()->second.front()->GetStats().IncrementMisses();
        }

        std::vector<std::future<StorageResult<size_t>>> futures;
        for (const auto& region : missing_regions) {
            off_t buffer_start_at        = region.first - offset;
            std::span<std::byte> sub_buffer{buffer.data() + buffer_start_at, region.second};
            futures.push_back(io_manager_->SubmitRead(origin_, fuse_path, region.first, sub_buffer));
        }
        for (size_t i = 0; i < futures.size(); ++i) {
            auto start_time = std::chrono::steady_clock::now();
            auto res        = futures[i].get();
            auto end_time   = std::chrono::steady_clock::now();

            if (res) {
                bytes_from_origin += *res;
                size_t bytes_actually_read = *res;

                if (bytes_actually_read > 0) {
                    off_t region_offset = missing_regions[i].first;
                    double fetch_cost_ms =
                        std::max(1.0, static_cast<double>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        end_time - start_time
                                    )
                                        .count()));

                    off_t buffer_start_at = region_offset - offset;
                    std::vector<std::byte> data_to_cache(bytes_actually_read);
                    std::copy_n(buffer.data() + buffer_start_at, bytes_actually_read, data_to_cache.begin());

                    io_manager_->SubmitTask([this,
                                             file_id,
                                             fuse_path,
                                             region_offset,
                                             data_to_cache = std::move(data_to_cache),
                                             fetch_cost_ms]() mutable {
                        this->CacheRegionAsync(
                            file_id, fuse_path, region_offset, std::move(data_to_cache),
                            fetch_cost_ms
                        );
                    });
                }
            } else {
                return std::unexpected(res.error());
            }
        }
    }

    return bytes_from_cache + bytes_from_origin;
}

StorageResult<size_t> CacheManager::WriteFile(
    fs::path& fuse_path, off_t offset, std::span<std::byte>& data
)
{
    auto file_mutex = file_lock_manager_->GetFileLock(fuse_path);
    std::lock_guard file_lock(*file_mutex);

    auto attr_res_before = origin_->GetAttributes(fuse_path);
    auto res             = origin_->Write(fuse_path, offset, data);
    if (!res)
        return std::unexpected(res.error());

    if (attr_res_before) {
        FileId file_id{attr_res_before->st_dev, attr_res_before->st_ino};
        for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
            for (const auto& tier : it->second) {
                if (tier->GetItemMetadata(file_id)) {
                    tier->InvalidateRegion(file_id, fuse_path, offset, data.size());
                }
            }
        }
    }

    return res.value();
}

void CacheManager::InvalidateAndPurgeByPath(const fs::path& fuse_path)
{
    auto attr_res = origin_->GetAttributes(fuse_path);
    if (!attr_res) {
        return; // File doesn't exist, nothing to do.
    }
    FileId file_id{attr_res->st_dev, attr_res->st_ino};

    for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
        for (const auto& tier : it->second) {
            tier->InvalidateAndPurgeItem(file_id);
        }
    }
}

StorageResult<void> CacheManager::Remove(std::filesystem::path& fuse_path)
{
    auto file_mutex = file_lock_manager_->GetFileLock(fuse_path);
    std::lock_guard file_lock(*file_mutex);

    auto attr_res_before = origin_->GetAttributes(fuse_path);
    if (!attr_res_before) {
        return {}; // Already gone
    }
    FileId file_id{attr_res_before->st_dev, attr_res_before->st_ino};

    auto res = origin_->Remove(fuse_path);
    if (!res) {
        return res;
    }

    auto attr_res_after = origin_->GetAttributes(fuse_path);
    bool is_last_link   = !attr_res_after.has_value() ||
                        (attr_res_after->st_ino != file_id.st_ino);

    for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
        for (const auto& tier : it->second) {
            if (is_last_link) {
                tier->InvalidateAndPurgeItem(file_id);
            } else {
                tier->RemoveLink(file_id, fuse_path);
            }
        }
    }

    return {};
}

StorageResult<void> CacheManager::TruncateFile(std::filesystem::path& fuse_path, off_t size)
{
    auto file_mutex = file_lock_manager_->GetFileLock(fuse_path);
    std::lock_guard file_lock(*file_mutex);

    auto attr_res = origin_->GetAttributes(fuse_path);
    if (!attr_res) {
        return origin_->Truncate(fuse_path, size);
    }
    FileId file_id{attr_res->st_dev, attr_res->st_ino};
    off_t old_size = attr_res->st_size;

    auto res = origin_->Truncate(fuse_path, size);
    if (!res) {
        return res;
    }

    if (size < old_size) {
        off_t invalid_offset = size;
        size_t invalid_size  = old_size - size;
        for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
            for (const auto& tier : it->second) {
                if (tier->GetItemMetadata(file_id)) {
                    tier->InvalidateRegion(file_id, fuse_path, invalid_offset, invalid_size);
                }
            }
        }
    }

    return {};
}

StorageResult<void> CacheManager::Move(
    std::filesystem::path& from_fuse_path, std::filesystem::path& to_fuse_path
)
{
    auto mutex1 = file_lock_manager_->GetFileLock(std::min(from_fuse_path, to_fuse_path));
    auto mutex2 = file_lock_manager_->GetFileLock(std::max(from_fuse_path, to_fuse_path));
    std::scoped_lock file_locks(*mutex1, *mutex2);

    auto attr_res = origin_->GetAttributes(from_fuse_path);
    if (!attr_res) {
        // Renaming something that doesn't exist, let origin handle it.
        return origin_->Move(from_fuse_path, to_fuse_path);
    }
    FileId file_id{attr_res->st_dev, attr_res->st_ino};

    InvalidateAndPurgeByPath(to_fuse_path); // Invalidate destination if it exists

    auto res = origin_->Move(from_fuse_path, to_fuse_path);
    if (res) {
        for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
            for (const auto& tier : it->second) {
                if (tier->GetItemMetadata(file_id)) {
                    tier->RenameLink(file_id, from_fuse_path, to_fuse_path);
                }
            }
        }
    }
    return res;
}

StorageResult<void> CacheManager::CreateHardLink(const fs::path& from_path, const fs::path& to_path)
{
    auto mutex1 = file_lock_manager_->GetFileLock(std::min(from_path, to_path));
    auto mutex2 = file_lock_manager_->GetFileLock(std::max(from_path, to_path));
    std::scoped_lock file_locks(*mutex1, *mutex2);

    auto attr_res = origin_->GetAttributes(from_path);
    if (!attr_res) {
        return std::unexpected(attr_res.error());
    }
    FileId file_id{attr_res->st_dev, attr_res->st_ino};

    InvalidateAndPurgeByPath(to_path); // Invalidate destination if it exists

    auto link_res = origin_->CreateHardLink(from_path, to_path);
    if (link_res) {
        for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
            for (const auto& tier : it->second) {
                if (tier->GetItemMetadata(file_id)) {
                    tier->AddLink(file_id, to_path);
                }
            }
        }
    }
    return link_res;
}

StorageResult<void> CacheManager::Fsync(const fs::path& fuse_path, bool is_data_sync)
{
    auto file_mutex = file_lock_manager_->GetFileLock(fuse_path);
    std::lock_guard file_lock(*file_mutex);

    auto attr_res = origin_->GetAttributes(fuse_path);
    if (!attr_res) {
        return std::unexpected(attr_res.error());
    }
    FileId file_id{attr_res->st_dev, attr_res->st_ino};

    for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
        for (const auto& tier : it->second) {
            if (tier->GetItemMetadata(file_id)) {
                auto res = tier->GetStorage()->Fsync(fuse_path, is_data_sync);
                if (!res) return res;
            }
        }
    }

    return origin_->Fsync(fuse_path, is_data_sync);
}

StorageResult<void> CacheManager::CreateFile(std::filesystem::path& fuse_path, mode_t mode)
{
    auto file_mutex = file_lock_manager_->GetFileLock(fuse_path);
    std::lock_guard file_lock(*file_mutex);
    InvalidateAndPurgeByPath(fuse_path);
    return origin_->CreateFile(fuse_path, mode);
}

StorageResult<void> CacheManager::CreateSpecialFile(
    std::filesystem::path& fuse_path, mode_t mode, dev_t rdev
)
{
    return origin_->CreateSpecialFile(fuse_path, mode, rdev);
}

StorageResult<void> CacheManager::CreateDirectory(std::filesystem::path& fuse_path, mode_t mode)
{
    return origin_->CreateDirectory(fuse_path, mode);
}

StorageResult<void> CacheManager::SetPermissions(const fs::path& fuse_path, mode_t mode)
{
    return origin_->SetPermissions(fuse_path, mode);
}

StorageResult<void> CacheManager::SetOwner(const fs::path& fuse_path, uid_t uid, gid_t gid)
{
    return origin_->SetOwner(fuse_path, uid, gid);
}

StorageResult<void> CacheManager::SetXattr(
    const fs::path& fuse_path, const std::string& name, const char* value, size_t size, int flags
)
{
    return origin_->SetXattr(fuse_path, name, value, size, flags);
}

StorageResult<ssize_t> CacheManager::GetXattr(
    const fs::path& fuse_path, const std::string& name, char* value, size_t size
)
{
    return origin_->GetXattr(fuse_path, name, value, size);
}

StorageResult<ssize_t> CacheManager::ListXattr(const fs::path& fuse_path, char* list, size_t size)
{
    return origin_->ListXattr(fuse_path, list, size);
}

StorageResult<void> CacheManager::RemoveXattr(const fs::path& fuse_path, const std::string& name)
{
    return origin_->RemoveXattr(fuse_path, name);
}

StorageResult<struct statvfs> CacheManager::GetFilesystemStats(fs::path& fuse_path)
{
    return origin_->GetFilesystemStats(fuse_path.string());
}

std::shared_ptr<std::mutex> CacheManager::GetFileLock(const fs::path& path)
{
    return file_lock_manager_->GetFileLock(path);
}

void CacheManager::CacheRegionAsync(
    const FileId& file_id, const fs::path& fuse_path, off_t offset, std::vector<std::byte> region_data,
    double fetch_cost_ms
)
{
    if (region_data.empty())
        return;

    size_t size = region_data.size();
    std::span<std::byte> region_span{region_data};

    auto origin_meta_res = GetOriginCoherencyMetadata(fuse_path);
    if (!origin_meta_res) {
        spdlog::warn("CacheRegionAsync for {} failed: could not get origin metadata.", fuse_path.string());
        return;
    }

    std::shared_ptr<CacheTier> best_tier = nullptr;
    if (!tier_to_cache_.empty()) {
        auto top_tier_level = tier_to_cache_.rbegin()->first;
        if (!tier_to_cache_.at(top_tier_level).empty()) {
            best_tier = tier_to_cache_.at(top_tier_level).front();
        }
    }
    if (!best_tier) {
        spdlog::debug("CacheRegionAsync for {}: no cache tiers available to cache to.", fuse_path.string());
        return;
    }

    double initial_heat = best_tier->CalculateInitialRegionHeat(fetch_cost_ms, size);
    auto tier_res       = tier_selector_->SelectTierForWrite(initial_heat, size, tier_to_cache_);

    if (!tier_res || !tier_res.value()) {
        if (!tier_res) {
            spdlog::warn(
                "CacheRegionAsync for {}: tier selection failed with error: {}", fuse_path.string(),
                tier_res.error().message()
            );
        } else {
            spdlog::debug(
                "CacheRegionAsync for {}: no suitable cache tier found or region not worth inserting.",
                fuse_path.string()
            );
        }
        return;
    }
    auto tier = tier_res.value();

    auto cache_res =
        tier->CacheRegion(file_id, fuse_path, offset, region_span, *origin_meta_res, fetch_cost_ms);
    if (!cache_res) {
        spdlog::warn(
            "CacheRegionAsync for {} failed: tier->CacheRegion returned an error: {}", fuse_path.string(),
            cache_res.error().message()
        );
    }
}


void CacheManager::TryPromoteBlock(
    const FileId& file_id, const fs::path& fuse_path, off_t offset, size_t size,
    std::shared_ptr<CacheTier> source_tier
)
{
    auto source_tier_level = source_tier->GetTier();

    std::shared_ptr<CacheTier> destination_tier = nullptr;
    for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
        if (it->first > source_tier_level) {
            if (!it->second.empty()) {
                destination_tier = it->second.front();
                break;
            }
        }
    }

    if (!destination_tier) {
        return;
    }

    destination_tier->GetStats().IncrementPromotions();

    io_manager_->SubmitTask([this, file_id, fuse_path, offset, size, source_tier, destination_tier]() mutable {
        std::vector<std::byte> data_buffer(size);
        std::span<std::byte> buffer_span{data_buffer};

        auto read_res = source_tier->GetStorage()->Read(fuse_path, offset, buffer_span);
        if (!read_res) {
            spdlog::warn(
                "Promotion of block for {} failed during read from source tier {}: {}",
                fuse_path.string(), source_tier->GetTier(), read_res.error().message()
            );
            return;
        }

        auto origin_meta_res = GetOriginCoherencyMetadata(fuse_path);
        if (!origin_meta_res) {
            spdlog::warn(
                "Promotion of block for {} failed getting origin metadata: {}", fuse_path.string(),
                origin_meta_res.error().message()
            );
            return;
        }

        const double base_fetch_cost_ms = 1.0;
        auto cache_res = destination_tier->CacheRegion(
            file_id, fuse_path, offset, buffer_span, *origin_meta_res, base_fetch_cost_ms
        );

        if (cache_res) {
            source_tier->InvalidateRegion(file_id, fuse_path, offset, size);
        } else {
            spdlog::warn(
                "Promotion of block for {} failed during write to destination tier {}: {}",
                fuse_path.string(), destination_tier->GetTier(), cache_res.error().message()
            );
        }
    });
}

StorageResult<CoherencyMetadata> CacheManager::GetOriginCoherencyMetadata(
    const fs::path& fuse_path
) const
{
    auto res = origin_->GetAttributes(fuse_path);
    if (!res) {
        return std::unexpected(res.error());
    }
    return CoherencyMetadata{res.value().st_mtime, res.value().st_size};
}

StorageResult<void> CacheManager::CheckPermissions(
    const fs::path& fuse_path, int access_mask, uid_t caller_uid, gid_t caller_gid
)
{
    auto attr_res = this->GetAttributes(const_cast<fs::path&>(fuse_path));
    if (!attr_res) {
        return std::unexpected(attr_res.error());
    }
    const struct stat& file_attrs = attr_res.value();

    const uid_t file_uid   = file_attrs.st_uid;
    const gid_t file_gid   = file_attrs.st_gid;
    const mode_t file_mode = file_attrs.st_mode;

    if (caller_uid == 0) {
        if ((access_mask & X_OK) && !S_ISDIR(file_mode) &&
            !(file_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
            return std::unexpected(make_error_code(StorageErrc::PermissionDenied));
        }
        return {};
    }

    mode_t avail = 0;

    if (caller_uid == file_uid) {
        avail = file_mode & S_IRWXU;
    } else {
        bool in_group = (caller_gid == file_gid);
        if (!in_group) {
            int ngroups = getgroups(0, nullptr);
            if (ngroups < 0) {
                return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
            }
            if (ngroups > 0) {
                std::vector<gid_t> groups(ngroups);
                if (getgroups(ngroups, groups.data()) != ngroups) {
                    return std::unexpected(make_error_code(ErrnoToStorageErrc(errno)));
                }
                in_group = std::find(groups.begin(), groups.end(), file_gid) != groups.end();
            }
        }
        if (in_group) {
            avail = file_mode & S_IRWXG;
        } else {
            avail = file_mode & S_IRWXO;
        }
    }

    mode_t need = 0;
    if (access_mask & R_OK)
        need |= S_IRUSR;
    if (access_mask & W_OK)
        need |= S_IWUSR;
    if (access_mask & X_OK)
        need |= S_IXUSR;

    if (avail == (file_mode & S_IRWXG)) {
        need >>= 3;
    } else if (avail == (file_mode & S_IRWXO)) {
        need >>= 6;
    }

    if ((avail & need) == need) {
        return {};
    }

    return std::unexpected(make_error_code(StorageErrc::PermissionDenied));
}

}  // namespace DistributedCacheFS::Cache
