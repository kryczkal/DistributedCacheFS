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

//------------------------------------------------------------------------------//
// Class Creation and Destruction
//------------------------------------------------------------------------------//
CacheManager::CacheManager(const Config::NodeConfig& config, std::shared_ptr<IStorage> origin)
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

//------------------------------------------------------------------------------//
// Public Methods
//------------------------------------------------------------------------------//

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
            
            cache_instance->SetMappingCallback(
                [this](const fs::path& p,
                       const std::shared_ptr<CacheTier>& tier,
                       bool add)
                {
                    std::unique_lock w(metadata_mutex_);
                    if (add) {
                        file_to_cache_[p] = tier;
                    } else {
                        auto it = file_to_cache_.find(p);
                        if (it != file_to_cache_.end() && it->second == tier) {
                            file_to_cache_.erase(it);
                        }
                    }
                });

            tier_to_cache_[cache_definition.tier].push_back(std::move(cache_instance));
        }
    }
    spdlog::trace("CacheManager::InitializeAll -> Success");
    return {};
}

StorageResult<void> CacheManager::ShutdownAll()
{
    std::unique_lock lock(metadata_mutex_);
    spdlog::debug("CacheManager::ShutdownAll()");
    spdlog::info("Shutting down CacheManager ...");
    std::error_code first_error;

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
        return std::unexpected(first_error);
    }

    spdlog::trace("CacheManager::ShutdownAll -> Success");
    return {};
}

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
            RemoveMetadataInvalidateCache(fuse_path, cache_tier);
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
    return origin_->ListDirectory(fuse_path);
}

StorageResult<size_t> CacheManager::ReadFile(
    std::filesystem::path& fuse_path, off_t offset, std::span<std::byte>& buffer
)
{
    spdlog::debug("CacheManager::ReadFile({}, {}, {})", fuse_path.string(), offset, buffer.size());
    if (fuse_path.empty() || fuse_path == ".")
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

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
        if (hit->first) {
            TryPromoteItem(fuse_path);
            return hit->second;
        }
    }

    return FetchAndTryCache(fuse_path, offset, buffer);
}

StorageResult<size_t> CacheManager::WriteFile(
    fs::path& fuse_path, off_t offset, std::span<std::byte>& data
)
{
    spdlog::debug("CacheManager::WriteFile({}, {}, {})", fuse_path.string(), offset, data.size());
    if (fuse_path.empty() || fuse_path == ".") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    auto res = origin_->Write(fuse_path, offset, data);
    if (!res) {
        return std::unexpected(res.error());
    }
    size_t bytes_written = res.value();

    auto cache_tier_it = file_to_cache_.find(fuse_path);
    if (cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto inv_res = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!inv_res) {
            spdlog::error("Failed to invalidate cache on write for {}: {}", fuse_path.string(), inv_res.error().message());
            return std::unexpected(inv_res.error());
        }
    }

    return bytes_written;
}

StorageResult<void> CacheManager::CreateFile(std::filesystem::path& fuse_path, mode_t mode)
{
    spdlog::debug("CacheManager::CreateFile({}, {:o})", fuse_path.string(), mode);
    if (fuse_path.empty() || fuse_path == ".") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    auto res = origin_->CreateFile(fuse_path, mode);
    if (!res) {
        return std::unexpected(res.error());
    }

    if (auto cache_tier_it = file_to_cache_.find(fuse_path); cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto inv_res = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!inv_res) return std::unexpected(inv_res.error());
    }
    return {};
}

StorageResult<void> CacheManager::CreateDirectory(std::filesystem::path& fuse_path, mode_t mode)
{
    spdlog::debug("CacheManager::CreateDirectory({}, {:o})", fuse_path.string(), mode);
    if (fuse_path.empty() || fuse_path == ".") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    auto res = origin_->CreateDirectory(fuse_path, mode);
    if (!res) {
        return std::unexpected(res.error());
    }
    
    if (auto cache_tier_it = file_to_cache_.find(fuse_path); cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto inv_res = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!inv_res) return std::unexpected(inv_res.error());
    }
    return {};
}

StorageResult<void> CacheManager::Remove(std::filesystem::path& fuse_path)
{
    spdlog::debug("CacheManager::Remove({})", fuse_path.string());
    if (fuse_path.empty() || fuse_path == ".") {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    auto res = origin_->Remove(fuse_path);
    if (!res) {
        return std::unexpected(res.error());
    }

    if (auto cache_tier_it = file_to_cache_.find(fuse_path); cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto inv_res = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!inv_res) return std::unexpected(inv_res.error());
    }
    return {};
}

StorageResult<void> CacheManager::TruncateFile(std::filesystem::path& fuse_path, off_t size)
{
    spdlog::debug("CacheManager::TruncateFile({}, {})", fuse_path.string(), size);
    if (fuse_path.empty() || fuse_path == "." || size < 0) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    
    auto res = origin_->Truncate(fuse_path, size);
    if (!res) {
        return std::unexpected(res.error());
    }

    if (auto cache_tier_it = file_to_cache_.find(fuse_path); cache_tier_it != file_to_cache_.end()) {
        auto& cache_tier = cache_tier_it->second;
        auto inv_res = RemoveMetadataInvalidateCache(fuse_path, cache_tier);
        if (!inv_res) return std::unexpected(inv_res.error());
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

    auto res = origin_->Move(from_fuse_path, to_fuse_path);
    if (!res) {
        return std::unexpected(res.error());
    }

    if (auto it = file_to_cache_.find(from_fuse_path); it != file_to_cache_.end()) {
        auto inv_res = RemoveMetadataInvalidateCache(from_fuse_path, it->second);
        if (!inv_res) return std::unexpected(inv_res.error());
    }

    if (auto it = file_to_cache_.find(to_fuse_path); it != file_to_cache_.end()) {
        auto inv_res = RemoveMetadataInvalidateCache(to_fuse_path, it->second);
        if (!inv_res) return std::unexpected(inv_res.error());
    }

    return {};
}

StorageResult<struct statvfs> CacheManager::GetFilesystemStats(fs::path& fuse_path)
{
    spdlog::debug("CacheManager::GetFilesystemStats({})", fuse_path.string());
    if (fuse_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    struct statvfs origin_statvfs = {};
    return origin_statvfs;
}

StorageResult<void> CacheManager::SetPermissions(const fs::path& fuse_path, mode_t mode)
{
    spdlog::debug("CacheManager::SetPermissions({}, {:o})", fuse_path.string(), mode);
    if (fuse_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }

    auto origin_res = origin_->SetPermissions(fuse_path, mode);
    if (!origin_res) {
        return std::unexpected(origin_res.error());
    }

    if (auto it = file_to_cache_.find(fuse_path); it != file_to_cache_.end()) {
        auto invalidation_res = RemoveMetadataInvalidateCache(fuse_path, it->second);
        if (!invalidation_res) {
            spdlog::warn("SetPermissions: Failed to invalidate cache entry for {}: {}", fuse_path.string(), invalidation_res.error().message());
        }
    }
    return {};
}

StorageResult<void> CacheManager::SetOwner(const fs::path& fuse_path, uid_t uid, gid_t gid)
{
    spdlog::debug("CacheManager::SetOwner({}, uid={}, gid={})", fuse_path.string(), uid, gid);
    if (fuse_path.empty()) {
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));
    }
    
    auto origin_res = origin_->SetOwner(fuse_path, uid, gid);
    if (!origin_res) {
        return std::unexpected(origin_res.error());
    }

    if (auto it = file_to_cache_.find(fuse_path); it != file_to_cache_.end()) {
        auto invalidation_res = RemoveMetadataInvalidateCache(fuse_path, it->second);
        if (!invalidation_res) {
            spdlog::warn("SetOwner: Failed to invalidate cache entry for {}: {}", fuse_path.string(), invalidation_res.error().message());
        }
    }
    return {};
}

//------------------------------------------------------------------------------//
// Private Methods
//------------------------------------------------------------------------------//

StorageResult<size_t> CacheManager::FetchAndTryCache(
    fs::path& fuse_path, off_t offset, std::span<std::byte>& buffer
)
{
    spdlog::debug("CacheManager::FetchAndTryCache({})", fuse_path.string());
    if (offset < 0 || fuse_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    auto origin_attr = origin_->GetAttributes(fuse_path);
    if (!origin_attr) return std::unexpected(origin_attr.error());

    auto now = std::chrono::system_clock::now();
    auto read_res = origin_->Read(fuse_path, offset, buffer);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - now);
    if (!read_res) return std::unexpected(read_res.error());
    
    const size_t bytes_for_caller = *read_res;
    const double fetch_cost_ms = static_cast<double>(elapsed.count()) > 0.0 ? static_cast<double>(elapsed.count()) : 1.0;
    
    ItemMetadata meta{
        fuse_path,
        {0.0, fetch_cost_ms, std::time(nullptr)},
        {origin_attr->st_mtime, origin_attr->st_size}
    };
    meta.heat_metadata.heat = CacheTier::CalculateInitialItemHeat(fuse_path, meta);
    
    auto tier_res = SelectCacheTierForWrite(meta);
    if (!tier_res) return std::unexpected(tier_res.error());
    auto tier = tier_res.value();
    if (!tier) return bytes_for_caller;

    auto free_up_space_res = tier->FreeUpSpace(origin_attr->st_size);
    if (!free_up_space_res) return std::unexpected(free_up_space_res.error());

    constexpr std::size_t kBlk = 1 << 20;
    std::vector<std::byte> blk(kBlk);
    std::span<std::byte> blk_span{blk};
    size_t total_read = 0;
    while (total_read < static_cast<size_t>(origin_attr->st_size)) {
        const size_t want = std::min(kBlk, static_cast<size_t>(origin_attr->st_size) - total_read);
        blk_span = {blk.data(), want};
        auto r = origin_->Read(fuse_path, static_cast<off_t>(total_read), blk_span);
        if (!r) return std::unexpected(r.error());
        if (*r == 0) break;
        std::span<std::byte> cblk{blk.data(), *r};
        auto w = tier->GetStorage()->Write(fuse_path, static_cast<off_t>(total_read), cblk);
        if (!w || *w != *r) return std::unexpected(make_error_code(StorageErrc::IOError));
        total_read += *r;
    }

    auto insert_meta_res = tier->InsertItemMetadata(meta);
    if (!insert_meta_res) return std::unexpected(insert_meta_res.error());

    std::unique_lock w_lock(metadata_mutex_);
    file_to_cache_[fuse_path] = tier;
    
    return bytes_for_caller;
}

StorageResult<std::shared_ptr<CacheTier>> CacheManager::SelectCacheTierForWrite(
    const ItemMetadata& item_metadata
)
{
    std::shared_lock tiers_rlock(tier_mutex_);
    if (tier_to_cache_.empty()) {
        return nullptr;
    }

    for (auto it = tier_to_cache_.rbegin(); it != tier_to_cache_.rend(); ++it) {
        for (const auto& tier : it->second) {
            auto worth = tier->IsItemWorthInserting(item_metadata);
            if (!worth) return std::unexpected(worth.error());
            if (*worth) return tier;
        }
    }
    return nullptr;
}

StorageResult<void> CacheManager::RemoveMetadataInvalidateCache(
    const fs::path& fuse_path, const std::shared_ptr<CacheTier>& cache_tier
)
{
    spdlog::debug("CacheManager::RemoveMetadataInvalidateCache({})", fuse_path.string());
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
    if (fuse_path.empty())
        return std::unexpected(make_error_code(StorageErrc::InvalidPath));

    std::shared_ptr<CacheTier> current_tier;
    {
        std::shared_lock meta_rlock(metadata_mutex_);
        auto it = file_to_cache_.find(fuse_path);
        if (it == file_to_cache_.end()) return {};
        current_tier = it->second;
    }
    if (current_tier->GetTier() == 0) return {};

    std::vector<std::shared_ptr<CacheTier>> faster_tiers;
    {
        std::shared_lock tiers_rlock(tier_mutex_);
        for (const auto& [lvl, vec] : tier_to_cache_) {
            if (lvl < current_tier->GetTier())
                faster_tiers.insert(faster_tiers.end(), vec.begin(), vec.end());
        }
    }
    if (faster_tiers.empty()) return {};

    auto meta_res = current_tier->GetItemMetadata(fuse_path);
    if (!meta_res) return std::unexpected(meta_res.error());
    const ItemMetadata meta = meta_res.value();

    std::vector<std::byte> buf(meta.coherency_metadata.size_bytes);
    std::span<std::byte> span{buf};
    auto read_res = current_tier->GetStorage()->Read(fuse_path, 0, span);
    if (!read_res || *read_res != span.size())
        return std::unexpected(read_res ? make_error_code(StorageErrc::IOError) : read_res.error());

    for (const auto& faster : faster_tiers) {
        faster->RefreshRandomHeats();

        auto worth = faster->IsItemWorthInserting(meta);
        if (!worth) return std::unexpected(worth.error());
        if (!*worth) continue;

        auto forcibly_res = faster->CacheItemForcibly(fuse_path, 0, span, meta);
        if (!forcibly_res) {
            spdlog::error("Promotion failed during forcible cache: {}", forcibly_res.error().message());
            return std::unexpected(forcibly_res.error());
        }

        spdlog::info("Promoted item {} from tier {} to tier {}", fuse_path.string(), current_tier->GetTier(), faster->GetTier());
        {
            std::unique_lock meta_wlock(metadata_mutex_);
            file_to_cache_[fuse_path] = faster;
        }
        auto invalidate_res = current_tier->InvalidateAndRemoveItem(fuse_path);
        if (!invalidate_res) {
            spdlog::warn("Failed to remove item from original tier after promotion: {}", invalidate_res.error().message());
        }
        return {}; 
    }

    return {};
}

StorageResult<CoherencyMetadata> CacheManager::GetOriginCoherencyMetadata(const fs::path& fuse_path
) const
{
    auto res = origin_->GetAttributes(fuse_path);
    if (!res) {
        return std::unexpected(res.error());
    }
    return CoherencyMetadata{res.value().st_mtime, res.value().st_size};
}

}  // namespace DistributedCacheFS::Cache
