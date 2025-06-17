#include "cache/tier_selector.hpp"

#include "cache/cache_tier.hpp"

#include <expected>

namespace DistributedCacheFS::Cache
{

Storage::StorageResult<std::shared_ptr<CacheTier>> DefaultTierSelector::SelectTierForWrite(
    double new_region_heat, size_t new_region_size, const TierToCacheMap& available_tiers
)
{
    if (available_tiers.empty()) {
        return nullptr;
    }

    for (auto it = available_tiers.rbegin(); it != available_tiers.rend(); ++it) {
        for (const auto& tier : it->second) {
            auto worth_res = tier->IsRegionWorthInserting(new_region_heat, new_region_size);
            if (!worth_res) {
                return std::unexpected(worth_res.error());
            }

            if (*worth_res) {
                return tier;
            }
        }
    }

    return nullptr;
}

}  // namespace DistributedCacheFS::Cache
