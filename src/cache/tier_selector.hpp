#ifndef DISTRIBUTEDCACHEFS_SRC_CACHE_TIER_SELECTOR_HPP_
#define DISTRIBUTEDCACHEFS_SRC_CACHE_TIER_SELECTOR_HPP_

#include "cache/block_metadata.hpp"
#include "storage/storage_error.hpp"

#include <memory>

namespace DistributedCacheFS::Cache
{

class ITierSelector
{
    public:
    virtual ~ITierSelector() = default;

    virtual Storage::StorageResult<std::shared_ptr<CacheTier>> SelectTierForWrite(
        double new_region_heat, size_t new_region_size, const TierToCacheMap& available_tiers
    ) = 0;
};

class DefaultTierSelector : public ITierSelector
{
    public:
    DefaultTierSelector()          = default;
    ~DefaultTierSelector() override = default;

    Storage::StorageResult<std::shared_ptr<CacheTier>> SelectTierForWrite(
        double new_region_heat, size_t new_region_size, const TierToCacheMap& available_tiers
    ) override;
};

}  // namespace DistributedCacheFS::Cache

#endif  // DISTRIBUTEDCACHEFS_SRC_CACHE_TIER_SELECTOR_HPP_
