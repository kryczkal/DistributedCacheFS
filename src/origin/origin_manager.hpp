#ifndef DISTRIBUTEDCACHEFS_SRC_ORIGIN_ORIGIN_MANAGER_HPP_
#define DISTRIBUTEDCACHEFS_SRC_ORIGIN_ORIGIN_MANAGER_HPP_

#include <memory>
#include "config/config_types.hpp"
#include "origin/i_origin_interface.hpp"

namespace DistributedCacheFS::Origin
{

class OriginManager
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    explicit OriginManager(const Config::OriginDefinition& definition);
    ~OriginManager() = default;

    OriginManager(const OriginManager&)            = delete;
    OriginManager& operator=(const OriginManager&) = delete;
    OriginManager(OriginManager&&)                 = delete;
    OriginManager& operator=(OriginManager&&)      = delete;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    // Provides access to the underlying origin interface
    IOriginInterface* GetOrigin() const;

    // Initialization and Shutdown
    Storage::StorageResult<void> Initialize();
    Storage::StorageResult<void> Shutdown();

    //------------------------------------------------------------------------------//
    // Public Fields
    //------------------------------------------------------------------------------//

    private:
    //------------------------------------------------------------------------------//
    // Private Methods
    //------------------------------------------------------------------------------//

    //------------------------------------------------------------------------------//
    // Private Fields
    //------------------------------------------------------------------------------//
    Config::OriginDefinition definition_;
    std::unique_ptr<IOriginInterface> origin_instance_;

    //------------------------------------------------------------------------------//
    // Helpers
    //------------------------------------------------------------------------------//
};

}  // namespace DistributedCacheFS::Origin

#endif  // DISTRIBUTEDCACHEFS_SRC_ORIGIN_ORIGIN_MANAGER_HPP_
