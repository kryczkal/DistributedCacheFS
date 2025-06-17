#ifndef DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_FACTORY_HPP_
#define DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_FACTORY_HPP_

#include "config/config_types.hpp"
#include "storage/i_storage.hpp"
#include "storage/local_storage.hpp"

namespace DistributedCacheFS::Storage
{

class StorageFactory
{
    private:
    //------------------------------------------------------------------------------//
    // Internal Types
    //------------------------------------------------------------------------------//

    public:
    //------------------------------------------------------------------------------//
    // Class Creation and Destruction
    //------------------------------------------------------------------------------//
    StorageFactory()                                 = delete;
    StorageFactory(const StorageFactory&)            = delete;
    StorageFactory& operator=(const StorageFactory&) = delete;
    StorageFactory(StorageFactory&&)                 = delete;
    StorageFactory& operator=(StorageFactory&&)      = delete;
    ~StorageFactory()                                = delete;

    //------------------------------------------------------------------------------//
    // Public Methods
    //------------------------------------------------------------------------------//

    static StorageResult<std::unique_ptr<IStorage>> Create(
        const Config::StorageDefinition& definition
    )
    {
        switch (definition.type) {
            case Config::StorageType::Local:
                return std::make_unique<LocalStorage>(definition);
            case Config::StorageType::Shared:
                return std::unexpected(
                    make_error_code(StorageErrc::NotSupported)
                );  // Not implemented yet
            default:
                return std::unexpected(make_error_code(StorageErrc::NotSupported));
        }
    }
};

}  // namespace DistributedCacheFS::Storage

#endif  // DISTRIBUTEDCACHEFS_SRC_STORAGE_STORAGE_FACTORY_HPP_
