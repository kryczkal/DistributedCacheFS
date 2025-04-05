#include "origin_manager.hpp"
#include "origin/local_origin.hpp"
#include "origin/origin_manager.hpp"

#include <spdlog/spdlog.h>
#include <stdexcept>

namespace DistributedCacheFS::Origin
{

OriginManager::OriginManager(const Config::OriginDefinition& definition) : definition_(definition)
{
    // Instantiate the correct origin type based on config
    switch (definition_.type) {
        case Config::OriginType::Local:
            origin_instance_ = std::make_unique<LocalOrigin>(definition_);
            spdlog::info(
                "OriginManager created with LocalOrigin for path: {}", definition_.path.string()
            );
            break;
        default:
            throw std::runtime_error("Unsupported OriginType configured.");
    }
}

IOriginInterface* OriginManager::GetOrigin() const { return origin_instance_.get(); }

Storage::StorageResult<void> OriginManager::Initialize()
{
    if (!origin_instance_) {
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::UnknownError));
    }
    return origin_instance_->Initialize();
}

Storage::StorageResult<void> OriginManager::Shutdown()
{
    if (!origin_instance_) {
        return std::unexpected(Storage::make_error_code(Storage::StorageErrc::UnknownError));
    }
    return origin_instance_->Shutdown();
}

}  // namespace DistributedCacheFS::Origin
