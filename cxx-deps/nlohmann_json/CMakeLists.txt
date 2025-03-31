message(STATUS "Adding nlohmann_json")

include(FetchContent)

set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)

# ------------------------------------------------------------------------------ #
# Interface Library
# ------------------------------------------------------------------------------ #
add_library(libJson INTERFACE)
target_link_libraries(libJson INTERFACE nlohmann_json::nlohmann_json)