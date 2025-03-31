message(STATUS "Adding nlohmann_json")

include(FetchContent)

FetchContent_Declare(
        libnlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(libnlohmann_json)