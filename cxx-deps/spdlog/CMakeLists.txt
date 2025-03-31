message(STATUS "Adding spdlog")

include(FetchContent)

FetchContent_Declare(
    spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog
        GIT_TAG v1.15.2
)
FetchContent_MakeAvailable(spdlog)

# ------------------------------------------------------------------------------ #
#  Interface Library
# ------------------------------------------------------------------------------ #

add_library(
    libspdlog
    INTERFACE
)

target_include_directories(
    libspdlog
    INTERFACE
        ${spdlog_SOURCE_DIR}/include
)
