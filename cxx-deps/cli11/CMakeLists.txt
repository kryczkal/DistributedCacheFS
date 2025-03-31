message(STATUS "Adding cli11")

include(FetchContent)

FetchContent_Declare(
        cli11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG        v2.5.0
)

set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(cli11)

# ------------------------------------------------------------------------------ #
# Interface Library
# ------------------------------------------------------------------------------ #
add_library(libCli11 INTERFACE)
target_link_libraries(libCli11 INTERFACE CLI11::CLI11)

message(STATUS "CLI11 interface library 'libCli11' created.")