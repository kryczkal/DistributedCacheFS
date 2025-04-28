message(STATUS "Adding Boost")

include(FetchContent)

set(BOOST_INCLUDE_LIBRARIES
        core
        thread
        filesystem
        system
        program_options
        multi_index
        container
        heap
)
set(BOOST_ENABLE_CMAKE ON CACHE BOOL "" FORCE)

Set(FETCHCONTENT_QUIET FALSE)
FetchContent_Declare(
        Boost
        URL https://github.com/boostorg/boost/releases/download/boost-1.88.0/boost-1.88.0-cmake.7z
        USES_TERMINAL_DOWNLOAD TRUE
        GIT_PROGRESS TRUE
        DOWNLOAD_NO_EXTRACT FALSE
)
FetchContent_MakeAvailable(Boost)

# ---------------------------------------------------------------------- #
#  Interface library
# ---------------------------------------------------------------------- #
add_library(libBoost INTERFACE)
target_link_libraries(
        libBoost
        INTERFACE
        Boost::container
        Boost::core
        Boost::filesystem
        Boost::thread
        Boost::system
        Boost::multi_index
        Boost::heap
)