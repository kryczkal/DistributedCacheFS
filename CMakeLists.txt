cmake_minimum_required(VERSION 3.30)
set(PROJECT_NAME "CachingFS")
set(PROJECT_DESCRIPTION "Caching File System")
set(PROJECT_VERSION "0.1.0")

project(${PROJECT_NAME} VERSION ${PROJECT_VERSION} DESCRIPTION ${PROJECT_DESCRIPTION} LANGUAGES CXX)

# ------------------------------------------------------------------------------ #
#  Compiler & Standard
# ------------------------------------------------------------------------------ #

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------------------------------------ #
#  Dependencies
# ------------------------------------------------------------------------------ #

add_subdirectory(cxx-deps)

# ------------------------------------------------------------------------------ #
#  Source Files
# ------------------------------------------------------------------------------ #

file(GLOB_RECURSE
    SRC_FILES
    src/*.cpp
    src/*.hpp
    main.cpp
)

# ------------------------------------------------------------------------------ #
#  Executable
# ------------------------------------------------------------------------------ #

add_executable(
        ${PROJECT_NAME}
        ${SRC_FILES}
)

# ------------------------------------------------------------------------------ #
#  Include Directories & Link Libraries
# ------------------------------------------------------------------------------ #

target_include_directories(
        ${PROJECT_NAME}
        PRIVATE
        src
)

target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        libnlohmann_json
)

target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        libfuse3
)

target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        libspdlog
)