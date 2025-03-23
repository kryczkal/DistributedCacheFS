cmake_minimum_required(VERSION 3.30)
set(PROJECT_NAME "CachingFS")
set(PROJECT_DESCRIPTION "Caching File System")

project(${PROJECT_NAME} LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE
    SRC_FILES
    src/*.cpp
    src/*.hpp
    main.cpp
)

add_executable(
        ${PROJECT_NAME}
        ${SRC_FILES}
)

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE
        src
)

# Fuse3
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE REQUIRED fuse3)
target_include_directories(
    ${PROJECT_NAME}
    PRIVATE
        ${FUSE_INCLUDE_DIRS}
)
target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
        ${FUSE_LIBRARIES}
)
