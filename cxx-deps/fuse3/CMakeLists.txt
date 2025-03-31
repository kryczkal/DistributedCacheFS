message(STATUS "Adding fuse3")

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE REQUIRED fuse3)

# ------------------------------------------------------------------------------ #
#  Interface library
# ------------------------------------------------------------------------------ #

add_library(libfuse3 INTERFACE)
target_include_directories(
    libfuse3
    INTERFACE
        ${FUSE_INCLUDE_DIRS}
)

target_link_libraries(
    libfuse3
    INTERFACE
        ${FUSE_LIBRARIES}
)