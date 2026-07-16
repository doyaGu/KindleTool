cmake_minimum_required(VERSION 3.21)
# Legacy C compatibility oracle. The mainline implementation is the root Cargo workspace.
project(KindleToolLegacy VERSION 1.6.6 LANGUAGES C)

option(KINDLETOOL_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

add_executable(kindletool
    KindleTool/kindle_tool.c
    KindleTool/create.c
    KindleTool/convert.c
    KindleTool/nettle_pem.c
)
if(MSVC)
    target_sources(kindletool PRIVATE KindleTool/msvc_compat.c)
endif()

target_compile_features(kindletool PRIVATE c_std_11)
target_include_directories(kindletool PRIVATE KindleTool)

# Direct searches deliberately avoid relying on an unstable Nettle CMake package
# name. They work with vcpkg's toolchain file and CMAKE_PREFIX_PATH alike.
find_path(LIBARCHIVE_INCLUDE_DIR archive.h REQUIRED)
find_library(LIBARCHIVE_LIBRARY NAMES archive libarchive REQUIRED)
find_path(NETTLE_INCLUDE_DIR nettle/rsa.h REQUIRED)
find_library(NETTLE_LIBRARY NAMES nettle REQUIRED)
find_library(HOGWEED_LIBRARY NAMES hogweed REQUIRED)
find_library(GMP_LIBRARY NAMES gmp libgmp REQUIRED)
find_package(ZLIB REQUIRED)

target_include_directories(kindletool PRIVATE ${LIBARCHIVE_INCLUDE_DIR} ${NETTLE_INCLUDE_DIR})
target_link_libraries(kindletool PRIVATE
    ${LIBARCHIVE_LIBRARY}
    ${NETTLE_LIBRARY}
    ${HOGWEED_LIBRARY}
    ${GMP_LIBRARY}
    ZLIB::ZLIB
)

if(MSVC)
    target_compile_definitions(kindletool PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(kindletool PRIVATE /W4 /permissive-)
    target_link_libraries(kindletool PRIVATE bcrypt)
    if(KINDLETOOL_WARNINGS_AS_ERRORS)
        target_compile_options(kindletool PRIVATE /WX)
    endif()
else()
    target_compile_options(kindletool PRIVATE -Wall -Wextra -Wpedantic)
    if(KINDLETOOL_WARNINGS_AS_ERRORS)
        target_compile_options(kindletool PRIVATE -Werror)
    endif()
endif()
