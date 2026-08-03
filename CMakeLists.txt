cmake_minimum_required(VERSION 3.20)
project(depotkit VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DEPOTKIT_BUILD_SHARED "Build shared library" OFF)
option(DEPOTKIT_BUILD_TESTS "Build unit tests" ON)

include(FetchContent)

# zlib
find_package(ZLIB QUIET)
if(NOT ZLIB_FOUND)
  FetchContent_Declare(zlib
    URL https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(zlib)
  if(TARGET zlibstatic)
    set(DEPOTKIT_ZLIB_TARGET zlibstatic)
  elseif(TARGET ZLIB::ZLIB)
    set(DEPOTKIT_ZLIB_TARGET ZLIB::ZLIB)
  else()
    message(FATAL_ERROR "zlib target not found")
  endif()
else()
  set(DEPOTKIT_ZLIB_TARGET ZLIB::ZLIB)
endif()

# zstd
find_package(zstd QUIET)
if(NOT zstd_FOUND AND NOT TARGET zstd::libzstd)
  FetchContent_Declare(zstd
    URL https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz
    SOURCE_SUBDIR build/cmake
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(zstd)
endif()
if(TARGET zstd::libzstd_static)
  set(DEPOTKIT_ZSTD_TARGET zstd::libzstd_static)
elseif(TARGET libzstd_static)
  set(DEPOTKIT_ZSTD_TARGET libzstd_static)
elseif(TARGET zstd::libzstd)
  set(DEPOTKIT_ZSTD_TARGET zstd::libzstd)
else()
  message(FATAL_ERROR "zstd target not found")
endif()

set(DEPOTKIT_SOURCES
  src/api.cpp
  src/util/util.cpp
  src/crypto/depot_crypto.cpp
  src/manifest/manifest.cpp
  src/http/http.cpp
  src/steam/session.cpp
  src/engine/engine.cpp
  third_party/lzma/LzmaDec.c
)

if(DEPOTKIT_BUILD_SHARED)
  add_library(depotkit SHARED ${DEPOTKIT_SOURCES})
  target_compile_definitions(depotkit PRIVATE DEPOTKIT_BUILD DEPOTKIT_SHARED)
else()
  add_library(depotkit STATIC ${DEPOTKIT_SOURCES})
endif()
# Static depotkit is linked into steamidra's shared plugin (.so) - needs PIC on Linux.
set_property(TARGET depotkit PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(depotkit
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(depotkit PRIVATE DEPOTKIT_HAVE_ZLIB DEPOTKIT_HAVE_ZSTD DEPOTKIT_HAVE_LZMA)
target_include_directories(depotkit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lzma)
target_link_libraries(depotkit PRIVATE ${DEPOTKIT_ZLIB_TARGET} ${DEPOTKIT_ZSTD_TARGET})

# System HTTP/crypto must be PUBLIC so static consumers pick them up.
if(WIN32)
  target_link_libraries(depotkit PUBLIC winhttp bcrypt crypt32 ws2_32)
else()
  find_package(CURL REQUIRED)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(depotkit PUBLIC CURL::libcurl OpenSSL::SSL OpenSSL::Crypto)
endif()

add_executable(depotkit-cli tools/depotkit_cli.cpp)
target_link_libraries(depotkit-cli PRIVATE depotkit)

if(DEPOTKIT_BUILD_TESTS)
  enable_testing()
  add_executable(depotkit_test_manifest tests/test_manifest.cpp)
  target_link_libraries(depotkit_test_manifest PRIVATE depotkit)
  add_test(NAME manifest_roundtrip COMMAND depotkit_test_manifest)
endif()

install(TARGETS depotkit depotkit-cli
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(FILES include/depotkit.h DESTINATION include)
