# Sindarin SDK - CMake Build Configuration
#
# This CMakeLists.txt handles vcpkg dependency detection and copying
# libraries for static linking.
#
# Usage:
#   cmake -S . -B build
#   cmake --build build
#
# Or use presets:
#   cmake --preset linux-gcc-release
#   cmake --build --preset linux-gcc-release

cmake_minimum_required(VERSION 3.21)

project(sindarin-pkg-sdk
    VERSION 1.0.0
    DESCRIPTION "Sindarin SDK - Dependencies for static linking"
    LANGUAGES C
)

#------------------------------------------------------------------------------
# Build Configuration
#------------------------------------------------------------------------------
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Output directory
set(SN_DEPS_DIR ${CMAKE_SOURCE_DIR}/deps)

#------------------------------------------------------------------------------
# VCPKG Dependencies Detection
#------------------------------------------------------------------------------
# Automatically detect vcpkg installed packages and copy them to deps/
# This makes the dependencies available for static linking.

# Determine vcpkg triplet based on platform
if(WIN32)
    set(VCPKG_TRIPLET "x64-mingw-static")
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        set(VCPKG_TRIPLET "arm64-osx")
    else()
        set(VCPKG_TRIPLET "x64-osx")
    endif()
else()
    set(VCPKG_TRIPLET "x64-linux")
endif()

# Find vcpkg installation directory
# In manifest mode, packages are installed to vcpkg_installed/ in project root
# In classic mode, packages are in vcpkg/installed/
set(VCPKG_INSTALLED_DIR "")

# First check manifest mode (vcpkg_installed in project root)
if(EXISTS "${CMAKE_SOURCE_DIR}/vcpkg_installed/${VCPKG_TRIPLET}")
    set(VCPKG_INSTALLED_DIR "${CMAKE_SOURCE_DIR}/vcpkg_installed/${VCPKG_TRIPLET}")
endif()

# Then check VCPKG_ROOT environment variable
if("${VCPKG_INSTALLED_DIR}" STREQUAL "" AND DEFINED ENV{VCPKG_ROOT})
    set(VCPKG_INSTALLED_DIR "$ENV{VCPKG_ROOT}/installed/${VCPKG_TRIPLET}")
endif()

# Finally check classic mode (vcpkg/installed in project root)
if("${VCPKG_INSTALLED_DIR}" STREQUAL "" OR NOT EXISTS "${VCPKG_INSTALLED_DIR}")
    set(VCPKG_INSTALLED_DIR "${CMAKE_SOURCE_DIR}/vcpkg/installed/${VCPKG_TRIPLET}")
endif()

# Create deps directory structure
file(MAKE_DIRECTORY ${SN_DEPS_DIR})
file(MAKE_DIRECTORY ${SN_DEPS_DIR}/include)
file(MAKE_DIRECTORY ${SN_DEPS_DIR}/lib)

# Copy vcpkg dependencies if found
if(EXISTS "${VCPKG_INSTALLED_DIR}")
    message(STATUS "Found vcpkg installation: ${VCPKG_INSTALLED_DIR}")

    # Copy headers
    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/zlib.h")
        message(STATUS "  Copying zlib headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/zlib.h" DESTINATION ${SN_DEPS_DIR}/include)
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/zconf.h" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/yyjson.h")
        message(STATUS "  Copying yyjson headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/yyjson.h" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/libxml2/libxml")
        message(STATUS "  Copying libxml2 headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/libxml2/libxml" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/yaml.h")
        message(STATUS "  Copying libyaml headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/yaml.h" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/openssl/ssl.h")
        message(STATUS "  Copying openssl headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/openssl" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/ngtcp2/ngtcp2.h")
        message(STATUS "  Copying ngtcp2 headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/ngtcp2" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/libssh/libssh.h")
        message(STATUS "  Copying libssh headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/libssh" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/git2.h")
        message(STATUS "  Copying libgit2 headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/git2.h" DESTINATION ${SN_DEPS_DIR}/include)
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/git2" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    if(EXISTS "${VCPKG_INSTALLED_DIR}/include/curl/curl.h")
        message(STATUS "  Copying curl headers...")
        file(INSTALL "${VCPKG_INSTALLED_DIR}/include/curl" DESTINATION ${SN_DEPS_DIR}/include)
    endif()

    # Copy libraries based on platform
    if(WIN32)
        # Windows (MinGW): Copy .a static libraries and .dll if present
        file(GLOB ZLIB_LIBS "${VCPKG_INSTALLED_DIR}/lib/libz*.a" "${VCPKG_INSTALLED_DIR}/lib/zlib*.a")
        file(GLOB YYJSON_LIBS "${VCPKG_INSTALLED_DIR}/lib/libyyjson*.a" "${VCPKG_INSTALLED_DIR}/lib/yyjson*.a")
        file(GLOB XML2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libxml2*.a" "${VCPKG_INSTALLED_DIR}/lib/xml2*.a")
        file(GLOB YAML_LIBS "${VCPKG_INSTALLED_DIR}/lib/libyaml*.a" "${VCPKG_INSTALLED_DIR}/lib/yaml*.a")
        file(GLOB OPENSSL_LIBS "${VCPKG_INSTALLED_DIR}/lib/libssl*.a" "${VCPKG_INSTALLED_DIR}/lib/libcrypto*.a")
        file(GLOB NGTCP2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libngtcp2*.a")
        file(GLOB SSH_LIBS "${VCPKG_INSTALLED_DIR}/lib/libssh*.a")
        file(GLOB GIT2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libgit2*.a" "${VCPKG_INSTALLED_DIR}/lib/git2*.a")
        file(GLOB GIT2_DEPS_LIBS "${VCPKG_INSTALLED_DIR}/lib/libhttp_parser*.a" "${VCPKG_INSTALLED_DIR}/lib/libpcre2-8*.a" "${VCPKG_INSTALLED_DIR}/lib/libssh2*.a")
        file(GLOB CURL_LIBS "${VCPKG_INSTALLED_DIR}/lib/libcurl*.a" "${VCPKG_INSTALLED_DIR}/lib/curl*.a")
        file(GLOB ZLIB_DLLS "${VCPKG_INSTALLED_DIR}/bin/libz*.dll" "${VCPKG_INSTALLED_DIR}/bin/zlib*.dll")
        file(GLOB YYJSON_DLLS "${VCPKG_INSTALLED_DIR}/bin/libyyjson*.dll" "${VCPKG_INSTALLED_DIR}/bin/yyjson*.dll")

        foreach(LIB ${ZLIB_LIBS} ${YYJSON_LIBS} ${XML2_LIBS} ${YAML_LIBS} ${OPENSSL_LIBS} ${NGTCP2_LIBS} ${SSH_LIBS} ${GIT2_LIBS} ${GIT2_DEPS_LIBS} ${CURL_LIBS})
            message(STATUS "  Copying library: ${LIB}")
            file(INSTALL ${LIB} DESTINATION ${SN_DEPS_DIR}/lib)
        endforeach()
        foreach(DLL ${ZLIB_DLLS} ${YYJSON_DLLS})
            message(STATUS "  Copying DLL: ${DLL}")
            file(INSTALL ${DLL} DESTINATION ${SN_DEPS_DIR}/lib)
        endforeach()
    elseif(APPLE)
        # macOS: Copy static or dynamic libraries
        file(GLOB ZLIB_LIBS "${VCPKG_INSTALLED_DIR}/lib/libz.*")
        file(GLOB YYJSON_LIBS "${VCPKG_INSTALLED_DIR}/lib/libyyjson.*")
        file(GLOB XML2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libxml2.*")
        file(GLOB YAML_LIBS "${VCPKG_INSTALLED_DIR}/lib/libyaml.*")
        file(GLOB OPENSSL_LIBS "${VCPKG_INSTALLED_DIR}/lib/libssl.*" "${VCPKG_INSTALLED_DIR}/lib/libcrypto.*")
        file(GLOB NGTCP2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libngtcp2*.*")
        file(GLOB SSH_LIBS "${VCPKG_INSTALLED_DIR}/lib/libssh.*")
        file(GLOB GIT2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libgit2.*")
        file(GLOB GIT2_DEPS_LIBS "${VCPKG_INSTALLED_DIR}/lib/libhttp_parser.*" "${VCPKG_INSTALLED_DIR}/lib/libpcre2-8.*" "${VCPKG_INSTALLED_DIR}/lib/libssh2.*")
        file(GLOB CURL_LIBS "${VCPKG_INSTALLED_DIR}/lib/libcurl.*")

        foreach(LIB ${ZLIB_LIBS} ${YYJSON_LIBS} ${XML2_LIBS} ${YAML_LIBS} ${OPENSSL_LIBS} ${NGTCP2_LIBS} ${SSH_LIBS} ${GIT2_LIBS} ${GIT2_DEPS_LIBS} ${CURL_LIBS})
            message(STATUS "  Copying library: ${LIB}")
            file(INSTALL ${LIB} DESTINATION ${SN_DEPS_DIR}/lib)
        endforeach()
    else()
        # Linux: Copy static libraries (.a files) for self-contained executables
        file(GLOB ZLIB_LIBS "${VCPKG_INSTALLED_DIR}/lib/libz.a")
        file(GLOB YYJSON_LIBS "${VCPKG_INSTALLED_DIR}/lib/libyyjson.a")
        file(GLOB XML2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libxml2.a")
        file(GLOB YAML_LIBS "${VCPKG_INSTALLED_DIR}/lib/libyaml.a")
        file(GLOB OPENSSL_LIBS "${VCPKG_INSTALLED_DIR}/lib/libssl.a" "${VCPKG_INSTALLED_DIR}/lib/libcrypto.a")
        file(GLOB NGTCP2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libngtcp2*.a")
        file(GLOB SSH_LIBS "${VCPKG_INSTALLED_DIR}/lib/libssh.a")
        file(GLOB GIT2_LIBS "${VCPKG_INSTALLED_DIR}/lib/libgit2.a")
        file(GLOB GIT2_DEPS_LIBS "${VCPKG_INSTALLED_DIR}/lib/libhttp_parser.a" "${VCPKG_INSTALLED_DIR}/lib/libpcre2-8.a" "${VCPKG_INSTALLED_DIR}/lib/libssh2.a")
        file(GLOB CURL_LIBS "${VCPKG_INSTALLED_DIR}/lib/libcurl.a")

        foreach(LIB ${ZLIB_LIBS} ${YYJSON_LIBS} ${XML2_LIBS} ${YAML_LIBS} ${OPENSSL_LIBS} ${NGTCP2_LIBS} ${SSH_LIBS} ${GIT2_LIBS} ${GIT2_DEPS_LIBS} ${CURL_LIBS})
            message(STATUS "  Copying library: ${LIB}")
            file(INSTALL ${LIB} DESTINATION ${SN_DEPS_DIR}/lib)
        endforeach()
    endif()

    message(STATUS "  Dependencies copied to: ${SN_DEPS_DIR}")

    # Set variables for downstream consumers
    set(SINDARIN_SDK_DEPS_DIR ${SN_DEPS_DIR} CACHE PATH "Sindarin SDK dependencies directory")
    set(SINDARIN_SDK_INCLUDE_DIR ${SN_DEPS_DIR}/include CACHE PATH "Sindarin SDK include directory")
    set(SINDARIN_SDK_LIB_DIR ${SN_DEPS_DIR}/lib CACHE PATH "Sindarin SDK library directory")

else()
    message(STATUS "vcpkg not found at: ${VCPKG_INSTALLED_DIR}")
    message(STATUS "Run 'make setup' to install dependencies via vcpkg")
endif()

#------------------------------------------------------------------------------
# Configuration Summary
#------------------------------------------------------------------------------
message(STATUS "")
message(STATUS "Sindarin SDK Configuration:")
message(STATUS "  Version:     ${PROJECT_VERSION}")
message(STATUS "  Platform:    ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Triplet:     ${VCPKG_TRIPLET}")
message(STATUS "  Deps dir:    ${SN_DEPS_DIR}")
message(STATUS "")
