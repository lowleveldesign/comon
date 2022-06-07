cmake_minimum_required(VERSION 3.22)

set(VCPKG_INSTALLED_DIR "${CMAKE_BINARY_DIR}/vcpkg_installed")

project(comon)

if(DEFINED ENV{COMON_VERSION_MAJOR})
    set(comon_VERSION_MAJOR $ENV{COMON_VERSION_MAJOR})
else()
    set(comon_VERSION_MAJOR 1)
endif()

if(DEFINED ENV{COMON_VERSION_MINOR})
    set(comon_VERSION_MINOR $ENV{COMON_VERSION_MINOR})
else()
    set(comon_VERSION_MINOR 0)
endif()

if(DEFINED ENV{COMON_VERSION_PATCH})
    set(comon_VERSION_PATCH $ENV{COMON_VERSION_PATCH})
else()
    set(comon_VERSION_PATCH 0)
endif()

if(DEFINED ENV{COMON_VERSION_TWEAK})
    set(comon_VERSION_TWEAK $ENV{COMON_VERSION_TWEAK})
else()
    set(comon_VERSION_TWEAK 0)
endif()

set(comon_VERSION
  ${comon_VERSION_MAJOR}.${comon_VERSION_MINOR}.${comon_VERSION_PATCH}.${comon_VERSION_TWEAK}
)

message("Building version ${comon_VERSION}")

add_compile_definitions(UNICODE)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")

add_subdirectory(comon)
