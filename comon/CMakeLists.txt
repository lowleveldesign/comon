cmake_minimum_required(VERSION 3.22)

set(BUILD_SHARED_LIBS YES)

find_package(WIL CONFIG REQUIRED)
find_package(SQLiteCpp CONFIG REQUIRED)

configure_file(resource.h resource.h COPYONLY)
configure_file(resource.rc.in resource.rc @ONLY)

add_library(comon
	"cometa.cpp" "comonitor.cpp" "comonitor_breakpoints.cpp" "ext.cpp" "ext.def" "helpers.cpp"
	"cohelp.cpp" "dbgsession.cpp" "${CMAKE_CURRENT_BINARY_DIR}/resource.rc" "arch.cpp"
	"include/comon.h" "include/lfu_cache.h" "include/cometa.h" "include/comonitor.h"
	"include/dbgsession.h" "include/arch.h")

target_include_directories(comon PRIVATE "include")

set_property(TARGET comon PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_link_libraries(comon PRIVATE
	WIL::WIL
	SQLiteCpp
	dbgeng
)

target_compile_definitions(comon PRIVATE
	EXT_MAJOR_VER=${comon_VERSION_MAJOR}
	EXT_MINOR_VER=${comon_VERSION_MINOR}
	EXT_PATCH_VER=${comon_VERSION_PATCH}
	EXT_TWEAK_VER=${comon_VERSION_TWEAK}
)

set_target_properties(comon PROPERTIES
    LINK_OPTIONS LINKER:/MANIFEST:NO
)

install(TARGETS comon RUNTIME DESTINATION ".")
install(FILES $<TARGET_PDB_FILE:comon> DESTINATION ".")

