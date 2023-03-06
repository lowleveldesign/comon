cmake_minimum_required(VERSION 3.22)

set(BUILD_SHARED_LIBS YES)

find_package(WIL CONFIG REQUIRED)
find_package(SQLiteCpp CONFIG REQUIRED)

configure_file(resource.h resource.h COPYONLY)
configure_file(resource.rc.in resource.rc @ONLY)

add_library(comon
	"cometa.h"
	"cometa.cpp"
	"cometa_helpers.cpp"
	"comon.h"
	"comonitor.h"
	"comonitor.cpp"
	"comonitor_com_breakpoints.cpp"
	"ext.cpp"
	"ext.def"
	"helpers.cpp"
	"cohelp.cpp"
	"dbgsession.h" 
	"dbgsession.cpp"
	"${CMAKE_CURRENT_BINARY_DIR}/resource.rc"
	"arch.h"
	"arch.cpp"
	"lfu_cache.h"
)

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

if (VCPKG_TARGET_TRIPLET STREQUAL "x64-windows-static")
	target_compile_definitions(comon PRIVATE
		ARCH_X64
	)
endif()

set_target_properties(comon PROPERTIES
	LINK_OPTIONS LINKER:/MANIFEST:NO
)

install(TARGETS comon RUNTIME DESTINATION ".")
install(FILES $<TARGET_PDB_FILE:comon> DESTINATION ".")

