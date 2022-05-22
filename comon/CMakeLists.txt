cmake_minimum_required(VERSION 3.22)

set(BUILD_SHARED_LIBS YES)

find_package(WIL CONFIG REQUIRED)
find_package(SQLiteCpp CONFIG REQUIRED)

add_library(comon
	"cometa.cpp" "comonitor.cpp" "ext.cpp" "ext.def" "helpers.cpp" "cohelp.cpp" 
	  "dbgsession.cpp" "include/comon.h" "include/lfu_cache.h" 
	 "include/cometa.h" "include/comonitor.h" "include/dbgsession.h" "include/arch.h" "arch.cpp")

target_include_directories(comon PRIVATE "include")

set_property(TARGET comon PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_link_libraries(comon PRIVATE
	WIL::WIL
	SQLiteCpp
	dbgeng
)

target_compile_definitions(comon PRIVATE
	EXT_MAJOR_VER=${CMAKE_PROJECT_VERSION_MAJOR}
	EXT_MINOR_VER=${CMAKE_PROJECT_VERSION_MINOR}
)

set_target_properties(comon PROPERTIES
    LINK_OPTIONS LINKER:/MANIFEST:NO
)

install(TARGETS comon RUNTIME DESTINATION ".")
install(FILES $<TARGET_PDB_FILE:comon> DESTINATION ".")

