# This folder is self-contained: it can also be added directly to an
# application project with add_subdirectory().
enable_language(C)

find_package(Qt6 6.12 REQUIRED COMPONENTS Core CorePrivate Sql SqlPrivate)

# SQLite3 Multiple Ciphers build configuration. The driver includes the
# amalgamation header, so both targets below get the same definitions.
set(SQLITE3MC_DEFINITIONS
    THREADSAFE=1
    SQLITE_MAX_ATTACHED=10
    SQLITE_SOUNDEX
    SQLITE_ENABLE_EXPLAIN_COMMENTS
    SQLITE_ENABLE_COLUMN_METADATA
    CODEC_TYPE=CODEC_TYPE_CHACHA20
    SQLITE_SECURE_DELETE
    SQLITE_ENABLE_FTS3
    SQLITE_ENABLE_FTS3_PARENTHESIS
    SQLITE_ENABLE_FTS4
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_JSON1
    SQLITE_ENABLE_RTREE
    SQLITE_CORE
    SQLITE_ENABLE_EXTFUNC
    SQLITE_ENABLE_CSV
    SQLITE_ENABLE_SHA3
    SQLITE_ENABLE_CARRAY
    SQLITE_ENABLE_FILEIO
    SQLITE_ENABLE_SERIES
    SQLITE_TEMP_STORE=2
    SQLITE_USE_URI
    SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_OMIT_COMPLETE
)
# Compile-time hardening for both targets of the plugin (clang on macOS, iOS
# and Android). Flags the compiler does not know are skipped.
option(SQLITECIPHER_HARDENING "Build the plugin with compiler and linker hardening flags" ON)

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)

function(ASqliteCipherHardening target)

    if(NOT SQLITECIPHER_HARDENING)
        return()
    endif()

    # Export nothing but the Qt plugin entry points: the bundled SQLite stays
    # private to the plugin.
    set_target_properties(${target} PROPERTIES
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
    )

    # Stack canaries for every function with a local array or address-taken local.
    check_c_compiler_flag(-fstack-protector-strong SQLITECIPHER_HAS_STACK_PROTECTOR_STRONG)
    if(SQLITECIPHER_HAS_STACK_PROTECTOR_STRONG)
        target_compile_options(${target} PRIVATE -fstack-protector-strong)
    endif()

    # Uninitialized stack variables read as zero instead of leftover data.
    check_c_compiler_flag(-ftrivial-auto-var-init=zero SQLITECIPHER_HAS_AUTO_VAR_INIT_ZERO)
    if(SQLITECIPHER_HAS_AUTO_VAR_INIT_ZERO)
        target_compile_options(${target} PRIVATE -ftrivial-auto-var-init=zero)
    endif()

    # Bounds-checked libc string / memory functions. Needs optimization, so it
    # is left out of Debug builds. Level 3 also checks buffers whose size is
    # only known at run time; it needs __builtin_dynamic_object_size in the
    # compiler. C library headers that do not implement level 3 (yet) treat
    # it as level 2, so asking for 3 never gives less than 2.
	check_c_source_compiles(
		"int main(int argc, char **argv){
			(void)argv; char buf[8];
			return (int)__builtin_dynamic_object_size(buf, 1) - 8 + argc - argc;
		}"
		SQLITECIPHER_HAS_DYNAMIC_OBJECT_SIZE
	)
    if(SQLITECIPHER_HAS_DYNAMIC_OBJECT_SIZE)
        set(fortify_level 3)
    else()
        set(fortify_level 2)
    endif()
    target_compile_options(${target} PRIVATE
        "$<$<NOT:$<CONFIG:Debug>>:SHELL:-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=${fortify_level}>"
    )

    # Format string mistakes are errors.
    target_compile_options(${target} PRIVATE -Wformat -Wformat-security -Werror=format-security)

    if(ANDROID)
        # Pointer authentication and branch target identification on arm64.
        if(ANDROID_ABI STREQUAL "arm64-v8a")
            check_c_compiler_flag(-mbranch-protection=standard SQLITECIPHER_HAS_BRANCH_PROTECTION)
            if(SQLITECIPHER_HAS_BRANCH_PROTECTION)
                target_compile_options(${target} PRIVATE -mbranch-protection=standard)
            endif()
        endif()

        # Read-only relocations, immediate binding, non-executable stack.
        get_target_property(target_type ${target} TYPE)
        if(target_type STREQUAL "MODULE_LIBRARY" OR target_type STREQUAL "SHARED_LIBRARY")
            target_link_options(${target} PRIVATE
                "LINKER:-z,relro"
                "LINKER:-z,now"
                "LINKER:-z,noexecstack"
            )
        endif()
    endif()
endfunction()

# The amalgamation is compiled on its own so that its C flags stay local to it.
add_library(sqlite3mc OBJECT
    sqlite3/sqlite3mc_amalgamation.c
    sqlite3/sqlite3mc_amalgamation.h
)
set_target_properties(sqlite3mc PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    AUTOMOC OFF
)
target_compile_definitions(sqlite3mc PRIVATE ${SQLITE3MC_DEFINITIONS})

ASqliteCipherHardening(sqlite3mc)

target_compile_options(sqlite3mc PRIVATE -w -Wno-error=format-security)

# Hardware accelerated ciphers are selected at run time. Apple targets need no
# extra flags; for Android these are the flags the SQLite3 Multiple Ciphers
# project uses itself.
if(ANDROID)
	if(ANDROID_ABI STREQUAL "arm64-v8a")
		target_compile_options(sqlite3mc PRIVATE
			-march=armv8-a+crypto
			-mbranch-protection=standard
		)
	elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
		target_compile_options(sqlite3mc PRIVATE
			-march=armv7-a
			-mfpu=neon
		)
	elseif(ANDROID_ABI STREQUAL "x86_64")
		target_compile_options(sqlite3mc PRIVATE
			-mvaes
			-fcf-protection=full
		)
	elseif(ANDROID_ABI STREQUAL "x86")
		target_compile_options(sqlite3mc PRIVATE
			-maes
			-msse4.2
		)
	endif()
endif()

qt_add_plugin(sqlitecipher
    PLUGIN_TYPE sqldrivers
	CLASS_NAME ASqliteCipherDriverPlugin
)

target_sources(sqlitecipher
	PRIVATE
		$<TARGET_OBJECTS:sqlite3mc>
		ASqliteCipherDriverPlugin.json
		asqlitecipherdatamodels.h
		asqliteciphermain.cpp
		asqlitecipherdriver.cpp
		asqlitecipherdriver.h
		asqliteciphermemory.cpp
		asqliteciphermemory.h
		asqliteciphersecurebuffer.h
		asqliteciphersecurebuffer.cpp
		asqlitecipherprivate.h
)

target_include_directories(sqlitecipher PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/sqlite3
)

target_compile_definitions(sqlitecipher PRIVATE
    QT_NO_CAST_TO_ASCII
    QT_NO_CAST_FROM_ASCII
    ${SQLITE3MC_DEFINITIONS}
)

get_target_property(sqlitecipher_type sqlitecipher TYPE)
if(sqlitecipher_type STREQUAL "STATIC_LIBRARY")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/sqlitecipher_import.cpp.in"
		"#include <QtPlugin>\n\nQ_IMPORT_PLUGIN(ASqliteCipherDriverPlugin)\n")
    configure_file("${CMAKE_CURRENT_BINARY_DIR}/sqlitecipher_import.cpp.in"
        "${CMAKE_CURRENT_BINARY_DIR}/sqlitecipher_import.cpp" COPYONLY)
    target_sources(sqlitecipher PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/sqlitecipher_import.cpp")
endif()

set_target_properties(sqlitecipher PROPERTIES
    AUTOMOC ON
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

ASqliteCipherHardening(sqlitecipher)

target_link_libraries(sqlitecipher PRIVATE
    Qt6::Core
    Qt6::CorePrivate
    Qt6::Sql
    Qt6::SqlPrivate
)

set_target_properties(sqlitecipher PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/plugins/sqldrivers"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/plugins/sqldrivers"
)

# -----------------------------------------------
# Installation into the Qt kit. Only offered when this is the main project,
# so that it never becomes part of an application's own install step.
# Run one of these from the build folder:
#   cmake --install .                         (add "--config Release" for Xcode builds)
#   cmake --build . --target install_plugin   (builds the plugin first, installs only the plugin)
#
# Two things are installed:
#  - the plugin, next to the other SQL drivers of the Qt kit
#  - a CMake file next to the CMake files of Qt Sql, which registers the plugin
#    with Qt. From then on every application built with this kit that uses
#    Qt Sql gets the driver on its own: linked in on iOS, packaged into the
#    APK on Android, loaded from the kit on macOS.

get_filename_component(sqlitecipher_project_dir "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
if(CMAKE_SOURCE_DIR STREQUAL sqlitecipher_project_dir)
    set(SQLITECIPHER_INSTALL_DIR "${QT6_INSTALL_PREFIX}/${QT6_INSTALL_PLUGINS}/sqldrivers"
        CACHE PATH "Directory the sqlitecipher plugin is installed to")
    set(SQLITECIPHER_CMAKE_INSTALL_DIR "${Qt6Sql_DIR}"
        CACHE PATH "Directory the CMake file registering the plugin with Qt is installed to")
    message(STATUS "sqlitecipher plugin install directory: ${SQLITECIPHER_INSTALL_DIR}")
    message(STATUS "sqlitecipher Qt registration directory: ${SQLITECIPHER_CMAKE_INSTALL_DIR}")

    if(IOS)
        install(CODE "
            set(NEW_LIB \"$<TARGET_FILE:sqlitecipher>\")
            set(DEST_LIB \"${SQLITECIPHER_INSTALL_DIR}/$<TARGET_FILE_NAME:sqlitecipher>\")
            include(\"${CMAKE_CURRENT_SOURCE_DIR}/InstallAppleStaticLibrary.cmake\")"
            COMPONENT sqlitecipher
        )
    else()
        install(TARGETS sqlitecipher
            LIBRARY DESTINATION "${SQLITECIPHER_INSTALL_DIR}" COMPONENT sqlitecipher
            ARCHIVE DESTINATION "${SQLITECIPHER_INSTALL_DIR}" COMPONENT sqlitecipher
        )
    endif()

	configure_file(Qt6ASqliteCipherDriverPluginConfig.cmake.in
		"${CMAKE_CURRENT_BINARY_DIR}/Qt6ASqliteCipherDriverPluginConfig.cmake.genex" @ONLY)
    file(GENERATE
		OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/qtkit/$<CONFIG>/Qt6ASqliteCipherDriverPluginConfig.cmake"
		INPUT "${CMAKE_CURRENT_BINARY_DIR}/Qt6ASqliteCipherDriverPluginConfig.cmake.genex"
    )
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/qtkit/$<CONFIG>/Qt6ASqliteCipherDriverPluginConfig.cmake"
        DESTINATION "${SQLITECIPHER_CMAKE_INSTALL_DIR}" COMPONENT sqlitecipher
    )

    add_custom_target(install_plugin
        COMMAND "${CMAKE_COMMAND}" --install "${CMAKE_BINARY_DIR}" --component sqlitecipher --config "$<CONFIG>"
        DEPENDS sqlitecipher
        COMMENT "Installing the sqlitecipher plugin to ${SQLITECIPHER_INSTALL_DIR}"
        VERBATIM
    )
endif()

# -----------------------------------------------
# Makes the plugin of this build tree available to an application target of
# the same build tree (the demo and the test, or an application that added
# this project with add_subdirectory()). Applications built separately get the
# plugin from the Qt kit once it is installed there.
#  - static Qt (iOS): links the whole plugin, which registers itself with Qt
#  - Android: bundles it into the APK (and links Qt Gui, which every Android package needs)
#  - macOS: copies it into a "sqldrivers" folder next to the executable, one of
#    the places Qt looks for SQL drivers

function(ASqliteCipherUsePlugin target)

	if(TARGET Qt6::ASqliteCipherDriverPlugin)
		qt_import_plugins(${target} EXCLUDE Qt6::ASqliteCipherDriverPlugin)
    endif()

    get_target_property(plugin_type sqlitecipher TYPE)
    if(plugin_type STREQUAL "STATIC_LIBRARY")
        target_link_libraries(${target} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,sqlitecipher>")
    elseif(ANDROID)
        add_dependencies(${target} sqlitecipher)
        get_target_property(plugin_dir sqlitecipher LIBRARY_OUTPUT_DIRECTORY)
        set_property(TARGET ${target} APPEND PROPERTY QT_ANDROID_EXTRA_PLUGINS "${plugin_dir}")
        find_package(Qt6 6.12 REQUIRED COMPONENTS Gui)
        target_link_libraries(${target} PRIVATE Qt6::Gui)
    else()
        add_custom_target(${target}_sqlitecipher ALL
            COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_FILE_DIR:${target}>/sqldrivers"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                    "$<TARGET_FILE:sqlitecipher>"
                    "$<TARGET_FILE_DIR:${target}>/sqldrivers/$<TARGET_FILE_NAME:sqlitecipher>"
            DEPENDS sqlitecipher
            COMMENT "Copying the sqlitecipher plugin next to ${target}"
            VERBATIM
        )
        add_dependencies(${target} ${target}_sqlitecipher)
    endif()
endfunction()
