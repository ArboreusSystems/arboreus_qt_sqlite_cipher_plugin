# Installs a static library built for one Apple SDK (iOS device or iOS
# simulator) into a Qt kit that serves both.
#
# Qt for iOS ships one library file holding the device and the simulator
# architectures. To match that, the architectures of NEW_LIB replace the same
# architectures in DEST_LIB and all other architectures already in DEST_LIB are
# kept. Installing the device build and the simulator build one after the
# other therefore gives one library for both.
#
# Input variables: NEW_LIB, DEST_LIB, optional LIPO.

cmake_policy(VERSION 3.24)

if(NOT LIPO)
    find_program(LIPO lipo REQUIRED)
endif()

function(_sqlitecipher_archs file out_var)
    execute_process(COMMAND "${LIPO}" -archs "${file}"
        OUTPUT_VARIABLE archs OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE result)
    if(NOT result EQUAL 0)
        set(archs "")
    endif()
    separate_arguments(archs)
    set(${out_var} "${archs}" PARENT_SCOPE)
endfunction()

function(_sqlitecipher_install NEW_LIB)
    get_filename_component(dest_dir "${DEST_LIB}" DIRECTORY)
    file(MAKE_DIRECTORY "${dest_dir}")

    _sqlitecipher_archs("${NEW_LIB}" new_archs)
    if(NOT new_archs)
        message(FATAL_ERROR "sqlitecipher: ${NEW_LIB} is not a library lipo can read.")
    endif()
    set(kept_archs "")
    if(EXISTS "${DEST_LIB}")
        _sqlitecipher_archs("${DEST_LIB}" old_archs)
        foreach(arch IN LISTS old_archs)
            if(NOT arch IN_LIST new_archs)
                list(APPEND kept_archs "${arch}")
            endif()
        endforeach()
    endif()

    if(kept_archs)
        # Pull the architectures to keep out of the installed library ...
        set(inputs "")
        list(LENGTH old_archs old_arch_count)
        foreach(arch IN LISTS kept_archs)
            set(slice "${DEST_LIB}.${arch}.tmp")
            if(old_arch_count EQUAL 1)
                # A library with a single architecture is kept as it is.
                file(COPY_FILE "${DEST_LIB}" "${slice}")
            else()
                execute_process(COMMAND "${LIPO}" "${DEST_LIB}" -thin "${arch}" -output "${slice}"
                    RESULT_VARIABLE result)
                if(NOT result EQUAL 0)
                    message(FATAL_ERROR "sqlitecipher: lipo could not extract ${arch} from ${DEST_LIB}.")
                endif()
            endif()
            list(APPEND inputs "${slice}")
        endforeach()
        # ... and combine them with the new build.
        execute_process(COMMAND "${LIPO}" -create ${inputs} "${NEW_LIB}" -output "${DEST_LIB}.tmp"
            RESULT_VARIABLE result)
        file(REMOVE ${inputs})
        if(NOT result EQUAL 0)
            file(REMOVE "${DEST_LIB}.tmp")
            message(FATAL_ERROR "sqlitecipher: lipo could not combine ${NEW_LIB} with ${DEST_LIB}.")
        endif()
        file(RENAME "${DEST_LIB}.tmp" "${DEST_LIB}")
        message(STATUS "Installing: ${DEST_LIB} (${new_archs} updated; ${kept_archs} kept)")
    else()
        file(COPY_FILE "${NEW_LIB}" "${DEST_LIB}")
        message(STATUS "Installing: ${DEST_LIB} (${new_archs})")
    endif()
endfunction()

# Xcode keeps the device and the simulator build in separate folders
# ("Release-iphoneos", "Release-iphonesimulator"). When the path handed in
# does not exist as such, take whatever has been built there.
set(new_libs "")
if(EXISTS "${NEW_LIB}")
    list(APPEND new_libs "${NEW_LIB}")
else()
    get_filename_component(new_name "${NEW_LIB}" NAME)
    get_filename_component(new_dir "${NEW_LIB}" DIRECTORY)
    file(GLOB new_libs "${new_dir}-*/${new_name}")
endif()
if(NOT new_libs)
    message(FATAL_ERROR "sqlitecipher: ${NEW_LIB} has not been built yet.")
endif()

foreach(new_lib IN LISTS new_libs)
    _sqlitecipher_install("${new_lib}")
endforeach()
