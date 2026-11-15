cmake_minimum_required(VERSION 3.24)

project(ASqliteCipherPlugin LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.12 REQUIRED COMPONENTS Core CorePrivate Sql SqlPrivate)

qt_standard_project_setup()

add_subdirectory(sqlitecipher)

# The test and the demo are only built when this is the main project, not when
# the plugin is added to an application with add_subdirectory().
if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory(test_plugin)
    add_subdirectory(demo)
endif()
