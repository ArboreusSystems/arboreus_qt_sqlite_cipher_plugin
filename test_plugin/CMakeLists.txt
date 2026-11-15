find_package(Qt6 6.12 REQUIRED COMPONENTS Test)

qt_add_executable(sqlitecipher_test_plugin
    main.cpp
)

target_compile_definitions(sqlitecipher_test_plugin PRIVATE QT_DEPRECATED_WARNINGS)

target_link_libraries(sqlitecipher_test_plugin PRIVATE
    Qt6::Core
    Qt6::Sql
    Qt6::Test
)

ASqliteCipherUsePlugin(sqlitecipher_test_plugin)

if(NOT CMAKE_CROSSCOMPILING)
    add_test(NAME sqlitecipher_test_plugin COMMAND sqlitecipher_test_plugin)
endif()
