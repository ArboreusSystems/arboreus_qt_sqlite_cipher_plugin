qt_add_executable(demo
    main.cpp
)

target_link_libraries(demo PRIVATE
    Qt6::Core
    Qt6::Sql
)

ASqliteCipherUsePlugin(demo)
