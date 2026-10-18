cmake_minimum_required(VERSION 3.24)

project(vx6_browser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets WebEngineWidgets WebEngineCore)

qt_standard_project_setup()

qt_add_executable(vx6-browser
    src/main.cpp
    src/browserwindow.cpp
    src/browserwindow.h
    src/vx6backend.cpp
    src/vx6backend.h
    src/vx6schemehandler.cpp
    src/vx6schemehandler.h
)

target_include_directories(vx6-browser PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(vx6-browser PRIVATE
    Qt6::Widgets
    Qt6::WebEngineWidgets
    Qt6::WebEngineCore
)

