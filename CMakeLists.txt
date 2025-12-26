cmake_minimum_required(VERSION 3.14)

# 项目名称与版本
project(MiniMachO VERSION 6.0.0 LANGUAGES CXX)

# 设置 C++ 标准 (C++17 是现代 C++ 的分水岭)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译选项：开启所有警告 (Wall) -> 这体现了你对代码质量的要求
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# 定义可执行文件
add_executable(minimacho main.cpp)

# 如果未来要加多线程支持，现在就可以预留
find_package(Threads REQUIRED)
target_link_libraries(minimacho PRIVATE Threads::Threads)

# 提示信息
message(STATUS "Build config for ${PROJECT_NAME} ready!")