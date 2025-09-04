cmake_minimum_required(VERSION 3.18)
project(AsyncPostLogger LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find Boost (need system and coroutine headers)
find_package(Boost REQUIRED COMPONENTS system)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Boost not found")
endif()

# Find SQLite3
find_package(SQLite3 REQUIRED)
if(NOT SQLite3_FOUND)
    message(FATAL_ERROR "SQLite3 not found")
endif()

add_executable(async_post_logger async_post_logger.cpp)

target_include_directories(async_post_logger PRIVATE ${Boost_INCLUDE_DIRS} ${SQLite3_INCLUDE_DIRS})
target_link_libraries(async_post_logger PRIVATE ${Boost_LIBRARIES} SQLite::SQLite3)

# Optional: warnings
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(async_post_logger PRIVATE -Wall -Wextra -Wpedantic)
endif()
