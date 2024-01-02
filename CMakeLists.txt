cmake_minimum_required(VERSION 3.1)

project(
  cpp-my-redis
  VERSION 1.0
  LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE)
  add_definitions(-DDEBUG)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g") # 添加调试信息
endif()

add_executable(server server-mac.cpp hashtable.cpp zset.cpp avl.cpp heap.cpp
                      threadpool.cpp)
add_executable(client client.cpp)

target_compile_features(server PUBLIC cxx_std_11)
set_target_properties(server PROPERTIES CXX_EXTENSIONS OFF)
target_compile_features(client PUBLIC cxx_std_11)
set_target_properties(client PROPERTIES CXX_EXTENSIONS OFF)
