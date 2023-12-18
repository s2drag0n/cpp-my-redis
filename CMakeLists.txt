cmake_minimum_required(VERSION 3.1)

project(
  cpp-my-redis
  VERSION 1.0
  LANGUAGES CXX)

add_executable(server server-mac.cpp hashtable.cpp)
add_executable(client client.cpp)

target_compile_features(server PUBLIC cxx_std_11)
set_target_properties(server PROPERTIES CXX_EXTENSIONS OFF)
target_compile_features(client PUBLIC cxx_std_11)
set_target_properties(client PROPERTIES CXX_EXTENSIONS OFF)
