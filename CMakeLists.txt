cmake_minimum_required(VERSION 3.16)
project(Tuscan-Leather)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_COMPILER clang-12)
set(CMAKE_CXX_COMPILER clang++-12)

add_executable(Tuscan-Leather src/main.cpp src/kernelVM.cpp src/kernelVM.h src/snapshot.cpp src/snapshot.h src/breakpoint.cpp src/breakpoint.h src/mutation.cpp src/mutation.h)