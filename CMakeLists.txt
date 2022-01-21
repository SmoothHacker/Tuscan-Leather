cmake_minimum_required(VERSION 3.16)
project(Tuscan-Leather C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER clang)

add_executable(Tuscan-Leather src/main.c src/kernelVM.c src/kernelVM.h src/snapshot.c src/snapshot.h src/breakpoint.c src/breakpoint.h)