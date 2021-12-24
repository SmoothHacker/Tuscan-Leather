cmake_minimum_required(VERSION 3.16)
project(LateRegistration C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER clang)

add_executable(LateRegistration src/main.c src/kernelVM.c src/kernelVM.h src/snapshot.c src/snapshot.h)