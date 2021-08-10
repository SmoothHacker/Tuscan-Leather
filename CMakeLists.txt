cmake_minimum_required(VERSION 3.16)
project(LateRegistration C)

set(CMAKE_C_STANDARD 11)

add_executable(LateRegistration src/main.c src/kernelVM.c src/kernelVM.h)
