cmake_minimum_required(VERSION 3.16)
project(LateRegistration C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast -ggdb")

add_executable(LateRegistration src/main.c src/kernelVM.c src/kernelVM.h src/Snapshot.c src/Snapshot.h src/debugging.c src/debugging.h)
