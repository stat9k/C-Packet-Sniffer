cmake_minimum_required(VERSION 3.7)
project(C_Packet_Sniffer)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c packet_headers.h)
add_executable(C_Packet_Sniffer ${SOURCE_FILES})