
# author        Oliver Blaser
# date          26.11.2022
# copyright     GNU GPLv3 - Copyright (c) 2022 Oliver Blaser

cmake_minimum_required(VERSION 3.13)

project(pem-rsa-publickey-tool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

include_directories(../../src/)

set(SOURCES
../../src/middleware/util.cpp
../../src/main.cpp
)

add_executable(pem-rsa-publickey-tool ${SOURCES})
