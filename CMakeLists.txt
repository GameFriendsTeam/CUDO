cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
set(PROJECT_NAME CUDO)

project(${PROJECT_NAME})

add_executable(${PROJECT_NAME}
	CUDO.cpp
	CUDO.h
)

