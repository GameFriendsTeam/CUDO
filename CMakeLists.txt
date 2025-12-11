cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
set(PROJECT_NAME CUDO)

project(${PROJECT_NAME})

add_executable(${PROJECT_NAME}
	CUDO.cpp
	CUDO.h
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES config.ini DESTINATION share/YourApp)
include(CPack)
set(CPACK_PACKAGE_NAME "YourApp")
set(CPACK_PACKAGE_VERSION "1.0")
# Выбор генератора (NSIS, ZIP, DMG и т.д.)
set(CPACK_GENERATOR "NSIS") # Для Windows EXE-установщика