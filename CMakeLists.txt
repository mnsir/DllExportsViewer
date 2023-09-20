cmake_minimum_required (VERSION 3.8)

project ("DllExportsViewer")

add_executable (Try "src/module.h" "src/sandbox.cpp" "src/module.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Try PROPERTY CXX_STANDARD 20)
endif()