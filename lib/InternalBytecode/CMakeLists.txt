# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_definitions(-DHERMES_CMAKE_BUILD)

if(IMPORT_HOST_COMPILERS)
  file(TO_CMAKE_PATH "${IMPORT_HOST_COMPILERS}" IMPORT_HOST_COMPILERS_CMAKE)
  include(${IMPORT_HOST_COMPILERS_CMAKE})
  set(hermesc_EXE native-hermesc)
else()
  set(hermesc_EXE hermesc)
endif()

add_hermes_library(hermesInternalBytecode
    InternalBytecode.cpp
)

set(JS_COMPILER_FLAGS "-O" "-Wno-undefined-variable" "-g0")

                                                                
                                                         
if(NOT CMAKE_HOST_WIN32)
  set(concatenate "cat")
else()
  set(concatenate "type")
endif()

                                                                                   
file(GLOB internal_bytecode_sources "*.js")
list(SORT internal_bytecode_sources)

                                                                                             
set(internal_bytecode_sources_native_path "")
foreach(cmake_path IN LISTS internal_bytecode_sources)
  file(TO_NATIVE_PATH ${cmake_path} native_path)
  list(APPEND internal_bytecode_sources_native_path ${native_path})
endforeach()

add_custom_command(
  OUTPUT InternalBytecode.js
  COMMAND ${concatenate} ${internal_bytecode_sources_native_path} > ${CMAKE_CURRENT_BINARY_DIR}/InternalBytecode.js
  DEPENDS ${internal_bytecode_sources}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  VERBATIM
)

                                                 
add_custom_command(
  OUTPUT InternalBytecode.hbc
  COMMAND ${hermesc_EXE} ${JS_COMPILER_FLAGS} -emit-binary -out=${CMAKE_CURRENT_BINARY_DIR}/InternalBytecode.hbc ${CMAKE_CURRENT_BINARY_DIR}/InternalBytecode.js
  DEPENDS ${hermesc_EXE} InternalBytecode.js
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  VERBATIM
)

                                                                              
                                                                              
add_custom_command(
  OUTPUT InternalBytecode.inc
  COMMAND ${Python_EXECUTABLE} xxd.py ${CMAKE_CURRENT_BINARY_DIR}/InternalBytecode.hbc > ${CMAKE_CURRENT_BINARY_DIR}/InternalBytecode.inc
  DEPENDS xxd.py InternalBytecode.hbc
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  VERBATIM
)

set_source_files_properties(InternalBytecode.cpp
  PROPERTIES
  OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/InternalBytecode.inc
)

                                              
target_include_directories(hermesInternalBytecode
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
)
