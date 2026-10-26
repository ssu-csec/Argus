# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

set(HERMES_LINK_COMPONENTS LLVHSupport)

add_hermes_tool(hermesc
  hermesc.cpp
  ${ALL_HEADER_FILES}
  )

target_link_libraries(hermesc
  hermesCompilerDriver
  hermesAST
  hermesHBCBackend
  hermesBackend
  hermesInst
  hermesOptimizer
  hermesFrontend
  hermesParser
  hermesSupport
)

                                                             
                                                                               
                                                  
if(NOT CMAKE_CROSSCOMPILING)
                                                                             
  export(TARGETS hermesc FILE ${CMAKE_BINARY_DIR}/ImportHostCompilers.cmake NAMESPACE native-)
endif()

install(TARGETS hermesc
  RUNTIME DESTINATION bin
)
