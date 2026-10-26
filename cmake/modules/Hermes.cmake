# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)
include(CheckCXXSourceCompiles)
include(CMakePrintHelpers)

set(HERMES_TOOLS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin/${CMAKE_CFG_INTDIR}")

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  set(GCC 1)
  set(GCC_COMPATIBLE 1)
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CLANG 1)
  set(GCC_COMPATIBLE 1)
  if (CMAKE_CXX_SIMULATE_ID MATCHES "MSVC")
    set(CLANG_CL 1)
  endif ()
endif ()

                                                                              
                                                             
if (EMSCRIPTEN AND EMSCRIPTEN_FASTCOMP)
                                                      
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s BINARYEN_TRAP_MODE=clamp")
endif()

                                  
if (MSVC)
                                                                          
                                                                              
                                                                          
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:10000000")
elseif (MINGW)                      
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,16777216")
endif ()

if (WIN32)
  set(LLVM_HAVE_LINK_VERSION_SCRIPT 0)
  if (CYGWIN)
    set(LLVM_ON_WIN32 0)
    set(LLVM_ON_UNIX 1)
  else (CYGWIN)
    set(LLVM_ON_WIN32 1)
    set(LLVM_ON_UNIX 0)
  endif (CYGWIN)
else (WIN32)
  if (FUCHSIA OR UNIX)
    set(LLVM_ON_WIN32 0)
    set(LLVM_ON_UNIX 1)
    if (APPLE OR ${CMAKE_SYSTEM_NAME} MATCHES "AIX")
      set(LLVM_HAVE_LINK_VERSION_SCRIPT 0)
    else ()
      set(LLVM_HAVE_LINK_VERSION_SCRIPT 1)
    endif ()
  else (FUCHSIA OR UNIX)
    MESSAGE(SEND_ERROR "Unable to determine platform")
  endif (FUCHSIA OR UNIX)
endif (WIN32)

function(hermes_update_compile_flags name)
  get_property(sources TARGET ${name} PROPERTY SOURCES)
  if ("${sources}" MATCHES "\\.c(;|$)")
    set(update_src_props ON)
  endif ()

  set(flags "")

  if (NOT HERMES_ENABLE_EH_RTTI)
    if (GCC_COMPATIBLE)
      set(flags "${flags} -fno-exceptions -fno-rtti")
    elseif (MSVC)
      set(flags "${flags} /EHs-c- /GR-")
    endif ()
  endif ()

  if (update_src_props)
    foreach (fn ${sources})
      get_filename_component(suf ${fn} EXT)
      if ("${suf}" STREQUAL ".cpp")
        set_property(SOURCE ${fn} APPEND_STRING PROPERTY
          COMPILE_FLAGS "${flags}")
      endif ()
    endforeach ()
  else ()
                                                     
    set_property(TARGET ${name} APPEND_STRING PROPERTY
      COMPILE_FLAGS "${flags}")
  endif ()
endfunction()

function(add_hermes_library name)
  cmake_parse_arguments(ARG "" "" "LINK_LIBS" ${ARGN})
  add_library(${name} STATIC ${ARG_UNPARSED_ARGUMENTS})
  target_link_libraries(${name} ${ARG_LINK_LIBS} ${HERMES_LINK_COMPONENTS})
  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
  hermes_update_compile_flags(${name})
  if (HERMES_ENABLE_BITCODE)
    target_compile_options(${name} PUBLIC "-fembed-bitcode")
  endif ()
endfunction(add_hermes_library)

function(add_hermes_executable name)
  cmake_parse_arguments(ARG "" "" "LINK_LIBS" ${ARGN})
  add_executable(${name} ${ARG_UNPARSED_ARGUMENTS})
  target_link_libraries(${name} ${ARG_LINK_LIBS} ${HERMES_LINK_COMPONENTS})
  target_link_options(${name} PRIVATE ${HERMES_EXTRA_LINKER_FLAGS})
  hermes_update_compile_flags(${name})
endfunction(add_hermes_executable)

function(add_hermes_tool name)
  add_hermes_executable(${name} ${ARGN})

                                                                          
                                                
  if (NOT "${CMAKE_CFG_INTDIR}" STREQUAL ".")
    string(REPLACE ${CMAKE_CFG_INTDIR} "" HERMES_TOOLS_OUTPUT_DIR "${HERMES_TOOLS_OUTPUT_DIR}")
  endif ()

  set_property(TARGET ${name} PROPERTY RUNTIME_OUTPUT_DIRECTORY
    "${HERMES_TOOLS_OUTPUT_DIR}")
endfunction(add_hermes_tool)

                                                                         
                                                                            
                               
                                                                            
          
macro(find_global_package name)
                                                                              
                                                  
  if (((NOT "${CMAKE_SYSROOT}" STREQUAL "") OR
  (NOT "${CMAKE_FIND_ROOT_PATH}" STREQUAL "")) AND
  (NOT "${${name}_ROOT}" STREQUAL ""))

    list(APPEND CMAKE_FIND_ROOT_PATH "${${name}_ROOT}")
    find_package(${name} ${ARGN})
    list(REMOVE_AT CMAKE_FIND_ROOT_PATH -1)

  else ()

    find_package(${name} ${ARGN})

  endif ()
endmacro(find_global_package)

function(append value)
  foreach (variable ${ARGN})
    set(${variable} "${${variable}} ${value}" PARENT_SCOPE)
  endforeach (variable)
endfunction()

function(append_if condition value)
  if (${condition})
    foreach (variable ${ARGN})
      set(${variable} "${${variable}} ${value}" PARENT_SCOPE)
    endforeach (variable)
  endif ()
endfunction()

macro(add_flag_if_supported flag name)
  check_c_compiler_flag("-Werror ${flag}" "C_SUPPORTS_${name}")
  append_if("C_SUPPORTS_${name}" "${flag}" CMAKE_C_FLAGS)
  check_cxx_compiler_flag("-Werror ${flag}" "CXX_SUPPORTS_${name}")
  append_if("CXX_SUPPORTS_${name}" "${flag}" CMAKE_CXX_FLAGS)
endmacro()

function(add_flag_or_print_warning flag name)
  check_c_compiler_flag("-Werror ${flag}" "C_SUPPORTS_${name}")
  check_cxx_compiler_flag("-Werror ${flag}" "CXX_SUPPORTS_${name}")
  if (C_SUPPORTS_${name} AND CXX_SUPPORTS_${name})
    message(STATUS "Building with ${flag}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}" PARENT_SCOPE)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} ${flag}" PARENT_SCOPE)
  else ()
    message(WARNING "${flag} is not supported.")
  endif ()
endfunction()


 
                 
 
if (XCODE)
                                                              
                                                         
                                                              
                                                      
               
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_ABOUT_RETURN_TYPE "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_ABOUT_MISSING_NEWLINE "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_UNUSED_VALUE "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_UNUSED_VARIABLE "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_SIGN_COMPARE "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_UNUSED_FUNCTION "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_INITIALIZER_NOT_FULLY_BRACKETED "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_HIDDEN_VIRTUAL_FUNCTIONS "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_UNINITIALIZED_AUTOS "YES")
  set(CMAKE_XCODE_ATTRIBUTE_CLANG_WARN_BOOL_CONVERSION "YES")
  set(CMAKE_XCODE_ATTRIBUTE_CLANG_WARN_EMPTY_BODY "YES")
  set(CMAKE_XCODE_ATTRIBUTE_CLANG_WARN_ENUM_CONVERSION "YES")
  set(CMAKE_XCODE_ATTRIBUTE_CLANG_WARN_INT_CONVERSION "YES")
  set(CMAKE_XCODE_ATTRIBUTE_CLANG_WARN_CONSTANT_CONVERSION "YES")
  set(CMAKE_XCODE_ATTRIBUTE_GCC_WARN_NON_VIRTUAL_DESTRUCTOR "YES")
endif ()

if (MSVC)
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19.0)
                                                                          
                                                                          
    add_definitions("-D_DEBUG_POINTER_IMPL=")
  endif ()

  if (MSVC11)
    add_definitions(-D_VARIADIC_MAX=10)
  endif ()

                                                      
  add_definitions(
                                                                            
    -D_CRT_SECURE_NO_DEPRECATE
    -D_CRT_SECURE_NO_WARNINGS
    -D_CRT_NONSTDC_NO_DEPRECATE
    -D_CRT_NONSTDC_NO_WARNINGS
    -D_SCL_SECURE_NO_DEPRECATE
    -D_SCL_SECURE_NO_WARNINGS
  )

                                                                           
                       
                  
                   
        

                              
                                                  

                                                                             
                     
  append("/Zc:inline" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

                                   
  append("/Oi" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

                                    
  append("/Zc:rvalueCast" CMAKE_CXX_FLAGS)

  if (NOT CLANG_CL)
    set(msvc_warning_flags
                          
      -wd4141                                                                                              
      -wd4146                                                                                  
      -wd4180                                                                        
      -wd4244                                                                                    
      -wd4258                                                                                                              
      -wd4267                                                                               
      -wd4291                                                                                                                               
      -wd4345                                                                                                                               
      -wd4351                                                                                 
      -wd4355                                                           
      -wd4456                                                       
      -wd4457                                                           
      -wd4458                                                     
      -wd4459                                                           
      -wd4503                                                                               
      -wd4624                                                                                                                 
      -wd4722                                                                        
      -wd4800                                                                                    
      -wd4100                                           
      -wd4127                                                
      -wd4512                                                        
      -wd4505                                                          
      -wd4610                                               
      -wd4510                                                        
      -wd4702                              
      -wd4245                                      
      -wd4706                                                      
      -wd4310                                           
      -wd4701                                                      
      -wd4703                                                              
      -wd4389                                      
      -wd4611                                                                                      
      -wd4805                                                                    
      -wd4204                                                                             
      -wd4577                                                                                                                 
      -wd4091                                                                         
                                                                          
                                                                              
      -wd4592                                                                                      
      -wd4319                                                                          

                                                                            
                                                                                   
                                                                                  
                                          
                                                                                 
                                                              
      -wd4324                                                             

                          
      -w14062                                                                            

                                    
      -we4238                                                                               
      )
  endif (NOT CLANG_CL)
  foreach (flag ${msvc_warning_flags})
    append("${flag}" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
  endforeach (flag)
endif (MSVC)

if (GCC_COMPATIBLE)
                                                                           
                                                    
  if (NOT CLANG_CL)
    append("-Wall" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
  endif ()

  append("-Wextra -Wno-unused-parameter -Wwrite-strings" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
  append("-Wcast-qual" CMAKE_CXX_FLAGS)

                                                                           
                                                                         
                       
  check_cxx_compiler_flag("-Wmissing-field-initializers" CXX_SUPPORTS_MISSING_FIELD_INITIALIZERS_FLAG)
  if (CXX_SUPPORTS_MISSING_FIELD_INITIALIZERS_FLAG)
    if (CMAKE_COMPILER_IS_GNUCXX)
      append("-Wno-missing-field-initializers" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    else ()
      append("-Wmissing-field-initializers" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    endif ()
  endif ()

                                                                               
                    
  if (CMAKE_COMPILER_IS_GNUCXX)
    check_cxx_compiler_flag("-Wmaybe-uninitialized" MAYBE_UNINITIALIZED_FLAG)
    append_if(MAYBE_UNINITIALIZED_FLAG "-Wno-maybe-uninitialized" CMAKE_CXX_FLAGS)
    if (NOT MAYBE_UNINITIALIZED_FLAG)
                                                                                
                                                                                 
                                                
      check_cxx_compiler_flag("-Wuninitialized" UNINITIALIZED_FLAG)
      append_if(UNINITIALIZED_FLAG "-Wno-uninitialized" CMAKE_CXX_FLAGS)
    endif ()

                                                                                         
    check_cxx_compiler_flag("-Winit-list-lifetime" INIT_LIST_LIFETIME_FLAG)
    append_if(INIT_LIST_LIFETIME_FLAG "-Wno-init-list-lifetime" CMAKE_CXX_FLAGS)

                                                                                   
                                                                                    
    check_cxx_compiler_flag("-Wredundant-move" REDUNDANT_MOVE_FLAG)
    append_if(REDUNDANT_MOVE_FLAG "-Wno-redundant-move" CMAKE_CXX_FLAGS)
  endif ()

                                                   
  check_cxx_compiler_flag("-Wdeprecated-copy" DEPRECATED_COPY_FLAG)
  append_if(DEPRECATED_COPY_FLAG "-Wno-deprecated-copy" CMAKE_CXX_FLAGS)

                                                                          
                       
  check_cxx_compiler_flag("-Wclass-memaccess" CXX_SUPPORTS_CLASS_MEMACCESS_FLAG)
  append_if(CXX_SUPPORTS_CLASS_MEMACCESS_FLAG "-Wno-class-memaccess" CMAKE_CXX_FLAGS)

                                                                                
  check_cxx_compiler_flag("-Wnoexcept-type" CXX_SUPPORTS_NOEXCEPT_TYPE_FLAG)
  append_if(CXX_SUPPORTS_NOEXCEPT_TYPE_FLAG "-Wno-noexcept-type" CMAKE_CXX_FLAGS)

                                                                            
                                                                          
                                                                      
                                                                          
                                                                            
                                                                              
                                                                           
                        
  if (NOT CMAKE_COMPILER_IS_GNUCXX AND NOT WIN32)
    set(OLD_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -std=c++17 -Werror=non-virtual-dtor")
    CHECK_CXX_SOURCE_COMPILES("class base {public: virtual void anchor();protected: ~base();};
                             class derived final : public base { public: ~derived();};
                             int main() { return 0; }"
      CXX_WONT_WARN_ON_FINAL_NONVIRTUALDTOR)
    set(CMAKE_REQUIRED_FLAGS ${OLD_CMAKE_REQUIRED_FLAGS})
    append_if(CXX_WONT_WARN_ON_FINAL_NONVIRTUALDTOR
      "-Wnon-virtual-dtor" CMAKE_CXX_FLAGS)
  endif ()

                                                  
  add_flag_if_supported("-Wdelete-non-virtual-dtor" DELETE_NON_VIRTUAL_DTOR_FLAG)

                                                                  
                                                                          
                               
                                                                                               

                                                                         
                                      
  add_flag_if_supported("-ffp-contract=on" FP_CONTRACT_FLAG)

                                         
  check_cxx_compiler_flag("-Wrange-loop-analysis" RANGE_ANALYSIS_FLAG)
  append_if(RANGE_ANALYSIS_FLAG "-Wno-range-loop-analysis" CMAKE_CXX_FLAGS)
endif (GCC_COMPATIBLE)
