/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_COMPILER_H
#define HERMES_SUPPORT_COMPILER_H

#include "llvh/Support/Compiler.h"

#include <type_traits>

                                                                      
                                         

                                                                        
                                                                  
                           
#ifdef _MSC_VER
#define HERMES_EMPTY_BASES __declspec(empty_bases)
#else
#define HERMES_EMPTY_BASES
#endif

                                                                               
                                                                         
                                                                            
                                                                         
                                                                  
                                                                               
                                                
#if __has_attribute(warn_unused) || LLVM_GNUC_PREREQ(4, 9, 0)
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES __attribute__((warn_unused))
#else
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES
#endif

                                                                            
                                            
                                                                         
                     
                                                                    
#if __has_attribute(warn_unused_result) && defined(__clang__)
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE \
  __attribute__((warn_unused_result))
#else
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE
#endif

#if __has_attribute(format) && defined(__clang__)
#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check) \
  __attribute__((format(archetype, string_index, first_to_check)))
#else
#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check)
#endif

#ifndef LLVM_PTR_SIZE
#error "LLVM_PTR_SIZE needs to be defined"
#endif

                                                                        
                                                                        
                                                                     
#if !defined(HERMES_FBCODE_BUILD) && !defined(HERMES_LARGE_STACK_DEPTH) && \
    (defined(HERMES_UBSAN) || LLVM_ADDRESS_SANITIZER_BUILD)
#define HERMES_LIMIT_STACK_DEPTH
#endif

#if LLVM_THREAD_SANITIZER_BUILD
                                              
#ifdef __cplusplus
extern "C" {
#endif
void AnnotateIgnoreReadsBegin(const char *file, int line);
void AnnotateIgnoreReadsEnd(const char *file, int line);
void AnnotateIgnoreWritesBegin(const char *file, int line);
void AnnotateIgnoreWritesEnd(const char *file, int line);
void AnnotateBenignRaceSized(
    const char *file,
    int line,
    const volatile void *address,
    size_t size,
    const char *description);
void AnnotateThreadName(const char *file, int line, const char *name);
#ifdef __cplusplus
}
#endif

                                                                           
#define TsanIgnoreReadsBegin() AnnotateIgnoreReadsBegin(__FILE__, __LINE__)

                                   
#define TsanIgnoreReadsEnd() AnnotateIgnoreReadsEnd(__FILE__, __LINE__)

                                                                             
#define TsanIgnoreWritesBegin() AnnotateIgnoreWritesBegin(__FILE__, __LINE__)

                                    
#define TsanIgnoreWritesEnd() AnnotateIgnoreWritesEnd(__FILE__, __LINE__)

                                                        
                                                                      
                                                                                
                                                                         
                                     
#define TsanBenignRaceSized(address, size, description) \
  AnnotateBenignRaceSized(__FILE__, __LINE__, address, size, description)

                                                            
#define TsanThreadName(name) AnnotateThreadName(__FILE__, __LINE__, name)
#else
#define TsanIgnoreReadsBegin()
#define TsanIgnoreReadsEnd()
#define TsanBenignRaceSized(address, size, description)
#define TsanThreadName(name)
#endif

namespace hermes {

                                                                              
                                                                     
                                                                     
                                                                            
                                   
template <typename T>
T toRValue(T x) {
  return x;
}

}                    

#endif                             
