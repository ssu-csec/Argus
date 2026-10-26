/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_ERRORHANDLING_H
#define HERMES_SUPPORT_ERRORHANDLING_H

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/ErrorHandling.h"

#include <cstdlib>
#include <system_error>

                                                                          
                                                                             
                                                               
#define HERMES_EXTRA_DEBUG(x) x

namespace hermes {

                                                                    
enum class OOMError : int {
                                                            
  None = 0,
                                                       
                                                                     
               
  MaxHeapReached,
                                                                           
                                                  
  MaxStorageReached,
                                                                            
                                                                 
  Effective,
                                                                        
  SuperSegmentAlloc,
                                                                         
  CopyableVectorCapacityIntegerOverflow,
                                                                     
                       
  TestVMLimitReached,
};

const std::error_category &oom_category();
std::error_code make_error_code(OOMError err);
std::string convert_error_to_message(std::error_code code);

                                                                           
                                                                              
LLVM_ATTRIBUTE_NORETURN void hermes_fatal(const char *msg);
LLVM_ATTRIBUTE_NORETURN void hermes_fatal(const std::string &msg);
LLVM_ATTRIBUTE_NORETURN void hermes_fatal(
    llvh::StringRef prefix,
    std::error_code code);

}                    

                                                                      
             
namespace std {
template <>
struct is_error_code_enum<hermes::OOMError> : public std::true_type {};
}                 

#endif                                  
