/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
   
                                                                              
                                                                                
   
                                                                                
                                                                            
                                                                            
                                                                          
                                                                             
                                          
   
                                                                                
                                                                               
                                                             
   
                                                                                

#ifndef HERMES_SUPPORT_STACKOVERFLOWGUARD_H
#define HERMES_SUPPORT_STACKOVERFLOWGUARD_H

#include <cstddef>
#include "hermes/Support/OSCompat.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/raw_ostream.h"

namespace hermes {

#ifdef HERMES_CHECK_NATIVE_STACK

class StackOverflowGuard {
  explicit StackOverflowGuard(unsigned stackGap) : nativeStackGap(stackGap) {}

 public:
                                                             
  const void *nativeStackHigh{nullptr};
                                                            
                                                                             
                     
  size_t nativeStackSize{0};
                                                      
  unsigned nativeStackGap;

  static StackOverflowGuard nativeStackGuard(unsigned stackGap) {
    return StackOverflowGuard(stackGap);
  }

                                                                       
                                                                            
                                
  inline bool isOverflowing() {
                                                                      
                                                                      
                                            
                                                                  
                                                                       
                                                        
                                                                
                                                                          
    if (LLVM_LIKELY(!(
            (uintptr_t)nativeStackHigh - (uintptr_t)__builtin_frame_address(0) >
            nativeStackSize))) {
                                                          
                                                                              
                                                                     
                                                                         
                                  
      return false;
    }
                                                                         
                                             
    return isStackOverflowingSlowPath();
  }

                                                            
  inline void clearStackBounds() {
    nativeStackHigh = nullptr;
    nativeStackSize = 0;
  }

 private:
                                     
                                      
                                                                       
                       
  bool isStackOverflowingSlowPath() {
    auto [highPtr, size] = oscompat::thread_stack_bounds(nativeStackGap);
    nativeStackHigh = (const char *)highPtr;
    nativeStackSize = size;
    return LLVM_UNLIKELY(
        (uintptr_t)nativeStackHigh - (uintptr_t)__builtin_frame_address(0) >
        nativeStackSize);
  }
};

#else

class StackOverflowGuard {
  explicit StackOverflowGuard(size_t max) : maxCallDepth(max) {}

 public:
                                                              
                                      
  size_t callDepth{0};
                                                                 
  size_t maxCallDepth;

  static StackOverflowGuard depthCounterGuard(unsigned stackGap) {
    return StackOverflowGuard(stackGap);
  }

                                                                    
                   
  inline bool isOverflowing() {
    return callDepth > maxCallDepth;
  }
};

#endif

}                    

#endif                                       
