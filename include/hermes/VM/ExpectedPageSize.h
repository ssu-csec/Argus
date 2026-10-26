/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_EXPECTEDPAGESIZE_H
#define HERMES_VM_EXPECTEDPAGESIZE_H

#include "hermes/Support/OSCompat.h"

#include <cstddef>

namespace hermes {
namespace vm {
namespace pagesize {

                                                               
                                                           
                                                                   
                                                                    
                                                                     
                                                              
                                                        
constexpr size_t kExpectedPageSize =
#if defined(__APPLE__)
    16 * 1024
#else
    4 * 1024
#endif
    ;

                                                                          
                                                                    
                                     
inline bool expectedPageSizeIsSafe() {
  return oscompat::page_size() <= kExpectedPageSize &&
      (kExpectedPageSize % oscompat::page_size()) == 0;
}

}                      
}                
}                    

#endif                                
