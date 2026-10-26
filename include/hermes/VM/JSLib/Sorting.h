/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSLIB_SORTING_H
#define HERMES_VM_JSLIB_SORTING_H

#include <cstdint>

#include "hermes/VM/CallResult.h"

                                                                              
                                                                             
                                                                           
                                                                              
                                                                           

namespace hermes {
namespace vm {

                                                                  
                                                                   
                                                                     
                                                              
            
class SortModel {
 public:
                                      
  virtual ExecutionStatus swap(uint32_t a, uint32_t b) = 0;

                                                
                                                                        
  virtual CallResult<int> compare(uint32_t a, uint32_t b) = 0;

  virtual ~SortModel() = 0;
};

                                                                             
                                                                           
ExecutionStatus quickSort(SortModel *sm, uint32_t begin, uint32_t end);

}                
}                    

#endif
