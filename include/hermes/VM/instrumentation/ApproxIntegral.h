/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_INSTRUMENTATION_APPROXINTEGRAL_H
#define HERMES_VM_INSTRUMENTATION_APPROXINTEGRAL_H

#include <cassert>
#include <cstdint>

namespace hermes {
namespace vm {

                                                                               
                                                                               
          
   
                   
                                      
                                      
   
                
   
                                
   
                                                                              
                                                                            
                                                                              
                                                                          
                      
   
                                                                     
class ApproxIntegral {
 public:
                                     
     
                                                    
                                                                                
                                                                
     
                                                                              
                      
  inline void push(int64_t x, int64_t y);

                                                                               
  inline int64_t area() const;

 private:
                                                               
  int64_t xLast_{0};
  int64_t yLast_{0};

                                                                               
                                                                            
                           
  int64_t total_{0};
};

void ApproxIntegral::push(int64_t x, int64_t y) {
  assert(x >= xLast_ && "Points must be pushed in x-axis order.");

  total_ += (x - xLast_) * (y + yLast_);
  xLast_ = x;
  yLast_ = y;
}

int64_t ApproxIntegral::area() const {
  return total_ / 2;
}

}                
}                    

#endif                                              
