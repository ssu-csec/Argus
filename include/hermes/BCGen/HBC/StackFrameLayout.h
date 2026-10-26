/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                                              
                                              
                                                                                
#ifndef HERMES_BCGEN_HBC_STACKFRAMELAYOUT_H
#define HERMES_BCGEN_HBC_STACKFRAMELAYOUT_H

#include <cstdint>

namespace hermes {
namespace hbc {

                                                                                
                                                                              
                                         
   
             
                                                     
                                                                    
          
                                          
                                          
                                                     
                                                                          
                                                 
                                                      
                                                    
                                                    
                                                                  
                                          
                                          
          
                                          
          
          
                                          
                                          
                                                     
                                                                          
                
   
                                                                           
                                                                             
                                                                          
   
                                                                                
                                                                            
                                                                     
                                                                            
   
                                                          
                                                                                
                                                                               
          
                                                   
                                                                     
                                                                        
                         
                                         
                                                                               
                                                  
                                                                                
                                    
   
                                                      
                                                                     
                                                                           
                                                                            
                                        
   
struct StackFrameLayout {
  enum {
                                           
    FirstLocal = 1,
                                             
    Scratch = 0,
                                                                               
                                             
    PreviousFrame = -1,
                                         
    SavedIP = -2,
                               
                                                                            
                                                                                
                                                                         
                                                                              
    SavedCodeBlock = -3,
                                                                             
    ArgCount = -4,
                                                                               
                                                                
    NewTarget = -5,
                                                                                
                                                                           
                                                                            
                                                                      
    CalleeClosureOrCB = -6,
                            
    ThisArg = -7,
                                    
    FirstArg = -8,

                                                                              
                                                                               
                                                                 
                                                     
    CallerExtraRegistersAtEnd = PreviousFrame - CalleeClosureOrCB + 1,

                                                                              
                               
    CalleeExtraRegistersAtStart = Scratch + 1,
  };

                                                                            
                                                                          
                                                                     
                                                                            
                                                                               
                                                                             
                                             
                                                                          
                                                                        
                     
  static uint32_t callerOutgoingRegisters(uint32_t numArgsExcludingThis) {
                                                                   
    uint32_t totalCount = CallerExtraRegistersAtEnd + numArgsExcludingThis + 1;
    return totalCount >= numArgsExcludingThis ? totalCount : UINT32_MAX;
  }
};

}                 
}                    

#endif                                       
