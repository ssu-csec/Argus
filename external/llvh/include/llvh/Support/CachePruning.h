//=- CachePruning.h - Helper to manage the pruning of a cache dir -*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements pruning of a directory intended for cache storage, using
// various policies.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_CACHE_PRUNING_H
#define LLVM_SUPPORT_CACHE_PRUNING_H

#include "llvh/ADT/StringRef.h"
#include <chrono>

namespace llvh {

template <typename T> class Expected;

                                                               
                                                            
struct CachePruningPolicy {
                                                                             
                                                                           
                                                                            
              
  llvh::Optional<std::chrono::seconds> Interval = std::chrono::seconds(1200);

                                                                                
                                                                      
                               
  std::chrono::seconds Expiration = std::chrono::hours(7 * 24);      

                                                                             
                                                                         
                                                                                
                                                                               
                                    
  unsigned MaxSizePercentageOfAvailableSpace = 75;

                                                                                
                                                                               
                                                                   
  uint64_t MaxSizeBytes = 0;

                                                                               
                                        
     
                                                                     
                                                                                
                                                                             
                                                                                
                                                                           
                                                                        
  uint64_t MaxSizeFiles = 1000000;
};

                                                                               
                                                  
                                                                    
                                                                             
                                                          
Expected<CachePruningPolicy> parseCachePruningPolicy(StringRef PolicyStr);

                                                                     
                                                  
   
                                                                              
                                                                              
                          
bool pruneCache(StringRef Path, CachePruningPolicy Policy);

}                  

#endif
