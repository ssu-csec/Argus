/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PROCESSSTATS_H
#define HERMES_VM_PROCESSSTATS_H

#include "hermes/VM/instrumentation/ApproxIntegral.h"

#include "llvh/Support/raw_ostream.h"

#include <chrono>

namespace hermes {
namespace vm {

                                                                          
                                                                             
                                                                              
                                                                         
                                                                   
class ProcessStats {
 public:
  using Clock = std::chrono::steady_clock;

                                                         
  struct Info {
                                                                                
                     
    int64_t RSSkB;

                                                                              
                  
    int64_t VAkB;

                                                                
    void printJSON(llvh::raw_ostream &os);
  };

                                                                              
                                                                  
  ProcessStats();

                                                        
  inline Clock::time_point initTime() const;

                                                                                
                                                                      
  void sample(Clock::time_point now);

                                                               
  Info getIntegratedInfo() const;

 private:
                                                 
  const Clock::time_point initTime_;

                                                                          
  const Info initInfo_;

                                                                       
                                           
  ApproxIntegral iRSSkBms_;

                                                                           
                                           
  ApproxIntegral iVAkBms_;
};

ProcessStats::Clock::time_point ProcessStats::initTime() const {
  return initTime_;
}

}                
}                    

#endif                            
