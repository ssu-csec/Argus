/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PROFILER_GLOBALPROFILER_H
#define HERMES_VM_PROFILER_GLOBALPROFILER_H

#include "hermes/VM/Profiler/SamplingProfiler.h"

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE

#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_set>

namespace hermes {
namespace vm {
namespace sampling_profiler {
                                                                         
                                                                               
                  
   
                                                                           
                                                         
                                   
   
                                                                        
                                                                        
                                                                
   
                                                                          
                                                                  
                                                                     
                                                                     
                            
   
                                                                
                                                            
   
                                                     
                                                              
                                                                      
                                                                            
                                                                         
                               
   
                                                                     
                                                                       
                                                       
                                                                        
                                                                          
                                                                             
             
   
                                                      
                                                                   
struct Sampler {
  virtual ~Sampler();

                                                               
  std::mutex profilerLock_;

                                                                           
                 
  std::unordered_set<SamplingProfiler *> profilers_;

                                                                     
  bool enabled_{false};

                                                                    
                                        
                                                   
  uint32_t sampledStackDepth_{0};
                                                                  
                                                         
                                                                             
                                           
  SamplingProfiler::StackTrace sampleStorage_{SamplingProfiler::kMaxStackDepth};

                                                                            
                                                                       
                   
  std::thread timerThread_;

                                                                             
                      
  std::condition_variable enabledCondVar_;

                                                     
                                                                    
  bool sampleStacks();

                                     
  void timerLoop(double meanHzFreq);

                                                         
  bool enable(double meanHzFreq);
  bool disable();

                                                                        
  bool enabled();

                                                                 
                                                                      
                                  
  void registerRuntime(SamplingProfiler *profiler);

                                                                      
                  
  void unregisterRuntime(SamplingProfiler *profiler);

                                              
  static Sampler *get();

 protected:
  Sampler() = default;

  void walkRuntimeStack(SamplingProfiler *profiler);

 private:
                                  
  bool sampleStack(SamplingProfiler *localProfiler);

                             

                                                                               
                                                                     
                                                                         
                                                   
  bool platformEnable();

                                                                           
                                                                             
                                                                         
                                                    
  bool platformDisable();

                                                                        
                                                                           
  void platformRegisterRuntime(SamplingProfiler *profiler);

                                                                               
                                                                             
                                                 
  void platformUnregisterRuntime(SamplingProfiler *profiler);

                                                                             
                                                         
                                                                            
  void platformPostSampleStack(SamplingProfiler *localProfiler);

                                                                               
                                                                              
                                                   
  bool platformSuspendVMAndWalkStack(SamplingProfiler *profiler);
};
}                               
}                
}                    

#endif                                        

#endif                                       
