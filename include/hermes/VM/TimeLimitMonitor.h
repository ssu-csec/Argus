/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_TIMELIMITMONITOR_H
#define HERMES_VM_TIMELIMITMONITOR_H

#include "llvh/ADT/DenseMap.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace hermes {
namespace vm {

class Runtime;

                                                                         
                                                                            
                                                                              
                                                                              
                                                  
class TimeLimitMonitor {
 public:
  using Deadline = std::chrono::steady_clock::time_point;

  ~TimeLimitMonitor();

                                                                              
                                  
  static std::shared_ptr<TimeLimitMonitor> getOrCreate();

                                                                               
                
  void watchRuntime(Runtime &runtime, std::chrono::milliseconds timeout);

                                             
  void unwatchRuntime(Runtime &runtime);

                                                                        
  const llvh::DenseMap<Runtime *, Deadline> &getWatchedRuntimes() const {
    return watchedRuntimes_;
  }

 private:
                                                                                
                                  
  void timerLoop();

                                                  
  std::mutex lock_;

                                                                                
                                   
  std::thread timerThread_;

                                                                                
                                         
  std::condition_variable timerLoopCond_;

                                                                    
  llvh::DenseMap<Runtime *, Deadline> watchedRuntimes_;

                                                                            
                                                            
  bool enabled_{true};

 public:
                                                                                
                       
  TimeLimitMonitor();
};

}                
}                    

#endif                                
