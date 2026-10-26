/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SAMPLINGTHREAD_H
#define HERMES_VM_SAMPLINGTHREAD_H

#include "hermes/VM/instrumentation/ProcessStats.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace hermes {
namespace vm {

                                                                         
                                                                          
class StatSamplingThread {
 public:
  using Clock = std::chrono::steady_clock;
  using Duration = Clock::duration;

                            
                                                             
  StatSamplingThread(Duration interval);

  ~StatSamplingThread();

                                                                       
  bool isRunning() const;

                                                                
  ProcessStats::Info stop();

                                                                            
                                                                              
  ProcessStats::Info info() const;

 private:
  using ExitGuard = std::unique_lock<std::mutex>;

                                                              
  bool stop_{false};

                  
  std::mutex mExit_;
  std::condition_variable exitMonitor_;

  Duration interval_;
  ProcessStats stats_;
  std::thread sampler_;

                                             
  void run();
};

}                
}                    

#endif                              
