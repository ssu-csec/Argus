/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SERIALEXECUTOR_SERIALEXECUTOR_H
#define HERMES_SERIALEXECUTOR_SERIALEXECUTOR_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#if !defined(_WINDOWS) && !defined(__EMSCRIPTEN__)
#include <pthread.h>
#else
#include <thread>
#endif

namespace hermes {

                                                                          
                                                                                
                
class SerialExecutor {
 private:
                                          
#if !defined(_WINDOWS) && !defined(__EMSCRIPTEN__)
  pthread_t tid_;
#else
  std::thread workerThread_;
#endif

                                                         
  std::deque<std::function<void()>> tasks_;

                                               
  std::mutex mutex_;

                                                                              
                                          
  std::condition_variable wakeUpSig_;

                                            
  bool shouldStop_{false};

                                                                               
                                                                          
  void run();

#if !defined(_WINDOWS) && !defined(__EMSCRIPTEN__)
                                      
  static void *threadMain(void *p);
#endif

 public:
                                                                         
               
  SerialExecutor(size_t stackSize = 0);

                                                                                
                                                 
  ~SerialExecutor();

                                           
  void add(std::function<void()> task);
};
}                    

#endif                                          
