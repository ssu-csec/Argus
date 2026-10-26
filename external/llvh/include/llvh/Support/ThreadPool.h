//===-- llvm/Support/ThreadPool.h - A ThreadPool implementation -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a crude C++11 based thread pool.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_THREAD_POOL_H
#define LLVM_SUPPORT_THREAD_POOL_H

#include "llvh/Config/llvm-config.h"
#include "llvh/Support/thread.h"

#include <future>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <utility>

namespace llvh {

                                                                           
            
   
                                                                             
                                      
class ThreadPool {
public:
  using TaskTy = std::function<void()>;
  using PackagedTaskTy = std::packaged_task<void()>;

                                                          
                             
  ThreadPool();

                                                
  ThreadPool(unsigned ThreadCount);

                                                                              
  ~ThreadPool();

                                                                               
                                                                               
  template <typename Function, typename... Args>
  inline std::shared_future<void> async(Function &&F, Args &&... ArgList) {
    auto Task =
        std::bind(std::forward<Function>(F), std::forward<Args>(ArgList)...);
    return asyncImpl(std::move(Task));
  }

                                                                               
                                                                               
  template <typename Function>
  inline std::shared_future<void> async(Function &&F) {
    return asyncImpl(std::forward<Function>(F));
  }

                                                                              
                                                                         
  void wait();

private:
                                                                               
                                                                               
  std::shared_future<void> asyncImpl(TaskTy F);

                       
  std::vector<llvh::thread> Threads;

                                              
  std::queue<PackagedTaskTy> Tasks;

                                                          
  std::mutex QueueLock;
  std::condition_variable QueueCondition;

                                              
  std::mutex CompletionLock;
  std::condition_variable CompletionCondition;

                                                      
  std::atomic<unsigned> ActiveThreads;

#if LLVM_ENABLE_THREADS                                      
                                                                    
  bool EnableFlag;
#endif
};
}

#endif                              
