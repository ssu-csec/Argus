//===-- llvm/Support/TaskQueue.h - A TaskQueue implementation ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a crude C++11 based task queue.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TASK_QUEUE_H
#define LLVM_SUPPORT_TASK_QUEUE_H

#include "llvh/Config/llvm-config.h"
#include "llvh/Support/ThreadPool.h"
#include "llvh/Support/thread.h"

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <utility>

namespace llvh {
                                                                         
                                                                           
                                                             
class TaskQueue {
                                                                             
                                                                         
                                                                  
                                                                             
                   
  template <typename Callable> struct Task {
    using ResultTy = typename std::result_of<Callable()>::type;
    explicit Task(Callable C, TaskQueue &Parent)
        : C(std::move(C)), P(std::make_shared<std::promise<ResultTy>>()),
          Parent(&Parent) {}

    template<typename T>
    void invokeCallbackAndSetPromise(T*) {
      P->set_value(C());
    }

    void invokeCallbackAndSetPromise(void*) {
      C();
      P->set_value();
    }

    void operator()() noexcept {
      ResultTy *Dummy = nullptr;
      invokeCallbackAndSetPromise(Dummy);
      Parent->completeTask();
    }

    Callable C;
    std::shared_ptr<std::promise<ResultTy>> P;
    TaskQueue *Parent;
  };

public:
                                          
  TaskQueue(ThreadPool &Scheduler) : Scheduler(Scheduler) { (void)Scheduler; }

                                                                        
  ~TaskQueue() {
    Scheduler.wait();
    assert(Tasks.empty());
  }

                                                                                
                                                                         
                           
  template <typename Callable>
  std::future<typename std::result_of<Callable()>::type> async(Callable &&C) {
#if !LLVM_ENABLE_THREADS
    static_assert(false,
                  "TaskQueue requires building with LLVM_ENABLE_THREADS!");
#endif
    Task<Callable> T{std::move(C), *this};
    using ResultTy = typename std::result_of<Callable()>::type;
    std::future<ResultTy> F = T.P->get_future();
    {
      std::lock_guard<std::mutex> Lock(QueueLock);
                                                                         
                                                                          
                          
      if (IsTaskInFlight)
        Tasks.push_back(std::move(T));
      else {
        Scheduler.async(std::move(T));
        IsTaskInFlight = true;
      }
    }
    return std::move(F);
  }

private:
  void completeTask() {
                                                                          
                                                                     
                                                           
    std::function<void()> Continuation;
    {
      std::lock_guard<std::mutex> Lock(QueueLock);
      if (Tasks.empty()) {
        IsTaskInFlight = false;
        return;
      }

      Continuation = std::move(Tasks.front());
      Tasks.pop_front();
    }
    Scheduler.async(std::move(Continuation));
  }

                                               
  ThreadPool &Scheduler;

                                                                               
               
  bool IsTaskInFlight = false;

                                                        
  std::mutex QueueLock;

                                               
  std::deque<std::function<void()>> Tasks;
};
}                  

#endif                             
