/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/TimeLimitMonitor.h"

#include "hermes/Support/OSCompat.h"
#include "hermes/VM/Runtime.h"

#include <algorithm>

namespace hermes {
namespace vm {

std::shared_ptr<TimeLimitMonitor> TimeLimitMonitor::getOrCreate() {
                                                                            
             
  static struct Singleton {
                                           
    std::mutex guard;

                                                                                
                                                                              
                                                                            
                         
    std::weak_ptr<TimeLimitMonitor> weakMonitor;
  } *singleton = new Singleton();

  std::lock_guard<std::mutex> singletonGuard{singleton->guard};
  if (auto monitor = singleton->weakMonitor.lock()) {
    return monitor;
  }

                                                                    
                                    
  auto monitor = std::make_shared<TimeLimitMonitor>();
  singleton->weakMonitor = monitor;
  return monitor;
}

TimeLimitMonitor::TimeLimitMonitor() {
                                                                             
                                 
  timerThread_ = std::thread(&TimeLimitMonitor::timerLoop, this);
}

TimeLimitMonitor::~TimeLimitMonitor() {
  {
    std::unique_lock<std::mutex> lockGuard(lock_);
                                                                                
                                    
    enabled_ = false;
  }

                                                    
  timerLoopCond_.notify_all();

                                                 
  timerThread_.join();
}

void TimeLimitMonitor::watchRuntime(
    Runtime &runtime,
    std::chrono::milliseconds timeout) {
  {
    std::lock_guard<std::mutex> lockGuard(lock_);
                                          
    auto runtimeDeadline = std::chrono::steady_clock::now() + timeout;

                                                                             
                         
    watchedRuntimes_[&runtime] = runtimeDeadline;
  }

                                                                 
                                                                        
             
  timerLoopCond_.notify_all();
}

void TimeLimitMonitor::unwatchRuntime(Runtime &runtime) {
  std::lock_guard<std::mutex> lockGuard(lock_);
  watchedRuntimes_.erase(&runtime);

                                                                               
                                                                         
                                                       
}

void TimeLimitMonitor::timerLoop() {
  oscompat::set_thread_name("time-limit-monitor");

  std::unique_lock<std::mutex> lockGuard(lock_);

                                                                              
                                                          
  static constexpr Deadline NoDeadline = Deadline::max();

  while (enabled_) {
                                                                              
                     
    Deadline nextDeadline = NoDeadline;
    Deadline now = std::chrono::steady_clock::now();

    for (auto it = watchedRuntimes_.begin(), end = watchedRuntimes_.end();
         it != end;) {
      auto curr = it++;

      if (curr->second <= now) {
                                                      
        curr->first->triggerTimeoutAsyncBreak();

                                                                            
        watchedRuntimes_.erase(curr);
      } else {
                                                                            
                                                       
        nextDeadline = std::min(nextDeadline, curr->second);
      }
    }

    if (nextDeadline != NoDeadline) {
                                                                               
                                                                               
                                                                                
                                                                           
      timerLoopCond_.wait_until(lockGuard, nextDeadline);
    } else {
                                                                               
                                                                               
                                                                        
      timerLoopCond_.wait(lockGuard);
    }
  }
}

}                
}                    
