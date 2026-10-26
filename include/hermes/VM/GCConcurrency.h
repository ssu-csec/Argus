/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_GCCONCURRENCY_H
#define HERMES_VM_GCCONCURRENCY_H

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace hermes {
namespace vm {

                                                                              
                                                                             
                                       
static constexpr bool kConcurrentGC =
#if defined(HERMESVM_ALLOW_CONCURRENT_GC) && \
    (defined(HERMESVM_GC_HADES) || defined(HERMESVM_GC_RUNTIME))
                                                           
    sizeof(void *) == 8
#else
    false
#endif
    ;

namespace impl {

                                                                            
                                                     
                                               
                                                                               
                                                                             
                                                                              
                                                                             
                                                                              
          
                                                                            
                                                                              
                                                                   
template <typename T>
class FakeAtomic final {
 public:
  constexpr FakeAtomic() : data_{} {}
  constexpr FakeAtomic(T desired) : data_{desired} {}

  T load(std::memory_order order) const {
    (void)order;
    return data_;
  }

  void store(T desired, std::memory_order order) {
    (void)order;
    data_ = desired;
  }

  T fetch_add(T arg, std::memory_order order) {
    (void)order;
    const T oldData = data_;
    data_ += arg;
    return oldData;
  }

  T exchange(T arg, std::memory_order order) {
    (void)order;
    const T oldData = data_;
    data_ = arg;
    return oldData;
  }

  T fetch_sub(T arg, std::memory_order order) {
    (void)order;
    const T oldData = data_;
    data_ -= arg;
    return oldData;
  }

                                   
  FakeAtomic &operator=(const FakeAtomic &) = delete;

 private:
  T data_;
};

                                                                          
                                                                  
class DebugMutex {
 public:
  DebugMutex() : tid_() {}
  ~DebugMutex() = default;

  operator bool() const {
                                             
                                                                      
    return tid_.load(std::memory_order_relaxed) == std::this_thread::get_id();
  }

  void lock() {
    inner_.lock();
    depth_++;
    tid_.store(std::this_thread::get_id(), std::memory_order_relaxed);
  }

  void unlock() {
    assert(depth_ && "Should not unlock an unlocked mutex");
    assert(
        tid_.load(std::memory_order_relaxed) == std::this_thread::get_id() &&
        "Mutex should be acquired and unlocked on the same thread");
    depth_--;
    if (!depth_) {
      tid_.store(std::thread::id{}, std::memory_order_relaxed);
    }
    inner_.unlock();
  }

  uint32_t depth() const {
    assert(*this && "Must hold the inner mutex to call depth");
    return depth_;
  }

 private:
  std::recursive_mutex inner_;
                                                                              
                                                                               
                                                                               
                                                                        
                      
  std::atomic<std::thread::id> tid_;
  uint32_t depth_{0};
};

                                                                  
                                                                                
                                                    
class FakeMutex {
 public:
  explicit FakeMutex() = default;

  operator bool() const {
    return true;
  }

  uint32_t depth() const {
    return 1;
  }

  void lock() {}
  bool try_lock() {
    return true;
  }
  void unlock() {}
};

}                  

                                                            
template <typename T>
using AtomicIfConcurrentGC = typename std::
    conditional<kConcurrentGC, std::atomic<T>, impl::FakeAtomic<T>>::type;

using Mutex = std::conditional<
    kConcurrentGC,
#ifndef NDEBUG
    impl::DebugMutex
#else
    std::recursive_mutex
#endif
    ,
    impl::FakeMutex>::type;

}                
}                    

#endif
