//===-- llvm/Support/ManagedStatic.h - Static Global wrapper ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the ManagedStatic class and the llvm_shutdown() function.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_MANAGEDSTATIC_H
#define LLVM_SUPPORT_MANAGEDSTATIC_H

#include <atomic>
#include <cstddef>

namespace llvh {

                                                     
template <class C> struct object_creator {
  static void *call() { return new C(); }
};

                                                     
   
template <typename T> struct object_deleter {
  static void call(void *Ptr) { delete (T *)Ptr; }
};
template <typename T, size_t N> struct object_deleter<T[N]> {
  static void call(void *Ptr) { delete[](T *)Ptr; }
};

                                                                              
                                                                            
                                                                              
                                                                           
                                                                              
                                                                            
                                                                  
                                                                               
                                                          
#if !defined(_MSC_VER) || (_MSC_VER >= 1925) || defined(__clang__)
#define LLVM_USE_CONSTEXPR_CTOR
#endif

                                                                      
class ManagedStaticBase {
protected:
#ifdef LLVM_USE_CONSTEXPR_CTOR
  mutable std::atomic<void *> Ptr{};
  mutable void (*DeleterFn)(void *) = nullptr;
  mutable const ManagedStaticBase *Next = nullptr;
#else
                                                                              
                              
  mutable std::atomic<void *> Ptr;
  mutable void (*DeleterFn)(void*);
  mutable const ManagedStaticBase *Next;
#endif

  void RegisterManagedStatic(void *(*creator)(), void (*deleter)(void*)) const;

public:
#ifdef LLVM_USE_CONSTEXPR_CTOR
  constexpr ManagedStaticBase() = default;
#endif

                                                                          
  bool isConstructed() const { return Ptr != nullptr; }

  void destroy() const;
};

                                                                                
                                                                               
                                                                         
                                                       
   
template <class C, class Creator = object_creator<C>,
          class Deleter = object_deleter<C>>
class ManagedStatic : public ManagedStaticBase {
public:
               
  C &operator*() {
    void *Tmp = Ptr.load(std::memory_order_acquire);
    if (!Tmp)
      RegisterManagedStatic(Creator::call, Deleter::call);

    return *static_cast<C *>(Ptr.load(std::memory_order_relaxed));
  }

  C *operator->() { return &**this; }

  const C &operator*() const {
    void *Tmp = Ptr.load(std::memory_order_acquire);
    if (!Tmp)
      RegisterManagedStatic(Creator::call, Deleter::call);

    return *static_cast<C *>(Ptr.load(std::memory_order_relaxed));
  }

  const C *operator->() const { return &**this; }
};

                                                                       
void llvm_shutdown();

                                                                
                                         
struct llvm_shutdown_obj {
  llvm_shutdown_obj() = default;
  ~llvm_shutdown_obj() { llvm_shutdown(); }
};

}                      

#endif                                
