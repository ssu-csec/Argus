//===--- CrashRecoveryContext.h - Crash Recovery ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_CRASHRECOVERYCONTEXT_H
#define LLVM_SUPPORT_CRASHRECOVERYCONTEXT_H

#include "llvh/ADT/STLExtras.h"

namespace llvh {
class CrashRecoveryContextCleanup;

                                 
   
                                                                             
                                                                             
                                                                            
                                                                               
                          
   
                                                  
                                                                              
                                             
   
         
                                
   
                   
                                  
   
                                              
                                                              
          
   
                                      
        
            
   
                                                                              
                                                                                
                                              
class CrashRecoveryContext {
  void *Impl;
  CrashRecoveryContextCleanup *head;

public:
  CrashRecoveryContext() : Impl(nullptr), head(nullptr) {}
  ~CrashRecoveryContext();

                                                                          
               
                                            
  void registerCleanup(CrashRecoveryContextCleanup *cleanup);

  void unregisterCleanup(CrashRecoveryContextCleanup *cleanup);

                            
  static void Enable();

                             
  static void Disable();

                                                                        
                                             
  static CrashRecoveryContext *GetCurrent();

                                                                   
  static bool isRecoveringFromCrash();

                                                                          
                          
     
                                                                           
                                                                             
                                                                         
                                   
  bool RunSafely(function_ref<void()> Fn);
  bool RunSafely(void (*Fn)(void*), void *UserData) {
    return RunSafely([&]() { Fn(UserData); });
  }

                                                                         
                                                                           
                            
     
                                                   
     
                                                                           
                                           
  bool RunSafelyOnThread(function_ref<void()>, unsigned RequestedStackSize = 0);
  bool RunSafelyOnThread(void (*Fn)(void*), void *UserData,
                         unsigned RequestedStackSize = 0) {
    return RunSafelyOnThread([&]() { Fn(UserData); }, RequestedStackSize);
  }

                                                                     
                                                                     
  void HandleCrash();
};

                                            
   
                                                                                
                      
   
                                                                               
                             
class CrashRecoveryContextCleanup {
protected:
  CrashRecoveryContext *context;
  CrashRecoveryContextCleanup(CrashRecoveryContext *context)
      : context(context), cleanupFired(false) {}

public:
  bool cleanupFired;

  virtual ~CrashRecoveryContextCleanup();
  virtual void recoverResources() = 0;

  CrashRecoveryContext *getContext() const {
    return context;
  }

private:
  friend class CrashRecoveryContext;
  CrashRecoveryContextCleanup *prev, *next;
};

                                                                            
               
   
                                                         
                                          
   
                                                                        
                                         
   
                                                                             
                                                                               
template<typename Derived, typename T>
class CrashRecoveryContextCleanupBase : public CrashRecoveryContextCleanup {
protected:
  T *resource;
  CrashRecoveryContextCleanupBase(CrashRecoveryContext *context, T *resource)
      : CrashRecoveryContextCleanup(context), resource(resource) {}

public:
                              
                                                                 
                                                                             
                      
  static Derived *create(T *x) {
    if (x) {
      if (CrashRecoveryContext *context = CrashRecoveryContext::GetCurrent())
        return new Derived(context, x);
    }
    return nullptr;
  }
};

                                                                       
template <typename T>
class CrashRecoveryContextDestructorCleanup : public
  CrashRecoveryContextCleanupBase<CrashRecoveryContextDestructorCleanup<T>, T> {
public:
  CrashRecoveryContextDestructorCleanup(CrashRecoveryContext *context,
                                        T *resource)
      : CrashRecoveryContextCleanupBase<
            CrashRecoveryContextDestructorCleanup<T>, T>(context, resource) {}

  virtual void recoverResources() {
    this->resource->~T();
  }
};

                                                                     
template <typename T>
class CrashRecoveryContextDeleteCleanup : public
  CrashRecoveryContextCleanupBase<CrashRecoveryContextDeleteCleanup<T>, T> {
public:
  CrashRecoveryContextDeleteCleanup(CrashRecoveryContext *context, T *resource)
    : CrashRecoveryContextCleanupBase<
        CrashRecoveryContextDeleteCleanup<T>, T>(context, resource) {}

  void recoverResources() override { delete this->resource; }
};

                                                                           
template <typename T>
class CrashRecoveryContextReleaseRefCleanup : public
  CrashRecoveryContextCleanupBase<CrashRecoveryContextReleaseRefCleanup<T>, T> {
public:
  CrashRecoveryContextReleaseRefCleanup(CrashRecoveryContext *context,
                                        T *resource)
    : CrashRecoveryContextCleanupBase<CrashRecoveryContextReleaseRefCleanup<T>,
          T>(context, resource) {}

  void recoverResources() override { this->resource->Release(); }
};

                                                
   
                                              
                                                                     
   
                                                                                
                                                                             
                       
   
         
                                 
            
                                                     
                                                         
            
        
   
                   
                                  
   
                                              
                                                              
          
            
   
                                                                         
                                                                                
                                                                         
                                                                               
                                                                              
                                                                       
template <typename T, typename Cleanup = CrashRecoveryContextDeleteCleanup<T> >
class CrashRecoveryContextCleanupRegistrar {
  CrashRecoveryContextCleanup *cleanup;

public:
  CrashRecoveryContextCleanupRegistrar(T *x)
    : cleanup(Cleanup::create(x)) {
    if (cleanup)
      cleanup->getContext()->registerCleanup(cleanup);
  }

  ~CrashRecoveryContextCleanupRegistrar() { unregister(); }

  void unregister() {
    if (cleanup && !cleanup->cleanupFired)
      cleanup->getContext()->unregisterCleanup(cleanup);
    cleanup = nullptr;
  }
};
}                      

#endif                                       
