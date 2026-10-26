/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PUBLIC_CRASHMANAGER_H
#define HERMES_PUBLIC_CRASHMANAGER_H

#include <hermes/Public/HermesExport.h>

#include <cstddef>
#include <functional>

namespace hermes {
namespace vm {

                                                                            
                                         
class HERMES_EXPORT CrashManager {
 public:
                                                                             
                   
  using CallbackKey = int;
                                                                               
                                                                  
  using CallbackFunc = std::function<void(int fd)>;

                                                                         
                                                                       
                         
                                                            
  virtual void registerMemory(void *mem, size_t length) = 0;

                                                                                
  virtual void unregisterMemory(void *mem) = 0;

                                                                         
                                                                                
            
                                                                           
                                
                                                      
  virtual void setCustomData(const char *key, const char *val) = 0;

                                                                          
                                                                 
  virtual void removeCustomData(const char *key) = 0;

                                                                             
  virtual void setContextualCustomData(const char *key, const char *val) = 0;

                                                                    
                              
  virtual void removeContextualCustomData(const char *key) = 0;

                                                                        
                                                                             
                                                          
                                                         
                                                                             
                                                                              
  virtual CallbackKey registerCallback(CallbackFunc callback) = 0;

                                                                                
                                                                     
                                  
  virtual void unregisterCallback(CallbackKey key) = 0;

                           
  struct HeapInformation {
                                                     
    size_t used_{0};
                                                            
                                        
    size_t size_{0};
  };

                                  
                                                  
  virtual void setHeapInfo(const HeapInformation &heapInfo) = 0;

  virtual ~CrashManager();
};

                                     
class HERMES_EXPORT NopCrashManager final : public CrashManager {
 public:
  void registerMemory(void *, size_t) override {}
  void unregisterMemory(void *) override {}
  void setCustomData(const char *, const char *) override {}
  void removeCustomData(const char *) override {}
  void setContextualCustomData(const char *, const char *) override {}
  void removeContextualCustomData(const char *) override {}
  CallbackKey registerCallback(CallbackFunc             ) override {
    return 0;
  }
  void unregisterCallback(CallbackKey        ) override {}
  void setHeapInfo(const HeapInformation &             ) override {}

  ~NopCrashManager() override;
};

}                
}                    
#endif
