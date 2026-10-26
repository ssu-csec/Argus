/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_STORAGEPROVIDER_H
#define HERMES_VM_STORAGEPROVIDER_H

#include "llvh/Support/ErrorOr.h"

#include <limits>
#include <memory>

namespace hermes {
namespace vm {

                                                                               
              
class StorageProvider {
 public:
  StorageProvider() = default;
  virtual ~StorageProvider();

                     
        

                                                    
  static std::unique_ptr<StorageProvider> mmapProvider();

                                                       
  static std::unique_ptr<StorageProvider> contiguousVAProvider(size_t size);

                                 
  static std::unique_ptr<StorageProvider> mallocProvider();

        

                                        
  llvh::ErrorOr<void *> newStorage() {
    return newStorage(nullptr);
  }
                                                                              
                                                                            
                                                        
  llvh::ErrorOr<void *> newStorage(const char *name);

                                                                                
                                                                            
                                              
  void deleteStorage(void *storage);

                                                                         
  size_t numSucceededAllocs() const;

                                                                        
               
  size_t numFailedAllocs() const;

                                                                    
  size_t numDeletedAllocs() const;

                                                                          
                  
  size_t numLiveAllocs() const;

 protected:
  virtual llvh::ErrorOr<void *> newStorageImpl(const char *name) = 0;
  virtual void deleteStorageImpl(void *storage) = 0;

 private:
  size_t numSucceededAllocs_{0};
  size_t numFailedAllocs_{0};
  size_t numDeletedAllocs_{0};
};

                                                               
                                                                   
                                                              
                                                                            
                                                                                
                                                                 
                                                       
                                                              
                                       
llvh::ErrorOr<std::pair<void *, size_t>>
vmAllocateAllowLess(size_t sz, size_t minSz, size_t alignment);

}                
}                    

#endif
