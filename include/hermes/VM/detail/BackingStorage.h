/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_BACKING_STORAGE_H
#define HERMES_VM_BACKING_STORAGE_H

#include "hermes/Public/GCConfig.h"
#include "hermes/VM/AllocSource.h"

#include <tuple>

namespace hermes {
namespace vm {
namespace detail {

                                                                                
             
struct BackingStorage {
  friend void swap(BackingStorage &, BackingStorage &);

                                                                              
              
     
                                                                     
                                                                              
                                        
                                                   
  BackingStorage(
      gcheapsize_t sz,
      gcheapsize_t minSz,
      AllocSource src = AllocSource::VMAllocate);

                                                                        
                                                   
  BackingStorage(gcheapsize_t sz, AllocSource src = AllocSource::VMAllocate);

                                                                               
                                                 
  BackingStorage(gcheapsize_t sz, gcheapsize_t minSz, const char *name);

                                                                               
                                                 
  BackingStorage(gcheapsize_t sz, const char *name);

  BackingStorage() = default;
  BackingStorage(const BackingStorage &) = delete;
  BackingStorage(BackingStorage &&);

  BackingStorage &operator=(BackingStorage);

  ~BackingStorage();

                                                                          
     
                                                                 
                                                         
     
                                                  
                                              
                                                                  
     
                                                                               
                                           
  void markUnused(char *from, char *to);

                                                            
  inline char *lowLim() const {
    return lowLim_;
  }

                                                            
  inline char *hiLim() const {
    return hiLim_;
  }

  inline gcheapsize_t size() const {
    return hiLim_ - lowLim_;
  }

                                                                       
  bool contains(void *ptr) const;

 private:
  BackingStorage(
      const std::tuple<char *, void *, size_t> &alloc,
      AllocSource src);

  char *lowLim_;
  char *hiLim_;
                                                     
                                                                               
                           
  void *origPointer_;
  AllocSource src_;
};

}                    
}                
}                    

#endif                               
