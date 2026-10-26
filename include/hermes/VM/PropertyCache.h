/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef PROJECT_PROPERTYCACHE_H
#define PROJECT_PROPERTYCACHE_H

#include "hermes/VM/GCPointer.h"
#include "hermes/VM/SymbolID.h"
#include "hermes/VM/WeakRoot.h"

namespace hermes {
namespace vm {
using SlotIndex = uint32_t;

class HiddenClass;

                                        
                                                 
                                                                    
                          
struct PropertyCacheEntry {
                   
  WeakRoot<HiddenClass> clazz{nullptr};

                            
  SlotIndex slot{0};
};

}                
}                    
#endif                           
