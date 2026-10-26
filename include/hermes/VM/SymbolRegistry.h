/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SYMBOLREGISTRY_H
#define HERMES_VM_SYMBOLREGISTRY_H

#include "hermes/Support/OptValue.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/SymbolID.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"

namespace hermes {
namespace vm {
struct SlotAcceptor;
class StringPrimitive;
class Runtime;

                                                                          
                                                                       
   
                                                                           
                                                                          
                         
   
                                                                       
                                                              
                                                     
   
                                                                           
                                                                               
                                                                               
                
class SymbolRegistry {
                                                         
                                                                              
                
  PinnedHermesValue stringMap_;

                                                                           
                                                                
                                                             
  llvh::DenseSet<SymbolID> registeredSymbols_{};

 public:
  explicit SymbolRegistry() {}

                                                           
                                                                
  void init(Runtime &runtime);

                                                            
  void markRoots(RootAcceptor &acceptor);

                                                                 
                                                            
                                                 
                                                                            
                              
  CallResult<SymbolID> getSymbolForKey(
      Runtime &runtime,
      Handle<StringPrimitive> key);

                                                                          
  bool hasSymbol(SymbolID symbol) const {
    return registeredSymbols_.find(symbol) != registeredSymbols_.end();
  }
};

}                
}                    

#endif
