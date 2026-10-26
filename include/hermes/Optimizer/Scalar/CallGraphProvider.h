/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_CALLGRAPH_PROVIDER_H
#define HERMES_OPTIMIZER_SCALAR_CALLGRAPH_PROVIDER_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"
#include "llvh/ADT/DenseSet.h"

namespace hermes {

class CallInst;
class Function;

                                                                         
                                                                   
                                                                   
                                                               
class CallGraphProvider {
 public:
                                                                   
                                                                    
                                                                
                                   
  llvh::DenseMap<CallInst *, llvh::DenseSet<Function *>> callees_;

                                                                 
                                                                
                                                                       
                                                                    
                                                                  
                                                                
  llvh::DenseMap<Function *, llvh::DenseSet<CallInst *>> callsites_;

                                                              
                                                                   
                                 
  bool hasUnknownCallees(CallInst *CI) {
    return callees_.count(CI) == 0;
  }

                                                                 
                                                                
                       
  bool hasUnknownCallsites(Function *F) {
    return callsites_.count(F) == 0;
  }

                                                                     
                                                              
                                                                  
                                                      
  llvh::DenseSet<Function *> &getKnownCallees(CallInst *CI) {
    auto a = callees_.find(CI);
    assert(a != callees_.end() && "Did not find CallInst in callees map.");
    return a->second;
  }

                                                                  
                                                                 
                                                                
                                                       
  llvh::DenseSet<CallInst *> &getKnownCallsites(Function *F) {
    auto a = callsites_.find(F);
    assert(a != callsites_.end() && "Did not find Function in callsites map.");
    return a->second;
  }

                                                                      
                                                                         

                                                                            
                                                                  
  llvh::DenseMap<LoadPropertyInst *, llvh::DenseSet<Instruction *>> receivers_;

  bool hasUnknownReceivers(LoadPropertyInst *LPI) {
    return receivers_.count(LPI) == 0;
  }

  llvh::DenseSet<Instruction *> &getKnownReceivers(LoadPropertyInst *LPI) {
    auto a = receivers_.find(LPI);
    assert(a != receivers_.end() && "Did not find LPI in receivers map.");
    return a->second;
  }

                                                                       
                                                                      
  llvh::DenseMap<Instruction *, llvh::DenseSet<Instruction *>> stores_;

  bool hasUnknownStores(Instruction *I) {
    return stores_.count(I) == 0;
  }

  llvh::DenseSet<Instruction *> &getKnownStores(Instruction *I) {
    assert(llvh::isa<AllocObjectInst>(I) || llvh::isa<AllocArrayInst>(I));
    auto a = stores_.find(I);
    assert(a != stores_.end() && "Did not find I in stores map");
    return a->second;
  }
};
}                    

#endif                                                
