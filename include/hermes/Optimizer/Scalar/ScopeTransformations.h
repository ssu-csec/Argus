/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_SCOPETRANSFORMATIONS_H
#define HERMES_OPTIMIZER_SCALAR_SCOPETRANSFORMATIONS_H

#include "hermes/Optimizer/PassManager/Pass.h"

#include "hermes/IR/IR.h"
#include "llvh/ADT/DenseSet.h"

namespace hermes {

                                           
class ScopeMerger : public FunctionPass {
 public:
  explicit ScopeMerger() : FunctionPass("ScopeMerger") {}
  ~ScopeMerger() override = default;

  bool runOnFunction(Function *F) override;

 private:
                                                                          
                                            
                                          
  void mergeInto(Function *F, ScopeDesc *parent, ScopeDesc *child);

                                                                              
                                                                                
                                                                      
  enum class HasEscapingVars { No, Yes };
  HasEscapingVars optimizeScope(Function *F, ScopeDesc *scopeDesc);

                                                                               
                                                                               
                                                                         
  ScopeDesc *mergedScope(ScopeDesc *scopeDesc);

                                                                             
                
  void updateSourceLevelScopes(Function *F);

                                            
  llvh::DenseMap<ScopeDesc *, ScopeDesc *> mergedMap_;
};

}                    

#endif                                                  
