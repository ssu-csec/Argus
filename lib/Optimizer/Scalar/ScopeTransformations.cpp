/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "scopetransformations"

#include "hermes/Optimizer/Scalar/ScopeTransformations.h"

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <vector>

namespace hermes {

void ScopeMerger::mergeInto(Function *F, ScopeDesc *parent, ScopeDesc *child) {
                             
  auto &newHome = parent->getMutableVariables();
  auto &oldHome = child->getMutableVariables();

  newHome.reserve(newHome.size() + oldHome.size());
  for (Variable *V : oldHome) {
    newHome.push_back(V);
    V->setParent(parent);
  }
  oldHome.clear();

                                    
  auto &innerScopesChild = child->getMutableInnerScopes();
  auto &innerScopesParent = parent->getMutableInnerScopes();

  innerScopesParent.reserve(innerScopesParent.size() + innerScopesChild.size());
  for (ScopeDesc *grandchild : innerScopesChild) {
    innerScopesParent.push_back(grandchild);
    grandchild->relocateTo(parent);
  }
  innerScopesChild.clear();

                                                                    
  auto findCreatorOf = [](ScopeDesc *S) -> ScopeCreationInst * {
    ScopeCreationInst *creator{};
    for (Instruction *user : S->getUsers()) {
      if (auto *SCI = llvh::dyn_cast<ScopeCreationInst>(user)) {
        assert(!creator && "Multiple instructions creating scope");
        creator = SCI;
      }
    }
    return creator;
  };

  ScopeCreationInst *createParent = findCreatorOf(parent);
  ScopeCreationInst *createChild = findCreatorOf(child);

  assert(
      (createParent || !createChild) &&
      "Inner scope can't be created without parent scope.");
  if (createParent && createChild) {
    assert(!llvh::isa<CreateScopeInst>(createChild));
    createChild->replaceAllUsesWith(createParent);
    createChild->eraseFromParent();
  }

                                           
  child->replaceAllUsesWith(parent);

                                                                                
                                                                           
                                       
  assert(mergedMap_.count(child) == 0);
  mergedMap_[child] = parent;
}

                                                         
static bool escapes(Function *F, Variable *var) {
  assert(
      F == var->getParent()->getFunction() &&
      "Variable should have been transferred.");

  for (Value *User : var->getUsers()) {
    if (auto *instr = llvh::dyn_cast<Instruction>(User)) {
      if (instr->getParent()->getParent() != F) {
        return true;
      }
    }
  }

  return false;
}

                                                                           
         
static bool hasAtLeastOneEscapingVar(Function *F, ScopeDesc *scopeDesc) {
  for (Variable *var : scopeDesc->getVariables()) {
    if (escapes(F, var)) {
      return true;
    }
  }

  return false;
}

ScopeMerger::HasEscapingVars ScopeMerger::optimizeScope(
    Function *F,
    ScopeDesc *scopeDesc) {
  assert(
      scopeDesc->getFunction() == F &&
      "should not try to optimize other function's scopes.");

                                               
  bool scopeDescHasEscapingVar = hasAtLeastOneEscapingVar(F, scopeDesc);

  auto &childrenScopes = scopeDesc->getMutableInnerScopes();
  std::vector<bool> merged(childrenScopes.size());
                                                                 
                                                                           
                                                                        
                                                                                
                      
  for (size_t i = 0, end = childrenScopes.size(); i < end; ++i) {
    ScopeDesc *childScope = childrenScopes[i];
                                                                             
                      
    if (childScope->getFunction() != F) {
      continue;
    }

                                                                              
                                
    HasEscapingVars childScopeHasEscapingVars = optimizeScope(F, childScope);

                                                                                
                                                                         
                                                                                
                                                                              
                                                                           
                                                                         
      
                     
                 
                    
                      
                        
                              
            
          
                    
        
      
                                                                                
                                                                        
                                                                            
                                                                                
                                                      
    if (!(childScope->getDynamic() &&
          childScopeHasEscapingVars == HasEscapingVars::Yes)) {
      mergeInto(F, scopeDesc, childScope);
                                                                           
                                                                  
      if (childScopeHasEscapingVars == HasEscapingVars::Yes) {
        scopeDescHasEscapingVar = true;
      }
                                  
      merged[i] = true;
    }
  }

                                                                               
                                              
  size_t curr = 0;
  for (size_t i = 0, end = childrenScopes.size(); i < end; ++i) {
    if (i >= merged.size() || !merged[i]) {
      childrenScopes[curr++] = childrenScopes[i];
    }
  }
  childrenScopes.resize(curr);

  return scopeDescHasEscapingVar ? HasEscapingVars::Yes : HasEscapingVars::No;
}

ScopeDesc *ScopeMerger::mergedScope(ScopeDesc *scopeDesc) {
  auto it = mergedMap_.find(scopeDesc);
  if (it == mergedMap_.end()) {
    return scopeDesc;
  }

                                                                              
  assert(it->second != scopeDesc);
  it->second = mergedScope(it->second);
  return it->second;
}

void ScopeMerger::updateSourceLevelScopes(Function *F) {
  for (BasicBlock &BB : *F) {
    for (Instruction &I : BB) {
      if (auto *S = I.getSourceLevelScope()) {
        I.setSourceLevelScope(mergedScope(S));
      }
    }
  }

  for (auto [childScope, mergedScope] : mergedMap_) {
    (void)mergedScope;
    Value::destroy(childScope);
  }
}

bool ScopeMerger::runOnFunction(Function *F) {
  mergedMap_.clear();
  optimizeScope(F, F->getFunctionScopeDesc());
  updateSourceLevelScopes(F);
  return !mergedMap_.empty();
}
}                    
