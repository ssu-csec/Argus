/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "simplestackpromotion"

#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/PassManager/Pass.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/Support/Debug.h"

STATISTIC(NumConstProm, "Number of loads of known constants promoted");
STATISTIC(NumVarCopy, "Number of variables copied to the stack");
STATISTIC(NumStoreOnlyVarDel, "Number of store only variables deleted");

namespace hermes {
namespace {
                                                                             
                                                         
                                        
bool tryPromoteConstVariable(Variable *var) {
  Value *storedVal = isStoreOnceVariable(var);

                                                               
  if (!storedVal || !llvh::isa<Literal>(storedVal))
    return false;

  LLVM_DEBUG(
      llvh::dbgs() << "Promoting const variable " << var->getName()
                   << " with literal value " << storedVal->getKindStr()
                   << "\n");
  IRBuilder::InstructionDestroyer destroyer;

                                                                               
  for (auto *U : var->getUsers()) {
    if (llvh::isa<LoadFrameInst>(U)) {
      U->replaceAllUsesWith(storedVal);
    } else {
      assert(llvh::isa<StoreFrameInst>(U) && "Access must be a load or store.");
    }
    destroyer.add(U);
  }
  NumConstProm++;
  return true;
}

                                                                             
                                                                              
                                                                            
                                                                        
                                              
bool tryCopyToStack(Variable *var) {
  auto *func = var->getParent()->getFunction();
  bool hasLoadInOwningFunction = false;
  bool hasStoreInInnerFunction = false;
  for (auto *U : var->getUsers()) {
    bool owningFunc = U->getParent()->getParent() == func;
    if (llvh::isa<LoadFrameInst>(U))
      hasLoadInOwningFunction |= owningFunc;
    else
      hasStoreInInnerFunction |= !owningFunc;
  }

                                                                              
                                                                                
                                                                          
                                                     
                                                                                
                                                                             
                                                  
  if (hasStoreInInnerFunction || !hasLoadInOwningFunction)
    return false;

  LLVM_DEBUG(llvh::dbgs() << "Promoting Variable: " << var->getName() << "\n");

  IRBuilder builder(func->getParent());

                                                                   
  builder.setInsertionPoint(&*func->begin()->begin());
  auto *stackVar = builder.createAllocStackInst(var->getName());

  IRBuilder::InstructionDestroyer destroyer;

  for (auto *U : var->getUsers()) {
                                                                          
    if (llvh::isa<LoadFrameInst>(U)) {
      if (U->getParent()->getParent() == func) {
        builder.setInsertionPoint(U);
        auto *loadStack = builder.createLoadStackInst(stackVar);
        U->replaceAllUsesWith(loadStack);
        destroyer.add(U);
      }
    } else {
                                                              
      auto *store = llvh::cast<StoreFrameInst>(U);
      builder.setInsertionPoint(store);
      builder.createStoreStackInst(store->getValue(), stackVar);
    }
  }

  NumVarCopy++;
  return true;
}

                                                              
                                                        
bool tryDeleteStoreOnlyVariable(Variable *var) {
  if (!var->hasUsers())
    return false;
  for (auto *U : var->getUsers())
    if (!llvh::isa<StoreFrameInst>(U))
      return false;
  LLVM_DEBUG(
      llvh::dbgs() << "Deleting stores to store-only Variable: "
                   << var->getName() << "\n");
  IRBuilder::InstructionDestroyer destroyer;
  for (auto *U : var->getUsers())
    destroyer.add(llvh::cast<StoreFrameInst>(U));
  NumStoreOnlyVarDel++;
  return true;
}

                                                  
                                                                                
                 
bool runOnFunction(Function *F) {
  bool changed = false;
  LLVM_DEBUG(
      llvh::dbgs() << "Promoting variables in " << F->getInternalNameStr()
                   << "\n");

  llvh::SmallVectorImpl<Variable *> &vars =
      F->getFunctionScopeDesc()->getMutableVariables();
  for (Variable *var : vars) {
                                                                                
                                                                          
    if (tryPromoteConstVariable(var)) {
      changed = true;
      continue;
    }
                                                                          
                                                                              
                                                
    changed |= tryCopyToStack(var);
                                                                           
                                                                       
                                                                          
                                                                         
    changed |= tryDeleteStoreOnlyVariable(var);
  }

                                        
  for (Variable *&var : vars) {
    if (!var->hasUsers()) {
      Value::destroy(var);
      var = nullptr;
      changed = true;
    }
  }
                                                            
  llvh::erase_if(vars, [](Variable *var) { return !var; });

  return changed;
}

                                                               
                                                          
                                                                             
                                                    
bool runSimpleStackPromotion(Module *M) {
  bool changed = false;
  for (Function &func : *M)
    changed |= runOnFunction(&func);
  return changed;
}

}             

std::unique_ptr<Pass> createSimpleStackPromotion() {
  class ThisPass : public ModulePass {
   public:
    explicit ThisPass() : ModulePass("SimpleStackPromotion") {}
    ~ThisPass() override = default;

    bool runOnModule(Module *M) override {
      return runSimpleStackPromotion(M);
    }
  };
  return std::make_unique<ThisPass>();
}
}                    
#undef DEBUG_TYPE
