/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "inline"
#include "hermes/Optimizer/Scalar/Inlining.h"

#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/Support/Debug.h"

STATISTIC(NumInlinedCalls, "Number of inlined calls");

namespace hermes {

                                                                       
                                                                           
static llvh::SmallVector<BasicBlock *, 4> orderDFS(Function *F) {
  llvh::SmallVector<BasicBlock *, 4> order{};
  llvh::SmallVector<BasicBlock *, 4> stack{};
  llvh::SmallDenseSet<BasicBlock *> visited{};

  stack.push_back(&*F->begin());
  while (!stack.empty()) {
    BasicBlock *BB = stack.back();
    stack.pop_back();
    if (!visited.insert(BB).second)
      continue;

    order.push_back(BB);

    for (auto *succ : successors(BB))
      stack.push_back(succ);
  }

  return order;
}

                                                                        
              
static bool canBeInlined(Function *F, Function *intoFunction) {
                                                                              
                                                                                
  if (F->getDefinitionKind() == Function::DefinitionKind::ES6Constructor ||
      F->getDefinitionKind() == Function::DefinitionKind::ES6DerivedConstructor)
    return false;

                                                       
                                                          
  if (!F->getFunctionScopeDesc()->getVariables().empty()) {
    return false;
  }

                                                          
  for (const ScopeDesc *inner : F->getFunctionScopeDesc()->getInnerScopes()) {
    if (inner->getFunction() == F) {
      return false;
    }
  }

                                                                            
                                                                    
  if (F->isStrictMode() != intoFunction->isStrictMode())
    return false;

  for (BasicBlock *oldBB : orderDFS(F)) {
    for (auto &I : *oldBB) {
      switch (I.getKind()) {
        case ValueKind::CreateArgumentsInstKind:
                                                                              
                 
        case ValueKind::GetNewTargetInstKind:
                                                                              
        case ValueKind::CreateFunctionInstKind:
        case ValueKind::CreateGeneratorInstKind:
                  
          return false;
        case ValueKind::CallBuiltinInstKind:
          if (cast<CallBuiltinInst>(&I)->getBuiltinIndex() ==
              BuiltinMethod::HermesBuiltin_copyRestArgs) {
            return false;
          }
          break;
        default:
          break;
      }
    }
  }

  return true;
}

                                                                               
                                                                
                                     
static void cloneScopesInto(
    Function *F,
    ScopeDesc *currScopeDesc,
    ScopeDesc *newScope,
    llvh::DenseMap<Value *, Value *> &operandMap) {
  if (currScopeDesc->getFunction() != F) {
                                                              
    return;
  }

                                                          
  operandMap[currScopeDesc] = newScope;
  for (Variable *V : currScopeDesc->getVariables()) {
    operandMap[V] = V->cloneIntoNewScope(newScope);
  }

                                                                                
              
  for (ScopeDesc *inner : currScopeDesc->getInnerScopes()) {
    ScopeDesc *newInnerScope = newScope->createInnerScope();
    newInnerScope->setFunction(newScope->getFunction());
    cloneScopesInto(F, inner, newInnerScope, operandMap);
  }
}

                                                                            
                                                           
                                   
                                                                      
                                   
                                                           
                                                    
static Value *inlineFunction(
    IRBuilder &builder,
    Function *F,
    CallInst *CI,
    BasicBlock *nextBlock) {
  Function *intoFunction = builder.getInsertionBlock()->getParent();

                                                                              
          
  llvh::DenseMap<Value *, Value *> operandMap{};

                                                          
  llvh::SmallVector<Value *, 8> translatedOperands{};

                                                            
  llvh::SmallVector<PhiInst *, 4> phis{};

                           
  BasicBlock *returnBlock = builder.createBasicBlock(intoFunction);
  Value *returnValue = nullptr;
                                                                              
                    
  BasicBlock *returnFrom = nullptr;

                                                                              
  const uint32_t statementIndexOffset = intoFunction->getStatementCount()
      ? *intoFunction->getStatementCount()
      : 0;
                                                                        
  const uint32_t inlineStatementCount =
      F->getStatementCount() ? *F->getStatementCount() : 0;
  intoFunction->setStatementCount(statementIndexOffset + inlineStatementCount);

                        

  Value *thisParam;
  if (!F->isStrictMode()) {
                                                                          
    thisParam = builder.createCoerceThisNSInst(CI->getThis());
  } else {
    thisParam = CI->getThis();
  }

  operandMap[F->getThisParameter()] = thisParam;
  {
    unsigned argIndex = 1;
    for (Parameter *param : F->getParameters()) {
      operandMap[param] = argIndex < CI->getNumArguments()
          ? CI->getArgument(argIndex)
          : cast<Value>(builder.getLiteralUndefined());
      ++argIndex;
    }
  }

                                      
  cloneScopesInto(
      F,
      F->getFunctionScopeDesc(),
      F->getFunctionScopeDesc()->getParent(),
      operandMap);

  auto order = orderDFS(F);

                          
  for (BasicBlock *oldBB : order) {
    operandMap[oldBB] = builder.createBasicBlock(intoFunction);
  }

                               
  builder.createBranchInst(cast<BasicBlock>(operandMap[order[0]]));

                                                                         
                          
  auto translateOperands = [&](Instruction *I) {
    translatedOperands.clear();

    for (unsigned i = 0, e = I->getNumOperands(); i != e; ++i) {
      Value *oldOp = I->getOperand(i);
      Value *newOp = nullptr;

      if (auto *oldV = llvh::dyn_cast<Variable>(oldOp)) {
                                                                        
                    
        auto newVarIt = operandMap.find(oldV);
        if (newVarIt != operandMap.end()) {
                                                                             
                      
          newOp = newVarIt->second;
        } else {
                                                                     
          assert(
              oldV->getParent()->getFunction() != F &&
              "old variable in inlinee should have been cloned.");
          newOp = oldOp;
        }
      } else if (
          llvh::isa<Instruction>(oldOp) || llvh::isa<Parameter>(oldOp) ||
          llvh::isa<BasicBlock>(oldOp) || llvh::isa<ScopeDesc>(oldOp)) {
                                                   
        newOp = operandMap[oldOp];
        assert(newOp && "operand not visited before instruction");
      } else if (
          llvh::isa<Label>(oldOp) || llvh::isa<Literal>(oldOp) ||
          llvh::isa<EmptySentinel>(oldOp)) {
                                              
        newOp = oldOp;
      } else {
        llvh::errs() << "INVALID OPERAND FOR : " << I->getKindStr() << '\n';
        llvh::errs() << "INVALID OPERAND     : " << oldOp->getKindStr() << '\n';
        llvm_unreachable("unexpected operand kind");
      }

      translatedOperands.push_back(newOp);
    }
  };

  ScopeCreationInst *inlineeParentScopeCreation{};

                                                                                
                                                                             
                                        
  auto getInlineeParentScopeCreation = [F, &inlineeParentScopeCreation]() {
                                                                         
                                       
    if (!inlineeParentScopeCreation) {
                                                                             
                                                                           
      for (Instruction *user :
           F->getFunctionScopeDesc()->getParent()->getUsers()) {
        if (auto *SCI = llvh::dyn_cast<ScopeCreationInst>(user)) {
                                                                              
                                                                           
                               
          assert(!inlineeParentScopeCreation && "scope should be created once");
          inlineeParentScopeCreation = SCI;
        }
      }
    }

                                                                             
                                 
    assert(
        inlineeParentScopeCreation && "F's scope's parent scope should exist!");
    return inlineeParentScopeCreation;
  };

                                                                        
                                                        
  for (BasicBlock *oldBB : order) {
    BasicBlock *newBB = cast<BasicBlock>(operandMap[oldBB]);
    assert(newBB->empty() && "BB visited more than once");

    builder.setInsertionBlock(newBB);

    for (auto &I : *oldBB) {
                                

      if (auto *phi = llvh::dyn_cast<PhiInst>(&I)) {
                                                                              
                                                                       
                                               
        translatedOperands.clear();
        translatedOperands.resize(phi->getNumOperands(), nullptr);
        phis.push_back(phi);
      } else {
        translateOperands(&I);
      }

      Instruction *newInst;

      if (llvh::isa<ReturnInst>(I)) {
                                                                              
        assert(
            translatedOperands.size() == 1 &&
            "ReturnInst expected to have 1 operand");
        newInst = builder.createBranchInst(returnBlock);
        builder.setInsertionBlock(returnBlock);

        if (!returnValue) {
                                                                            
                                           
          returnValue = translatedOperands[0];
          returnFrom = newBB;
        } else {
          if (returnBlock->empty()) {
                                                                            
                                
            auto *phi = builder.createPhiInst();
            phi->addEntry(returnValue, returnFrom);
            returnValue = phi;
            returnFrom = nullptr;
          }

                                        
          cast<PhiInst>(returnValue)->addEntry(translatedOperands[0], newBB);
        }
      } else if (auto *csi = llvh::dyn_cast<CreateScopeInst>(&I)) {
                                                                             
                                                                              
                                                                              
                 
        ScopeCreationInst *inlineeParentScopeCreation =
            getInlineeParentScopeCreation();
        (void)csi;
        assert(
            inlineeParentScopeCreation->getCreatedScopeDesc() ==
                operandMap[csi->getCreatedScopeDesc()] &&
            "inlinee scope should have been cloned into its parent");
        newInst = inlineeParentScopeCreation;
      } else {
        newInst = builder.cloneInst(&I, translatedOperands);
                                                            
        if (ScopeDesc *sourceLevelScope = I.getSourceLevelScope()) {
          auto *translatedScope =
              llvh::cast<ScopeDesc>(operandMap[sourceLevelScope]);
          assert(translatedScope && "source level scope not cloned");
          newInst->setSourceLevelScope(translatedScope);
        }
      }

      operandMap[&I] = newInst;

                                                                          
      newInst->setStatementIndex(
          newInst->getStatementIndex() + statementIndexOffset);
    }
  }

                                                                          
                   
  for (PhiInst *oldPhi : phis) {
    translateOperands(oldPhi);

    auto *newPhi = cast<PhiInst>(operandMap[oldPhi]);
    for (unsigned i = 0, e = translatedOperands.size(); i != e; ++i)
      newPhi->setOperand(translatedOperands[i], i);
  }

  builder.setInsertionBlock(returnBlock);
  builder.createBranchInst(nextBlock);

  return returnValue ? returnValue : cast<Value>(builder.getLiteralUndefined());
}

bool Inlining::runOnModule(Module *M) {
  if (!M->getContext().getOptimizationSettings().inlining)
    return false;

  bool changed = false;

  for (Function &F : *M) {
    for (Instruction *I : F.getUsers()) {
      auto *CFI = llvh::dyn_cast<CreateFunctionInst>(I);
      if (!CFI)
        continue;

                                                                        
                                                                                
                                                            

      if (!CFI->hasOneUser() ||
          CFI->getUsers()[0]->getKind() != ValueKind::CallInstKind) {
        continue;
      }
      auto *CI = cast<CallInst>(CFI->getUsers()[0]);
      if (!isDirectCallee(CFI, CI))
        continue;

      Function *intoFunction = CI->getParent()->getParent();

      auto *FC = CFI->getFunctionCode();
      if (!canBeInlined(FC, intoFunction))
        continue;

      LLVM_DEBUG(
          llvh::dbgs() << "Inlining function '" << FC->getInternalNameStr()
                       << "' ";
          FC->getContext().getSourceErrorManager().dumpCoords(
              llvh::dbgs(), FC->getSourceRange().Start);
          llvh::dbgs() << " into function '"
                       << intoFunction->getInternalNameStr() << "' ";
          FC->getContext().getSourceErrorManager().dumpCoords(
              llvh::dbgs(), intoFunction->getSourceRange().Start);
          llvh::dbgs() << "\n";);

      IRBuilder builder(M);

                                                                            
                          
      BasicBlock *nextBlock = builder.createBasicBlock(intoFunction);
      builder.setInsertionBlock(nextBlock);

                                           
      auto it = CI->getIterator();
      ++it;                       
      auto e = CI->getParent()->end();
      while (it != e)
        builder.transferInstructionToCurrentBlock(&*it++);

                              
      builder.setInsertionPointAfter(CI);

      auto *returnValue = inlineFunction(builder, FC, CI, nextBlock);
      CI->replaceAllUsesWith(returnValue);
      CI->eraseFromParent();

      ++NumInlinedCalls;
      changed = true;
    }
  }

  return changed;
}

std::unique_ptr<Pass> createInlining() {
  return std::make_unique<Inlining>();
}

}                    
#undef DEBUG_TYPE
