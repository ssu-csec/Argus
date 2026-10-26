/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/Lowering.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Inst/Inst.h"

#define DEBUG_TYPE "lowering"

using namespace hermes;

bool SwitchLowering::runOnFunction(Function *F) {
  bool changed = false;
  llvh::SmallVector<SwitchInst *, 4> switches;
                                     
  for (BasicBlock &BB : *F)
    for (auto &it : BB) {
      if (auto *S = llvh::dyn_cast<SwitchInst>(&it))
        switches.push_back(S);
    }

  for (auto *S : switches) {
    lowerSwitchIntoIfs(S);
    changed = true;
  }

  return changed;
}

void SwitchLowering::lowerSwitchIntoIfs(SwitchInst *switchInst) {
  IRBuilder builder(switchInst->getParent()->getParent());
  builder.setLocation(switchInst->getLocation());
  builder.setCurrentSourceLevelScope(switchInst->getSourceLevelScope());

  BasicBlock *defaultDest = switchInst->getDefaultDestination();
  BasicBlock *next = defaultDest;
  BasicBlock *currentBlock = switchInst->getParent();

                                                                          
                                                                           
                                                                       
                                             
  for (unsigned i = 0, e = switchInst->getNumCasePair(); i < e; ++i) {
                                                         
    BasicBlock *ifBlock = builder.createBasicBlock(currentBlock->getParent());

                                           
    unsigned idx = (e - i - 1);
    auto caseEntry = switchInst->getCasePair(idx);

    builder.setInsertionBlock(ifBlock);
    auto *pred = builder.createBinaryOperatorInst(
        caseEntry.first,
        switchInst->getInputValue(),
        BinaryOperatorInst::OpKind::StrictlyEqualKind);
                                                                         
                                                                           
                 
    builder.createCondBranchInst(pred, caseEntry.second, next);

                                                
    copyPhiTarget(caseEntry.second, currentBlock, ifBlock);

    if (next == defaultDest) {
                                                                     
                                                                  
      copyPhiTarget(next, currentBlock, ifBlock);
    }

    next = ifBlock;
  }

                                                              
  erasePhiTarget(defaultDest, currentBlock);
  for (unsigned i = 0, e = switchInst->getNumCasePair(); i < e; ++i) {
    erasePhiTarget(switchInst->getCasePair(i).second, currentBlock);
  }

  switchInst->eraseFromParent();
  builder.setInsertionBlock(currentBlock);
  builder.createBranchInst(next);
}

                                                         
void SwitchLowering::copyPhiTarget(
    BasicBlock *block,
    BasicBlock *previousBlock,
    BasicBlock *newBlock) {
  for (auto &inst : *block) {
    auto *phi = llvh::dyn_cast<PhiInst>(&inst);
    if (!phi)
      break;                                                 

    Value *currentValue = nullptr;
    for (int i = 0, e = phi->getNumEntries(); i < e; i++) {
      auto pair = phi->getEntry(i);
      if (pair.second != previousBlock)
        continue;
      currentValue = pair.first;
      break;
    }

    if (currentValue) {
      phi->addEntry(currentValue, newBlock);
    }
  }
}

void SwitchLowering::erasePhiTarget(BasicBlock *block, BasicBlock *toDelete) {
  for (auto &inst : *block) {
    auto *phi = llvh::dyn_cast<PhiInst>(&inst);
    if (!phi)
      break;                                                 

    for (signed i = (signed)phi->getNumEntries() - 1; i >= 0; i--) {
      auto pair = phi->getEntry(i);
      if (pair.second != toDelete)
        continue;
      phi->removeEntry(i);
                                                                          
    }
  }
}

                                                                          
                                                                                
                                                                             
                                                                               
                                                                               
                                                                            
                    
                                                                     
template <typename Func>
static llvh::SmallVector<BasicBlock *, 4> orderBlocksByDominance(
    const DominanceInfo &DI,
    BasicBlock *entry,
    Func &&pred) {
  class OrderBlocksContext : public DomTreeDFS::Visitor<
                                 OrderBlocksContext,
                                 DomTreeDFS::StackNode<OrderBlocksContext>> {
                                                                              
    Func pred_;

                                                                              
                                                                              
                                                                  
                                                                          
                                                                       
    bool stopAddingBasicBlock_{false};

                                                                             
                     
    llvh::SmallVector<BasicBlock *, 4> sortedBasicBlocks_{};

   public:
    OrderBlocksContext(
        const DominanceInfo &DI,
        BasicBlock *entryBlock,
        Func &&pred)
        : DomTreeDFS::Visitor<
              OrderBlocksContext,
              DomTreeDFS::StackNode<OrderBlocksContext>>(DI),
          pred_(std::forward<Func>(pred)) {
                                                        
      this->DFS(this->DT_.getNode(entryBlock));
    }

    llvh::SmallVector<BasicBlock *, 4> get() && {
      return std::move(sortedBasicBlocks_);
    }

                                                                            
                                  
    bool processNode(DomTreeDFS::StackNode<OrderBlocksContext> *SN) {
      assert(!SN->isDone() && "Visiting same basic block twice");

      BasicBlock *BB = SN->node()->getBlock();
                                                                         
      if (!pred_(BB))
        return false;

      while (!sortedBasicBlocks_.empty() &&
             !this->DT_.properlyDominates(sortedBasicBlocks_.back(), BB)) {
                                                                    
                                                                         
                                                                      
                                                                      
                                                                               
                                                               
                                                                           
                        
        sortedBasicBlocks_.pop_back();
        stopAddingBasicBlock_ = true;
      }
      if (!stopAddingBasicBlock_) {
        sortedBasicBlocks_.push_back(BB);
        return true;
      }
      return false;
    }
  };

  return OrderBlocksContext(DI, entry, std::forward<Func>(pred)).get();
}

LowerAllocObject::StoreList LowerAllocObject::collectStores(
    AllocObjectInst *allocInst,
    const BlockUserMap &userBasicBlockMap,
    const DominanceInfo &DI) {
                                                                        
  auto sortedBlocks = orderBlocksByDominance(
      DI, allocInst->getParent(), [&userBasicBlockMap](BasicBlock *BB) {
        return userBasicBlockMap.find(BB) != userBasicBlockMap.end();
      });

                                                                            
                                                            
  StoreList instrs;
  for (BasicBlock *BB : sortedBlocks) {
    for (StoreNewOwnPropertyInst *I : userBasicBlockMap.find(BB)->second) {
                                                            
      if (!I)
        return instrs;
      instrs.push_back(I);
    }
  }
  return instrs;
}

bool LowerAllocObject::runOnFunction(Function *F) {
                                                                                
                                                                             
                                                                     
                 
  auto tryAdd = [](AllocObjectInst *A, Instruction *U, StoreList &stores) {
                                                                          
                                                                        
    if (!stores.empty() && !stores.back())
      return;
    auto *SI = llvh::dyn_cast<StoreNewOwnPropertyInst>(U);
    if (!SI || SI->getStoredValue() == A || !SI->getIsEnumerable()) {
                                                                            
                                                                            
                                                                            
                                                                        
                                                                            
                                                                             
                                 
      stores.push_back(nullptr);
    } else {
      assert(
          SI->getObject() == A &&
          "SNOP using allocInst must use it as object or value");
      stores.push_back(SI);
    }
  };

                                                                 
                                                                           
  llvh::DenseMap<AllocObjectInst *, BlockUserMap> allocUsers;
  for (BasicBlock &BB : *F)
    for (Instruction &I : BB)
      for (size_t i = 0; i < I.getNumOperands(); ++i)
        if (auto *A = llvh::dyn_cast<AllocObjectInst>(I.getOperand(i)))
          tryAdd(A, &I, allocUsers[A][&BB]);

  bool changed = false;
  DominanceInfo DI(F);
  for (const auto &[A, userBasicBlockMap] : allocUsers) {
                                                                              
                      
    auto stores = collectStores(A, userBasicBlockMap, DI);
    changed |= lowerAllocObjectBuffer(A, stores, UINT16_MAX);
  }

  return changed;
}

                                                                   
                                                                              
                            
static constexpr int32_t kLiteralSavedBytes = static_cast<int32_t>(
    sizeof(inst::LoadConstIntInst) + sizeof(inst::PutNewOwnByIdInst) -
    sizeof(int32_t) - 1);
                                                                      
                                                                          
static constexpr int32_t kNonLiteralCostBytes = static_cast<int32_t>(
    1 + sizeof(inst::PutByIdInst) - sizeof(inst::PutNewOwnByIdInst));
                                                                    
                                                                                
                  
static constexpr uint32_t kNonLiteralPlaceholderLimit = 3;

                                                                          
           
static bool canSerialize(Value *V) {
  if (auto *LCI = llvh::dyn_cast_or_null<HBCLoadConstInst>(V)) {
    Literal *L = LCI->getConst();
    return llvh::isa<LiteralNull>(L) || llvh::isa<LiteralBool>(L) ||
        llvh::isa<LiteralNumber>(L) || llvh::isa<LiteralString>(L);
  }
  return false;
}

uint32_t LowerAllocObject::estimateBestNumElemsToSerialize(
    const StoreList &users,
    bool hasParent) {
                                                                           
                                                 
                                                                              
                                                                         
                                          
  int32_t curSaving = static_cast<int32_t>(sizeof(inst::NewObjectInst)) -
      static_cast<int32_t>(sizeof(inst::NewObjectWithBufferInst));
                                                                               
                       
  if (hasParent)
    curSaving -= sizeof(inst::CallBuiltinInst);
  int32_t maxSaving = 0;
  uint32_t optimumStopIndex = 0;
  uint32_t nonLiteralPlaceholderCount = 0;

  uint32_t curSize = 0;
  for (StoreNewOwnPropertyInst *I : users) {
    ++curSize;
    assert(
        (llvh::isa<LiteralString>(I->getProperty()) ||
         llvh::isa<LiteralNumber>(I->getProperty())) &&
        "StoreNewOwnPropertyInst property must be literal.");
    if (canSerialize(I->getStoredValue())) {
                                                          
      curSaving += kLiteralSavedBytes;
      if (curSaving > maxSaving) {
        maxSaving = curSaving;
        optimumStopIndex = curSize;
      }
    } else {
                                                                    
                                                      
      if (llvh::isa<LiteralNumber>(I->getProperty())) {
                                                                          
                                                                        
                                                                             
                                                 
                                                                            
                                                                         
                           
        continue;
      }
      if (nonLiteralPlaceholderCount == kNonLiteralPlaceholderLimit) {
                                                                          
        break;
      }
      nonLiteralPlaceholderCount++;
      curSaving -= kNonLiteralCostBytes;
    }
  }
  return optimumStopIndex;
}

bool LowerAllocObject::lowerAllocObjectBuffer(
    AllocObjectInst *allocInst,
    const StoreList &users,
    uint32_t maxSize) {
  auto size = estimateBestNumElemsToSerialize(
      users, !llvh::isa<EmptySentinel>(allocInst->getParentObject()));
  if (size == 0) {
    return false;
  }
  size = std::min(maxSize, size);

  Function *F = allocInst->getParent()->getParent();
  IRBuilder builder(F);
  HBCAllocObjectFromBufferInst::ObjectPropertyMap prop_map;
  for (uint32_t i = 0; i < size; ++i) {
    StoreNewOwnPropertyInst *I = users[i];
    Literal *propLiteral = nullptr;
                                                                      
    if (auto *LN = llvh::dyn_cast<LiteralNumber>(I->getProperty())) {
      assert(
          LN->convertToArrayIndex() &&
          "LiteralNumber can be a property name only if it can be converted to array index.");
      propLiteral = LN;
    } else {
      propLiteral = cast<LiteralString>(I->getProperty());
    }

    auto *loadInst = llvh::dyn_cast<HBCLoadConstInst>(I->getStoredValue());
                                                                 
                  
    if (canSerialize(loadInst)) {
      prop_map.push_back(
          std::pair<Literal *, Literal *>(propLiteral, loadInst->getConst()));
      I->eraseFromParent();
    } else if (llvh::isa<LiteralString>(propLiteral)) {
                                                                         
                                          
                                                
                                                                          
      prop_map.push_back(
          std::pair<Literal *, Literal *>(
              propLiteral, builder.getLiteralNull()));

                                                                          
                                                                   
                                                               
                           
      builder.setLocation(I->getLocation());
      builder.setCurrentSourceLevelScope(I->getSourceLevelScope());
      builder.setInsertionPoint(I);
      auto *NI = builder.createStorePropertyInst(
          I->getStoredValue(), I->getObject(), I->getProperty());
      I->replaceAllUsesWith(NI);
      I->eraseFromParent();
    }
  }

  builder.setLocation(allocInst->getLocation());
  builder.setCurrentSourceLevelScope(allocInst->getSourceLevelScope());
  builder.setInsertionPoint(allocInst);
  auto *alloc = builder.createHBCAllocObjectFromBufferInst(
      prop_map, allocInst->getSize());

                                                                           
                                                                          
  if (!llvh::isa<EmptySentinel>(allocInst->getParentObject())) {
    builder.createCallBuiltinInst(
        BuiltinMethod::HermesBuiltin_silentSetPrototypeOf,
        {alloc, allocInst->getParentObject()});
  }
  allocInst->replaceAllUsesWith(alloc);
  allocInst->eraseFromParent();

  return true;
}

bool LowerStoreInstrs::runOnFunction(Function *F) {
  IRBuilder builder(F);
  IRBuilder::InstructionDestroyer destroyer;
  bool changed = false;

  PostOrderAnalysis PO(F);
  llvh::SmallVector<BasicBlock *, 16> order(PO.rbegin(), PO.rend());
  for (auto *bbit : order) {
    for (auto &it : bbit->getInstList()) {
      auto *SSI = llvh::dyn_cast<StoreStackInst>(&it);
      if (!SSI)
        continue;

      Value *ptr = SSI->getPtr();
      Value *val = SSI->getValue();

      builder.setInsertionPoint(&it);
      auto dstReg = RA_.getRegister(ptr);
      auto *mov = builder.createMovInst(val);
      RA_.updateRegister(mov, dstReg);
      it.replaceAllUsesWith(mov);
      destroyer.add(&it);
      changed = true;
    }
  }
  return changed;
}

bool LowerNumericProperties::stringToNumericProperty(
    IRBuilder &builder,
    Instruction &Inst,
    unsigned operandIdx) {
  auto strLit = llvh::dyn_cast<LiteralString>(Inst.getOperand(operandIdx));
  if (!strLit)
    return false;

                                                           
  auto num = toArrayIndex(strLit->getValue().str());
  if (num) {
    Inst.setOperand(builder.getLiteralNumber(*num), operandIdx);
    return true;
  }

  return false;
}

bool LowerNumericProperties::runOnFunction(Function *F) {
  IRBuilder builder(F);
  IRBuilder::InstructionDestroyer destroyer{};

  bool changed = false;
  for (BasicBlock &BB : *F) {
    for (Instruction &Inst : BB) {
      if (llvh::isa<LoadPropertyInst>(&Inst)) {
        changed |= stringToNumericProperty(
            builder, Inst, LoadPropertyInst::PropertyIdx);
      } else if (llvh::isa<StorePropertyInst>(&Inst)) {
        changed |= stringToNumericProperty(
            builder, Inst, StorePropertyInst::PropertyIdx);
      } else if (llvh::isa<StoreOwnPropertyInst>(&Inst)) {
        changed |= stringToNumericProperty(
            builder, Inst, StoreOwnPropertyInst::PropertyIdx);
      } else if (llvh::isa<DeletePropertyInst>(&Inst)) {
        changed |= stringToNumericProperty(
            builder, Inst, DeletePropertyInst::PropertyIdx);
      } else if (llvh::isa<StoreGetterSetterInst>(&Inst)) {
        changed |= stringToNumericProperty(
            builder, Inst, StoreGetterSetterInst::PropertyIdx);
      }
    }
  }
  return changed;
}

bool LimitAllocArray::runOnFunction(Function *F) {
  bool changed = false;
  for (BasicBlock &BB : *F) {
    for (Instruction &I : BB) {
      auto *inst = llvh::dyn_cast<AllocArrayInst>(&I);
      if (!inst || inst->getElementCount() == 0)
        continue;

      IRBuilder builder(F);
      builder.setInsertionPointAfter(inst);
      builder.setLocation(inst->getLocation());
      builder.setCurrentSourceLevelScope(inst->getSourceLevelScope());

                                                                  
                                                                               
      {
        bool seenUnserializable = false;
        unsigned ind = -1;
        unsigned i = AllocArrayInst::ElementStartIdx;
        unsigned e = inst->getElementCount() + AllocArrayInst::ElementStartIdx;
        while (i < e) {
          ind++;
          seenUnserializable |=
              inst->getOperand(i)->getKind() == ValueKind::LiteralBigIntKind ||
              inst->getOperand(i)->getKind() == ValueKind::LiteralUndefinedKind;
          if (seenUnserializable) {
            e--;
            builder.createStoreOwnPropertyInst(
                inst->getOperand(i),
                inst,
                builder.getLiteralNumber(ind),
                IRBuilder::PropEnumerable::Yes);
            inst->removeOperand(i);
            changed = true;
            continue;
          }
          i++;
        }
      }

      if (inst->getElementCount() == 0)
        continue;

                                                                      
                                                                          
                                                                          
                         
      for (unsigned i = inst->getElementCount() - 1; i >= maxSize_; i--) {
        int operandOffset = AllocArrayInst::ElementStartIdx + i;
        builder.createStoreOwnPropertyInst(
            inst->getOperand(operandOffset),
            inst,
            builder.getLiteralNumber(i),
            IRBuilder::PropEnumerable::Yes);
        inst->removeOperand(operandOffset);
      }
      changed = true;
    }
  }
  return changed;
}

bool LowerCondBranch::isOperatorSupported(BinaryOperatorInst::OpKind op) {
  using OpKind = BinaryOperatorInst::OpKind;
  switch (op) {
    case OpKind::LessThanKind:     
    case OpKind::LessThanOrEqualKind:      
    case OpKind::GreaterThanKind:     
    case OpKind::GreaterThanOrEqualKind:      
    case OpKind::StrictlyEqualKind:
    case OpKind::StrictlyNotEqualKind:
    case OpKind::NotEqualKind:      
    case OpKind::EqualKind:      
      return true;
    default:
      return false;
  }
}

bool LowerCondBranch::runOnFunction(Function *F) {
  IRBuilder builder(F);
  bool changed = false;

  for (auto &BB : *F) {
    llvh::DenseMap<CondBranchInst *, CompareBranchInst *> condToCompMap;

    for (auto &I : BB) {
      auto *cbInst = llvh::dyn_cast<CondBranchInst>(&I);
                                        
      if (!cbInst)
        continue;

      Value *cond = cbInst->getCondition();

                                                                    
      if (!cond->hasOneUser())
        continue;

                                                 
      auto binopInst = llvh::dyn_cast<BinaryOperatorInst>(cond);
      if (!binopInst)
        continue;

      auto *LHS = binopInst->getLeftHandSide();
      auto *RHS = binopInst->getRightHandSide();

                                                                         
                              
      if (binopInst->hasSideEffect())
        if (cbInst->getPrevNode() != binopInst)
          continue;

                                              
      if (!isOperatorSupported(binopInst->getOperatorKind()))
        continue;

      builder.setInsertionPoint(cbInst);
      builder.setLocation(cbInst->getLocation());
      builder.setCurrentSourceLevelScope(cbInst->getSourceLevelScope());
      auto *cmpBranch = builder.createCompareBranchInst(
          LHS,
          RHS,
          binopInst->getOperatorKind(),
          cbInst->getTrueDest(),
          cbInst->getFalseDest());

      condToCompMap[cbInst] = cmpBranch;
      changed = true;
    }

    for (const auto &cbiter : condToCompMap) {
      auto binopInst =
          llvh::dyn_cast<BinaryOperatorInst>(cbiter.first->getCondition());

      cbiter.first->replaceAllUsesWith(condToCompMap[cbiter.first]);
      cbiter.first->eraseFromParent();
      binopInst->eraseFromParent();
    }
  }
  return changed;
}

bool LowerExponentiationOperator::runOnFunction(Function *F) {
  IRBuilder builder{F};
  llvh::DenseSet<Instruction *> toTransform{};
  bool changed = false;

  for (BasicBlock &bb : *F) {
    for (auto it = bb.begin(), e = bb.end(); it != e;            ) {
      auto *inst = &*it;
                                                                            
                   
      ++it;
      if (auto *binOp = llvh::dyn_cast<BinaryOperatorInst>(inst)) {
        if (binOp->getOperatorKind() ==
            BinaryOperatorInst::OpKind::ExponentiationKind) {
          changed |= lowerExponentiationOperator(builder, binOp);
        }
      }
    }
  }

  return changed;
}

bool LowerExponentiationOperator::lowerExponentiationOperator(
    IRBuilder &builder,
    BinaryOperatorInst *binOp) {
  assert(
      binOp->getOperatorKind() ==
          BinaryOperatorInst::OpKind::ExponentiationKind &&
      "lowerExponentiationOperator must take a ** operator");
                                                                    
  builder.setInsertionPoint(binOp);
  auto *result = builder.createCallBuiltinInst(
      BuiltinMethod::HermesBuiltin_exponentiationOperator,
      {binOp->getLeftHandSide(), binOp->getRightHandSide()});
  binOp->replaceAllUsesWith(result);
  binOp->eraseFromParent();
  return true;
}

#undef DEBUG_TYPE
