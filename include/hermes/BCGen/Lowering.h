/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_LOWERING_H
#define HERMES_BCGEN_LOWERING_H

#include "hermes/BCGen/RegAlloc.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/PassManager/Pass.h"
#include "hermes/Optimizer/PassManager/PassManager.h"

namespace hermes {

                                         
class SwitchLowering : public FunctionPass {
 public:
  explicit SwitchLowering() : FunctionPass("SwitchLowering") {}
  ~SwitchLowering() override = default;

  bool runOnFunction(Function *F) override;

 private:
                                                            
  void lowerSwitchIntoIfs(SwitchInst *switchInst);

                                               
  void
  copyPhiTarget(BasicBlock *block, BasicBlock *search, BasicBlock *replace);
                                                           
  void erasePhiTarget(BasicBlock *block, BasicBlock *toDelete);
};

                                                                             
               
class LowerAllocObject : public FunctionPass {
 public:
  explicit LowerAllocObject() : FunctionPass("LowerAllocObject") {}
  ~LowerAllocObject() override = default;

  bool runOnFunction(Function *F) override;

 private:
                                                                   
  using StoreList = llvh::SmallVector<StoreNewOwnPropertyInst *, 4>;
                                                                            
                                          
  using BlockUserMap = llvh::DenseMap<BasicBlock *, StoreList>;

                                                                           
                                                         
  StoreList collectStores(
      AllocObjectInst *allocInst,
      const BlockUserMap &userBasicBlockMap,
      const DominanceInfo &DI);
                                                                             
                                                                             
                              
  bool lowerAllocObjectBuffer(
      AllocObjectInst *allocInst,
      const StoreList &users,
      uint32_t maxSize);
                                                                    
                                                  
  uint32_t estimateBestNumElemsToSerialize(
      const StoreList &users,
      bool hasParent);
};

                                                                     
class LowerStoreInstrs : public FunctionPass {
 public:
  explicit LowerStoreInstrs(RegisterAllocator &RA)
      : FunctionPass("LowerStoreInstrs"), RA_(RA) {}
  ~LowerStoreInstrs() override = default;

  bool runOnFunction(Function *F) override;

 private:
  RegisterAllocator &RA_;
};

                                                                 
class LowerNumericProperties : public FunctionPass {
 public:
  explicit LowerNumericProperties() : FunctionPass("LowerNumericProperties") {}
  ~LowerNumericProperties() override = default;

  bool runOnFunction(Function *F) override;

 private:
  bool stringToNumericProperty(
      IRBuilder &builder,
      Instruction &Inst,
      unsigned operandIdx);
};

                                                             
                                                                         
                                                                          
                         
                                                                        
                                                                        
                       
class LimitAllocArray : public FunctionPass {
 public:
  explicit LimitAllocArray(unsigned maxSizeInclusive)
      : FunctionPass("LimitAllocArray"), maxSize_(maxSizeInclusive) {}
  ~LimitAllocArray() override = default;
  bool runOnFunction(Function *F) override;

 private:
  uint32_t maxSize_;
};

                                                                 
class LowerCondBranch : public FunctionPass {
 public:
  explicit LowerCondBranch() : FunctionPass("LowerCondBranch") {}
  ~LowerCondBranch() override = default;
  bool runOnFunction(Function *F) override;

 private:
                                                                               
             
  static bool isOperatorSupported(BinaryOperatorInst::OpKind op);
};

                                                                          
                                                     
                                                                           
                                                     
class LowerExponentiationOperator : public FunctionPass {
 public:
  explicit LowerExponentiationOperator()
      : FunctionPass("LowerExponentiationOperator") {}
  ~LowerExponentiationOperator() override = default;
  bool runOnFunction(Function *F) override;

 private:
                                                                       
                                            
  static bool lowerExponentiationOperator(
      IRBuilder &builder,
      BinaryOperatorInst *inst);
};

}                    

#endif
