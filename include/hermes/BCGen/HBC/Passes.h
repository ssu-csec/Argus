/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_PASSES_H
#define HERMES_BCGEN_HBC_PASSES_H

#include "hermes/BCGen/BCOpt.h"
#include "hermes/BCGen/HBC/Bytecode.h"
#include "hermes/BCGen/HBC/BytecodeGenerator.h"
#include "hermes/BCGen/HBC/BytecodeStream.h"
#include "hermes/BCGen/HBC/HBC.h"
#include "hermes/BCGen/HBC/ISel.h"
#include "hermes/BCGen/HBC/Passes.h"

namespace hermes {
namespace hbc {

using llvh::cast;
using llvh::dyn_cast;
using llvh::isa;

class LoadConstants : public FunctionPass {
                                                                    
                                                                         
  bool operandMustBeLiteral(Instruction *Inst, unsigned opIndex);

 public:
  explicit LoadConstants() : FunctionPass("LoadConstants") {}
  ~LoadConstants() override = default;

  bool runOnFunction(Function *F) override;
};

class LoadParameters : public FunctionPass {
 public:
  explicit LoadParameters() : FunctionPass("LoadParameters") {}
  ~LoadParameters() override = default;
  bool runOnFunction(Function *F) override;
};

                                                               
class LowerLoadStoreFrameInst : public FunctionPass {
                                                                       
  ScopeCreationInst *
  getScope(IRBuilder &builder, Variable *var, ScopeCreationInst *environment);

 public:
  explicit LowerLoadStoreFrameInst()
      : FunctionPass("LowerLoadStoreFrameInst") {}
  ~LowerLoadStoreFrameInst() override = default;
  bool runOnFunction(Function *F) override;
};

                                                                           
class LowerArgumentsArray : public FunctionPass {
 private:
  CreateArgumentsInst *getCreateArgumentsInst(Function *F);

 public:
  explicit LowerArgumentsArray() : FunctionPass("LowerArgumentsArray") {}
  ~LowerArgumentsArray() override = default;
  bool runOnFunction(Function *F) override;
};

                                                                             
                                                           
class DedupReifyArguments : public FunctionPass {
 public:
  explicit DedupReifyArguments() : FunctionPass("DedupReifyArguments") {}
  ~DedupReifyArguments() override = default;
  bool runOnFunction(Function *F) override;
};

class LowerConstruction : public FunctionPass {
 public:
  explicit LowerConstruction() : FunctionPass("LowerConstruction") {}
  ~LowerConstruction() override = default;
  bool runOnFunction(Function *F) override;
};

                                                                        
                                                                          
class LowerCalls : public FunctionPass {
 public:
  explicit LowerCalls(HVMRegisterAllocator &RA)
      : FunctionPass("LowerCalls"), RA_(RA) {}
  ~LowerCalls() override = default;
  bool runOnFunction(Function *F) override;

 protected:
  HVMRegisterAllocator &RA_;
};

                                                                             
                                                                             
                                          
class RecreateCheapValues : public FunctionPass {
 public:
  explicit RecreateCheapValues(HVMRegisterAllocator &RA)
      : FunctionPass("RecreateCheapValues"), RA_(RA) {}
  ~RecreateCheapValues() override = default;
  bool runOnFunction(Function *F) override;

 private:
  HVMRegisterAllocator &RA_;
};

                                                                           
                                                
                                                                           
                                                                              
                                                                               
                                  
class LoadConstantValueNumbering : public FunctionPass {
 public:
  explicit LoadConstantValueNumbering(HVMRegisterAllocator &RA)
      : FunctionPass("LoadConstantValueNumbering"), RA_(RA) {}
  ~LoadConstantValueNumbering() override = default;
  bool runOnFunction(Function *F) override;

 private:
  HVMRegisterAllocator &RA_;
};

                                                                          
                                  
class SpillRegisters : public FunctionPass {
 public:
  explicit SpillRegisters(HVMRegisterAllocator &RA)
      : FunctionPass("SpillRegisters"), RA_(RA) {}
  ~SpillRegisters() override = default;
  bool runOnFunction(Function *F) override;

 protected:
  HVMRegisterAllocator &RA_;
                                
  static const int boundary_ = 256;
                                                                
                                                                       
  static const int reserved_ = 6;

  bool requiresShortOutput(Instruction *I);
  bool requiresShortOperand(Instruction *I, int op);
  bool modifiesOperandRegister(Instruction *I, int op);

  bool isShort(Register reg) {
    return reg.getIndex() < boundary_;
  }
  Register getReserved(int i) {
    assert(i < reserved_ && "Using too many reserved regs.");
    return Register(i);
  }
                                                                   
  void reserveLowRegisters(Function *F) {
    RA_.allocateSpillTempCount(reserved_);
    for (auto &BB : F->getBasicBlockList()) {
      for (auto &inst : BB) {
        if (RA_.isAllocated(&inst)) {
          auto reg = RA_.getRegister(&inst);
          RA_.updateRegister(&inst, reg.getConsecutive(reserved_));
        }
      }
    }
  }
};

                                                          
                                                                       
                                                                            
                   
class LowerSwitchIntoJumpTables : public FunctionPass {
 public:
  explicit LowerSwitchIntoJumpTables()
      : FunctionPass("LowerSwitchIntoJumpTables") {}
  ~LowerSwitchIntoJumpTables() override = default;
  bool runOnFunction(Function *F) override;

 private:
  bool lowerIntoJumpTable(SwitchInst *switchInst);
};

}                 
}                    
#endif
