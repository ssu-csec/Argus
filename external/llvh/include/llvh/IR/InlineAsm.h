//===- llvm/InlineAsm.h - Class to represent inline asm strings -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class represents the inline asm strings, which are Value*'s that are
// used as the callee operand of call instructions.  InlineAsm's are uniqued
// like constants, and created via InlineAsm::get(...).
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_INLINEASM_H
#define LLVM_IR_INLINEASM_H

#include "llvh/ADT/StringRef.h"
#include "llvh/IR/Value.h"
#include <cassert>
#include <string>
#include <vector>

namespace llvh {

class FunctionType;
class PointerType;
template <class ConstantClass> class ConstantUniqueMap;

class InlineAsm final : public Value {
public:
  enum AsmDialect {
    AD_ATT,
    AD_Intel
  };

private:
  friend struct InlineAsmKeyType;
  friend class ConstantUniqueMap<InlineAsm>;

  std::string AsmString, Constraints;
  FunctionType *FTy;
  bool HasSideEffects;
  bool IsAlignStack;
  AsmDialect Dialect;

  InlineAsm(FunctionType *Ty, const std::string &AsmString,
            const std::string &Constraints, bool hasSideEffects,
            bool isAlignStack, AsmDialect asmDialect);

                                                                          
                                                          
  void destroyConstant();

public:
  InlineAsm(const InlineAsm &) = delete;
  InlineAsm &operator=(const InlineAsm &) = delete;

                                                                      
     
  static InlineAsm *get(FunctionType *Ty, StringRef AsmString,
                        StringRef Constraints, bool hasSideEffects,
                        bool isAlignStack = false,
                        AsmDialect asmDialect = AD_ATT);

  bool hasSideEffects() const { return HasSideEffects; }
  bool isAlignStack() const { return IsAlignStack; }
  AsmDialect getDialect() const { return Dialect; }

                                                
     
  PointerType *getType() const {
    return reinterpret_cast<PointerType*>(Value::getType());
  }

                                                                     
     
  FunctionType *getFunctionType() const;

  const std::string &getAsmString() const { return AsmString; }
  const std::string &getConstraintString() const { return Constraints; }

                                                                              
                                                                               
                             
     
  static bool Verify(FunctionType *Ty, StringRef Constraints);

                              
  enum ConstraintPrefix {
    isInput,                  
    isOutput,                  
    isClobber                  
  };

  using ConstraintCodeVector = std::vector<std::string>;

  struct SubConstraintInfo {
                                                                                
                                                                              
                                                                        
                                                                           
    int MatchingInput = -1;

                                                                               
                                 
    ConstraintCodeVector Codes;

                            
    SubConstraintInfo() = default;
  };

  using SubConstraintInfoVector = std::vector<SubConstraintInfo>;
  struct ConstraintInfo;
  using ConstraintInfoVector = std::vector<ConstraintInfo>;

  struct ConstraintInfo {
                                                                     
       
    ConstraintPrefix Type = isInput;

                                                                                
                                                           
    bool isEarlyClobber = false;

                                                                                
                                                                              
                                                                        
                                                                           
    int MatchingInput = -1;

                                                                               
                                    
    bool hasMatchingInput() const { return MatchingInput != -1; }

                                                                                
                              
    bool isCommutative = false;

                                                                             
                                                                            
                                                                                
                                                    
    bool isIndirect = false;

                                                                               
                                 
    ConstraintCodeVector Codes;

                                                                          
    bool isMultipleAlternative = false;

                                                                             
                                                                  
    SubConstraintInfoVector multipleAlternatives;

                                                            
    unsigned currentAlternativeIndex = 0;

                            
    ConstraintInfo() = default;

                                                                              
                                                                              
                                            
    bool Parse(StringRef Str, ConstraintInfoVector &ConstraintsSoFar);

                                                                               
                               
    void selectAlternative(unsigned index);
  };

                                                                         
                                                                              
                                                                           
  static ConstraintInfoVector ParseConstraints(StringRef ConstraintString);

                                                                        
                                                                  
  ConstraintInfoVector ParseConstraints() const {
    return ParseConstraints(Constraints);
  }

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == Value::InlineAsmVal;
  }

                                                                            
                    
    
                                                
                                                                    
                                                                            
                                    
                        
                                                                     
                                                                               
                                                                     
                                     
                                                                            
                          
            
                                                                  

  enum : uint32_t {
                                             
    Op_InputChain = 0,
    Op_AsmString = 1,
    Op_MDNode = 2,
    Op_ExtraInfo = 3,                                                
    Op_FirstOperand = 4,

                                                   
    MIOp_AsmString = 0,
    MIOp_ExtraInfo = 1,                                                
    MIOp_FirstOperand = 2,

                                                      
    Extra_HasSideEffects = 1,
    Extra_IsAlignStack = 2,
    Extra_AsmDialect = 4,
    Extra_MayLoad = 8,
    Extra_MayStore = 16,
    Extra_IsConvergent = 32,

                                                                          
                                                                            
                        
    Kind_RegUse = 1,                                    
    Kind_RegDef = 2,                                      
    Kind_RegDefEarlyClobber = 3,                                         
    Kind_Clobber = 4,                                        
    Kind_Imm = 5,                             
    Kind_Mem = 6,                                       

                               
                                                                             
                                                                          
                                        
    Constraint_Unknown = 0,
    Constraint_es,
    Constraint_i,
    Constraint_m,
    Constraint_o,
    Constraint_v,
    Constraint_Q,
    Constraint_R,
    Constraint_S,
    Constraint_T,
    Constraint_Um,
    Constraint_Un,
    Constraint_Uq,
    Constraint_Us,
    Constraint_Ut,
    Constraint_Uv,
    Constraint_Uy,
    Constraint_X,
    Constraint_Z,
    Constraint_ZC,
    Constraint_Zy,
    Constraints_Max = Constraint_Zy,
    Constraints_ShiftAmount = 16,

    Flag_MatchingOperand = 0x80000000
  };

  static unsigned getFlagWord(unsigned Kind, unsigned NumOps) {
    assert(((NumOps << 3) & ~0xffff) == 0 && "Too many inline asm operands!");
    assert(Kind >= Kind_RegUse && Kind <= Kind_Mem && "Invalid Kind");
    return Kind | (NumOps << 3);
  }

  static bool isRegDefKind(unsigned Flag){ return getKind(Flag) == Kind_RegDef;}
  static bool isImmKind(unsigned Flag) { return getKind(Flag) == Kind_Imm; }
  static bool isMemKind(unsigned Flag) { return getKind(Flag) == Kind_Mem; }
  static bool isRegDefEarlyClobberKind(unsigned Flag) {
    return getKind(Flag) == Kind_RegDefEarlyClobber;
  }
  static bool isClobberKind(unsigned Flag) {
    return getKind(Flag) == Kind_Clobber;
  }

                                                                          
                                                                             
                                   
  static unsigned getFlagWordForMatchingOp(unsigned InputFlag,
                                           unsigned MatchedOperandNo) {
    assert(MatchedOperandNo <= 0x7fff && "Too big matched operand");
    assert((InputFlag & ~0xffff) == 0 && "High bits already contain data");
    return InputFlag | Flag_MatchingOperand | (MatchedOperandNo << 16);
  }

                                                                        
                                                                             
               
                                                                             
                                   
  static unsigned getFlagWordForRegClass(unsigned InputFlag, unsigned RC) {
                                                                     
    ++RC;
    assert(!isImmKind(InputFlag) && "Immediates cannot have a register class");
    assert(!isMemKind(InputFlag) && "Memory operand cannot have a register class");
    assert(RC <= 0x7fff && "Too large register class ID");
    assert((InputFlag & ~0xffff) == 0 && "High bits already contain data");
    return InputFlag | (RC << 16);
  }

                                                                               
                                   
  static unsigned getFlagWordForMem(unsigned InputFlag, unsigned Constraint) {
    assert(isMemKind(InputFlag) && "InputFlag is not a memory constraint!");
    assert(Constraint <= 0x7fff && "Too large a memory constraint ID");
    assert(Constraint <= Constraints_Max && "Unknown constraint ID");
    assert((InputFlag & ~0xffff) == 0 && "High bits already contain data");
    return InputFlag | (Constraint << Constraints_ShiftAmount);
  }

  static unsigned convertMemFlagWordToMatchingFlagWord(unsigned InputFlag) {
    assert(isMemKind(InputFlag));
    return InputFlag & ~(0x7fff << Constraints_ShiftAmount);
  }

  static unsigned getKind(unsigned Flags) {
    return Flags & 7;
  }

  static unsigned getMemoryConstraintID(unsigned Flag) {
    assert(isMemKind(Flag));
    return (Flag >> Constraints_ShiftAmount) & 0x7fff;
  }

                                                                             
                              
  static unsigned getNumOperandRegisters(unsigned Flag) {
    return (Flag & 0xffff) >> 3;
  }

                                                                       
                                                                             
  static bool isUseOperandTiedToDef(unsigned Flag, unsigned &Idx) {
    if ((Flag & Flag_MatchingOperand) == 0)
      return false;
    Idx = (Flag & ~Flag_MatchingOperand) >> 16;
    return true;
  }

                                                                          
                                                          
  static bool hasRegClassConstraint(unsigned Flag, unsigned &RC) {
    if (Flag & Flag_MatchingOperand)
      return false;
    unsigned High = Flag >> 16;
                                                                               
                     
    if (!High)
      return false;
    RC = High - 1;
    return true;
  }
};

}                      

#endif                       
