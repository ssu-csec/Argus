//===-- llvm/Operator.h - Operator utility subclass -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines various classes for working with Instructions and
// ConstantExprs.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_OPERATOR_H
#define LLVM_IR_OPERATOR_H

#include "llvh/ADT/None.h"
#include "llvh/ADT/Optional.h"
#include "llvh/IR/Constants.h"
#include "llvh/IR/Instruction.h"
#include "llvh/IR/Type.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include <cstddef>

namespace llvh {

                                                                       
                                                         
class Operator : public User {
public:
                                                                                
                  
  Operator() = delete;
  ~Operator() = delete;

  void *operator new(size_t s) = delete;

                                                             
  unsigned getOpcode() const {
    if (const Instruction *I = dyn_cast<Instruction>(this))
      return I->getOpcode();
    return cast<ConstantExpr>(this)->getOpcode();
  }

                                                                
                               
  static unsigned getOpcode(const Value *V) {
    if (const Instruction *I = dyn_cast<Instruction>(V))
      return I->getOpcode();
    if (const ConstantExpr *CE = dyn_cast<ConstantExpr>(V))
      return CE->getOpcode();
    return Instruction::UserOp1;
  }

  static bool classof(const Instruction *) { return true; }
  static bool classof(const ConstantExpr *) { return true; }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) || isa<ConstantExpr>(V);
  }
};

                                                                              
                                                                            
                           
class OverflowingBinaryOperator : public Operator {
public:
  enum {
    NoUnsignedWrap = (1 << 0),
    NoSignedWrap   = (1 << 1)
  };

private:
  friend class Instruction;
  friend class ConstantExpr;

  void setHasNoUnsignedWrap(bool B) {
    SubclassOptionalData =
      (SubclassOptionalData & ~NoUnsignedWrap) | (B * NoUnsignedWrap);
  }
  void setHasNoSignedWrap(bool B) {
    SubclassOptionalData =
      (SubclassOptionalData & ~NoSignedWrap) | (B * NoSignedWrap);
  }

public:
                                                   
                                                      
  bool hasNoUnsignedWrap() const {
    return SubclassOptionalData & NoUnsignedWrap;
  }

                                                   
                                                    
  bool hasNoSignedWrap() const {
    return (SubclassOptionalData & NoSignedWrap) != 0;
  }

  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Add ||
           I->getOpcode() == Instruction::Sub ||
           I->getOpcode() == Instruction::Mul ||
           I->getOpcode() == Instruction::Shl;
  }
  static bool classof(const ConstantExpr *CE) {
    return CE->getOpcode() == Instruction::Add ||
           CE->getOpcode() == Instruction::Sub ||
           CE->getOpcode() == Instruction::Mul ||
           CE->getOpcode() == Instruction::Shl;
  }
  static bool classof(const Value *V) {
    return (isa<Instruction>(V) && classof(cast<Instruction>(V))) ||
           (isa<ConstantExpr>(V) && classof(cast<ConstantExpr>(V)));
  }
};

                                                               
                                          
class PossiblyExactOperator : public Operator {
public:
  enum {
    IsExact = (1 << 0)
  };

private:
  friend class Instruction;
  friend class ConstantExpr;

  void setIsExact(bool B) {
    SubclassOptionalData = (SubclassOptionalData & ~IsExact) | (B * IsExact);
  }

public:
                                                                           
  bool isExact() const {
    return SubclassOptionalData & IsExact;
  }

  static bool isPossiblyExactOpcode(unsigned OpC) {
    return OpC == Instruction::SDiv ||
           OpC == Instruction::UDiv ||
           OpC == Instruction::AShr ||
           OpC == Instruction::LShr;
  }

  static bool classof(const ConstantExpr *CE) {
    return isPossiblyExactOpcode(CE->getOpcode());
  }
  static bool classof(const Instruction *I) {
    return isPossiblyExactOpcode(I->getOpcode());
  }
  static bool classof(const Value *V) {
    return (isa<Instruction>(V) && classof(cast<Instruction>(V))) ||
           (isa<ConstantExpr>(V) && classof(cast<ConstantExpr>(V)));
  }
};

                                                                          
class FastMathFlags {
private:
  friend class FPMathOperator;

  unsigned Flags = 0;

  FastMathFlags(unsigned F) {
                                                                             
                                                                            
                                                                                
    if (F == 0x7F) Flags = ~0U;
    else Flags = F;
  }

public:
                                                                         
                          
                                                                           
                                                                           
  enum {
    AllowReassoc    = (1 << 0),
    NoNaNs          = (1 << 1),
    NoInfs          = (1 << 2),
    NoSignedZeros   = (1 << 3),
    AllowReciprocal = (1 << 4),
    AllowContract   = (1 << 5),
    ApproxFunc      = (1 << 6)
  };

  FastMathFlags() = default;

  bool any() const { return Flags != 0; }
  bool none() const { return Flags == 0; }
  bool all() const { return Flags == ~0U; }

  void clear() { Flags = 0; }
  void set()   { Flags = ~0U; }

                  
  bool allowReassoc() const    { return 0 != (Flags & AllowReassoc); }
  bool noNaNs() const          { return 0 != (Flags & NoNaNs); }
  bool noInfs() const          { return 0 != (Flags & NoInfs); }
  bool noSignedZeros() const   { return 0 != (Flags & NoSignedZeros); }
  bool allowReciprocal() const { return 0 != (Flags & AllowReciprocal); }
  bool allowContract() const   { return 0 != (Flags & AllowContract); }
  bool approxFunc() const      { return 0 != (Flags & ApproxFunc); }
                                    
  bool isFast() const          { return all(); }

                  
  void setAllowReassoc(bool B = true) {
    Flags = (Flags & ~AllowReassoc) | B * AllowReassoc;
  }
  void setNoNaNs(bool B = true) {
    Flags = (Flags & ~NoNaNs) | B * NoNaNs;
  }
  void setNoInfs(bool B = true) {
    Flags = (Flags & ~NoInfs) | B * NoInfs;
  }
  void setNoSignedZeros(bool B = true) {
    Flags = (Flags & ~NoSignedZeros) | B * NoSignedZeros;
  }
  void setAllowReciprocal(bool B = true) {
    Flags = (Flags & ~AllowReciprocal) | B * AllowReciprocal;
  }
  void setAllowContract(bool B = true) {
    Flags = (Flags & ~AllowContract) | B * AllowContract;
  }
  void setApproxFunc(bool B = true) {
    Flags = (Flags & ~ApproxFunc) | B * ApproxFunc;
  }
  void setFast(bool B = true) { B ? set() : clear(); }

  void operator&=(const FastMathFlags &OtherFlags) {
    Flags &= OtherFlags.Flags;
  }
};

                                                              
                                                                     
class FPMathOperator : public Operator {
private:
  friend class Instruction;

                                    
  void setFast(bool B) {
    setHasAllowReassoc(B);
    setHasNoNaNs(B);
    setHasNoInfs(B);
    setHasNoSignedZeros(B);
    setHasAllowReciprocal(B);
    setHasAllowContract(B);
    setHasApproxFunc(B);
  }

  void setHasAllowReassoc(bool B) {
    SubclassOptionalData =
    (SubclassOptionalData & ~FastMathFlags::AllowReassoc) |
    (B * FastMathFlags::AllowReassoc);
  }

  void setHasNoNaNs(bool B) {
    SubclassOptionalData =
      (SubclassOptionalData & ~FastMathFlags::NoNaNs) |
      (B * FastMathFlags::NoNaNs);
  }

  void setHasNoInfs(bool B) {
    SubclassOptionalData =
      (SubclassOptionalData & ~FastMathFlags::NoInfs) |
      (B * FastMathFlags::NoInfs);
  }

  void setHasNoSignedZeros(bool B) {
    SubclassOptionalData =
      (SubclassOptionalData & ~FastMathFlags::NoSignedZeros) |
      (B * FastMathFlags::NoSignedZeros);
  }

  void setHasAllowReciprocal(bool B) {
    SubclassOptionalData =
      (SubclassOptionalData & ~FastMathFlags::AllowReciprocal) |
      (B * FastMathFlags::AllowReciprocal);
  }

  void setHasAllowContract(bool B) {
    SubclassOptionalData =
        (SubclassOptionalData & ~FastMathFlags::AllowContract) |
        (B * FastMathFlags::AllowContract);
  }

  void setHasApproxFunc(bool B) {
    SubclassOptionalData =
        (SubclassOptionalData & ~FastMathFlags::ApproxFunc) |
        (B * FastMathFlags::ApproxFunc);
  }

                                                                
                                       
  void setFastMathFlags(FastMathFlags FMF) {
    SubclassOptionalData |= FMF.Flags;
  }

                                                           
                                                         
  void copyFastMathFlags(FastMathFlags FMF) {
    SubclassOptionalData = FMF.Flags;
  }

public:
                                                                             
  bool isFast() const {
    return ((SubclassOptionalData & FastMathFlags::AllowReassoc) != 0 &&
            (SubclassOptionalData & FastMathFlags::NoNaNs) != 0 &&
            (SubclassOptionalData & FastMathFlags::NoInfs) != 0 &&
            (SubclassOptionalData & FastMathFlags::NoSignedZeros) != 0 &&
            (SubclassOptionalData & FastMathFlags::AllowReciprocal) != 0 &&
            (SubclassOptionalData & FastMathFlags::AllowContract) != 0 &&
            (SubclassOptionalData & FastMathFlags::ApproxFunc) != 0);
  }

                                                                             
  bool hasAllowReassoc() const {
    return (SubclassOptionalData & FastMathFlags::AllowReassoc) != 0;
  }

                                                                         
  bool hasNoNaNs() const {
    return (SubclassOptionalData & FastMathFlags::NoNaNs) != 0;
  }

                                                                              
  bool hasNoInfs() const {
    return (SubclassOptionalData & FastMathFlags::NoInfs) != 0;
  }

                                                         
  bool hasNoSignedZeros() const {
    return (SubclassOptionalData & FastMathFlags::NoSignedZeros) != 0;
  }

                                                                             
  bool hasAllowReciprocal() const {
    return (SubclassOptionalData & FastMathFlags::AllowReciprocal) != 0;
  }

                                                                    
  bool hasAllowContract() const {
    return (SubclassOptionalData & FastMathFlags::AllowContract) != 0;
  }

                                                                               
                 
  bool hasApproxFunc() const {
    return (SubclassOptionalData & FastMathFlags::ApproxFunc) != 0;
  }

                                                              
  FastMathFlags getFastMathFlags() const {
    return FastMathFlags(SubclassOptionalData);
  }

                                                                               
                                                                       
                
  float getFPAccuracy() const;

  static bool classof(const Value *V) {
    unsigned Opcode;
    if (auto *I = dyn_cast<Instruction>(V))
      Opcode = I->getOpcode();
    else if (auto *CE = dyn_cast<ConstantExpr>(V))
      Opcode = CE->getOpcode();
    else
      return false;

    switch (Opcode) {
    case Instruction::FCmp:
      return true;
                                     
    case Instruction::ExtractElement:
    case Instruction::ShuffleVector:
    case Instruction::InsertElement:
      return false;
    default:
      return V->getType()->isFPOrFPVectorTy();
    }
  }
};

                                                                    
template<typename SuperClass, unsigned Opc>
class ConcreteOperator : public SuperClass {
public:
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Opc;
  }
  static bool classof(const ConstantExpr *CE) {
    return CE->getOpcode() == Opc;
  }
  static bool classof(const Value *V) {
    return (isa<Instruction>(V) && classof(cast<Instruction>(V))) ||
           (isa<ConstantExpr>(V) && classof(cast<ConstantExpr>(V)));
  }
};

class AddOperator
  : public ConcreteOperator<OverflowingBinaryOperator, Instruction::Add> {
};
class SubOperator
  : public ConcreteOperator<OverflowingBinaryOperator, Instruction::Sub> {
};
class MulOperator
  : public ConcreteOperator<OverflowingBinaryOperator, Instruction::Mul> {
};
class ShlOperator
  : public ConcreteOperator<OverflowingBinaryOperator, Instruction::Shl> {
};

class SDivOperator
  : public ConcreteOperator<PossiblyExactOperator, Instruction::SDiv> {
};
class UDivOperator
  : public ConcreteOperator<PossiblyExactOperator, Instruction::UDiv> {
};
class AShrOperator
  : public ConcreteOperator<PossiblyExactOperator, Instruction::AShr> {
};
class LShrOperator
  : public ConcreteOperator<PossiblyExactOperator, Instruction::LShr> {
};

class ZExtOperator : public ConcreteOperator<Operator, Instruction::ZExt> {};

class GEPOperator
  : public ConcreteOperator<Operator, Instruction::GetElementPtr> {
  friend class GetElementPtrInst;
  friend class ConstantExpr;

  enum {
    IsInBounds = (1 << 0),
                             
  };

  void setIsInBounds(bool B) {
    SubclassOptionalData =
      (SubclassOptionalData & ~IsInBounds) | (B * IsInBounds);
  }

public:
                                                                       
  bool isInBounds() const {
    return SubclassOptionalData & IsInBounds;
  }

                                                                            
           
  Optional<unsigned> getInRangeIndex() const {
    if (SubclassOptionalData >> 1 == 0) return None;
    return (SubclassOptionalData >> 1) - 1;
  }

  inline op_iterator       idx_begin()       { return op_begin()+1; }
  inline const_op_iterator idx_begin() const { return op_begin()+1; }
  inline op_iterator       idx_end()         { return op_end(); }
  inline const_op_iterator idx_end()   const { return op_end(); }

  Value *getPointerOperand() {
    return getOperand(0);
  }
  const Value *getPointerOperand() const {
    return getOperand(0);
  }
  static unsigned getPointerOperandIndex() {
    return 0U;                                                                
  }

                                                            
  Type *getPointerOperandType() const {
    return getPointerOperand()->getType();
  }

  Type *getSourceElementType() const;
  Type *getResultElementType() const;

                                                                
  unsigned getPointerAddressSpace() const {
    return getPointerOperandType()->getPointerAddressSpace();
  }

  unsigned getNumIndices() const {                              
    return getNumOperands() - 1;
  }

  bool hasIndices() const {
    return getNumOperands() > 1;
  }

                                                              
                                                                   
                                              
  bool hasAllZeroIndices() const {
    for (const_op_iterator I = idx_begin(), E = idx_end(); I != E; ++I) {
      if (ConstantInt *C = dyn_cast<ConstantInt>(I))
        if (C->isZero())
          continue;
      return false;
    }
    return true;
  }

                                                                          
                                                          
                                     
  bool hasAllConstantIndices() const {
    for (const_op_iterator I = idx_begin(), E = idx_end(); I != E; ++I) {
      if (!isa<ConstantInt>(I))
        return false;
    }
    return true;
  }

  unsigned countNonConstantIndices() const {
    return count_if(make_range(idx_begin(), idx_end()), [](const Use& use) {
        return !isa<ConstantInt>(*use);
      });
  }

                                                                     
     
                                                                              
                                                                          
                                                                         
                                                                            
                                                                                
                       
  bool accumulateConstantOffset(const DataLayout &DL, APInt &Offset) const;
};

class PtrToIntOperator
    : public ConcreteOperator<Operator, Instruction::PtrToInt> {
  friend class PtrToInt;
  friend class ConstantExpr;

public:
  Value *getPointerOperand() {
    return getOperand(0);
  }
  const Value *getPointerOperand() const {
    return getOperand(0);
  }

  static unsigned getPointerOperandIndex() {
    return 0U;                                                                
  }

                                                            
  Type *getPointerOperandType() const {
    return getPointerOperand()->getType();
  }

                                                                
  unsigned getPointerAddressSpace() const {
    return cast<PointerType>(getPointerOperandType())->getAddressSpace();
  }
};

class BitCastOperator
    : public ConcreteOperator<Operator, Instruction::BitCast> {
  friend class BitCastInst;
  friend class ConstantExpr;

public:
  Type *getSrcTy() const {
    return getOperand(0)->getType();
  }

  Type *getDestTy() const {
    return getType();
  }
};

}                      

#endif                      
