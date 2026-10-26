//===- llvm/Instructions.h - Instruction subclass definitions ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file exposes the class definitions of all of the subclasses of the
// Instruction class.  This is meant to be an easy way to get access to all
// instruction subclasses.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_INSTRUCTIONS_H
#define LLVM_IR_INSTRUCTIONS_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/ADT/iterator.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/BasicBlock.h"
#include "llvh/IR/CallingConv.h"
#include "llvh/IR/Constant.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/Function.h"
#include "llvh/IR/InstrTypes.h"
#include "llvh/IR/Instruction.h"
#include "llvh/IR/OperandTraits.h"
#include "llvh/IR/Type.h"
#include "llvh/IR/Use.h"
#include "llvh/IR/User.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/AtomicOrdering.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>

namespace llvh {

class APInt;
class ConstantInt;
class DataLayout;
class LLVMContext;

                                                                                
                                                  
                                                                                

                                                  
class AllocaInst : public UnaryInstruction {
  Type *AllocatedType;

protected:
                                                                   
  friend class Instruction;

  AllocaInst *cloneImpl() const;

public:
  explicit AllocaInst(Type *Ty, unsigned AddrSpace,
                      Value *ArraySize = nullptr,
                      const Twine &Name = "",
                      Instruction *InsertBefore = nullptr);
  AllocaInst(Type *Ty, unsigned AddrSpace, Value *ArraySize,
             const Twine &Name, BasicBlock *InsertAtEnd);

  AllocaInst(Type *Ty, unsigned AddrSpace,
             const Twine &Name, Instruction *InsertBefore = nullptr);
  AllocaInst(Type *Ty, unsigned AddrSpace,
             const Twine &Name, BasicBlock *InsertAtEnd);

  AllocaInst(Type *Ty, unsigned AddrSpace, Value *ArraySize, unsigned Align,
             const Twine &Name = "", Instruction *InsertBefore = nullptr);
  AllocaInst(Type *Ty, unsigned AddrSpace, Value *ArraySize, unsigned Align,
             const Twine &Name, BasicBlock *InsertAtEnd);

                                                                            
                                
  bool isArrayAllocation() const;

                                                                               
                                                   
  const Value *getArraySize() const { return getOperand(0); }
  Value *getArraySize() { return getOperand(0); }

                                                    
  PointerType *getType() const {
    return cast<PointerType>(Instruction::getType());
  }

                                                                            
                            
  Optional<uint64_t> getAllocationSizeInBits(const DataLayout &DL) const;

                                                                 
  Type *getAllocatedType() const { return AllocatedType; }
                                                                    
                                                                       
  void setAllocatedType(Type *Ty) { AllocatedType = Ty; }

                                                                       
                  
  unsigned getAlignment() const {
    return (1u << (getSubclassDataFromInstruction() & 31)) >> 1;
  }
  void setAlignment(unsigned Align);

                                                                               
                                                                    
                                                  
  bool isStaticAlloca() const;

                                                                                
                                                                              
  bool isUsedWithInAlloca() const {
    return getSubclassDataFromInstruction() & 32;
  }

                                                                               
  void setUsedWithInAlloca(bool V) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~32) |
                               (V ? 32 : 0));
  }

                                                                            
  bool isSwiftError() const {
    return getSubclassDataFromInstruction() & 64;
  }

                                                                    
  void setSwiftError(bool V) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~64) |
                               (V ? 64 : 0));
  }

                                                                      
  static bool classof(const Instruction *I) {
    return (I->getOpcode() == Instruction::Alloca);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }
};

                                                                                
                                                
                                                                                

                                                                               
                                                       
class LoadInst : public UnaryInstruction {
  void AssertOK();

protected:
                                                                   
  friend class Instruction;

  LoadInst *cloneImpl() const;

public:
  LoadInst(Value *Ptr, const Twine &NameStr, Instruction *InsertBefore);
  LoadInst(Value *Ptr, const Twine &NameStr, BasicBlock *InsertAtEnd);
  LoadInst(Type *Ty, Value *Ptr, const Twine &NameStr, bool isVolatile = false,
           Instruction *InsertBefore = nullptr);
  LoadInst(Value *Ptr, const Twine &NameStr, bool isVolatile = false,
           Instruction *InsertBefore = nullptr)
      : LoadInst(cast<PointerType>(Ptr->getType())->getElementType(), Ptr,
                 NameStr, isVolatile, InsertBefore) {}
  LoadInst(Value *Ptr, const Twine &NameStr, bool isVolatile,
           BasicBlock *InsertAtEnd);
  LoadInst(Value *Ptr, const Twine &NameStr, bool isVolatile, unsigned Align,
           Instruction *InsertBefore = nullptr)
      : LoadInst(cast<PointerType>(Ptr->getType())->getElementType(), Ptr,
                 NameStr, isVolatile, Align, InsertBefore) {}
  LoadInst(Type *Ty, Value *Ptr, const Twine &NameStr, bool isVolatile,
           unsigned Align, Instruction *InsertBefore = nullptr);
  LoadInst(Value *Ptr, const Twine &NameStr, bool isVolatile,
           unsigned Align, BasicBlock *InsertAtEnd);
  LoadInst(Value *Ptr, const Twine &NameStr, bool isVolatile, unsigned Align,
           AtomicOrdering Order, SyncScope::ID SSID = SyncScope::System,
           Instruction *InsertBefore = nullptr)
      : LoadInst(cast<PointerType>(Ptr->getType())->getElementType(), Ptr,
                 NameStr, isVolatile, Align, Order, SSID, InsertBefore) {}
  LoadInst(Type *Ty, Value *Ptr, const Twine &NameStr, bool isVolatile,
           unsigned Align, AtomicOrdering Order,
           SyncScope::ID SSID = SyncScope::System,
           Instruction *InsertBefore = nullptr);
  LoadInst(Value *Ptr, const Twine &NameStr, bool isVolatile,
           unsigned Align, AtomicOrdering Order, SyncScope::ID SSID,
           BasicBlock *InsertAtEnd);
  LoadInst(Value *Ptr, const char *NameStr, Instruction *InsertBefore);
  LoadInst(Value *Ptr, const char *NameStr, BasicBlock *InsertAtEnd);
  LoadInst(Type *Ty, Value *Ptr, const char *NameStr = nullptr,
           bool isVolatile = false, Instruction *InsertBefore = nullptr);
  explicit LoadInst(Value *Ptr, const char *NameStr = nullptr,
                    bool isVolatile = false,
                    Instruction *InsertBefore = nullptr)
      : LoadInst(cast<PointerType>(Ptr->getType())->getElementType(), Ptr,
                 NameStr, isVolatile, InsertBefore) {}
  LoadInst(Value *Ptr, const char *NameStr, bool isVolatile,
           BasicBlock *InsertAtEnd);

                                                                    
  bool isVolatile() const { return getSubclassDataFromInstruction() & 1; }

                                                     
  void setVolatile(bool V) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~1) |
                               (V ? 1 : 0));
  }

                                                                 
  unsigned getAlignment() const {
    return (1 << ((getSubclassDataFromInstruction() >> 1) & 31)) >> 1;
  }

  void setAlignment(unsigned Align);

                                                               
  AtomicOrdering getOrdering() const {
    return AtomicOrdering((getSubclassDataFromInstruction() >> 7) & 7);
  }

                                                                                
                        
  void setOrdering(AtomicOrdering Ordering) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~(7 << 7)) |
                               ((unsigned)Ordering << 7));
  }

                                                                    
  SyncScope::ID getSyncScopeID() const {
    return SSID;
  }

                                                                 
  void setSyncScopeID(SyncScope::ID SSID) {
    this->SSID = SSID;
  }

                                                                                
                  
  void setAtomic(AtomicOrdering Ordering,
                 SyncScope::ID SSID = SyncScope::System) {
    setOrdering(Ordering);
    setSyncScopeID(SSID);
  }

  bool isSimple() const { return !isAtomic() && !isVolatile(); }

  bool isUnordered() const {
    return (getOrdering() == AtomicOrdering::NotAtomic ||
            getOrdering() == AtomicOrdering::Unordered) &&
           !isVolatile();
  }

  Value *getPointerOperand() { return getOperand(0); }
  const Value *getPointerOperand() const { return getOperand(0); }
  static unsigned getPointerOperandIndex() { return 0U; }
  Type *getPointerOperandType() const { return getPointerOperand()->getType(); }

                                                       
  unsigned getPointerAddressSpace() const {
    return getPointerOperandType()->getPointerAddressSpace();
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Load;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }

                                                                              
                                                                               
                
  SyncScope::ID SSID;
};

                                                                                
                                                 
                                                                                

                                         
class StoreInst : public Instruction {
  void AssertOK();

protected:
                                                                   
  friend class Instruction;

  StoreInst *cloneImpl() const;

public:
  StoreInst(Value *Val, Value *Ptr, Instruction *InsertBefore);
  StoreInst(Value *Val, Value *Ptr, BasicBlock *InsertAtEnd);
  StoreInst(Value *Val, Value *Ptr, bool isVolatile = false,
            Instruction *InsertBefore = nullptr);
  StoreInst(Value *Val, Value *Ptr, bool isVolatile, BasicBlock *InsertAtEnd);
  StoreInst(Value *Val, Value *Ptr, bool isVolatile,
            unsigned Align, Instruction *InsertBefore = nullptr);
  StoreInst(Value *Val, Value *Ptr, bool isVolatile,
            unsigned Align, BasicBlock *InsertAtEnd);
  StoreInst(Value *Val, Value *Ptr, bool isVolatile,
            unsigned Align, AtomicOrdering Order,
            SyncScope::ID SSID = SyncScope::System,
            Instruction *InsertBefore = nullptr);
  StoreInst(Value *Val, Value *Ptr, bool isVolatile,
            unsigned Align, AtomicOrdering Order, SyncScope::ID SSID,
            BasicBlock *InsertAtEnd);

                                            
  void *operator new(size_t s) {
    return User::operator new(s, 2);
  }

                                                                   
  bool isVolatile() const { return getSubclassDataFromInstruction() & 1; }

                                                      
  void setVolatile(bool V) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~1) |
                               (V ? 1 : 0));
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                
  unsigned getAlignment() const {
    return (1 << ((getSubclassDataFromInstruction() >> 1) & 31)) >> 1;
  }

  void setAlignment(unsigned Align);

                                                                
  AtomicOrdering getOrdering() const {
    return AtomicOrdering((getSubclassDataFromInstruction() >> 7) & 7);
  }

                                                                         
                                
  void setOrdering(AtomicOrdering Ordering) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~(7 << 7)) |
                               ((unsigned)Ordering << 7));
  }

                                                                     
  SyncScope::ID getSyncScopeID() const {
    return SSID;
  }

                                                                  
  void setSyncScopeID(SyncScope::ID SSID) {
    this->SSID = SSID;
  }

                                                                           
                        
  void setAtomic(AtomicOrdering Ordering,
                 SyncScope::ID SSID = SyncScope::System) {
    setOrdering(Ordering);
    setSyncScopeID(SSID);
  }

  bool isSimple() const { return !isAtomic() && !isVolatile(); }

  bool isUnordered() const {
    return (getOrdering() == AtomicOrdering::NotAtomic ||
            getOrdering() == AtomicOrdering::Unordered) &&
           !isVolatile();
  }

  Value *getValueOperand() { return getOperand(0); }
  const Value *getValueOperand() const { return getOperand(0); }

  Value *getPointerOperand() { return getOperand(1); }
  const Value *getPointerOperand() const { return getOperand(1); }
  static unsigned getPointerOperandIndex() { return 1U; }
  Type *getPointerOperandType() const { return getPointerOperand()->getType(); }

                                                       
  unsigned getPointerAddressSpace() const {
    return getPointerOperandType()->getPointerAddressSpace();
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Store;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }

                                                                               
                                                                               
                
  SyncScope::ID SSID;
};

template <>
struct OperandTraits<StoreInst> : public FixedNumOperandTraits<StoreInst, 2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(StoreInst, Value)

                                                                                
                                                 
                                                                                

                                                        
class FenceInst : public Instruction {
  void Init(AtomicOrdering Ordering, SyncScope::ID SSID);

protected:
                                                                   
  friend class Instruction;

  FenceInst *cloneImpl() const;

public:
                                                              
                            
  FenceInst(LLVMContext &C, AtomicOrdering Ordering,
            SyncScope::ID SSID = SyncScope::System,
            Instruction *InsertBefore = nullptr);
  FenceInst(LLVMContext &C, AtomicOrdering Ordering, SyncScope::ID SSID,
            BasicBlock *InsertAtEnd);

                                             
  void *operator new(size_t s) {
    return User::operator new(s, 0);
  }

                                                                
  AtomicOrdering getOrdering() const {
    return AtomicOrdering(getSubclassDataFromInstruction() >> 1);
  }

                                                                          
                                                                  
  void setOrdering(AtomicOrdering Ordering) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & 1) |
                               ((unsigned)Ordering << 1));
  }

                                                                     
  SyncScope::ID getSyncScopeID() const {
    return SSID;
  }

                                                                  
  void setSyncScopeID(SyncScope::ID SSID) {
    this->SSID = SSID;
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Fence;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }

                                                                               
                                                                               
                
  SyncScope::ID SSID;
};

                                                                                
                                                         
                                                                                

                                                   
                                                                              
                                              
   
class AtomicCmpXchgInst : public Instruction {
  void Init(Value *Ptr, Value *Cmp, Value *NewVal,
            AtomicOrdering SuccessOrdering, AtomicOrdering FailureOrdering,
            SyncScope::ID SSID);

protected:
                                                                   
  friend class Instruction;

  AtomicCmpXchgInst *cloneImpl() const;

public:
  AtomicCmpXchgInst(Value *Ptr, Value *Cmp, Value *NewVal,
                    AtomicOrdering SuccessOrdering,
                    AtomicOrdering FailureOrdering,
                    SyncScope::ID SSID, Instruction *InsertBefore = nullptr);
  AtomicCmpXchgInst(Value *Ptr, Value *Cmp, Value *NewVal,
                    AtomicOrdering SuccessOrdering,
                    AtomicOrdering FailureOrdering,
                    SyncScope::ID SSID, BasicBlock *InsertAtEnd);

                                              
  void *operator new(size_t s) {
    return User::operator new(s, 3);
  }

                                                             
               
     
  bool isVolatile() const {
    return getSubclassDataFromInstruction() & 1;
  }

                                                 
     
  void setVolatile(bool V) {
     setInstructionSubclassData((getSubclassDataFromInstruction() & ~1) |
                                (unsigned)V);
  }

                                                      
  bool isWeak() const {
    return getSubclassDataFromInstruction() & 0x100;
  }

  void setWeak(bool IsWeak) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~0x100) |
                               (IsWeak << 8));
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                          
  AtomicOrdering getSuccessOrdering() const {
    return AtomicOrdering((getSubclassDataFromInstruction() >> 2) & 7);
  }

                                                                       
  void setSuccessOrdering(AtomicOrdering Ordering) {
    assert(Ordering != AtomicOrdering::NotAtomic &&
           "CmpXchg instructions can only be atomic.");
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~0x1c) |
                               ((unsigned)Ordering << 2));
  }

                                                                          
  AtomicOrdering getFailureOrdering() const {
    return AtomicOrdering((getSubclassDataFromInstruction() >> 5) & 7);
  }

                                                                       
  void setFailureOrdering(AtomicOrdering Ordering) {
    assert(Ordering != AtomicOrdering::NotAtomic &&
           "CmpXchg instructions can only be atomic.");
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~0xe0) |
                               ((unsigned)Ordering << 5));
  }

                                                                       
  SyncScope::ID getSyncScopeID() const {
    return SSID;
  }

                                                                    
  void setSyncScopeID(SyncScope::ID SSID) {
    this->SSID = SSID;
  }

  Value *getPointerOperand() { return getOperand(0); }
  const Value *getPointerOperand() const { return getOperand(0); }
  static unsigned getPointerOperandIndex() { return 0U; }

  Value *getCompareOperand() { return getOperand(1); }
  const Value *getCompareOperand() const { return getOperand(1); }

  Value *getNewValOperand() { return getOperand(2); }
  const Value *getNewValOperand() const { return getOperand(2); }

                                                       
  unsigned getPointerAddressSpace() const {
    return getPointerOperand()->getType()->getPointerAddressSpace();
  }

                                                                    
                                  
     
                                                                              
                                                                              
                                                                        
                                                    
  static AtomicOrdering
  getStrongestFailureOrdering(AtomicOrdering SuccessOrdering) {
    switch (SuccessOrdering) {
    default:
      llvm_unreachable("invalid cmpxchg success ordering");
    case AtomicOrdering::Release:
    case AtomicOrdering::Monotonic:
      return AtomicOrdering::Monotonic;
    case AtomicOrdering::AcquireRelease:
    case AtomicOrdering::Acquire:
      return AtomicOrdering::Acquire;
    case AtomicOrdering::SequentiallyConsistent:
      return AtomicOrdering::SequentiallyConsistent;
    }
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::AtomicCmpXchg;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }

                                                                          
                                                                             
                         
  SyncScope::ID SSID;
};

template <>
struct OperandTraits<AtomicCmpXchgInst> :
    public FixedNumOperandTraits<AtomicCmpXchgInst, 3> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(AtomicCmpXchgInst, Value)

                                                                                
                                                     
                                                                                

                                                           
                                                                             
                  
   
class AtomicRMWInst : public Instruction {
protected:
                                                                   
  friend class Instruction;

  AtomicRMWInst *cloneImpl() const;

public:
                                                                               
                                                                                
                                                                                
                                                           
  enum BinOp {
              
    Xchg,
                    
    Add,
                    
    Sub,
                    
    And,
                       
    Nand,
                    
    Or,
                    
    Xor,
                                    
    Max,
                                    
    Min,
                                      
    UMax,
                                      
    UMin,

    FIRST_BINOP = Xchg,
    LAST_BINOP = UMin,
    BAD_BINOP
  };

  AtomicRMWInst(BinOp Operation, Value *Ptr, Value *Val,
                AtomicOrdering Ordering, SyncScope::ID SSID,
                Instruction *InsertBefore = nullptr);
  AtomicRMWInst(BinOp Operation, Value *Ptr, Value *Val,
                AtomicOrdering Ordering, SyncScope::ID SSID,
                BasicBlock *InsertAtEnd);

                                            
  void *operator new(size_t s) {
    return User::operator new(s, 2);
  }

  BinOp getOperation() const {
    return static_cast<BinOp>(getSubclassDataFromInstruction() >> 5);
  }

  static StringRef getOperationName(BinOp Op);

  void setOperation(BinOp Operation) {
    unsigned short SubclassData = getSubclassDataFromInstruction();
    setInstructionSubclassData((SubclassData & 31) |
                               (Operation << 5));
  }

                                                                 
     
  bool isVolatile() const {
    return getSubclassDataFromInstruction() & 1;
  }

                                                    
     
  void setVolatile(bool V) {
     setInstructionSubclassData((getSubclassDataFromInstruction() & ~1) |
                                (unsigned)V);
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                              
  AtomicOrdering getOrdering() const {
    return AtomicOrdering((getSubclassDataFromInstruction() >> 2) & 7);
  }

                                                           
  void setOrdering(AtomicOrdering Ordering) {
    assert(Ordering != AtomicOrdering::NotAtomic &&
           "atomicrmw instructions can only be atomic.");
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~(7 << 2)) |
                               ((unsigned)Ordering << 2));
  }

                                                                   
  SyncScope::ID getSyncScopeID() const {
    return SSID;
  }

                                                                
  void setSyncScopeID(SyncScope::ID SSID) {
    this->SSID = SSID;
  }

  Value *getPointerOperand() { return getOperand(0); }
  const Value *getPointerOperand() const { return getOperand(0); }
  static unsigned getPointerOperandIndex() { return 0U; }

  Value *getValOperand() { return getOperand(1); }
  const Value *getValOperand() const { return getOperand(1); }

                                                       
  unsigned getPointerAddressSpace() const {
    return getPointerOperand()->getType()->getPointerAddressSpace();
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::AtomicRMW;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
  void Init(BinOp Operation, Value *Ptr, Value *Val,
            AtomicOrdering Ordering, SyncScope::ID SSID);

                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }

                                                                             
                                                                               
                
  SyncScope::ID SSID;
};

template <>
struct OperandTraits<AtomicRMWInst>
    : public FixedNumOperandTraits<AtomicRMWInst,2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(AtomicRMWInst, Value)

                                                                                
                                                      
                                                                                

                                                                            
                                                
  
inline Type *checkGEPType(Type *Ty) {
  assert(Ty && "Invalid GetElementPtrInst indices for type!");
  return Ty;
}

                                                      
                                         
   
class GetElementPtrInst : public Instruction {
  Type *SourceElementType;
  Type *ResultElementType;

  GetElementPtrInst(const GetElementPtrInst &GEPI);

                                                                              
                                                                              
                                                                          
                 
  inline GetElementPtrInst(Type *PointeeType, Value *Ptr,
                           ArrayRef<Value *> IdxList, unsigned Values,
                           const Twine &NameStr, Instruction *InsertBefore);
  inline GetElementPtrInst(Type *PointeeType, Value *Ptr,
                           ArrayRef<Value *> IdxList, unsigned Values,
                           const Twine &NameStr, BasicBlock *InsertAtEnd);

  void init(Value *Ptr, ArrayRef<Value *> IdxList, const Twine &NameStr);

protected:
                                                                   
  friend class Instruction;

  GetElementPtrInst *cloneImpl() const;

public:
  static GetElementPtrInst *Create(Type *PointeeType, Value *Ptr,
                                   ArrayRef<Value *> IdxList,
                                   const Twine &NameStr = "",
                                   Instruction *InsertBefore = nullptr) {
    unsigned Values = 1 + unsigned(IdxList.size());
    if (!PointeeType)
      PointeeType =
          cast<PointerType>(Ptr->getType()->getScalarType())->getElementType();
    else
      assert(
          PointeeType ==
          cast<PointerType>(Ptr->getType()->getScalarType())->getElementType());
    return new (Values) GetElementPtrInst(PointeeType, Ptr, IdxList, Values,
                                          NameStr, InsertBefore);
  }

  static GetElementPtrInst *Create(Type *PointeeType, Value *Ptr,
                                   ArrayRef<Value *> IdxList,
                                   const Twine &NameStr,
                                   BasicBlock *InsertAtEnd) {
    unsigned Values = 1 + unsigned(IdxList.size());
    if (!PointeeType)
      PointeeType =
          cast<PointerType>(Ptr->getType()->getScalarType())->getElementType();
    else
      assert(
          PointeeType ==
          cast<PointerType>(Ptr->getType()->getScalarType())->getElementType());
    return new (Values) GetElementPtrInst(PointeeType, Ptr, IdxList, Values,
                                          NameStr, InsertAtEnd);
  }

                                                                       
                                                  
  static GetElementPtrInst *CreateInBounds(Value *Ptr,
                                           ArrayRef<Value *> IdxList,
                                           const Twine &NameStr = "",
                                           Instruction *InsertBefore = nullptr){
    return CreateInBounds(nullptr, Ptr, IdxList, NameStr, InsertBefore);
  }

  static GetElementPtrInst *
  CreateInBounds(Type *PointeeType, Value *Ptr, ArrayRef<Value *> IdxList,
                 const Twine &NameStr = "",
                 Instruction *InsertBefore = nullptr) {
    GetElementPtrInst *GEP =
        Create(PointeeType, Ptr, IdxList, NameStr, InsertBefore);
    GEP->setIsInBounds(true);
    return GEP;
  }

  static GetElementPtrInst *CreateInBounds(Value *Ptr,
                                           ArrayRef<Value *> IdxList,
                                           const Twine &NameStr,
                                           BasicBlock *InsertAtEnd) {
    return CreateInBounds(nullptr, Ptr, IdxList, NameStr, InsertAtEnd);
  }

  static GetElementPtrInst *CreateInBounds(Type *PointeeType, Value *Ptr,
                                           ArrayRef<Value *> IdxList,
                                           const Twine &NameStr,
                                           BasicBlock *InsertAtEnd) {
    GetElementPtrInst *GEP =
        Create(PointeeType, Ptr, IdxList, NameStr, InsertAtEnd);
    GEP->setIsInBounds(true);
    return GEP;
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

  Type *getSourceElementType() const { return SourceElementType; }

  void setSourceElementType(Type *Ty) { SourceElementType = Ty; }
  void setResultElementType(Type *Ty) { ResultElementType = Ty; }

  Type *getResultElementType() const {
    assert(ResultElementType ==
           cast<PointerType>(getType()->getScalarType())->getElementType());
    return ResultElementType;
  }

                                                                   
  unsigned getAddressSpace() const {
                                                                               
                                                     
    return getPointerAddressSpace();
  }

                                                               
                                                       
     
                                                                   
                   
     
  static Type *getIndexedType(Type *Ty, ArrayRef<Value *> IdxList);
  static Type *getIndexedType(Type *Ty, ArrayRef<Constant *> IdxList);
  static Type *getIndexedType(Type *Ty, ArrayRef<uint64_t> IdxList);

  inline op_iterator       idx_begin()       { return op_begin()+1; }
  inline const_op_iterator idx_begin() const { return op_begin()+1; }
  inline op_iterator       idx_end()         { return op_end(); }
  inline const_op_iterator idx_end()   const { return op_end(); }

  inline iterator_range<op_iterator> indices() {
    return make_range(idx_begin(), idx_end());
  }

  inline iterator_range<const_op_iterator> indices() const {
    return make_range(idx_begin(), idx_end());
  }

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
    return getPointerOperandType()->getPointerAddressSpace();
  }

                                                  
                                                     
  static Type *getGEPReturnType(Value *Ptr, ArrayRef<Value *> IdxList) {
    return getGEPReturnType(
      cast<PointerType>(Ptr->getType()->getScalarType())->getElementType(),
      Ptr, IdxList);
  }
  static Type *getGEPReturnType(Type *ElTy, Value *Ptr,
                                ArrayRef<Value *> IdxList) {
    Type *PtrTy = PointerType::get(checkGEPType(getIndexedType(ElTy, IdxList)),
                                   Ptr->getType()->getPointerAddressSpace());
                 
    if (Ptr->getType()->isVectorTy()) {
      unsigned NumElem = Ptr->getType()->getVectorNumElements();
      return VectorType::get(PtrTy, NumElem);
    }
    for (Value *Index : IdxList)
      if (Index->getType()->isVectorTy()) {
        unsigned NumElem = Index->getType()->getVectorNumElements();
        return VectorType::get(PtrTy, NumElem);
      }
                 
    return PtrTy;
  }

  unsigned getNumIndices() const {                              
    return getNumOperands() - 1;
  }

  bool hasIndices() const {
    return getNumOperands() > 1;
  }

                                                       
                                                                           
                                              
  bool hasAllZeroIndices() const;

                                                       
                                                                              
                                     
  bool hasAllConstantIndices() const;

                                                             
                                                                      
  void setIsInBounds(bool b = true);

                                                      
  bool isInBounds() const;

                                                                     
     
                                                                              
                                                                          
                                                                         
                                                                            
                                                                          
                           
  bool accumulateConstantOffset(const DataLayout &DL, APInt &Offset) const;

                                                                      
  static bool classof(const Instruction *I) {
    return (I->getOpcode() == Instruction::GetElementPtr);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<GetElementPtrInst> :
  public VariadicOperandTraits<GetElementPtrInst, 1> {
};

GetElementPtrInst::GetElementPtrInst(Type *PointeeType, Value *Ptr,
                                     ArrayRef<Value *> IdxList, unsigned Values,
                                     const Twine &NameStr,
                                     Instruction *InsertBefore)
    : Instruction(getGEPReturnType(PointeeType, Ptr, IdxList), GetElementPtr,
                  OperandTraits<GetElementPtrInst>::op_end(this) - Values,
                  Values, InsertBefore),
      SourceElementType(PointeeType),
      ResultElementType(getIndexedType(PointeeType, IdxList)) {
  assert(ResultElementType ==
         cast<PointerType>(getType()->getScalarType())->getElementType());
  init(Ptr, IdxList, NameStr);
}

GetElementPtrInst::GetElementPtrInst(Type *PointeeType, Value *Ptr,
                                     ArrayRef<Value *> IdxList, unsigned Values,
                                     const Twine &NameStr,
                                     BasicBlock *InsertAtEnd)
    : Instruction(getGEPReturnType(PointeeType, Ptr, IdxList), GetElementPtr,
                  OperandTraits<GetElementPtrInst>::op_end(this) - Values,
                  Values, InsertAtEnd),
      SourceElementType(PointeeType),
      ResultElementType(getIndexedType(PointeeType, IdxList)) {
  assert(ResultElementType ==
         cast<PointerType>(getType()->getScalarType())->getElementType());
  init(Ptr, IdxList, NameStr);
}

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(GetElementPtrInst, Value)

                                                                                
                                               
                                                                                

                                                                           
                                                                              
                            
                                             
class ICmpInst: public CmpInst {
  void AssertOK() {
    assert(isIntPredicate() &&
           "Invalid ICmp predicate value");
    assert(getOperand(0)->getType() == getOperand(1)->getType() &&
          "Both operands to ICmp instruction are not of the same type!");
                                                 
    assert((getOperand(0)->getType()->isIntOrIntVectorTy() ||
            getOperand(0)->getType()->isPtrOrPtrVectorTy()) &&
           "Invalid operand types for ICmp instruction");
  }

protected:
                                                                   
  friend class Instruction;

                                 
  ICmpInst *cloneImpl() const;

public:
                                                           
  ICmpInst(
    Instruction *InsertBefore,                      
    Predicate pred,                                              
    Value *LHS,                                               
    Value *RHS,                                                
    const Twine &NameStr = ""                              
  ) : CmpInst(makeCmpResultType(LHS->getType()),
              Instruction::ICmp, pred, LHS, RHS, NameStr,
              InsertBefore) {
#ifndef NDEBUG
  AssertOK();
#endif
  }

                                               
  ICmpInst(
    BasicBlock &InsertAtEnd,                           
    Predicate pred,                                              
    Value *LHS,                                               
    Value *RHS,                                                
    const Twine &NameStr = ""                              
  ) : CmpInst(makeCmpResultType(LHS->getType()),
              Instruction::ICmp, pred, LHS, RHS, NameStr,
              &InsertAtEnd) {
#ifndef NDEBUG
  AssertOK();
#endif
  }

                                             
  ICmpInst(
    Predicate pred,                                             
    Value *LHS,                                              
    Value *RHS,                                               
    const Twine &NameStr = ""                             
  ) : CmpInst(makeCmpResultType(LHS->getType()),
              Instruction::ICmp, pred, LHS, RHS, NameStr) {
#ifndef NDEBUG
  AssertOK();
#endif
  }

                                                   
                                                                         
                         
                                                
  Predicate getSignedPredicate() const {
    return getSignedPredicate(getPredicate());
  }

                                                                       
                                                 
  static Predicate getSignedPredicate(Predicate pred);

                                                   
                                                                         
                           
                                                  
  Predicate getUnsignedPredicate() const {
    return getUnsignedPredicate(getPredicate());
  }

                                                                       
                                                   
  static Predicate getUnsignedPredicate(Predicate pred);

                                                                  
                              
  static bool isEquality(Predicate P) {
    return P == ICMP_EQ || P == ICMP_NE;
  }

                                                                  
                              
  bool isEquality() const {
    return isEquality(getPredicate());
  }

                                                                    
                                                
  bool isCommutative() const { return isEquality(); }

                                                                
     
  bool isRelational() const {
    return !isEquality();
  }

                                                                
     
  static bool isRelational(Predicate P) {
    return !isEquality(P);
  }

                                                                              
                                                                             
                                                                           
                 
                                         
  void swapOperands() {
    setPredicate(getSwappedPredicate());
    Op<0>().swap(Op<1>());
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::ICmp;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                               
                                                                                

                                                                           
                                                                           
                                                                           
                                                    
class FCmpInst: public CmpInst {
  void AssertOK() {
    assert(isFPPredicate() && "Invalid FCmp predicate value");
    assert(getOperand(0)->getType() == getOperand(1)->getType() &&
           "Both operands to FCmp instruction are not of the same type!");
                                                 
    assert(getOperand(0)->getType()->isFPOrFPVectorTy() &&
           "Invalid operand types for FCmp instruction");
  }

protected:
                                                                   
  friend class Instruction;

                                 
  FCmpInst *cloneImpl() const;

public:
                                                           
  FCmpInst(
    Instruction *InsertBefore,                     
    Predicate pred,                                              
    Value *LHS,                                               
    Value *RHS,                                                
    const Twine &NameStr = ""                              
  ) : CmpInst(makeCmpResultType(LHS->getType()),
              Instruction::FCmp, pred, LHS, RHS, NameStr,
              InsertBefore) {
    AssertOK();
  }

                                               
  FCmpInst(
    BasicBlock &InsertAtEnd,                           
    Predicate pred,                                              
    Value *LHS,                                               
    Value *RHS,                                                
    const Twine &NameStr = ""                              
  ) : CmpInst(makeCmpResultType(LHS->getType()),
              Instruction::FCmp, pred, LHS, RHS, NameStr,
              &InsertAtEnd) {
    AssertOK();
  }

                                             
  FCmpInst(
    Predicate pred,                                             
    Value *LHS,                                              
    Value *RHS,                                               
    const Twine &NameStr = ""                             
  ) : CmpInst(makeCmpResultType(LHS->getType()),
              Instruction::FCmp, pred, LHS, RHS, NameStr) {
    AssertOK();
  }

                                                                     
                                                 
  static bool isEquality(Predicate Pred) {
    return Pred == FCMP_OEQ || Pred == FCMP_ONE || Pred == FCMP_UEQ ||
           Pred == FCMP_UNE;
  }

                                                                     
                                                 
  bool isEquality() const { return isEquality(getPredicate()); }

                                                                        
                                                   
  bool isCommutative() const {
    return isEquality() ||
           getPredicate() == FCMP_FALSE ||
           getPredicate() == FCMP_TRUE ||
           getPredicate() == FCMP_ORD ||
           getPredicate() == FCMP_UNO;
  }

                                                                  
                                               
  bool isRelational() const { return !isEquality(); }

                                                                              
                                                                             
                                                                           
                 
                                         
  void swapOperands() {
    setPredicate(getSwappedPredicate());
    Op<0>().swap(Op<1>());
  }

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::FCmp;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

class CallInst;
class InvokeInst;

template <class T> struct CallBaseParent { using type = Instruction; };

template <> struct CallBaseParent<InvokeInst> { using type = TerminatorInst; };

                                                                                
                                                                      
                                                                             
                                                             
   
template <class InstTy>
class CallBase : public CallBaseParent<InstTy>::type,
                 public OperandBundleUser<InstTy, User::op_iterator> {
protected:
  AttributeList Attrs;                                       
  FunctionType *FTy;
  using BaseInstTy = typename CallBaseParent<InstTy>::type;

  template <class... ArgsTy>
  CallBase(AttributeList const &A, FunctionType *FT, ArgsTy &&... Args)
      : BaseInstTy(std::forward<ArgsTy>(Args)...), Attrs(A), FTy(FT) {}
  bool hasDescriptor() const { return Value::HasDescriptor; }

  using BaseInstTy::BaseInstTy;

  using OperandBundleUser<InstTy,
                          User::op_iterator>::isFnAttrDisallowedByOpBundle;
  using OperandBundleUser<InstTy, User::op_iterator>::getNumTotalBundleOperands;
  using OperandBundleUser<InstTy, User::op_iterator>::bundleOperandHasAttr;
  using Instruction::getSubclassDataFromInstruction;
  using Instruction::setInstructionSubclassData;

public:
  using Instruction::getContext;
  using OperandBundleUser<InstTy, User::op_iterator>::hasOperandBundles;
  using OperandBundleUser<InstTy,
                          User::op_iterator>::getBundleOperandsStartIndex;

  static bool classof(const Instruction *I) {
    llvm_unreachable(
        "CallBase is not meant to be used as part of the classof hierarchy");
  }

public:
                                                    
     
  AttributeList getAttributes() const { return Attrs; }

                                                 
     
  void setAttributes(AttributeList A) { Attrs = A; }

  FunctionType *getFunctionType() const { return FTy; }

  void mutateFunctionType(FunctionType *FTy) {
    Value::mutateType(FTy->getReturnType());
    this->FTy = FTy;
  }

                                          
     
  unsigned getNumArgOperands() const {
    return getNumOperands() - getNumTotalBundleOperands() - InstTy::ArgOffset;
  }

                                                                      
     
  Value *getArgOperand(unsigned i) const {
    assert(i < getNumArgOperands() && "Out of bounds!");
    return getOperand(i);
  }
  void setArgOperand(unsigned i, Value *v) {
    assert(i < getNumArgOperands() && "Out of bounds!");
    setOperand(i, v);
  }

                                                                         
  User::op_iterator arg_begin() { return op_begin(); }

                                                                   
  User::op_iterator arg_end() {
                                                 
    return op_end() - getNumTotalBundleOperands() - InstTy::ArgOffset;
  }

                                            
  iterator_range<User::op_iterator> arg_operands() {
    return make_range(arg_begin(), arg_end());
  }

                                                                         
  User::const_op_iterator arg_begin() const { return op_begin(); }

                                                                   
  User::const_op_iterator arg_end() const {
                                                 
    return op_end() - getNumTotalBundleOperands() - InstTy::ArgOffset;
  }

                                            
  iterator_range<User::const_op_iterator> arg_operands() const {
    return make_range(arg_begin(), arg_end());
  }

                                                         
  const Use &getArgOperandUse(unsigned i) const {
    assert(i < getNumArgOperands() && "Out of bounds!");
    return User::getOperandUse(i);
  }
  Use &getArgOperandUse(unsigned i) {
    assert(i < getNumArgOperands() && "Out of bounds!");
    return User::getOperandUse(i);
  }

                                                                      
                                               
  Value *getReturnedArgOperand() const {
    unsigned Index;

    if (Attrs.hasAttrSomewhere(Attribute::Returned, &Index) && Index)
      return getArgOperand(Index - AttributeList::FirstArgIndex);
    if (const Function *F = getCalledFunction())
      if (F->getAttributes().hasAttrSomewhere(Attribute::Returned, &Index) &&
          Index)
        return getArgOperand(Index - AttributeList::FirstArgIndex);

    return nullptr;
  }

  User::op_iterator op_begin() {
    return OperandTraits<CallBase>::op_begin(this);
  }

  User::const_op_iterator op_begin() const {
    return OperandTraits<CallBase>::op_begin(const_cast<CallBase *>(this));
  }

  User::op_iterator op_end() { return OperandTraits<CallBase>::op_end(this); }

  User::const_op_iterator op_end() const {
    return OperandTraits<CallBase>::op_end(const_cast<CallBase *>(this));
  }

  Value *getOperand(unsigned i_nocapture) const {
    assert(i_nocapture < OperandTraits<CallBase>::operands(this) &&
           "getOperand() out of range!");
    return cast_or_null<Value>(OperandTraits<CallBase>::op_begin(
                                   const_cast<CallBase *>(this))[i_nocapture]
                                   .get());
  }

  void setOperand(unsigned i_nocapture, Value *Val_nocapture) {
    assert(i_nocapture < OperandTraits<CallBase>::operands(this) &&
           "setOperand() out of range!");
    OperandTraits<CallBase>::op_begin(this)[i_nocapture] = Val_nocapture;
  }

  unsigned getNumOperands() const {
    return OperandTraits<CallBase>::operands(this);
  }
  template <int Idx_nocapture> Use &Op() {
    return User::OpFrom<Idx_nocapture>(this);
  }
  template <int Idx_nocapture> const Use &Op() const {
    return User::OpFrom<Idx_nocapture>(this);
  }

                                                       
                                   
     
  Function *getCalledFunction() const {
    return dyn_cast<Function>(Op<-InstTy::ArgOffset>());
  }

                                                          
  bool hasFnAttr(Attribute::AttrKind Kind) const {
    assert(Kind != Attribute::NoBuiltin &&
           "Use CallBase::isNoBuiltin() to check for Attribute::NoBuiltin");
    return hasFnAttrImpl(Kind);
  }

                                                          
  bool hasFnAttr(StringRef Kind) const { return hasFnAttrImpl(Kind); }

                                                                               
                    
  CallingConv::ID getCallingConv() const {
    return static_cast<CallingConv::ID>(getSubclassDataFromInstruction() >> 2);
  }
  void setCallingConv(CallingConv::ID CC) {
    auto ID = static_cast<unsigned>(CC);
    assert(!(ID & ~CallingConv::MaxID) && "Unsupported calling convention");
    setInstructionSubclassData((getSubclassDataFromInstruction() & 3) |
                               (ID << 2));
  }


                                                   
  void addAttribute(unsigned i, Attribute::AttrKind Kind) {
    AttributeList PAL = getAttributes();
    PAL = PAL.addAttribute(getContext(), i, Kind);
    setAttributes(PAL);
  }

                                                   
  void addAttribute(unsigned i, Attribute Attr) {
    AttributeList PAL = getAttributes();
    PAL = PAL.addAttribute(getContext(), i, Attr);
    setAttributes(PAL);
  }

                                                  
  void addParamAttr(unsigned ArgNo, Attribute::AttrKind Kind) {
    assert(ArgNo < getNumArgOperands() && "Out of bounds");
    AttributeList PAL = getAttributes();
    PAL = PAL.addParamAttribute(getContext(), ArgNo, Kind);
    setAttributes(PAL);
  }

                                                  
  void addParamAttr(unsigned ArgNo, Attribute Attr) {
    assert(ArgNo < getNumArgOperands() && "Out of bounds");
    AttributeList PAL = getAttributes();
    PAL = PAL.addParamAttribute(getContext(), ArgNo, Attr);
    setAttributes(PAL);
  }

                                                        
  void removeAttribute(unsigned i, Attribute::AttrKind Kind) {
    AttributeList PAL = getAttributes();
    PAL = PAL.removeAttribute(getContext(), i, Kind);
    setAttributes(PAL);
  }

                                                        
  void removeAttribute(unsigned i, StringRef Kind) {
    AttributeList PAL = getAttributes();
    PAL = PAL.removeAttribute(getContext(), i, Kind);
    setAttributes(PAL);
  }

                                                   
  void removeParamAttr(unsigned ArgNo, Attribute::AttrKind Kind) {
    assert(ArgNo < getNumArgOperands() && "Out of bounds");
    AttributeList PAL = getAttributes();
    PAL = PAL.removeParamAttribute(getContext(), ArgNo, Kind);
    setAttributes(PAL);
  }

                                                   
  void removeParamAttr(unsigned ArgNo, StringRef Kind) {
    assert(ArgNo < getNumArgOperands() && "Out of bounds");
    AttributeList PAL = getAttributes();
    PAL = PAL.removeParamAttribute(getContext(), ArgNo, Kind);
    setAttributes(PAL);
  }

                                                                   
  void addDereferenceableAttr(unsigned i, uint64_t Bytes) {
    AttributeList PAL = getAttributes();
    PAL = PAL.addDereferenceableAttr(getContext(), i, Bytes);
    setAttributes(PAL);
  }

                                                               
                 
  void addDereferenceableOrNullAttr(unsigned i, uint64_t Bytes) {
    AttributeList PAL = getAttributes();
    PAL = PAL.addDereferenceableOrNullAttr(getContext(), i, Bytes);
    setAttributes(PAL);
  }

                                                                 
  bool hasRetAttr(Attribute::AttrKind Kind) const {
    if (Attrs.hasAttribute(AttributeList::ReturnIndex, Kind))
      return true;

                                        
    if (const Function *F = getCalledFunction())
      return F->getAttributes().hasAttribute(AttributeList::ReturnIndex, Kind);
    return false;
  }

                                                                          
  bool paramHasAttr(unsigned ArgNo, Attribute::AttrKind Kind) const {
    assert(ArgNo < getNumArgOperands() && "Param index out of bounds!");

    if (Attrs.hasParamAttribute(ArgNo, Kind))
      return true;
    if (const Function *F = getCalledFunction())
      return F->getAttributes().hasParamAttribute(ArgNo, Kind);
    return false;
  }

                                                      
  Attribute getAttribute(unsigned i, Attribute::AttrKind Kind) const {
    return getAttributes().getAttribute(i, Kind);
  }

                                                      
  Attribute getAttribute(unsigned i, StringRef Kind) const {
    return getAttributes().getAttribute(i, Kind);
  }

                                                        
  Attribute getParamAttr(unsigned ArgNo, Attribute::AttrKind Kind) const {
    assert(ArgNo < getNumArgOperands() && "Out of bounds");
    return getAttributes().getParamAttr(ArgNo, Kind);
  }

                                                        
  Attribute getParamAttr(unsigned ArgNo, StringRef Kind) const {
    assert(ArgNo < getNumArgOperands() && "Out of bounds");
    return getAttributes().getParamAttr(ArgNo, Kind);
  }
                                                                        
        
     
                                                                              
                                                                              
                                                                       
     
                                      
     
                                                          
                                                               
                                                                               
                                         
  bool dataOperandHasImpliedAttr(unsigned i, Attribute::AttrKind Kind) const {
                                                                          
                                      
    assert(i < (getNumOperands() - InstTy::ArgOffset + 1) &&
           "Data operand index out of bounds!");

                                                                          
                                                                               
                                                                     

    if (i == AttributeList::ReturnIndex)
      return hasRetAttr(Kind);

                                                                      
                          
    if (i < (getNumArgOperands() + 1))
      return paramHasAttr(i - 1, Kind);

    assert(hasOperandBundles() && i >= (getBundleOperandsStartIndex() + 1) &&
           "Must be either a call argument or an operand bundle!");
    return bundleOperandHasAttr(i - 1, Kind);
  }

                                                
  unsigned getRetAlignment() const { return Attrs.getRetAlignment(); }

                                                                
  unsigned getParamAlignment(unsigned ArgNo) const {
    return Attrs.getParamAlignment(ArgNo);
  }

                                                               
                            
  uint64_t getDereferenceableBytes(unsigned i) const {
    return Attrs.getDereferenceableBytes(i);
  }

                                                                       
                            
  uint64_t getDereferenceableOrNullBytes(unsigned i) const {
    return Attrs.getDereferenceableOrNullBytes(i);
  }

                                                                     
  bool returnDoesNotAlias() const {
    return Attrs.hasAttribute(AttributeList::ReturnIndex, Attribute::NoAlias);
  }

                                                                  
              
  bool isNoBuiltin() const {
    return hasFnAttrImpl(Attribute::NoBuiltin) &&
      !hasFnAttrImpl(Attribute::Builtin);
  }

                                                                     
  bool isStrictFP() const { return hasFnAttr(Attribute::StrictFP); }

                                                    
  bool isNoInline() const { return hasFnAttr(Attribute::NoInline); }
  void setIsNoInline() {
    addAttribute(AttributeList::FunctionIndex, Attribute::NoInline);
  }
                                                   
  bool doesNotAccessMemory() const {
    return hasFnAttr(Attribute::ReadNone);
  }
  void setDoesNotAccessMemory() {
    addAttribute(AttributeList::FunctionIndex, Attribute::ReadNone);
  }

                                                                 
  bool onlyReadsMemory() const {
    return doesNotAccessMemory() || hasFnAttr(Attribute::ReadOnly);
  }
  void setOnlyReadsMemory() {
    addAttribute(AttributeList::FunctionIndex, Attribute::ReadOnly);
  }

                                                                  
  bool doesNotReadMemory() const {
    return doesNotAccessMemory() || hasFnAttr(Attribute::WriteOnly);
  }
  void setDoesNotReadMemory() {
    addAttribute(AttributeList::FunctionIndex, Attribute::WriteOnly);
  }

                                                                        
                       
  bool onlyAccessesArgMemory() const {
    return hasFnAttr(Attribute::ArgMemOnly);
  }
  void setOnlyAccessesArgMemory() {
    addAttribute(AttributeList::FunctionIndex, Attribute::ArgMemOnly);
  }

                                                              
                               
  bool onlyAccessesInaccessibleMemory() const {
    return hasFnAttr(Attribute::InaccessibleMemOnly);
  }
  void setOnlyAccessesInaccessibleMemory() {
    addAttribute(AttributeList::FunctionIndex, Attribute::InaccessibleMemOnly);
  }

                                                              
                                                                     
  bool onlyAccessesInaccessibleMemOrArgMem() const {
    return hasFnAttr(Attribute::InaccessibleMemOrArgMemOnly);
  }
  void setOnlyAccessesInaccessibleMemOrArgMem() {
    addAttribute(AttributeList::FunctionIndex, Attribute::InaccessibleMemOrArgMemOnly);
  }
                                          
  bool doesNotReturn() const { return hasFnAttr(Attribute::NoReturn); }
  void setDoesNotReturn() {
    addAttribute(AttributeList::FunctionIndex, Attribute::NoReturn);
  }

                                                                        
  bool doesNoCfCheck() const { return hasFnAttr(Attribute::NoCfCheck); }

                                          
  bool doesNotThrow() const { return hasFnAttr(Attribute::NoUnwind); }
  void setDoesNotThrow() {
    addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);
  }

                                                   
  bool cannotDuplicate() const {return hasFnAttr(Attribute::NoDuplicate); }
  void setCannotDuplicate() {
    addAttribute(AttributeList::FunctionIndex, Attribute::NoDuplicate);
  }

                                           
  bool isConvergent() const { return hasFnAttr(Attribute::Convergent); }
  void setConvergent() {
    addAttribute(AttributeList::FunctionIndex, Attribute::Convergent);
  }
  void setNotConvergent() {
    removeAttribute(AttributeList::FunctionIndex, Attribute::Convergent);
  }

                                                             
                       
  bool hasStructRetAttr() const {
    if (getNumArgOperands() == 0)
      return false;

                                             
    return paramHasAttr(0, Attribute::StructRet);
  }

                                                                     
  bool hasByValArgument() const {
    return Attrs.hasAttrSomewhere(Attribute::ByVal);
  }
                                                           
                  
  const Value *getCalledValue() const { return Op<-InstTy::ArgOffset>(); }
  Value *getCalledValue() { return Op<-InstTy::ArgOffset>(); }

                              
  void setCalledFunction(Value* Fn) {
    setCalledFunction(
        cast<FunctionType>(cast<PointerType>(Fn->getType())->getElementType()),
        Fn);
  }
  void setCalledFunction(FunctionType *FTy, Value *Fn) {
    this->FTy = FTy;
    assert(FTy == cast<FunctionType>(
                      cast<PointerType>(Fn->getType())->getElementType()));
    Op<-InstTy::ArgOffset>() = Fn;
  }

protected:
  template <typename AttrKind> bool hasFnAttrImpl(AttrKind Kind) const {
    if (Attrs.hasAttribute(AttributeList::FunctionIndex, Kind))
      return true;

                                                                            
                                                                    
    if (isFnAttrDisallowedByOpBundle(Kind))
      return false;

    if (const Function *F = getCalledFunction())
      return F->getAttributes().hasAttribute(AttributeList::FunctionIndex,
                                             Kind);
    return false;
  }
};

                                                                                
                                                               
                                                                              
                                                                               
                                            
   
class CallInst : public CallBase<CallInst> {
  friend class OperandBundleUser<CallInst, User::op_iterator>;

  CallInst(const CallInst &CI);

                                                      
                                                    
  inline CallInst(FunctionType *Ty, Value *Func, ArrayRef<Value *> Args,
                  ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr,
                  Instruction *InsertBefore);

  inline CallInst(Value *Func, ArrayRef<Value *> Args,
                  ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr,
                  Instruction *InsertBefore)
      : CallInst(cast<FunctionType>(
                     cast<PointerType>(Func->getType())->getElementType()),
                 Func, Args, Bundles, NameStr, InsertBefore) {}

  inline CallInst(Value *Func, ArrayRef<Value *> Args, const Twine &NameStr,
                  Instruction *InsertBefore)
      : CallInst(Func, Args, None, NameStr, InsertBefore) {}

                                                      
                                                    
  inline CallInst(Value *Func, ArrayRef<Value *> Args,
                  ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr,
                  BasicBlock *InsertAtEnd);

  explicit CallInst(Value *F, const Twine &NameStr, Instruction *InsertBefore);

  CallInst(Value *F, const Twine &NameStr, BasicBlock *InsertAtEnd);

  void init(Value *Func, ArrayRef<Value *> Args,
            ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr) {
    init(cast<FunctionType>(
             cast<PointerType>(Func->getType())->getElementType()),
         Func, Args, Bundles, NameStr);
  }
  void init(FunctionType *FTy, Value *Func, ArrayRef<Value *> Args,
            ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr);
  void init(Value *Func, const Twine &NameStr);

protected:
                                                                   
  friend class Instruction;

  CallInst *cloneImpl() const;

public:
  static constexpr int ArgOffset = 1;

  static CallInst *Create(Value *Func, ArrayRef<Value *> Args,
                          ArrayRef<OperandBundleDef> Bundles = None,
                          const Twine &NameStr = "",
                          Instruction *InsertBefore = nullptr) {
    return Create(cast<FunctionType>(
                      cast<PointerType>(Func->getType())->getElementType()),
                  Func, Args, Bundles, NameStr, InsertBefore);
  }

  static CallInst *Create(Value *Func, ArrayRef<Value *> Args,
                          const Twine &NameStr,
                          Instruction *InsertBefore = nullptr) {
    return Create(cast<FunctionType>(
                      cast<PointerType>(Func->getType())->getElementType()),
                  Func, Args, None, NameStr, InsertBefore);
  }

  static CallInst *Create(FunctionType *Ty, Value *Func, ArrayRef<Value *> Args,
                          const Twine &NameStr,
                          Instruction *InsertBefore = nullptr) {
    return new (unsigned(Args.size() + 1))
        CallInst(Ty, Func, Args, None, NameStr, InsertBefore);
  }

  static CallInst *Create(FunctionType *Ty, Value *Func, ArrayRef<Value *> Args,
                          ArrayRef<OperandBundleDef> Bundles = None,
                          const Twine &NameStr = "",
                          Instruction *InsertBefore = nullptr) {
    const unsigned TotalOps =
        unsigned(Args.size()) + CountBundleInputs(Bundles) + 1;
    const unsigned DescriptorBytes = Bundles.size() * sizeof(BundleOpInfo);

    return new (TotalOps, DescriptorBytes)
        CallInst(Ty, Func, Args, Bundles, NameStr, InsertBefore);
  }

  static CallInst *Create(Value *Func, ArrayRef<Value *> Args,
                          ArrayRef<OperandBundleDef> Bundles,
                          const Twine &NameStr, BasicBlock *InsertAtEnd) {
    const unsigned TotalOps =
        unsigned(Args.size()) + CountBundleInputs(Bundles) + 1;
    const unsigned DescriptorBytes = Bundles.size() * sizeof(BundleOpInfo);

    return new (TotalOps, DescriptorBytes)
        CallInst(Func, Args, Bundles, NameStr, InsertAtEnd);
  }

  static CallInst *Create(Value *Func, ArrayRef<Value *> Args,
                          const Twine &NameStr, BasicBlock *InsertAtEnd) {
    return new (unsigned(Args.size() + 1))
        CallInst(Func, Args, None, NameStr, InsertAtEnd);
  }

  static CallInst *Create(Value *F, const Twine &NameStr = "",
                          Instruction *InsertBefore = nullptr) {
    return new (1) CallInst(F, NameStr, InsertBefore);
  }

  static CallInst *Create(Value *F, const Twine &NameStr,
                          BasicBlock *InsertAtEnd) {
    return new (1) CallInst(F, NameStr, InsertAtEnd);
  }

                                                                         
                                   
     
                                                                               
                                                                                
                    
  static CallInst *Create(CallInst *CI, ArrayRef<OperandBundleDef> Bundles,
                          Instruction *InsertPt = nullptr);

                                           
                                                                         
                                                                       
                    
                                        
                                                                     
  static Instruction *CreateMalloc(Instruction *InsertBefore, Type *IntPtrTy,
                                   Type *AllocTy, Value *AllocSize,
                                   Value *ArraySize = nullptr,
                                   Function *MallocF = nullptr,
                                   const Twine &Name = "");
  static Instruction *CreateMalloc(BasicBlock *InsertAtEnd, Type *IntPtrTy,
                                   Type *AllocTy, Value *AllocSize,
                                   Value *ArraySize = nullptr,
                                   Function *MallocF = nullptr,
                                   const Twine &Name = "");
  static Instruction *CreateMalloc(Instruction *InsertBefore, Type *IntPtrTy,
                                   Type *AllocTy, Value *AllocSize,
                                   Value *ArraySize = nullptr,
                                   ArrayRef<OperandBundleDef> Bundles = None,
                                   Function *MallocF = nullptr,
                                   const Twine &Name = "");
  static Instruction *CreateMalloc(BasicBlock *InsertAtEnd, Type *IntPtrTy,
                                   Type *AllocTy, Value *AllocSize,
                                   Value *ArraySize = nullptr,
                                   ArrayRef<OperandBundleDef> Bundles = None,
                                   Function *MallocF = nullptr,
                                   const Twine &Name = "");
                                                              
  static Instruction *CreateFree(Value *Source, Instruction *InsertBefore);
  static Instruction *CreateFree(Value *Source, BasicBlock *InsertAtEnd);
  static Instruction *CreateFree(Value *Source,
                                 ArrayRef<OperandBundleDef> Bundles,
                                 Instruction *InsertBefore);
  static Instruction *CreateFree(Value *Source,
                                 ArrayRef<OperandBundleDef> Bundles,
                                 BasicBlock *InsertAtEnd);

                                         
  enum TailCallKind {
    TCK_None = 0,
    TCK_Tail = 1,
    TCK_MustTail = 2,
    TCK_NoTail = 3
  };
  TailCallKind getTailCallKind() const {
    return TailCallKind(getSubclassDataFromInstruction() & 3);
  }

  bool isTailCall() const {
    unsigned Kind = getSubclassDataFromInstruction() & 3;
    return Kind == TCK_Tail || Kind == TCK_MustTail;
  }

  bool isMustTailCall() const {
    return (getSubclassDataFromInstruction() & 3) == TCK_MustTail;
  }

  bool isNoTailCall() const {
    return (getSubclassDataFromInstruction() & 3) == TCK_NoTail;
  }

  void setTailCall(bool isTC = true) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~3) |
                               unsigned(isTC ? TCK_Tail : TCK_None));
  }

  void setTailCallKind(TailCallKind TCK) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~3) |
                               unsigned(TCK));
  }

                                              
  bool canReturnTwice() const { return hasFnAttr(Attribute::ReturnsTwice); }
  void setCanReturnTwice() {
    addAttribute(AttributeList::FunctionIndex, Attribute::ReturnsTwice);
  }

                                                    
  bool isInlineAsm() const { return isa<InlineAsm>(Op<-1>()); }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Call;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }
};

template <>
struct OperandTraits<CallBase<CallInst>>
    : public VariadicOperandTraits<CallBase<CallInst>, 1> {};

CallInst::CallInst(Value *Func, ArrayRef<Value *> Args,
                   ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr,
                   BasicBlock *InsertAtEnd)
    : CallBase<CallInst>(
          cast<FunctionType>(
              cast<PointerType>(Func->getType())->getElementType())
              ->getReturnType(),
          Instruction::Call,
          OperandTraits<CallBase<CallInst>>::op_end(this) -
              (Args.size() + CountBundleInputs(Bundles) + 1),
          unsigned(Args.size() + CountBundleInputs(Bundles) + 1), InsertAtEnd) {
  init(Func, Args, Bundles, NameStr);
}

CallInst::CallInst(FunctionType *Ty, Value *Func, ArrayRef<Value *> Args,
                   ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr,
                   Instruction *InsertBefore)
    : CallBase<CallInst>(Ty->getReturnType(), Instruction::Call,
                         OperandTraits<CallBase<CallInst>>::op_end(this) -
                             (Args.size() + CountBundleInputs(Bundles) + 1),
                         unsigned(Args.size() + CountBundleInputs(Bundles) + 1),
                         InsertBefore) {
  init(Ty, Func, Args, Bundles, NameStr);
}

                                                                                
                                                 
                                                                                

                                                        
   
class SelectInst : public Instruction {
  SelectInst(Value *C, Value *S1, Value *S2, const Twine &NameStr,
             Instruction *InsertBefore)
    : Instruction(S1->getType(), Instruction::Select,
                  &Op<0>(), 3, InsertBefore) {
    init(C, S1, S2);
    setName(NameStr);
  }

  SelectInst(Value *C, Value *S1, Value *S2, const Twine &NameStr,
             BasicBlock *InsertAtEnd)
    : Instruction(S1->getType(), Instruction::Select,
                  &Op<0>(), 3, InsertAtEnd) {
    init(C, S1, S2);
    setName(NameStr);
  }

  void init(Value *C, Value *S1, Value *S2) {
    assert(!areInvalidOperands(C, S1, S2) && "Invalid operands for select");
    Op<0>() = C;
    Op<1>() = S1;
    Op<2>() = S2;
  }

protected:
                                                                   
  friend class Instruction;

  SelectInst *cloneImpl() const;

public:
  static SelectInst *Create(Value *C, Value *S1, Value *S2,
                            const Twine &NameStr = "",
                            Instruction *InsertBefore = nullptr,
                            Instruction *MDFrom = nullptr) {
    SelectInst *Sel = new(3) SelectInst(C, S1, S2, NameStr, InsertBefore);
    if (MDFrom)
      Sel->copyMetadata(*MDFrom);
    return Sel;
  }

  static SelectInst *Create(Value *C, Value *S1, Value *S2,
                            const Twine &NameStr,
                            BasicBlock *InsertAtEnd) {
    return new(3) SelectInst(C, S1, S2, NameStr, InsertAtEnd);
  }

  const Value *getCondition() const { return Op<0>(); }
  const Value *getTrueValue() const { return Op<1>(); }
  const Value *getFalseValue() const { return Op<2>(); }
  Value *getCondition() { return Op<0>(); }
  Value *getTrueValue() { return Op<1>(); }
  Value *getFalseValue() { return Op<2>(); }

  void setCondition(Value *V) { Op<0>() = V; }
  void setTrueValue(Value *V) { Op<1>() = V; }
  void setFalseValue(Value *V) { Op<2>() = V; }

                                                           
                                                    
  static const char *areInvalidOperands(Value *Cond, Value *True, Value *False);

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

  OtherOps getOpcode() const {
    return static_cast<OtherOps>(Instruction::getOpcode());
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Select;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<SelectInst> : public FixedNumOperandTraits<SelectInst, 3> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(SelectInst, Value)

                                                                                
                                                 
                                                                                

                                                                    
                                                                              
   
class VAArgInst : public UnaryInstruction {
protected:
                                                                   
  friend class Instruction;

  VAArgInst *cloneImpl() const;

public:
  VAArgInst(Value *List, Type *Ty, const Twine &NameStr = "",
             Instruction *InsertBefore = nullptr)
    : UnaryInstruction(Ty, VAArg, List, InsertBefore) {
    setName(NameStr);
  }

  VAArgInst(Value *List, Type *Ty, const Twine &NameStr,
            BasicBlock *InsertAtEnd)
    : UnaryInstruction(Ty, VAArg, List, InsertAtEnd) {
    setName(NameStr);
  }

  Value *getPointerOperand() { return getOperand(0); }
  const Value *getPointerOperand() const { return getOperand(0); }
  static unsigned getPointerOperandIndex() { return 0U; }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == VAArg;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                          
                                                                                

                                               
                                   
   
class ExtractElementInst : public Instruction {
  ExtractElementInst(Value *Vec, Value *Idx, const Twine &NameStr = "",
                     Instruction *InsertBefore = nullptr);
  ExtractElementInst(Value *Vec, Value *Idx, const Twine &NameStr,
                     BasicBlock *InsertAtEnd);

protected:
                                                                   
  friend class Instruction;

  ExtractElementInst *cloneImpl() const;

public:
  static ExtractElementInst *Create(Value *Vec, Value *Idx,
                                   const Twine &NameStr = "",
                                   Instruction *InsertBefore = nullptr) {
    return new(2) ExtractElementInst(Vec, Idx, NameStr, InsertBefore);
  }

  static ExtractElementInst *Create(Value *Vec, Value *Idx,
                                   const Twine &NameStr,
                                   BasicBlock *InsertAtEnd) {
    return new(2) ExtractElementInst(Vec, Idx, NameStr, InsertAtEnd);
  }

                                                         
                                         
  static bool isValidOperands(const Value *Vec, const Value *Idx);

  Value *getVectorOperand() { return Op<0>(); }
  Value *getIndexOperand() { return Op<1>(); }
  const Value *getVectorOperand() const { return Op<0>(); }
  const Value *getIndexOperand() const { return Op<1>(); }

  VectorType *getVectorOperandType() const {
    return cast<VectorType>(getVectorOperand()->getType());
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::ExtractElement;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<ExtractElementInst> :
  public FixedNumOperandTraits<ExtractElementInst, 2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(ExtractElementInst, Value)

                                                                                
                                                         
                                                                                

                                              
                                   
   
class InsertElementInst : public Instruction {
  InsertElementInst(Value *Vec, Value *NewElt, Value *Idx,
                    const Twine &NameStr = "",
                    Instruction *InsertBefore = nullptr);
  InsertElementInst(Value *Vec, Value *NewElt, Value *Idx, const Twine &NameStr,
                    BasicBlock *InsertAtEnd);

protected:
                                                                   
  friend class Instruction;

  InsertElementInst *cloneImpl() const;

public:
  static InsertElementInst *Create(Value *Vec, Value *NewElt, Value *Idx,
                                   const Twine &NameStr = "",
                                   Instruction *InsertBefore = nullptr) {
    return new(3) InsertElementInst(Vec, NewElt, Idx, NameStr, InsertBefore);
  }

  static InsertElementInst *Create(Value *Vec, Value *NewElt, Value *Idx,
                                   const Twine &NameStr,
                                   BasicBlock *InsertAtEnd) {
    return new(3) InsertElementInst(Vec, NewElt, Idx, NameStr, InsertAtEnd);
  }

                                                        
                                         
  static bool isValidOperands(const Value *Vec, const Value *NewElt,
                              const Value *Idx);

                                                   
     
  VectorType *getType() const {
    return cast<VectorType>(Instruction::getType());
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::InsertElement;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<InsertElementInst> :
  public FixedNumOperandTraits<InsertElementInst, 3> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(InsertElementInst, Value)

                                                                                
                                                    
                                                                                

                                                          
                  
   
class ShuffleVectorInst : public Instruction {
protected:
                                                                   
  friend class Instruction;

  ShuffleVectorInst *cloneImpl() const;

public:
  ShuffleVectorInst(Value *V1, Value *V2, Value *Mask,
                    const Twine &NameStr = "",
                    Instruction *InsertBefor = nullptr);
  ShuffleVectorInst(Value *V1, Value *V2, Value *Mask,
                    const Twine &NameStr, BasicBlock *InsertAtEnd);

                                              
  void *operator new(size_t s) {
    return User::operator new(s, 3);
  }

                                                       
                                         
  static bool isValidOperands(const Value *V1, const Value *V2,
                              const Value *Mask);

                                                   
     
  VectorType *getType() const {
    return cast<VectorType>(Instruction::getType());
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

  Constant *getMask() const {
    return cast<Constant>(getOperand(2));
  }

                                                                          
                                        
  static int getMaskValue(const Constant *Mask, unsigned Elt);

                                                                             
                                               
  int getMaskValue(unsigned Elt) const {
    return getMaskValue(getMask(), Elt);
  }

                                                                               
                                              
  static void getShuffleMask(const Constant *Mask,
                             SmallVectorImpl<int> &Result);

                                                                             
                                              
  void getShuffleMask(SmallVectorImpl<int> &Result) const {
    return getShuffleMask(getMask(), Result);
  }

  SmallVector<int, 16> getShuffleMask() const {
    SmallVector<int, 16> Mask;
    getShuffleMask(Mask);
    return Mask;
  }

                                                                             
                                       
                                                           
                                                               
  bool changesLength() const {
    unsigned NumSourceElts = Op<0>()->getType()->getVectorNumElements();
    unsigned NumMaskElts = getMask()->getType()->getVectorNumElements();
    return NumSourceElts != NumMaskElts;
  }

                                                                           
                                       
                                                          
  bool increasesLength() const {
    unsigned NumSourceElts = Op<0>()->getType()->getVectorNumElements();
    unsigned NumMaskElts = getMask()->getType()->getVectorNumElements();
    return NumSourceElts < NumMaskElts;
  }

                                                                               
             
                            
                                                                        
  static bool isSingleSourceMask(ArrayRef<int> Mask);
  static bool isSingleSourceMask(const Constant *Mask) {
    assert(Mask->getType()->isVectorTy() && "Shuffle needs vector constant.");
    SmallVector<int, 16> MaskAsInts;
    getShuffleMask(Mask, MaskAsInts);
    return isSingleSourceMask(MaskAsInts);
  }

                                                                          
                                                        
                                                                
                                                      
  bool isSingleSource() const {
    return !changesLength() && isSingleSourceMask(getMask());
  }

                                                                               
                                                                     
                                                                               
                                                                              
                                
  static bool isIdentityMask(ArrayRef<int> Mask);
  static bool isIdentityMask(const Constant *Mask) {
    assert(Mask->getType()->isVectorTy() && "Shuffle needs vector constant.");
    SmallVector<int, 16> MaskAsInts;
    getShuffleMask(Mask, MaskAsInts);
    return isIdentityMask(MaskAsInts);
  }

                                                                          
                                                                              
                             
                                                                    
  bool isIdentity() const {
    return !changesLength() && isIdentityMask(getShuffleMask());
  }

                                                                          
                                  
  bool isIdentityWithPadding() const;

                                                                              
                    
  bool isIdentityWithExtract() const;

                                                                         
                                                                              
                                                                 
  bool isConcat() const;

                                                                               
                                                                
                                                                      
                            
                                                                             
                                                                            
                                                                       
                                                                             
  static bool isSelectMask(ArrayRef<int> Mask);
  static bool isSelectMask(const Constant *Mask) {
    assert(Mask->getType()->isVectorTy() && "Shuffle needs vector constant.");
    SmallVector<int, 16> MaskAsInts;
    getShuffleMask(Mask, MaskAsInts);
    return isSelectMask(MaskAsInts);
  }

                                                                          
                                                                               
                                                                          
                                 
                                                                
                                                                             
                                                                            
                                                      
  bool isSelect() const {
    return !changesLength() && isSelectMask(getMask());
  }

                                                                               
                        
                            
                                                                        
  static bool isReverseMask(ArrayRef<int> Mask);
  static bool isReverseMask(const Constant *Mask) {
    assert(Mask->getType()->isVectorTy() && "Shuffle needs vector constant.");
    SmallVector<int, 16> MaskAsInts;
    getShuffleMask(Mask, MaskAsInts);
    return isReverseMask(MaskAsInts);
  }

                                                                          
                        
                                                                    
                                                      
  bool isReverse() const {
    return !changesLength() && isReverseMask(getMask());
  }

                                                                               
                                                        
                                
                                                                        
  static bool isZeroEltSplatMask(ArrayRef<int> Mask);
  static bool isZeroEltSplatMask(const Constant *Mask) {
    assert(Mask->getType()->isVectorTy() && "Shuffle needs vector constant.");
    SmallVector<int, 16> MaskAsInts;
    getShuffleMask(Mask, MaskAsInts);
    return isZeroEltSplatMask(MaskAsInts);
  }

                                                                           
                                                                            
                     
                                                                    
                                                      
                                                        
  bool isZeroEltSplat() const {
    return !changesLength() && isZeroEltSplatMask(getMask());
  }

                                                           
                                                                            
                                                                         
                                                                   
                                                                              
                                                                                
                                                                    
                           
     
                                                              
     
                         
                     
                     
     
                           
                                                      
                                                      
     
                                                                              
                                                                          
                                                                               
                                                                                
                                          
     
                         
                           
                           
     
                           
                                                                 
                                                                 
  static bool isTransposeMask(ArrayRef<int> Mask);
  static bool isTransposeMask(const Constant *Mask) {
    assert(Mask->getType()->isVectorTy() && "Shuffle needs vector constant.");
    SmallVector<int, 16> MaskAsInts;
    getShuffleMask(Mask, MaskAsInts);
    return isTransposeMask(MaskAsInts);
  }

                                                                               
                                                                               
                                                                            
                          
                                                            
  bool isTranspose() const {
    return !changesLength() && isTransposeMask(getMask());
  }

                                                                              
                                                   
  static void commuteShuffleMask(MutableArrayRef<int> Mask,
                                 unsigned InVecNumElts) {
    for (int &Idx : Mask) {
      if (Idx == -1)
        continue;
      Idx = Idx < (int)InVecNumElts ? Idx + InVecNumElts : Idx - InVecNumElts;
      assert(Idx >= 0 && Idx < (int)InVecNumElts * 2 &&
             "shufflevector mask index out of range");
    }
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::ShuffleVector;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<ShuffleVectorInst> :
  public FixedNumOperandTraits<ShuffleVectorInst, 3> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(ShuffleVectorInst, Value)

                                                                                
                                                        
                                                                                

                                                      
                                          
   
class ExtractValueInst : public UnaryInstruction {
  SmallVector<unsigned, 4> Indices;

  ExtractValueInst(const ExtractValueInst &EVI);

                                                                            
                                                                               
                                                                            
                           
  inline ExtractValueInst(Value *Agg,
                          ArrayRef<unsigned> Idxs,
                          const Twine &NameStr,
                          Instruction *InsertBefore);
  inline ExtractValueInst(Value *Agg,
                          ArrayRef<unsigned> Idxs,
                          const Twine &NameStr, BasicBlock *InsertAtEnd);

  void init(ArrayRef<unsigned> Idxs, const Twine &NameStr);

protected:
                                                                   
  friend class Instruction;

  ExtractValueInst *cloneImpl() const;

public:
  static ExtractValueInst *Create(Value *Agg,
                                  ArrayRef<unsigned> Idxs,
                                  const Twine &NameStr = "",
                                  Instruction *InsertBefore = nullptr) {
    return new
      ExtractValueInst(Agg, Idxs, NameStr, InsertBefore);
  }

  static ExtractValueInst *Create(Value *Agg,
                                  ArrayRef<unsigned> Idxs,
                                  const Twine &NameStr,
                                  BasicBlock *InsertAtEnd) {
    return new ExtractValueInst(Agg, Idxs, NameStr, InsertAtEnd);
  }

                                                             
                                                                     
     
                                                                         
  static Type *getIndexedType(Type *Agg, ArrayRef<unsigned> Idxs);

  using idx_iterator = const unsigned*;

  inline idx_iterator idx_begin() const { return Indices.begin(); }
  inline idx_iterator idx_end()   const { return Indices.end(); }
  inline iterator_range<idx_iterator> indices() const {
    return make_range(idx_begin(), idx_end());
  }

  Value *getAggregateOperand() {
    return getOperand(0);
  }
  const Value *getAggregateOperand() const {
    return getOperand(0);
  }
  static unsigned getAggregateOperandIndex() {
    return 0U;                                                                
  }

  ArrayRef<unsigned> getIndices() const {
    return Indices;
  }

  unsigned getNumIndices() const {
    return (unsigned)Indices.size();
  }

  bool hasIndices() const {
    return true;
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::ExtractValue;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

ExtractValueInst::ExtractValueInst(Value *Agg,
                                   ArrayRef<unsigned> Idxs,
                                   const Twine &NameStr,
                                   Instruction *InsertBefore)
  : UnaryInstruction(checkGEPType(getIndexedType(Agg->getType(), Idxs)),
                     ExtractValue, Agg, InsertBefore) {
  init(Idxs, NameStr);
}

ExtractValueInst::ExtractValueInst(Value *Agg,
                                   ArrayRef<unsigned> Idxs,
                                   const Twine &NameStr,
                                   BasicBlock *InsertAtEnd)
  : UnaryInstruction(checkGEPType(getIndexedType(Agg->getType(), Idxs)),
                     ExtractValue, Agg, InsertAtEnd) {
  init(Idxs, NameStr);
}

                                                                                
                                                       
                                                                                

                                                            
                                  
   
class InsertValueInst : public Instruction {
  SmallVector<unsigned, 4> Indices;

  InsertValueInst(const InsertValueInst &IVI);

                                                                           
                                                                          
                                                                          
                                                      
  inline InsertValueInst(Value *Agg, Value *Val,
                         ArrayRef<unsigned> Idxs,
                         const Twine &NameStr,
                         Instruction *InsertBefore);
  inline InsertValueInst(Value *Agg, Value *Val,
                         ArrayRef<unsigned> Idxs,
                         const Twine &NameStr, BasicBlock *InsertAtEnd);

                                                                               
                                                           
  InsertValueInst(Value *Agg, Value *Val, unsigned Idx,
                  const Twine &NameStr = "",
                  Instruction *InsertBefore = nullptr);
  InsertValueInst(Value *Agg, Value *Val, unsigned Idx, const Twine &NameStr,
                  BasicBlock *InsertAtEnd);

  void init(Value *Agg, Value *Val, ArrayRef<unsigned> Idxs,
            const Twine &NameStr);

protected:
                                                                   
  friend class Instruction;

  InsertValueInst *cloneImpl() const;

public:
                                            
  void *operator new(size_t s) {
    return User::operator new(s, 2);
  }

  static InsertValueInst *Create(Value *Agg, Value *Val,
                                 ArrayRef<unsigned> Idxs,
                                 const Twine &NameStr = "",
                                 Instruction *InsertBefore = nullptr) {
    return new InsertValueInst(Agg, Val, Idxs, NameStr, InsertBefore);
  }

  static InsertValueInst *Create(Value *Agg, Value *Val,
                                 ArrayRef<unsigned> Idxs,
                                 const Twine &NameStr,
                                 BasicBlock *InsertAtEnd) {
    return new InsertValueInst(Agg, Val, Idxs, NameStr, InsertAtEnd);
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

  using idx_iterator = const unsigned*;

  inline idx_iterator idx_begin() const { return Indices.begin(); }
  inline idx_iterator idx_end()   const { return Indices.end(); }
  inline iterator_range<idx_iterator> indices() const {
    return make_range(idx_begin(), idx_end());
  }

  Value *getAggregateOperand() {
    return getOperand(0);
  }
  const Value *getAggregateOperand() const {
    return getOperand(0);
  }
  static unsigned getAggregateOperandIndex() {
    return 0U;                                                                
  }

  Value *getInsertedValueOperand() {
    return getOperand(1);
  }
  const Value *getInsertedValueOperand() const {
    return getOperand(1);
  }
  static unsigned getInsertedValueOperandIndex() {
    return 1U;                                                                
  }

  ArrayRef<unsigned> getIndices() const {
    return Indices;
  }

  unsigned getNumIndices() const {
    return (unsigned)Indices.size();
  }

  bool hasIndices() const {
    return true;
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::InsertValue;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<InsertValueInst> :
  public FixedNumOperandTraits<InsertValueInst, 2> {
};

InsertValueInst::InsertValueInst(Value *Agg,
                                 Value *Val,
                                 ArrayRef<unsigned> Idxs,
                                 const Twine &NameStr,
                                 Instruction *InsertBefore)
  : Instruction(Agg->getType(), InsertValue,
                OperandTraits<InsertValueInst>::op_begin(this),
                2, InsertBefore) {
  init(Agg, Val, Idxs, NameStr);
}

InsertValueInst::InsertValueInst(Value *Agg,
                                 Value *Val,
                                 ArrayRef<unsigned> Idxs,
                                 const Twine &NameStr,
                                 BasicBlock *InsertAtEnd)
  : Instruction(Agg->getType(), InsertValue,
                OperandTraits<InsertValueInst>::op_begin(this),
                2, InsertAtEnd) {
  init(Agg, Val, Idxs, NameStr);
}

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(InsertValueInst, Value)

                                                                                
                                              
                                                                                

                                                                            
                                                                           
                                      
  
class PHINode : public Instruction {
                                                                
                                 
  unsigned ReservedSpace;

  PHINode(const PHINode &PN);

  explicit PHINode(Type *Ty, unsigned NumReservedValues,
                   const Twine &NameStr = "",
                   Instruction *InsertBefore = nullptr)
    : Instruction(Ty, Instruction::PHI, nullptr, 0, InsertBefore),
      ReservedSpace(NumReservedValues) {
    setName(NameStr);
    allocHungoffUses(ReservedSpace);
  }

  PHINode(Type *Ty, unsigned NumReservedValues, const Twine &NameStr,
          BasicBlock *InsertAtEnd)
    : Instruction(Ty, Instruction::PHI, nullptr, 0, InsertAtEnd),
      ReservedSpace(NumReservedValues) {
    setName(NameStr);
    allocHungoffUses(ReservedSpace);
  }

protected:
                                                                   
  friend class Instruction;

  PHINode *cloneImpl() const;

                                                                 
                                                                              
                                                                       
  void allocHungoffUses(unsigned N) {
    User::allocHungoffUses(N,             true);
  }

public:
                                                                           
                                                                            
  static PHINode *Create(Type *Ty, unsigned NumReservedValues,
                         const Twine &NameStr = "",
                         Instruction *InsertBefore = nullptr) {
    return new PHINode(Ty, NumReservedValues, NameStr, InsertBefore);
  }

  static PHINode *Create(Type *Ty, unsigned NumReservedValues,
                         const Twine &NameStr, BasicBlock *InsertAtEnd) {
    return new PHINode(Ty, NumReservedValues, NameStr, InsertAtEnd);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                           
                                                               

  using block_iterator = BasicBlock **;
  using const_block_iterator = BasicBlock * const *;

  block_iterator block_begin() {
    Use::UserRef *ref =
      reinterpret_cast<Use::UserRef*>(op_begin() + ReservedSpace);
    return reinterpret_cast<block_iterator>(ref + 1);
  }

  const_block_iterator block_begin() const {
    const Use::UserRef *ref =
      reinterpret_cast<const Use::UserRef*>(op_begin() + ReservedSpace);
    return reinterpret_cast<const_block_iterator>(ref + 1);
  }

  block_iterator block_end() {
    return block_begin() + getNumOperands();
  }

  const_block_iterator block_end() const {
    return block_begin() + getNumOperands();
  }

  iterator_range<block_iterator> blocks() {
    return make_range(block_begin(), block_end());
  }

  iterator_range<const_block_iterator> blocks() const {
    return make_range(block_begin(), block_end());
  }

  op_range incoming_values() { return operands(); }

  const_op_range incoming_values() const { return operands(); }

                                         
     
  unsigned getNumIncomingValues() const { return getNumOperands(); }

                                    
     
  Value *getIncomingValue(unsigned i) const {
    return getOperand(i);
  }
  void setIncomingValue(unsigned i, Value *V) {
    assert(V && "PHI node got a null value!");
    assert(getType() == V->getType() &&
           "All operands to PHI node must be the same type as the PHI node!");
    setOperand(i, V);
  }

  static unsigned getOperandNumForIncomingValue(unsigned i) {
    return i;
  }

  static unsigned getIncomingValueNumForOperand(unsigned i) {
    return i;
  }

                                              
     
  BasicBlock *getIncomingBlock(unsigned i) const {
    return block_begin()[i];
  }

                                               
                               
     
  BasicBlock *getIncomingBlock(const Use &U) const {
    assert(this == U.getUser() && "Iterator doesn't point to PHI's Uses?");
    return getIncomingBlock(unsigned(&U - op_begin()));
  }

                                               
                            
     
  BasicBlock *getIncomingBlock(Value::const_user_iterator I) const {
    return getIncomingBlock(I.getUse());
  }

  void setIncomingBlock(unsigned i, BasicBlock *BB) {
    assert(BB && "PHI node got a null basic block!");
    block_begin()[i] = BB;
  }

                                                      
     
  void addIncoming(Value *V, BasicBlock *BB) {
    if (getNumOperands() == ReservedSpace)
      growOperands();                    
                                    
    setNumHungOffUseOperands(getNumOperands() + 1);
    setIncomingValue(getNumOperands() - 1, V);
    setIncomingBlock(getNumOperands() - 1, BB);
  }

                                                    
                                                                         
     
                                                                                
                                                                              
                                                                                
                                                                
     
  Value *removeIncomingValue(unsigned Idx, bool DeletePHIIfEmpty = true);

  Value *removeIncomingValue(const BasicBlock *BB, bool DeletePHIIfEmpty=true) {
    int Idx = getBasicBlockIndex(BB);
    assert(Idx >= 0 && "Invalid basic block argument to remove!");
    return removeIncomingValue(Idx, DeletePHIIfEmpty);
  }

                                                   
                                                                       
     
  int getBasicBlockIndex(const BasicBlock *BB) const {
    for (unsigned i = 0, e = getNumOperands(); i != e; ++i)
      if (block_begin()[i] == BB)
        return i;
    return -1;
  }

  Value *getIncomingValueForBlock(const BasicBlock *BB) const {
    int Idx = getBasicBlockIndex(BB);
    assert(Idx >= 0 && "Invalid basic block argument!");
    return getIncomingValue(Idx);
  }

                                                          
                                                          
  Value *hasConstantValue() const;

                                                  
                                                                    
                      
  bool hasConstantOrUndefValue() const;

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::PHI;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
  void growOperands();
};

template <>
struct OperandTraits<PHINode> : public HungoffOperandTraits<2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(PHINode, Value)

                                                                                
                                                 
                                                                                

                                                                                
                                                           
                                                                                
                                                                        
                                                                      
                                                                           
            
   
class LandingPadInst : public Instruction {
                                                                
                                 
  unsigned ReservedSpace;

  LandingPadInst(const LandingPadInst &LP);

public:
  enum ClauseType { Catch, Filter };

private:
  explicit LandingPadInst(Type *RetTy, unsigned NumReservedValues,
                          const Twine &NameStr, Instruction *InsertBefore);
  explicit LandingPadInst(Type *RetTy, unsigned NumReservedValues,
                          const Twine &NameStr, BasicBlock *InsertAtEnd);

                                              
  void *operator new(size_t s) {
    return User::operator new(s);
  }

  void growOperands(unsigned Size);
  void init(unsigned NumReservedValues, const Twine &NameStr);

protected:
                                                                   
  friend class Instruction;

  LandingPadInst *cloneImpl() const;

public:
                                                                            
                                                                                
  static LandingPadInst *Create(Type *RetTy, unsigned NumReservedClauses,
                                const Twine &NameStr = "",
                                Instruction *InsertBefore = nullptr);
  static LandingPadInst *Create(Type *RetTy, unsigned NumReservedClauses,
                                const Twine &NameStr, BasicBlock *InsertAtEnd);

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                       
                                                                            
                                  
  bool isCleanup() const { return getSubclassDataFromInstruction() & 1; }

                                                             
  void setCleanup(bool V) {
    setInstructionSubclassData((getSubclassDataFromInstruction() & ~1) |
                               (V ? 1 : 0));
  }

                                                      
  void addClause(Constant *ClauseVal);

                                                                       
                                            
  Constant *getClause(unsigned Idx) const {
    return cast<Constant>(getOperandList()[Idx]);
  }

                                                                  
  bool isCatch(unsigned Idx) const {
    return !isa<ArrayType>(getOperandList()[Idx]->getType());
  }

                                                                   
  bool isFilter(unsigned Idx) const {
    return isa<ArrayType>(getOperandList()[Idx]->getType());
  }

                                                     
  unsigned getNumClauses() const { return getNumOperands(); }

                                                              
                        
  void reserveClauses(unsigned Size) { growOperands(Size); }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::LandingPad;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<LandingPadInst> : public HungoffOperandTraits<1> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(LandingPadInst, Value)

                                                                                
                                                 
                                                                                

                                                                                
                                                               
                                                  
   
class ReturnInst : public TerminatorInst {
  ReturnInst(const ReturnInst &RI);

private:
                             
                                                           
                                                           
                                                           
                                                                            
                                                                            
                                                                              
                                                                              
    
                                                                               
                           
  explicit ReturnInst(LLVMContext &C, Value *retVal = nullptr,
                      Instruction *InsertBefore = nullptr);
  ReturnInst(LLVMContext &C, Value *retVal, BasicBlock *InsertAtEnd);
  explicit ReturnInst(LLVMContext &C, BasicBlock *InsertAtEnd);

protected:
                                                                   
  friend class Instruction;

  ReturnInst *cloneImpl() const;

public:
  static ReturnInst* Create(LLVMContext &C, Value *retVal = nullptr,
                            Instruction *InsertBefore = nullptr) {
    return new(!!retVal) ReturnInst(C, retVal, InsertBefore);
  }

  static ReturnInst* Create(LLVMContext &C, Value *retVal,
                            BasicBlock *InsertAtEnd) {
    return new(!!retVal) ReturnInst(C, retVal, InsertAtEnd);
  }

  static ReturnInst* Create(LLVMContext &C, BasicBlock *InsertAtEnd) {
    return new(0) ReturnInst(C, InsertAtEnd);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                     
  Value *getReturnValue() const {
    return getNumOperands() != 0 ? getOperand(0) : nullptr;
  }

  unsigned getNumSuccessors() const { return 0; }

                                                                      
  static bool classof(const Instruction *I) {
    return (I->getOpcode() == Instruction::Ret);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
  friend TerminatorInst;

  BasicBlock *getSuccessor(unsigned idx) const {
    llvm_unreachable("ReturnInst has no successors!");
  }

  void setSuccessor(unsigned idx, BasicBlock *B) {
    llvm_unreachable("ReturnInst has no successors!");
  }
};

template <>
struct OperandTraits<ReturnInst> : public VariadicOperandTraits<ReturnInst> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(ReturnInst, Value)

                                                                                
                                                 
                                                                                

                                                                                
                                                    
   
class BranchInst : public TerminatorInst {
                                                                 
                                                                             
                                                                           
                                      
  BranchInst(const BranchInst &BI);
                                                                                
                                                         
                                                               
                                                                                
                                                                                
                                                                              
                                                                              
  explicit BranchInst(BasicBlock *IfTrue, Instruction *InsertBefore = nullptr);
  BranchInst(BasicBlock *IfTrue, BasicBlock *IfFalse, Value *Cond,
             Instruction *InsertBefore = nullptr);
  BranchInst(BasicBlock *IfTrue, BasicBlock *InsertAtEnd);
  BranchInst(BasicBlock *IfTrue, BasicBlock *IfFalse, Value *Cond,
             BasicBlock *InsertAtEnd);

  void AssertOK();

protected:
                                                                   
  friend class Instruction;

  BranchInst *cloneImpl() const;

public:
                                                           
     
                                                                         
                                       
  struct succ_op_iterator
      : iterator_adaptor_base<succ_op_iterator, value_op_iterator,
                              std::random_access_iterator_tag, BasicBlock *,
                              ptrdiff_t, BasicBlock *, BasicBlock *> {
    explicit succ_op_iterator(value_op_iterator I) : iterator_adaptor_base(I) {}

    BasicBlock *operator*() const { return cast<BasicBlock>(*I); }
    BasicBlock *operator->() const { return operator*(); }
  };

                                              
  struct const_succ_op_iterator
      : iterator_adaptor_base<const_succ_op_iterator, const_value_op_iterator,
                              std::random_access_iterator_tag,
                              const BasicBlock *, ptrdiff_t, const BasicBlock *,
                              const BasicBlock *> {
    explicit const_succ_op_iterator(const_value_op_iterator I)
        : iterator_adaptor_base(I) {}

    const BasicBlock *operator*() const { return cast<BasicBlock>(*I); }
    const BasicBlock *operator->() const { return operator*(); }
  };

  static BranchInst *Create(BasicBlock *IfTrue,
                            Instruction *InsertBefore = nullptr) {
    return new(1) BranchInst(IfTrue, InsertBefore);
  }

  static BranchInst *Create(BasicBlock *IfTrue, BasicBlock *IfFalse,
                            Value *Cond, Instruction *InsertBefore = nullptr) {
    return new(3) BranchInst(IfTrue, IfFalse, Cond, InsertBefore);
  }

  static BranchInst *Create(BasicBlock *IfTrue, BasicBlock *InsertAtEnd) {
    return new(1) BranchInst(IfTrue, InsertAtEnd);
  }

  static BranchInst *Create(BasicBlock *IfTrue, BasicBlock *IfFalse,
                            Value *Cond, BasicBlock *InsertAtEnd) {
    return new(3) BranchInst(IfTrue, IfFalse, Cond, InsertAtEnd);
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

  bool isUnconditional() const { return getNumOperands() == 1; }
  bool isConditional()   const { return getNumOperands() == 3; }

  Value *getCondition() const {
    assert(isConditional() && "Cannot get condition of an uncond branch!");
    return Op<-3>();
  }

  void setCondition(Value *V) {
    assert(isConditional() && "Cannot set condition of unconditional branch!");
    Op<-3>() = V;
  }

  unsigned getNumSuccessors() const { return 1+isConditional(); }

  BasicBlock *getSuccessor(unsigned i) const {
    assert(i < getNumSuccessors() && "Successor # out of range for Branch!");
    return cast_or_null<BasicBlock>((&Op<-1>() - i)->get());
  }

  void setSuccessor(unsigned idx, BasicBlock *NewSucc) {
    assert(idx < getNumSuccessors() && "Successor # out of range for Branch!");
    *(&Op<-1>() - idx) = NewSucc;
  }

                                                     
     
                                                                         
                                                                       
                                                 
  void swapSuccessors();

  iterator_range<succ_op_iterator> successors() {
    return make_range(
        succ_op_iterator(std::next(value_op_begin(), isConditional() ? 1 : 0)),
        succ_op_iterator(value_op_end()));
  }

  iterator_range<const_succ_op_iterator> successors() const {
    return make_range(const_succ_op_iterator(
                          std::next(value_op_begin(), isConditional() ? 1 : 0)),
                      const_succ_op_iterator(value_op_end()));
  }

                                                                      
  static bool classof(const Instruction *I) {
    return (I->getOpcode() == Instruction::Br);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<BranchInst> : public VariadicOperandTraits<BranchInst, 1> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(BranchInst, Value)

                                                                                
                                                 
                                                                                

                                                                                
                   
   
class SwitchInst : public TerminatorInst {
  unsigned ReservedSpace;

                                       
                                                    
                                   
                                                 
  SwitchInst(const SwitchInst &SI);

                                                                            
                                                                               
                                                                         
                                             
  SwitchInst(Value *Value, BasicBlock *Default, unsigned NumCases,
             Instruction *InsertBefore);

                                                                            
                                                                               
                                                                     
                                                          
  SwitchInst(Value *Value, BasicBlock *Default, unsigned NumCases,
             BasicBlock *InsertAtEnd);

                                             
  void *operator new(size_t s) {
    return User::operator new(s);
  }

  void init(Value *Value, BasicBlock *Default, unsigned NumReserved);
  void growOperands();

protected:
                                                                   
  friend class Instruction;

  SwitchInst *cloneImpl() const;

public:
       
  static const unsigned DefaultPseudoIndex = static_cast<unsigned>(~0L-1);

  template <typename CaseHandleT> class CaseIteratorImpl;

                                                                             
                                                     
     
                                                                              
                       
  template <typename SwitchInstT, typename ConstantIntT, typename BasicBlockT>
  class CaseHandleImpl {
                                                            
    friend class SwitchInst::CaseIteratorImpl<
        CaseHandleImpl<SwitchInstT, ConstantIntT, BasicBlockT>>;

  protected:
                                                                       
    using SwitchInstType = SwitchInstT;

    SwitchInstT *SI;
    ptrdiff_t Index;

    CaseHandleImpl() = default;
    CaseHandleImpl(SwitchInstT *SI, ptrdiff_t Index) : SI(SI), Index(Index) {}

  public:
                                             
    ConstantIntT *getCaseValue() const {
      assert((unsigned)Index < SI->getNumCases() &&
             "Index out the number of cases.");
      return reinterpret_cast<ConstantIntT *>(SI->getOperand(2 + Index * 2));
    }

                                            
    BasicBlockT *getCaseSuccessor() const {
      assert(((unsigned)Index < SI->getNumCases() ||
              (unsigned)Index == DefaultPseudoIndex) &&
             "Index out the number of cases.");
      return SI->getSuccessor(getSuccessorIndex());
    }

                                       
    unsigned getCaseIndex() const { return Index; }

                                                                            
    unsigned getSuccessorIndex() const {
      assert(((unsigned)Index == DefaultPseudoIndex ||
              (unsigned)Index < SI->getNumCases()) &&
             "Index out the number of cases.");
      return (unsigned)Index != DefaultPseudoIndex ? Index + 1 : 0;
    }

    bool operator==(const CaseHandleImpl &RHS) const {
      assert(SI == RHS.SI && "Incompatible operators.");
      return Index == RHS.Index;
    }
  };

  using ConstCaseHandle =
      CaseHandleImpl<const SwitchInst, const ConstantInt, const BasicBlock>;

  class CaseHandle
      : public CaseHandleImpl<SwitchInst, ConstantInt, BasicBlock> {
    friend class SwitchInst::CaseIteratorImpl<CaseHandle>;

  public:
    CaseHandle(SwitchInst *SI, ptrdiff_t Index) : CaseHandleImpl(SI, Index) {}

                                            
    void setValue(ConstantInt *V) {
      assert((unsigned)Index < SI->getNumCases() &&
             "Index out the number of cases.");
      SI->setOperand(2 + Index*2, reinterpret_cast<Value*>(V));
    }

                                                
    void setSuccessor(BasicBlock *S) {
      SI->setSuccessor(getSuccessorIndex(), S);
    }
  };

  template <typename CaseHandleT>
  class CaseIteratorImpl
      : public iterator_facade_base<CaseIteratorImpl<CaseHandleT>,
                                    std::random_access_iterator_tag,
                                    CaseHandleT> {
    using SwitchInstT = typename CaseHandleT::SwitchInstType;

    CaseHandleT Case;

  public:
                                                                             
                                       
    CaseIteratorImpl() = default;

                                                                    
                    
    CaseIteratorImpl(SwitchInstT *SI, unsigned CaseNum) : Case(SI, CaseNum) {}

                                                                    
                                         
    static CaseIteratorImpl fromSuccessorIndex(SwitchInstT *SI,
                                               unsigned SuccessorIndex) {
      assert(SuccessorIndex < SI->getNumSuccessors() &&
             "Successor index # out of range!");
      return SuccessorIndex != 0 ? CaseIteratorImpl(SI, SuccessorIndex - 1)
                                 : CaseIteratorImpl(SI, DefaultPseudoIndex);
    }

                                                                               
                
    operator CaseIteratorImpl<ConstCaseHandle>() const {
      return CaseIteratorImpl<ConstCaseHandle>(Case.SI, Case.Index);
    }

    CaseIteratorImpl &operator+=(ptrdiff_t N) {
                                                
                                                  
      assert(Case.Index + N >= 0 &&
             (unsigned)(Case.Index + N) <= Case.SI->getNumCases() &&
             "Case.Index out the number of cases.");
      Case.Index += N;
      return *this;
    }
    CaseIteratorImpl &operator-=(ptrdiff_t N) {
                                                   
                                                       
      assert(Case.Index - N >= 0 &&
             (unsigned)(Case.Index - N) <= Case.SI->getNumCases() &&
             "Case.Index out the number of cases.");
      Case.Index -= N;
      return *this;
    }
    ptrdiff_t operator-(const CaseIteratorImpl &RHS) const {
      assert(Case.SI == RHS.Case.SI && "Incompatible operators.");
      return Case.Index - RHS.Case.Index;
    }
    bool operator==(const CaseIteratorImpl &RHS) const {
      return Case == RHS.Case;
    }
    bool operator<(const CaseIteratorImpl &RHS) const {
      assert(Case.SI == RHS.Case.SI && "Incompatible operators.");
      return Case.Index < RHS.Case.Index;
    }
    CaseHandleT &operator*() { return Case; }
    const CaseHandleT &operator*() const { return Case; }
  };

  using CaseIt = CaseIteratorImpl<CaseHandle>;
  using ConstCaseIt = CaseIteratorImpl<ConstCaseHandle>;

  static SwitchInst *Create(Value *Value, BasicBlock *Default,
                            unsigned NumCases,
                            Instruction *InsertBefore = nullptr) {
    return new SwitchInst(Value, Default, NumCases, InsertBefore);
  }

  static SwitchInst *Create(Value *Value, BasicBlock *Default,
                            unsigned NumCases, BasicBlock *InsertAtEnd) {
    return new SwitchInst(Value, Default, NumCases, InsertAtEnd);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                     
  Value *getCondition() const { return getOperand(0); }
  void setCondition(Value *V) { setOperand(0, V); }

  BasicBlock *getDefaultDest() const {
    return cast<BasicBlock>(getOperand(1));
  }

  void setDefaultDest(BasicBlock *DefaultCase) {
    setOperand(1, reinterpret_cast<Value*>(DefaultCase));
  }

                                                                            
                   
  unsigned getNumCases() const {
    return getNumOperands()/2 - 1;
  }

                                                                        
                 
  CaseIt case_begin() {
    return CaseIt(this, 0);
  }

                                                                       
                 
  ConstCaseIt case_begin() const {
    return ConstCaseIt(this, 0);
  }

                                                                        
                 
  CaseIt case_end() {
    return CaseIt(this, getNumCases());
  }

                                                                       
                 
  ConstCaseIt case_end() const {
    return ConstCaseIt(this, getNumCases());
  }

                                            
  iterator_range<CaseIt> cases() {
    return make_range(case_begin(), case_end());
  }

                                                     
  iterator_range<ConstCaseIt> cases() const {
    return make_range(case_begin(), case_end());
  }

                                                          
                                                                   
                                                
                                                                          
                             
  CaseIt case_default() {
    return CaseIt(this, DefaultPseudoIndex);
  }
  ConstCaseIt case_default() const {
    return ConstCaseIt(this, DefaultPseudoIndex);
  }

                                                                        
                                                                          
                                                                         
              
  CaseIt findCaseValue(const ConstantInt *C) {
    CaseIt I = llvh::find_if(
        cases(), [C](CaseHandle &Case) { return Case.getCaseValue() == C; });
    if (I != case_end())
      return I;

    return case_default();
  }
  ConstCaseIt findCaseValue(const ConstantInt *C) const {
    ConstCaseIt I = llvh::find_if(cases(), [C](ConstCaseHandle &Case) {
      return Case.getCaseValue() == C;
    });
    if (I != case_end())
      return I;

    return case_default();
  }

                                                                            
                                                                 
  ConstantInt *findCaseDest(BasicBlock *BB) {
    if (BB == getDefaultDest())
      return nullptr;

    ConstantInt *CI = nullptr;
    for (auto Case : cases()) {
      if (Case.getCaseSuccessor() != BB)
        continue;

      if (CI)
        return nullptr;                              

      CI = Case.getCaseValue();
    }

    return CI;
  }

                                             
           
                                                                      
                              
  void addCase(ConstantInt *OnVal, BasicBlock *Dest);

                                                                              
                                                                              
                          
           
                                                                                
                                                                            
           
  CaseIt removeCase(CaseIt I);

  unsigned getNumSuccessors() const { return getNumOperands()/2; }
  BasicBlock *getSuccessor(unsigned idx) const {
    assert(idx < getNumSuccessors() &&"Successor idx out of range for switch!");
    return cast<BasicBlock>(getOperand(idx*2+1));
  }
  void setSuccessor(unsigned idx, BasicBlock *NewSucc) {
    assert(idx < getNumSuccessors() && "Successor # out of range for switch!");
    setOperand(idx * 2 + 1, NewSucc);
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Switch;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<SwitchInst> : public HungoffOperandTraits<2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(SwitchInst, Value)

                                                                                
                                                   
                                                                                

                                                                                
                                
   
class IndirectBrInst : public TerminatorInst {
  unsigned ReservedSpace;

                                      
                                    
  IndirectBrInst(const IndirectBrInst &IBI);

                                                        
                                                                               
                                                                               
                                            
  IndirectBrInst(Value *Address, unsigned NumDests, Instruction *InsertBefore);

                                                        
                                                                               
                                                                           
                                                         
  IndirectBrInst(Value *Address, unsigned NumDests, BasicBlock *InsertAtEnd);

                                             
  void *operator new(size_t s) {
    return User::operator new(s);
  }

  void init(Value *Address, unsigned NumDests);
  void growOperands();

protected:
                                                                   
  friend class Instruction;

  IndirectBrInst *cloneImpl() const;

public:
                                                           
     
                                                                         
                                           
  struct succ_op_iterator
      : iterator_adaptor_base<succ_op_iterator, value_op_iterator,
                              std::random_access_iterator_tag, BasicBlock *,
                              ptrdiff_t, BasicBlock *, BasicBlock *> {
    explicit succ_op_iterator(value_op_iterator I) : iterator_adaptor_base(I) {}

    BasicBlock *operator*() const { return cast<BasicBlock>(*I); }
    BasicBlock *operator->() const { return operator*(); }
  };

                                              
  struct const_succ_op_iterator
      : iterator_adaptor_base<const_succ_op_iterator, const_value_op_iterator,
                              std::random_access_iterator_tag,
                              const BasicBlock *, ptrdiff_t, const BasicBlock *,
                              const BasicBlock *> {
    explicit const_succ_op_iterator(const_value_op_iterator I)
        : iterator_adaptor_base(I) {}

    const BasicBlock *operator*() const { return cast<BasicBlock>(*I); }
    const BasicBlock *operator->() const { return operator*(); }
  };

  static IndirectBrInst *Create(Value *Address, unsigned NumDests,
                                Instruction *InsertBefore = nullptr) {
    return new IndirectBrInst(Address, NumDests, InsertBefore);
  }

  static IndirectBrInst *Create(Value *Address, unsigned NumDests,
                                BasicBlock *InsertAtEnd) {
    return new IndirectBrInst(Address, NumDests, InsertAtEnd);
  }

                                     
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                     
  Value *getAddress() { return getOperand(0); }
  const Value *getAddress() const { return getOperand(0); }
  void setAddress(Value *V) { setOperand(0, V); }

                                                        
                             
  unsigned getNumDestinations() const { return getNumOperands()-1; }

                                       
  BasicBlock *getDestination(unsigned i) { return getSuccessor(i); }
  const BasicBlock *getDestination(unsigned i) const { return getSuccessor(i); }

                        
     
  void addDestination(BasicBlock *Dest);

                                                          
                             
  void removeDestination(unsigned i);

  unsigned getNumSuccessors() const { return getNumOperands()-1; }
  BasicBlock *getSuccessor(unsigned i) const {
    return cast<BasicBlock>(getOperand(i+1));
  }
  void setSuccessor(unsigned i, BasicBlock *NewSucc) {
    setOperand(i + 1, NewSucc);
  }

  iterator_range<succ_op_iterator> successors() {
    return make_range(succ_op_iterator(std::next(value_op_begin())),
                      succ_op_iterator(value_op_end()));
  }

  iterator_range<const_succ_op_iterator> successors() const {
    return make_range(const_succ_op_iterator(std::next(value_op_begin())),
                      const_succ_op_iterator(value_op_end()));
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::IndirectBr;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<IndirectBrInst> : public HungoffOperandTraits<1> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(IndirectBrInst, Value)

                                                                                
                                                 
                                                                                

                                                                   
                                   
   
class InvokeInst : public CallBase<InvokeInst> {
  friend class OperandBundleUser<InvokeInst, User::op_iterator>;

  InvokeInst(const InvokeInst &BI);

                                                         
     
                                                       
  inline InvokeInst(Value *Func, BasicBlock *IfNormal, BasicBlock *IfException,
                    ArrayRef<Value *> Args, ArrayRef<OperandBundleDef> Bundles,
                    unsigned Values, const Twine &NameStr,
                    Instruction *InsertBefore)
      : InvokeInst(cast<FunctionType>(
                       cast<PointerType>(Func->getType())->getElementType()),
                   Func, IfNormal, IfException, Args, Bundles, Values, NameStr,
                   InsertBefore) {}

  inline InvokeInst(FunctionType *Ty, Value *Func, BasicBlock *IfNormal,
                    BasicBlock *IfException, ArrayRef<Value *> Args,
                    ArrayRef<OperandBundleDef> Bundles, unsigned Values,
                    const Twine &NameStr, Instruction *InsertBefore);
                                                         
     
                                                       
  inline InvokeInst(Value *Func, BasicBlock *IfNormal, BasicBlock *IfException,
                    ArrayRef<Value *> Args, ArrayRef<OperandBundleDef> Bundles,
                    unsigned Values, const Twine &NameStr,
                    BasicBlock *InsertAtEnd);


  void init(Value *Func, BasicBlock *IfNormal, BasicBlock *IfException,
            ArrayRef<Value *> Args, ArrayRef<OperandBundleDef> Bundles,
            const Twine &NameStr) {
    init(cast<FunctionType>(
             cast<PointerType>(Func->getType())->getElementType()),
         Func, IfNormal, IfException, Args, Bundles, NameStr);
  }

  void init(FunctionType *FTy, Value *Func, BasicBlock *IfNormal,
            BasicBlock *IfException, ArrayRef<Value *> Args,
            ArrayRef<OperandBundleDef> Bundles, const Twine &NameStr);

protected:
                                                                   
  friend class Instruction;

  InvokeInst *cloneImpl() const;

public:
  static constexpr int ArgOffset = 3;
  static InvokeInst *Create(Value *Func, BasicBlock *IfNormal,
                            BasicBlock *IfException, ArrayRef<Value *> Args,
                            const Twine &NameStr,
                            Instruction *InsertBefore = nullptr) {
    return Create(cast<FunctionType>(
                      cast<PointerType>(Func->getType())->getElementType()),
                  Func, IfNormal, IfException, Args, None, NameStr,
                  InsertBefore);
  }

  static InvokeInst *Create(Value *Func, BasicBlock *IfNormal,
                            BasicBlock *IfException, ArrayRef<Value *> Args,
                            ArrayRef<OperandBundleDef> Bundles = None,
                            const Twine &NameStr = "",
                            Instruction *InsertBefore = nullptr) {
    return Create(cast<FunctionType>(
                      cast<PointerType>(Func->getType())->getElementType()),
                  Func, IfNormal, IfException, Args, Bundles, NameStr,
                  InsertBefore);
  }

  static InvokeInst *Create(FunctionType *Ty, Value *Func, BasicBlock *IfNormal,
                            BasicBlock *IfException, ArrayRef<Value *> Args,
                            const Twine &NameStr,
                            Instruction *InsertBefore = nullptr) {
    unsigned Values = unsigned(Args.size()) + 3;
    return new (Values) InvokeInst(Ty, Func, IfNormal, IfException, Args, None,
                                   Values, NameStr, InsertBefore);
  }

  static InvokeInst *Create(FunctionType *Ty, Value *Func, BasicBlock *IfNormal,
                            BasicBlock *IfException, ArrayRef<Value *> Args,
                            ArrayRef<OperandBundleDef> Bundles = None,
                            const Twine &NameStr = "",
                            Instruction *InsertBefore = nullptr) {
    unsigned Values = unsigned(Args.size()) + CountBundleInputs(Bundles) + 3;
    unsigned DescriptorBytes = Bundles.size() * sizeof(BundleOpInfo);

    return new (Values, DescriptorBytes)
        InvokeInst(Ty, Func, IfNormal, IfException, Args, Bundles, Values,
                   NameStr, InsertBefore);
  }

  static InvokeInst *Create(Value *Func,
                            BasicBlock *IfNormal, BasicBlock *IfException,
                            ArrayRef<Value *> Args, const Twine &NameStr,
                            BasicBlock *InsertAtEnd) {
    unsigned Values = unsigned(Args.size()) + 3;
    return new (Values) InvokeInst(Func, IfNormal, IfException, Args, None,
                                   Values, NameStr, InsertAtEnd);
  }

  static InvokeInst *Create(Value *Func, BasicBlock *IfNormal,
                            BasicBlock *IfException, ArrayRef<Value *> Args,
                            ArrayRef<OperandBundleDef> Bundles,
                            const Twine &NameStr, BasicBlock *InsertAtEnd) {
    unsigned Values = unsigned(Args.size()) + CountBundleInputs(Bundles) + 3;
    unsigned DescriptorBytes = Bundles.size() * sizeof(BundleOpInfo);

    return new (Values, DescriptorBytes)
        InvokeInst(Func, IfNormal, IfException, Args, Bundles, Values, NameStr,
                   InsertAtEnd);
  }

                                                                         
                                   
     
                                                                               
                                                                             
                            
  static InvokeInst *Create(InvokeInst *II, ArrayRef<OperandBundleDef> Bundles,
                            Instruction *InsertPt = nullptr);

                                                                        
  bool doesNoCfCheck() const { return hasFnAttr(Attribute::NoCfCheck); }

                                          
  bool doesNotThrow() const { return hasFnAttr(Attribute::NoUnwind); }
  void setDoesNotThrow() {
    addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);
  }

                                                       
                                   
     
  Function *getCalledFunction() const {
    return dyn_cast<Function>(Op<-3>());
  }

                                                           
                 
  const Value *getCalledValue() const { return Op<-3>(); }
        Value *getCalledValue()       { return Op<-3>(); }

                              
  void setCalledFunction(Value* Fn) {
    setCalledFunction(
        cast<FunctionType>(cast<PointerType>(Fn->getType())->getElementType()),
        Fn);
  }
  void setCalledFunction(FunctionType *FTy, Value *Fn) {
    this->FTy = FTy;
    assert(FTy == cast<FunctionType>(
                      cast<PointerType>(Fn->getType())->getElementType()));
    Op<-3>() = Fn;
  }

                                                      
  BasicBlock *getNormalDest() const {
    return cast<BasicBlock>(Op<-2>());
  }
  BasicBlock *getUnwindDest() const {
    return cast<BasicBlock>(Op<-1>());
  }
  void setNormalDest(BasicBlock *B) {
    Op<-2>() = reinterpret_cast<Value*>(B);
  }
  void setUnwindDest(BasicBlock *B) {
    Op<-1>() = reinterpret_cast<Value*>(B);
  }

                                                         
                                     
  LandingPadInst *getLandingPadInst() const;

  BasicBlock *getSuccessor(unsigned i) const {
    assert(i < 2 && "Successor # out of range for invoke!");
    return i == 0 ? getNormalDest() : getUnwindDest();
  }

  void setSuccessor(unsigned idx, BasicBlock *NewSucc) {
    assert(idx < 2 && "Successor # out of range for invoke!");
    *(&Op<-2>() + idx) = reinterpret_cast<Value*>(NewSucc);
  }

  unsigned getNumSuccessors() const { return 2; }

                                                                      
  static bool classof(const Instruction *I) {
    return (I->getOpcode() == Instruction::Invoke);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:

                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }
};

template <>
struct OperandTraits<CallBase<InvokeInst>>
    : public VariadicOperandTraits<CallBase<InvokeInst>, 3> {};

InvokeInst::InvokeInst(FunctionType *Ty, Value *Func, BasicBlock *IfNormal,
                       BasicBlock *IfException, ArrayRef<Value *> Args,
                       ArrayRef<OperandBundleDef> Bundles, unsigned Values,
                       const Twine &NameStr, Instruction *InsertBefore)
    : CallBase<InvokeInst>(Ty->getReturnType(), Instruction::Invoke,
                           OperandTraits<CallBase<InvokeInst>>::op_end(this) -
                               Values,
                           Values, InsertBefore) {
  init(Ty, Func, IfNormal, IfException, Args, Bundles, NameStr);
}

InvokeInst::InvokeInst(Value *Func, BasicBlock *IfNormal,
                       BasicBlock *IfException, ArrayRef<Value *> Args,
                       ArrayRef<OperandBundleDef> Bundles, unsigned Values,
                       const Twine &NameStr, BasicBlock *InsertAtEnd)
    : CallBase<InvokeInst>(
          cast<FunctionType>(
              cast<PointerType>(Func->getType())->getElementType())
              ->getReturnType(),
          Instruction::Invoke,
          OperandTraits<CallBase<InvokeInst>>::op_end(this) - Values, Values,
          InsertAtEnd) {
  init(Func, IfNormal, IfException, Args, Bundles, NameStr);
}


                                                                                
                                                
                                                                                

                                                                                
                                           
   
class ResumeInst : public TerminatorInst {
  ResumeInst(const ResumeInst &RI);

  explicit ResumeInst(Value *Exn, Instruction *InsertBefore=nullptr);
  ResumeInst(Value *Exn, BasicBlock *InsertAtEnd);

protected:
                                                                   
  friend class Instruction;

  ResumeInst *cloneImpl() const;

public:
  static ResumeInst *Create(Value *Exn, Instruction *InsertBefore = nullptr) {
    return new(1) ResumeInst(Exn, InsertBefore);
  }

  static ResumeInst *Create(Value *Exn, BasicBlock *InsertAtEnd) {
    return new(1) ResumeInst(Exn, InsertAtEnd);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                           
  Value *getValue() const { return Op<0>(); }

  unsigned getNumSuccessors() const { return 0; }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Resume;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
  friend TerminatorInst;

  BasicBlock *getSuccessor(unsigned idx) const {
    llvm_unreachable("ResumeInst has no successors!");
  }

  void setSuccessor(unsigned idx, BasicBlock *NewSucc) {
    llvm_unreachable("ResumeInst has no successors!");
  }
};

template <>
struct OperandTraits<ResumeInst> :
    public FixedNumOperandTraits<ResumeInst, 1> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(ResumeInst, Value)

                                                                                
                                                
                                                                                
class CatchSwitchInst : public TerminatorInst {
                                                                
                                 
  unsigned ReservedSpace;

                             
                                          
                                              
  CatchSwitchInst(const CatchSwitchInst &CSI);

                                                   
                                                                              
                                                    
                                                                      
  CatchSwitchInst(Value *ParentPad, BasicBlock *UnwindDest,
                  unsigned NumHandlers, const Twine &NameStr,
                  Instruction *InsertBefore);

                                                   
                                                                              
                                                    
                                                                               
  CatchSwitchInst(Value *ParentPad, BasicBlock *UnwindDest,
                  unsigned NumHandlers, const Twine &NameStr,
                  BasicBlock *InsertAtEnd);

                                             
  void *operator new(size_t s) { return User::operator new(s); }

  void init(Value *ParentPad, BasicBlock *UnwindDest, unsigned NumReserved);
  void growOperands(unsigned Size);

protected:
                                                                   
  friend class Instruction;

  CatchSwitchInst *cloneImpl() const;

public:
  static CatchSwitchInst *Create(Value *ParentPad, BasicBlock *UnwindDest,
                                 unsigned NumHandlers,
                                 const Twine &NameStr = "",
                                 Instruction *InsertBefore = nullptr) {
    return new CatchSwitchInst(ParentPad, UnwindDest, NumHandlers, NameStr,
                               InsertBefore);
  }

  static CatchSwitchInst *Create(Value *ParentPad, BasicBlock *UnwindDest,
                                 unsigned NumHandlers, const Twine &NameStr,
                                 BasicBlock *InsertAtEnd) {
    return new CatchSwitchInst(ParentPad, UnwindDest, NumHandlers, NameStr,
                               InsertAtEnd);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                          
  Value *getParentPad() const { return getOperand(0); }
  void setParentPad(Value *ParentPad) { setOperand(0, ParentPad); }

                                          
  bool hasUnwindDest() const { return getSubclassDataFromInstruction() & 1; }
  bool unwindsToCaller() const { return !hasUnwindDest(); }
  BasicBlock *getUnwindDest() const {
    if (hasUnwindDest())
      return cast<BasicBlock>(getOperand(1));
    return nullptr;
  }
  void setUnwindDest(BasicBlock *UnwindDest) {
    assert(UnwindDest);
    assert(hasUnwindDest());
    setOperand(1, UnwindDest);
  }

                                                         
                                             
  unsigned getNumHandlers() const {
    if (hasUnwindDest())
      return getNumOperands() - 2;
    return getNumOperands() - 1;
  }

private:
  static BasicBlock *handler_helper(Value *V) { return cast<BasicBlock>(V); }
  static const BasicBlock *handler_helper(const Value *V) {
    return cast<BasicBlock>(V);
  }

public:
  using DerefFnTy = BasicBlock *(*)(Value *);
  using handler_iterator = mapped_iterator<op_iterator, DerefFnTy>;
  using handler_range = iterator_range<handler_iterator>;
  using ConstDerefFnTy = const BasicBlock *(*)(const Value *);
  using const_handler_iterator =
      mapped_iterator<const_op_iterator, ConstDerefFnTy>;
  using const_handler_range = iterator_range<const_handler_iterator>;

                                                                              
  handler_iterator handler_begin() {
    op_iterator It = op_begin() + 1;
    if (hasUnwindDest())
      ++It;
    return handler_iterator(It, DerefFnTy(handler_helper));
  }

                                                                 
                      
  const_handler_iterator handler_begin() const {
    const_op_iterator It = op_begin() + 1;
    if (hasUnwindDest())
      ++It;
    return const_handler_iterator(It, ConstDerefFnTy(handler_helper));
  }

                                                                
                                     
  handler_iterator handler_end() {
    return handler_iterator(op_end(), DerefFnTy(handler_helper));
  }

                                                                      
                      
  const_handler_iterator handler_end() const {
    return const_handler_iterator(op_end(), ConstDerefFnTy(handler_helper));
  }

                                            
  handler_range handlers() {
    return make_range(handler_begin(), handler_end());
  }

                                            
  const_handler_range handlers() const {
    return make_range(handler_begin(), handler_end());
  }

                                               
           
                                                                            
                                 
  void addHandler(BasicBlock *Dest);

  void removeHandler(handler_iterator HI);

  unsigned getNumSuccessors() const { return getNumOperands() - 1; }
  BasicBlock *getSuccessor(unsigned Idx) const {
    assert(Idx < getNumSuccessors() &&
           "Successor # out of range for catchswitch!");
    return cast<BasicBlock>(getOperand(Idx + 1));
  }
  void setSuccessor(unsigned Idx, BasicBlock *NewSucc) {
    assert(Idx < getNumSuccessors() &&
           "Successor # out of range for catchswitch!");
    setOperand(Idx + 1, NewSucc);
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::CatchSwitch;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<CatchSwitchInst> : public HungoffOperandTraits<2> {};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(CatchSwitchInst, Value)

                                                                                
                                                     
                                                                                
class CleanupPadInst : public FuncletPadInst {
private:
  explicit CleanupPadInst(Value *ParentPad, ArrayRef<Value *> Args,
                          unsigned Values, const Twine &NameStr,
                          Instruction *InsertBefore)
      : FuncletPadInst(Instruction::CleanupPad, ParentPad, Args, Values,
                       NameStr, InsertBefore) {}
  explicit CleanupPadInst(Value *ParentPad, ArrayRef<Value *> Args,
                          unsigned Values, const Twine &NameStr,
                          BasicBlock *InsertAtEnd)
      : FuncletPadInst(Instruction::CleanupPad, ParentPad, Args, Values,
                       NameStr, InsertAtEnd) {}

public:
  static CleanupPadInst *Create(Value *ParentPad, ArrayRef<Value *> Args = None,
                                const Twine &NameStr = "",
                                Instruction *InsertBefore = nullptr) {
    unsigned Values = 1 + Args.size();
    return new (Values)
        CleanupPadInst(ParentPad, Args, Values, NameStr, InsertBefore);
  }

  static CleanupPadInst *Create(Value *ParentPad, ArrayRef<Value *> Args,
                                const Twine &NameStr, BasicBlock *InsertAtEnd) {
    unsigned Values = 1 + Args.size();
    return new (Values)
        CleanupPadInst(ParentPad, Args, Values, NameStr, InsertAtEnd);
  }

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::CleanupPad;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                   
                                                                                
class CatchPadInst : public FuncletPadInst {
private:
  explicit CatchPadInst(Value *CatchSwitch, ArrayRef<Value *> Args,
                        unsigned Values, const Twine &NameStr,
                        Instruction *InsertBefore)
      : FuncletPadInst(Instruction::CatchPad, CatchSwitch, Args, Values,
                       NameStr, InsertBefore) {}
  explicit CatchPadInst(Value *CatchSwitch, ArrayRef<Value *> Args,
                        unsigned Values, const Twine &NameStr,
                        BasicBlock *InsertAtEnd)
      : FuncletPadInst(Instruction::CatchPad, CatchSwitch, Args, Values,
                       NameStr, InsertAtEnd) {}

public:
  static CatchPadInst *Create(Value *CatchSwitch, ArrayRef<Value *> Args,
                              const Twine &NameStr = "",
                              Instruction *InsertBefore = nullptr) {
    unsigned Values = 1 + Args.size();
    return new (Values)
        CatchPadInst(CatchSwitch, Args, Values, NameStr, InsertBefore);
  }

  static CatchPadInst *Create(Value *CatchSwitch, ArrayRef<Value *> Args,
                              const Twine &NameStr, BasicBlock *InsertAtEnd) {
    unsigned Values = 1 + Args.size();
    return new (Values)
        CatchPadInst(CatchSwitch, Args, Values, NameStr, InsertAtEnd);
  }

                           
  CatchSwitchInst *getCatchSwitch() const {
    return cast<CatchSwitchInst>(Op<-1>());
  }
  void setCatchSwitch(Value *CatchSwitch) {
    assert(CatchSwitch);
    Op<-1>() = CatchSwitch;
  }

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::CatchPad;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                      
                                                                                

class CatchReturnInst : public TerminatorInst {
  CatchReturnInst(const CatchReturnInst &RI);
  CatchReturnInst(Value *CatchPad, BasicBlock *BB, Instruction *InsertBefore);
  CatchReturnInst(Value *CatchPad, BasicBlock *BB, BasicBlock *InsertAtEnd);

  void init(Value *CatchPad, BasicBlock *BB);

protected:
                                                                   
  friend class Instruction;

  CatchReturnInst *cloneImpl() const;

public:
  static CatchReturnInst *Create(Value *CatchPad, BasicBlock *BB,
                                 Instruction *InsertBefore = nullptr) {
    assert(CatchPad);
    assert(BB);
    return new (2) CatchReturnInst(CatchPad, BB, InsertBefore);
  }

  static CatchReturnInst *Create(Value *CatchPad, BasicBlock *BB,
                                 BasicBlock *InsertAtEnd) {
    assert(CatchPad);
    assert(BB);
    return new (2) CatchReturnInst(CatchPad, BB, InsertAtEnd);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                            
  CatchPadInst *getCatchPad() const { return cast<CatchPadInst>(Op<0>()); }
  void setCatchPad(CatchPadInst *CatchPad) {
    assert(CatchPad);
    Op<0>() = CatchPad;
  }

  BasicBlock *getSuccessor() const { return cast<BasicBlock>(Op<1>()); }
  void setSuccessor(BasicBlock *NewSucc) {
    assert(NewSucc);
    Op<1>() = NewSucc;
  }
  unsigned getNumSuccessors() const { return 1; }

                                                                  
                                                                 
  Value *getCatchSwitchParentPad() const {
    return getCatchPad()->getCatchSwitch()->getParentPad();
  }

                                                                      
  static bool classof(const Instruction *I) {
    return (I->getOpcode() == Instruction::CatchRet);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
  friend TerminatorInst;

  BasicBlock *getSuccessor(unsigned Idx) const {
    assert(Idx < getNumSuccessors() && "Successor # out of range for catchret!");
    return getSuccessor();
  }

  void setSuccessor(unsigned Idx, BasicBlock *B) {
    assert(Idx < getNumSuccessors() && "Successor # out of range for catchret!");
    setSuccessor(B);
  }
};

template <>
struct OperandTraits<CatchReturnInst>
    : public FixedNumOperandTraits<CatchReturnInst, 2> {};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(CatchReturnInst, Value)

                                                                                
                                                        
                                                                                

class CleanupReturnInst : public TerminatorInst {
private:
  CleanupReturnInst(const CleanupReturnInst &RI);
  CleanupReturnInst(Value *CleanupPad, BasicBlock *UnwindBB, unsigned Values,
                    Instruction *InsertBefore = nullptr);
  CleanupReturnInst(Value *CleanupPad, BasicBlock *UnwindBB, unsigned Values,
                    BasicBlock *InsertAtEnd);

  void init(Value *CleanupPad, BasicBlock *UnwindBB);

protected:
                                                                   
  friend class Instruction;

  CleanupReturnInst *cloneImpl() const;

public:
  static CleanupReturnInst *Create(Value *CleanupPad,
                                   BasicBlock *UnwindBB = nullptr,
                                   Instruction *InsertBefore = nullptr) {
    assert(CleanupPad);
    unsigned Values = 1;
    if (UnwindBB)
      ++Values;
    return new (Values)
        CleanupReturnInst(CleanupPad, UnwindBB, Values, InsertBefore);
  }

  static CleanupReturnInst *Create(Value *CleanupPad, BasicBlock *UnwindBB,
                                   BasicBlock *InsertAtEnd) {
    assert(CleanupPad);
    unsigned Values = 1;
    if (UnwindBB)
      ++Values;
    return new (Values)
        CleanupReturnInst(CleanupPad, UnwindBB, Values, InsertAtEnd);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

  bool hasUnwindDest() const { return getSubclassDataFromInstruction() & 1; }
  bool unwindsToCaller() const { return !hasUnwindDest(); }

                           
  CleanupPadInst *getCleanupPad() const {
    return cast<CleanupPadInst>(Op<0>());
  }
  void setCleanupPad(CleanupPadInst *CleanupPad) {
    assert(CleanupPad);
    Op<0>() = CleanupPad;
  }

  unsigned getNumSuccessors() const { return hasUnwindDest() ? 1 : 0; }

  BasicBlock *getUnwindDest() const {
    return hasUnwindDest() ? cast<BasicBlock>(Op<1>()) : nullptr;
  }
  void setUnwindDest(BasicBlock *NewDest) {
    assert(NewDest);
    assert(hasUnwindDest());
    Op<1>() = NewDest;
  }

                                                                      
  static bool classof(const Instruction *I) {
    return (I->getOpcode() == Instruction::CleanupRet);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
  friend TerminatorInst;

  BasicBlock *getSuccessor(unsigned Idx) const {
    assert(Idx == 0);
    return getUnwindDest();
  }

  void setSuccessor(unsigned Idx, BasicBlock *B) {
    assert(Idx == 0);
    setUnwindDest(B);
  }

                                                                             
                                                          
  void setInstructionSubclassData(unsigned short D) {
    Instruction::setInstructionSubclassData(D);
  }
};

template <>
struct OperandTraits<CleanupReturnInst>
    : public VariadicOperandTraits<CleanupReturnInst,              1> {};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(CleanupReturnInst, Value)

                                                                                
                                                  
                                                                                

                                                                                
                                                             
                                                                               
                                       
   
class UnreachableInst : public TerminatorInst {
protected:
                                                                   
  friend class Instruction;

  UnreachableInst *cloneImpl() const;

public:
  explicit UnreachableInst(LLVMContext &C, Instruction *InsertBefore = nullptr);
  explicit UnreachableInst(LLVMContext &C, BasicBlock *InsertAtEnd);

                                             
  void *operator new(size_t s) {
    return User::operator new(s, 0);
  }

  unsigned getNumSuccessors() const { return 0; }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Unreachable;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

private:
  friend TerminatorInst;

  BasicBlock *getSuccessor(unsigned idx) const {
    llvm_unreachable("UnreachableInst has no successors!");
  }

  void setSuccessor(unsigned idx, BasicBlock *B) {
    llvm_unreachable("UnreachableInst has no successors!");
  }
};

                                                                                
                                                  
                                                                                

                                                        
class TruncInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                  
  TruncInst *cloneImpl() const;

public:
                                                          
  TruncInst(
    Value *S,                                                         
    Type *Ty,                                                                 
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  TruncInst(
    Value *S,                                                   
    Type *Ty,                                                           
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Trunc;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                 
                                                                                

                                                          
class ZExtInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                 
  ZExtInst *cloneImpl() const;

public:
                                                          
  ZExtInst(
    Value *S,                                                             
    Type *Ty,                                                          
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                               
  ZExtInst(
    Value *S,                                                       
    Type *Ty,                                                    
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == ZExt;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                 
                                                                                

                                                            
class SExtInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                 
  SExtInst *cloneImpl() const;

public:
                                                          
  SExtInst(
    Value *S,                                                             
    Type *Ty,                                                          
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  SExtInst(
    Value *S,                                                       
    Type *Ty,                                                    
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == SExt;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                    
                                                                                

                                                               
class FPTruncInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                    
  FPTruncInst *cloneImpl() const;

public:
                                                          
  FPTruncInst(
    Value *S,                                                         
    Type *Ty,                                                       
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                          
  FPTruncInst(
    Value *S,                                                   
    Type *Ty,                                                 
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == FPTrunc;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                  
                                                                                

                                                               
class FPExtInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                  
  FPExtInst *cloneImpl() const;

public:
                                                          
  FPExtInst(
    Value *S,                                                        
    Type *Ty,                                                     
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  FPExtInst(
    Value *S,                                                  
    Type *Ty,                                               
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == FPExt;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                   
                                                                                

                                                                    
class UIToFPInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                   
  UIToFPInst *cloneImpl() const;

public:
                                                          
  UIToFPInst(
    Value *S,                                                         
    Type *Ty,                                                      
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  UIToFPInst(
    Value *S,                                                   
    Type *Ty,                                                
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == UIToFP;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                   
                                                                                

                                                                       
class SIToFPInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                   
  SIToFPInst *cloneImpl() const;

public:
                                                          
  SIToFPInst(
    Value *S,                                                         
    Type *Ty,                                                      
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  SIToFPInst(
    Value *S,                                                   
    Type *Ty,                                                
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == SIToFP;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                   
                                                                                

                                                                        
class FPToUIInst  : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                   
  FPToUIInst *cloneImpl() const;

public:
                                                          
  FPToUIInst(
    Value *S,                                                         
    Type *Ty,                                                      
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  FPToUIInst(
    Value *S,                                                   
    Type *Ty,                                                
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                               
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == FPToUI;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                   
                                                                                

                                                                       
class FPToSIInst  : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                   
  FPToSIInst *cloneImpl() const;

public:
                                                          
  FPToSIInst(
    Value *S,                                                         
    Type *Ty,                                                      
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  FPToSIInst(
    Value *S,                                                   
    Type *Ty,                                                
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == FPToSI;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                     
                                                                                

                                                              
class IntToPtrInst : public CastInst {
public:
                                                                   
  friend class Instruction;

                                                          
  IntToPtrInst(
    Value *S,                                                         
    Type *Ty,                                                      
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  IntToPtrInst(
    Value *S,                                                   
    Type *Ty,                                                
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                      
  IntToPtrInst *cloneImpl() const;

                                                                   
  unsigned getAddressSpace() const {
    return getType()->getPointerAddressSpace();
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == IntToPtr;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                     
                                                                                

                                                              
class PtrToIntInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                      
  PtrToIntInst *cloneImpl() const;

public:
                                                          
  PtrToIntInst(
    Value *S,                                                         
    Type *Ty,                                                      
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  PtrToIntInst(
    Value *S,                                                   
    Type *Ty,                                                
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                               
  Value *getPointerOperand() { return getOperand(0); }
                               
  const Value *getPointerOperand() const { return getOperand(0); }
                                                    
  static unsigned getPointerOperandIndex() { return 0U; }

                                                       
  unsigned getPointerAddressSpace() const {
    return getPointerOperand()->getType()->getPointerAddressSpace();
  }

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == PtrToInt;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                
                                                                                

                                                                
class BitCastInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                     
  BitCastInst *cloneImpl() const;

public:
                                                          
  BitCastInst(
    Value *S,                                                      
    Type *Ty,                                                     
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  BitCastInst(
    Value *S,                                                
    Type *Ty,                                               
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == BitCast;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                   
                                                                                

                                                                              
               
class AddrSpaceCastInst : public CastInst {
protected:
                                                                   
  friend class Instruction;

                                           
  AddrSpaceCastInst *cloneImpl() const;

public:
                                                          
  AddrSpaceCastInst(
    Value *S,                                                      
    Type *Ty,                                                     
    const Twine &NameStr = "",                                             
    Instruction *InsertBefore = nullptr                                         
  );

                                                       
  AddrSpaceCastInst(
    Value *S,                                                
    Type *Ty,                                               
    const Twine &NameStr,                                            
    BasicBlock *InsertAtEnd                                                    
  );

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == AddrSpaceCast;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

                               
  Value *getPointerOperand() {
    return getOperand(0);
  }

                               
  const Value *getPointerOperand() const {
    return getOperand(0);
  }

                                                    
  static unsigned getPointerOperandIndex() {
    return 0U;
  }

                                                       
  unsigned getSrcAddressSpace() const {
    return getPointerOperand()->getType()->getPointerAddressSpace();
  }

                                              
  unsigned getDestAddressSpace() const {
    return getType()->getPointerAddressSpace();
  }
};

                                                                         
                                                      
inline Value *getLoadStorePointerOperand(Value *V) {
  if (auto *Load = dyn_cast<LoadInst>(V))
    return Load->getPointerOperand();
  if (auto *Store = dyn_cast<StoreInst>(V))
    return Store->getPointerOperand();
  return nullptr;
}

                                                                       
                                                                   
inline Value *getPointerOperand(Value *V) {
  if (auto *Ptr = getLoadStorePointerOperand(V))
    return Ptr;
  if (auto *Gep = dyn_cast<GetElementPtrInst>(V))
    return Gep->getPointerOperand();
  return nullptr;
}

                                                                              
inline unsigned getLoadStoreAlignment(Value *I) {
  assert((isa<LoadInst>(I) || isa<StoreInst>(I)) &&
         "Expected Load or Store instruction");
  if (auto *LI = dyn_cast<LoadInst>(I))
    return LI->getAlignment();
  return cast<StoreInst>(I)->getAlignment();
}

                                                                              
                              
inline unsigned getLoadStoreAddressSpace(Value *I) {
  assert((isa<LoadInst>(I) || isa<StoreInst>(I)) &&
         "Expected Load or Store instruction");
  if (auto *LI = dyn_cast<LoadInst>(I))
    return LI->getPointerAddressSpace();
  return cast<StoreInst>(I)->getPointerAddressSpace();
}

}                      

#endif                          
