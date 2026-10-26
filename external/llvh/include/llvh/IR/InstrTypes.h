//===- llvm/InstrTypes.h - Important Instruction subclasses -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines various meta classes of instructions that exist in the VM
// representation.  Specific concrete subclasses of these may be found in the
// i*.h files...
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_IR_INSTRTYPES_H
#define LLVM_IR_INSTRTYPES_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/Constants.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/Instruction.h"
#include "llvh/IR/LLVMContext.h"
#include "llvh/IR/OperandTraits.h"
#include "llvh/IR/Type.h"
#include "llvh/IR/User.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

namespace llvh {

                                                                                
                                                  
                                                                                

                                                              
                                                                   
   
class TerminatorInst : public Instruction {
protected:
  TerminatorInst(Type *Ty, Instruction::TermOps iType,
                 Use *Ops, unsigned NumOps,
                 Instruction *InsertBefore = nullptr)
    : Instruction(Ty, iType, Ops, NumOps, InsertBefore) {}

  TerminatorInst(Type *Ty, Instruction::TermOps iType,
                 Use *Ops, unsigned NumOps, BasicBlock *InsertAtEnd)
    : Instruction(Ty, iType, Ops, NumOps, InsertAtEnd) {}

public:
                                                                      
  static bool classof(const Instruction *I) {
    return I->isTerminator();
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                                  
                                                                                

class UnaryInstruction : public Instruction {
protected:
  UnaryInstruction(Type *Ty, unsigned iType, Value *V,
                   Instruction *IB = nullptr)
    : Instruction(Ty, iType, &Op<0>(), 1, IB) {
    Op<0>() = V;
  }
  UnaryInstruction(Type *Ty, unsigned iType, Value *V, BasicBlock *IAE)
    : Instruction(Ty, iType, &Op<0>(), 1, IAE) {
    Op<0>() = V;
  }

public:
                                           
  void *operator new(size_t s) {
    return User::operator new(s, 1);
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                      
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::Alloca ||
           I->getOpcode() == Instruction::Load ||
           I->getOpcode() == Instruction::VAArg ||
           I->getOpcode() == Instruction::ExtractValue ||
           (I->getOpcode() >= CastOpsBegin && I->getOpcode() < CastOpsEnd);
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<UnaryInstruction> :
  public FixedNumOperandTraits<UnaryInstruction, 1> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(UnaryInstruction, Value)

                                                                                
                                                 
                                                                                

class BinaryOperator : public Instruction {
  void AssertOK();

protected:
  BinaryOperator(BinaryOps iType, Value *S1, Value *S2, Type *Ty,
                 const Twine &Name, Instruction *InsertBefore);
  BinaryOperator(BinaryOps iType, Value *S1, Value *S2, Type *Ty,
                 const Twine &Name, BasicBlock *InsertAtEnd);

                                                                   
  friend class Instruction;

  BinaryOperator *cloneImpl() const;

public:
                                            
  void *operator new(size_t s) {
    return User::operator new(s, 2);
  }

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                  
                                                                               
                                                                              
                                                               
     
  static BinaryOperator *Create(BinaryOps Op, Value *S1, Value *S2,
                                const Twine &Name = Twine(),
                                Instruction *InsertBefore = nullptr);

                                                                  
                                                                             
                           
     
  static BinaryOperator *Create(BinaryOps Op, Value *S1, Value *S2,
                                const Twine &Name, BasicBlock *InsertAtEnd);

                                                                   
                                                                             
                                    
#define HANDLE_BINARY_INST(N, OPC, CLASS) \
  static BinaryOperator *Create##OPC(Value *V1, Value *V2, \
                                     const Twine &Name = "") {\
    return Create(Instruction::OPC, V1, V2, Name);\
  }
#include "llvh/IR/Instruction.def"
#define HANDLE_BINARY_INST(N, OPC, CLASS) \
  static BinaryOperator *Create##OPC(Value *V1, Value *V2, \
                                     const Twine &Name, BasicBlock *BB) {\
    return Create(Instruction::OPC, V1, V2, Name, BB);\
  }
#include "llvh/IR/Instruction.def"
#define HANDLE_BINARY_INST(N, OPC, CLASS) \
  static BinaryOperator *Create##OPC(Value *V1, Value *V2, \
                                     const Twine &Name, Instruction *I) {\
    return Create(Instruction::OPC, V1, V2, Name, I);\
  }
#include "llvh/IR/Instruction.def"

  static BinaryOperator *CreateWithCopiedFlags(BinaryOps Opc,
                                               Value *V1, Value *V2,
                                               BinaryOperator *CopyBO,
                                               const Twine &Name = "") {
    BinaryOperator *BO = Create(Opc, V1, V2, Name);
    BO->copyIRFlags(CopyBO);
    return BO;
  }

  static BinaryOperator *CreateFAddFMF(Value *V1, Value *V2,
                                       BinaryOperator *FMFSource,
                                       const Twine &Name = "") {
    return CreateWithCopiedFlags(Instruction::FAdd, V1, V2, FMFSource, Name);
  }
  static BinaryOperator *CreateFSubFMF(Value *V1, Value *V2,
                                       BinaryOperator *FMFSource,
                                       const Twine &Name = "") {
    return CreateWithCopiedFlags(Instruction::FSub, V1, V2, FMFSource, Name);
  }
  static BinaryOperator *CreateFMulFMF(Value *V1, Value *V2,
                                       BinaryOperator *FMFSource,
                                       const Twine &Name = "") {
    return CreateWithCopiedFlags(Instruction::FMul, V1, V2, FMFSource, Name);
  }
  static BinaryOperator *CreateFDivFMF(Value *V1, Value *V2,
                                       BinaryOperator *FMFSource,
                                       const Twine &Name = "") {
    return CreateWithCopiedFlags(Instruction::FDiv, V1, V2, FMFSource, Name);
  }
  static BinaryOperator *CreateFRemFMF(Value *V1, Value *V2,
                                       BinaryOperator *FMFSource,
                                       const Twine &Name = "") {
    return CreateWithCopiedFlags(Instruction::FRem, V1, V2, FMFSource, Name);
  }
  static BinaryOperator *CreateFNegFMF(Value *Op, BinaryOperator *FMFSource,
                                       const Twine &Name = "") {
    Value *Zero = ConstantFP::getNegativeZero(Op->getType());
    return CreateWithCopiedFlags(Instruction::FSub, Zero, Op, FMFSource);
  }

  static BinaryOperator *CreateNSW(BinaryOps Opc, Value *V1, Value *V2,
                                   const Twine &Name = "") {
    BinaryOperator *BO = Create(Opc, V1, V2, Name);
    BO->setHasNoSignedWrap(true);
    return BO;
  }
  static BinaryOperator *CreateNSW(BinaryOps Opc, Value *V1, Value *V2,
                                   const Twine &Name, BasicBlock *BB) {
    BinaryOperator *BO = Create(Opc, V1, V2, Name, BB);
    BO->setHasNoSignedWrap(true);
    return BO;
  }
  static BinaryOperator *CreateNSW(BinaryOps Opc, Value *V1, Value *V2,
                                   const Twine &Name, Instruction *I) {
    BinaryOperator *BO = Create(Opc, V1, V2, Name, I);
    BO->setHasNoSignedWrap(true);
    return BO;
  }

  static BinaryOperator *CreateNUW(BinaryOps Opc, Value *V1, Value *V2,
                                   const Twine &Name = "") {
    BinaryOperator *BO = Create(Opc, V1, V2, Name);
    BO->setHasNoUnsignedWrap(true);
    return BO;
  }
  static BinaryOperator *CreateNUW(BinaryOps Opc, Value *V1, Value *V2,
                                   const Twine &Name, BasicBlock *BB) {
    BinaryOperator *BO = Create(Opc, V1, V2, Name, BB);
    BO->setHasNoUnsignedWrap(true);
    return BO;
  }
  static BinaryOperator *CreateNUW(BinaryOps Opc, Value *V1, Value *V2,
                                   const Twine &Name, Instruction *I) {
    BinaryOperator *BO = Create(Opc, V1, V2, Name, I);
    BO->setHasNoUnsignedWrap(true);
    return BO;
  }

  static BinaryOperator *CreateExact(BinaryOps Opc, Value *V1, Value *V2,
                                     const Twine &Name = "") {
    BinaryOperator *BO = Create(Opc, V1, V2, Name);
    BO->setIsExact(true);
    return BO;
  }
  static BinaryOperator *CreateExact(BinaryOps Opc, Value *V1, Value *V2,
                                     const Twine &Name, BasicBlock *BB) {
    BinaryOperator *BO = Create(Opc, V1, V2, Name, BB);
    BO->setIsExact(true);
    return BO;
  }
  static BinaryOperator *CreateExact(BinaryOps Opc, Value *V1, Value *V2,
                                     const Twine &Name, Instruction *I) {
    BinaryOperator *BO = Create(Opc, V1, V2, Name, I);
    BO->setIsExact(true);
    return BO;
  }

#define DEFINE_HELPERS(OPC, NUWNSWEXACT)                                       \
  static BinaryOperator *Create##NUWNSWEXACT##OPC(Value *V1, Value *V2,        \
                                                  const Twine &Name = "") {    \
    return Create##NUWNSWEXACT(Instruction::OPC, V1, V2, Name);                \
  }                                                                            \
  static BinaryOperator *Create##NUWNSWEXACT##OPC(                             \
      Value *V1, Value *V2, const Twine &Name, BasicBlock *BB) {               \
    return Create##NUWNSWEXACT(Instruction::OPC, V1, V2, Name, BB);            \
  }                                                                            \
  static BinaryOperator *Create##NUWNSWEXACT##OPC(                             \
      Value *V1, Value *V2, const Twine &Name, Instruction *I) {               \
    return Create##NUWNSWEXACT(Instruction::OPC, V1, V2, Name, I);             \
  }

  DEFINE_HELPERS(Add, NSW)                
  DEFINE_HELPERS(Add, NUW)                
  DEFINE_HELPERS(Sub, NSW)                
  DEFINE_HELPERS(Sub, NUW)                
  DEFINE_HELPERS(Mul, NSW)                
  DEFINE_HELPERS(Mul, NUW)                
  DEFINE_HELPERS(Shl, NSW)                
  DEFINE_HELPERS(Shl, NUW)                

  DEFINE_HELPERS(SDiv, Exact)                    
  DEFINE_HELPERS(UDiv, Exact)                    
  DEFINE_HELPERS(AShr, Exact)                    
  DEFINE_HELPERS(LShr, Exact)                    

#undef DEFINE_HELPERS

                                                                              
                                       
     
                                                                          
     
  static BinaryOperator *CreateNeg(Value *Op, const Twine &Name = "",
                                   Instruction *InsertBefore = nullptr);
  static BinaryOperator *CreateNeg(Value *Op, const Twine &Name,
                                   BasicBlock *InsertAtEnd);
  static BinaryOperator *CreateNSWNeg(Value *Op, const Twine &Name = "",
                                      Instruction *InsertBefore = nullptr);
  static BinaryOperator *CreateNSWNeg(Value *Op, const Twine &Name,
                                      BasicBlock *InsertAtEnd);
  static BinaryOperator *CreateNUWNeg(Value *Op, const Twine &Name = "",
                                      Instruction *InsertBefore = nullptr);
  static BinaryOperator *CreateNUWNeg(Value *Op, const Twine &Name,
                                      BasicBlock *InsertAtEnd);
  static BinaryOperator *CreateFNeg(Value *Op, const Twine &Name = "",
                                    Instruction *InsertBefore = nullptr);
  static BinaryOperator *CreateFNeg(Value *Op, const Twine &Name,
                                    BasicBlock *InsertAtEnd);
  static BinaryOperator *CreateNot(Value *Op, const Twine &Name = "",
                                   Instruction *InsertBefore = nullptr);
  static BinaryOperator *CreateNot(Value *Op, const Twine &Name,
                                   BasicBlock *InsertAtEnd);

                                                                  
     
  static bool isNeg(const Value *V);
  static bool isFNeg(const Value *V, bool IgnoreZeroSign=false);
  static bool isNot(const Value *V);

                                                                          
                                                  
     
  static const Value *getNegArgument(const Value *BinOp);
  static       Value *getNegArgument(      Value *BinOp);
  static const Value *getFNegArgument(const Value *BinOp);
  static       Value *getFNegArgument(      Value *BinOp);
  static const Value *getNotArgument(const Value *BinOp);
  static       Value *getNotArgument(      Value *BinOp);

  BinaryOps getOpcode() const {
    return static_cast<BinaryOps>(Instruction::getOpcode());
  }

                                                    
                                                                   
                                                                           
                                                            
     
  bool swapOperands();

                                                                      
  static bool classof(const Instruction *I) {
    return I->isBinaryOp();
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<BinaryOperator> :
  public FixedNumOperandTraits<BinaryOperator, 2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(BinaryOperator, Value)

                                                                                
                                               
                                                                                

                                                                 
                                                                     
                                    
   
                                     
                                       
class CastInst : public UnaryInstruction {
protected:
                                                                         
  CastInst(Type *Ty, unsigned iType, Value *S,
           const Twine &NameStr = "", Instruction *InsertBefore = nullptr)
    : UnaryInstruction(Ty, iType, S, InsertBefore) {
    setName(NameStr);
  }
                                                                      
  CastInst(Type *Ty, unsigned iType, Value *S,
           const Twine &NameStr, BasicBlock *InsertAtEnd)
    : UnaryInstruction(Ty, iType, S, InsertAtEnd) {
    setName(NameStr);
  }

public:
                                                                         
                                                                             
                                                                       
                                                                          
                                                                      
                                              
  static CastInst *Create(
    Instruction::CastOps,                                           
    Value *S,                                                       
    Type *Ty,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );
                                                                         
                                                                             
                                                                             
                                                                            
                    
                                              
  static CastInst *Create(
    Instruction::CastOps,                                            
    Value *S,                                                       
    Type *Ty,                                                  
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                               
  static CastInst *CreateZExtOrBitCast(
    Value *S,                                                       
    Type *Ty,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                               
  static CastInst *CreateZExtOrBitCast(
    Value *S,                                                       
    Type *Ty,                                                  
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                               
  static CastInst *CreateSExtOrBitCast(
    Value *S,                                                       
    Type *Ty,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                               
  static CastInst *CreateSExtOrBitCast(
    Value *S,                                                       
    Type *Ty,                                                  
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                                                     
  static CastInst *CreatePointerCast(
    Value *S,                                                               
    Type *Ty,                                                  
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                                                     
  static CastInst *CreatePointerCast(
    Value *S,                                                               
    Type *Ty,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                                            
  static CastInst *CreatePointerBitCastOrAddrSpaceCast(
    Value *S,                                                               
    Type *Ty,                                                  
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                                            
  static CastInst *CreatePointerBitCastOrAddrSpaceCast(
    Value *S,                                                               
    Type *Ty,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                                                    
     
                                                                         
                                                                      
                                                                              
                
  static CastInst *CreateBitOrPointerCast(
    Value *S,                                                               
    Type *Ty,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                                            
  static CastInst *CreateIntegerCast(
    Value *S,                                                               
    Type *Ty,                                                    
    bool isSigned,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                                            
  static CastInst *CreateIntegerCast(
    Value *S,                                                               
    Type *Ty,                                                          
    bool isSigned,                                                    
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                                             
  static CastInst *CreateFPCast(
    Value *S,                                                          
    Type *Ty,                                                 
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                                             
  static CastInst *CreateFPCast(
    Value *S,                                                          
    Type *Ty,                                                 
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                                
  static CastInst *CreateTruncOrBitCast(
    Value *S,                                                       
    Type *Ty,                                                    
    const Twine &Name = "",                              
    Instruction *InsertBefore = nullptr                                     
  );

                                                
  static CastInst *CreateTruncOrBitCast(
    Value *S,                                                       
    Type *Ty,                                                  
    const Twine &Name,                                  
    BasicBlock *InsertAtEnd                                               
  );

                                                                      
  static bool isCastable(
    Type *SrcTy,                                                   
    Type *DestTy                                                 
  );

                                                          
  static bool isBitCastable(
    Type *SrcTy,                                                   
    Type *DestTy                                                 
  );

                                                                       
                                 
     
                                                                         
                                              
  static bool isBitOrNoopPointerCastable(
      Type *SrcTy,                                                    
      Type *DestTy,                                                 
      const DataLayout &DL);

                                                                          
            
                                                
  static Instruction::CastOps getCastOpcode(
    const Value *Val,                       
    bool SrcIsSigned,                                           
    Type *Ty,                                                    
    bool DstIsSigned                                            
  );

                                                                          
                                                                            
                                     
                                                                               
                                                
  bool isIntegerCast() const;

                                                                            
                                                                            
                                
                                             
                                           
  bool isLosslessCast() const;

                                                                         
                                                                             
                                                                               
                                                                              
                                                                        
               
                                                      
  static bool isNoopCast(
    Instruction::CastOps Opcode,                    
    Type *SrcTy,                           
    Type *DstTy,                           
    const DataLayout &DL                                              
  );

                                             
     
                                                            
  bool isNoopCast(const DataLayout &DL) const;

                                                                             
                                                                   
                                                                    
                                                                    
                                       
                                            
  static unsigned isEliminableCastPair(
    Instruction::CastOps firstOpcode,                           
    Instruction::CastOps secondOpcode,                           
    Type *SrcTy,                       
    Type *MidTy,                                           
    Type *DstTy,                       
    Type *SrcIntPtrTy,                                                      
    Type *MidIntPtrTy,                                                      
    Type *DstIntPtrTy                                                       
  );

                                        
  Instruction::CastOps getOpcode() const {
    return Instruction::CastOps(Instruction::getOpcode());
  }

                                              
  Type* getSrcTy() const { return getOperand(0)->getType(); }
                                                   
  Type* getDestTy() const { return getType(); }

                                                                          
                                
                                                   
                                                        
  static bool castIsValid(Instruction::CastOps op, Value *S, Type *DstTy);

                                                                       
  static bool classof(const Instruction *I) {
    return I->isCast();
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

                                                                                
                                              
                                                                                

                                                                 
                                                   
class CmpInst : public Instruction {
public:
                                                                            
                                                                             
                                                                            
                                                               
     
                                                                              
                                                                             
                   
  enum Predicate {
                                                         
    FCMP_FALSE =  0,                                              
    FCMP_OEQ   =  1,                                           
    FCMP_OGT   =  2,                                                  
    FCMP_OGE   =  3,                                                           
    FCMP_OLT   =  4,                                               
    FCMP_OLE   =  5,                                                        
    FCMP_ONE   =  6,                                                          
    FCMP_ORD   =  7,                                           
    FCMP_UNO   =  8,                                                        
    FCMP_UEQ   =  9,                                            
    FCMP_UGT   = 10,                                                   
    FCMP_UGE   = 11,                                                           
    FCMP_ULT   = 12,                                                
    FCMP_ULE   = 13,                                                        
    FCMP_UNE   = 14,                                                
    FCMP_TRUE  = 15,                                             
    FIRST_FCMP_PREDICATE = FCMP_FALSE,
    LAST_FCMP_PREDICATE = FCMP_TRUE,
    BAD_FCMP_PREDICATE = FCMP_TRUE + 1,
    ICMP_EQ    = 32,            
    ICMP_NE    = 33,                
    ICMP_UGT   = 34,                            
    ICMP_UGE   = 35,                                
    ICMP_ULT   = 36,                         
    ICMP_ULE   = 37,                             
    ICMP_SGT   = 38,                          
    ICMP_SGE   = 39,                              
    ICMP_SLT   = 40,                       
    ICMP_SLE   = 41,                           
    FIRST_ICMP_PREDICATE = ICMP_EQ,
    LAST_ICMP_PREDICATE = ICMP_SLE,
    BAD_ICMP_PREDICATE = ICMP_SLE + 1
  };

protected:
  CmpInst(Type *ty, Instruction::OtherOps op, Predicate pred,
          Value *LHS, Value *RHS, const Twine &Name = "",
          Instruction *InsertBefore = nullptr);

  CmpInst(Type *ty, Instruction::OtherOps op, Predicate pred,
          Value *LHS, Value *RHS, const Twine &Name,
          BasicBlock *InsertAtEnd);

public:
                                            
  void *operator new(size_t s) {
    return User::operator new(s, 2);
  }

                                                                          
                                                                           
                                                                           
                                                                             
                      
  static CmpInst *Create(OtherOps Op,
                         Predicate predicate, Value *S1,
                         Value *S2, const Twine &Name = "",
                         Instruction *InsertBefore = nullptr);

                                                                              
                                                                             
                               
                      
  static CmpInst *Create(OtherOps Op, Predicate predicate, Value *S1,
                         Value *S2, const Twine &Name, BasicBlock *InsertAtEnd);

                                             
  OtherOps getOpcode() const {
    return static_cast<OtherOps>(Instruction::getOpcode());
  }

                                                
  Predicate getPredicate() const {
    return Predicate(getSubclassDataFromInstruction());
  }

                                                                    
  void setPredicate(Predicate P) { setInstructionSubclassData(P); }

  static bool isFPPredicate(Predicate P) {
    return P >= FIRST_FCMP_PREDICATE && P <= LAST_FCMP_PREDICATE;
  }

  static bool isIntPredicate(Predicate P) {
    return P >= FIRST_ICMP_PREDICATE && P <= LAST_ICMP_PREDICATE;
  }

  static StringRef getPredicateName(Predicate P);

  bool isFPPredicate() const { return isFPPredicate(getPredicate()); }
  bool isIntPredicate() const { return isIntPredicate(getPredicate()); }

                                                    
                                                           
                                                                             
                                                        
  Predicate getInversePredicate() const {
    return getInversePredicate(getPredicate());
  }

                                                    
                                                           
                                                                       
                                             
  static Predicate getInversePredicate(Predicate pred);

                                              
                                                     
                                                                           
                                                                     
               
                                                          
  Predicate getSwappedPredicate() const {
    return getSwappedPredicate(getPredicate());
  }

                                                                      
                
                                                           
  static Predicate getSwappedPredicate(Predicate pred);

                                                                              
                                                                              
                                                
                                                                       
                            
                                                
  Predicate getFlippedStrictnessPredicate() const {
    return getFlippedStrictnessPredicate(getPredicate());
  }

                                                                      
                
                                                
  static Predicate getFlippedStrictnessPredicate(Predicate pred);

                                                                  
                                                           
  Predicate getNonStrictPredicate() const {
    return getNonStrictPredicate(getPredicate());
  }

                                                                      
                
                                                                        
                                                                       
                                                           
  static Predicate getNonStrictPredicate(Predicate pred);

                                                
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                   
                                                                  
                          
  void swapOperands();

                                                                   
                                               
  bool isCommutative() const;

                                                                   
                                                          
  bool isEquality() const;

                                                                 
                                                                 
  bool isSigned() const {
    return isSigned(getPredicate());
  }

                                                                   
                                                                    
  bool isUnsigned() const {
    return isUnsigned(getPredicate());
  }

                                                                             
                                                                 
                                              
  static Predicate getSignedPredicate(Predicate pred);

                                                                             
                                                                              
                                       
                                              
  Predicate getSignedPredicate() {
    return getSignedPredicate(getPredicate());
  }

                                 
                                                                
  bool isTrueWhenEqual() const {
    return isTrueWhenEqual(getPredicate());
  }

                                 
                                                                 
  bool isFalseWhenEqual() const {
    return isFalseWhenEqual(getPredicate());
  }

                                                                  
                                                          
  static bool isUnsigned(Predicate predicate);

                                                                
                                                        
  static bool isSigned(Predicate predicate);

                                                         
  static bool isOrdered(Predicate predicate);

                                                           
  static bool isUnordered(Predicate predicate);

                                                                            
  static bool isTrueWhenEqual(Predicate predicate);

                                                                             
  static bool isFalseWhenEqual(Predicate predicate);

                                                                              
               
  static bool isImpliedTrueByMatchingCmp(Predicate Pred1, Predicate Pred2);

                                                                               
               
  static bool isImpliedFalseByMatchingCmp(Predicate Pred1, Predicate Pred2);

                                                                       
  static bool classof(const Instruction *I) {
    return I->getOpcode() == Instruction::ICmp ||
           I->getOpcode() == Instruction::FCmp;
  }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }

                                        
  static Type* makeCmpResultType(Type* opnd_type) {
    if (VectorType* vt = dyn_cast<VectorType>(opnd_type)) {
      return VectorType::get(Type::getInt1Ty(opnd_type->getContext()),
                             vt->getNumElements());
    }
    return Type::getInt1Ty(opnd_type->getContext());
  }

private:
                                                                                
                                           
  void setValueSubclassData(unsigned short D) {
    Value::setValueSubclassData(D);
  }
};

                                                         
template <>
struct OperandTraits<CmpInst> : public FixedNumOperandTraits<CmpInst, 2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(CmpInst, Value)

                                                                                
                                                 
                                                                                
class FuncletPadInst : public Instruction {
private:
  FuncletPadInst(const FuncletPadInst &CPI);

  explicit FuncletPadInst(Instruction::FuncletPadOps Op, Value *ParentPad,
                          ArrayRef<Value *> Args, unsigned Values,
                          const Twine &NameStr, Instruction *InsertBefore);
  explicit FuncletPadInst(Instruction::FuncletPadOps Op, Value *ParentPad,
                          ArrayRef<Value *> Args, unsigned Values,
                          const Twine &NameStr, BasicBlock *InsertAtEnd);

  void init(Value *ParentPad, ArrayRef<Value *> Args, const Twine &NameStr);

protected:
                                                                   
  friend class Instruction;
  friend class CatchPadInst;
  friend class CleanupPadInst;

  FuncletPadInst *cloneImpl() const;

public:
                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                    
     
  unsigned getNumArgOperands() const { return getNumOperands() - 1; }

                           

                                                            
     
                                                                              
                        
  Value *getParentPad() const { return Op<-1>(); }
  void setParentPad(Value *ParentPad) {
    assert(ParentPad);
    Op<-1>() = ParentPad;
  }

                                                                            
     
  Value *getArgOperand(unsigned i) const { return getOperand(i); }
  void setArgOperand(unsigned i, Value *v) { setOperand(i, v); }

                                                           
  op_range arg_operands() { return op_range(op_begin(), op_end() - 1); }

                                                           
  const_op_range arg_operands() const {
    return const_op_range(op_begin(), op_end() - 1);
  }

                                                                      
  static bool classof(const Instruction *I) { return I->isFuncletPad(); }
  static bool classof(const Value *V) {
    return isa<Instruction>(V) && classof(cast<Instruction>(V));
  }
};

template <>
struct OperandTraits<FuncletPadInst>
    : public VariadicOperandTraits<FuncletPadInst,              1> {};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(FuncletPadInst, Value)

                                                                   
                    
struct OperandBundleUse {
  ArrayRef<Use> Inputs;

  OperandBundleUse() = default;
  explicit OperandBundleUse(StringMapEntry<uint32_t> *Tag, ArrayRef<Use> Inputs)
      : Inputs(Inputs), Tag(Tag) {}

                                                                       
                          
  bool operandHasAttr(unsigned Idx, Attribute::AttrKind A) const {
    if (isDeoptOperandBundle())
      if (A == Attribute::ReadOnly || A == Attribute::NoCapture)
        return Inputs[Idx]->getType()->isPointerTy();

                                                             
    return false;
  }

                                                        
  StringRef getTagName() const {
    return Tag->getKey();
  }

                                                          
     
                                                                                
                                                                       
                                                   
  uint32_t getTagID() const {
    return Tag->getValue();
  }

                                                      
  bool isDeoptOperandBundle() const {
    return getTagID() == LLVMContext::OB_deopt;
  }

                                                        
  bool isFuncletOperandBundle() const {
    return getTagID() == LLVMContext::OB_funclet;
  }

private:
                                                                   
  StringMapEntry<uint32_t> *Tag;
};

                                                                     
                              
   
                                                                              
                                                                             
                                               
template <typename InputTy> class OperandBundleDefT {
  std::string Tag;
  std::vector<InputTy> Inputs;

public:
  explicit OperandBundleDefT(std::string Tag, std::vector<InputTy> Inputs)
      : Tag(std::move(Tag)), Inputs(std::move(Inputs)) {}
  explicit OperandBundleDefT(std::string Tag, ArrayRef<InputTy> Inputs)
      : Tag(std::move(Tag)), Inputs(Inputs) {}

  explicit OperandBundleDefT(const OperandBundleUse &OBU) {
    Tag = OBU.getTagName();
    Inputs.insert(Inputs.end(), OBU.Inputs.begin(), OBU.Inputs.end());
  }

  ArrayRef<InputTy> inputs() const { return Inputs; }

  using input_iterator = typename std::vector<InputTy>::const_iterator;

  size_t input_size() const { return Inputs.size(); }
  input_iterator input_begin() const { return Inputs.begin(); }
  input_iterator input_end() const { return Inputs.end(); }

  StringRef getTag() const { return Tag; }
};

using OperandBundleDef = OperandBundleDefT<Value *>;
using ConstOperandBundleDef = OperandBundleDefT<const Value *>;

                                                                   
            
   
                                                                              
                                                                              
                                                 
   
                                           
   
                                                                           
                                                                           
                                                                           
                                                                           
                                                                           
                                                                                
                                                                              
                                                                                
                                                            
                                                            
                                                            
                                                            
                                                            
   
   
                                                                               
                                                                               
                                                    
   
                                                                             
                                                                           
                                                                            
         
   
                                                                               
                                                                              
                                                                                
                                                                              
                                                                                
                                                                         
                     
   
                                                                           
                                                                               
                                                    
   
                                                                            
template <typename InstrTy, typename OpIteratorTy> class OperandBundleUser {
public:
                                                                     
  unsigned getNumOperandBundles() const {
    return std::distance(bundle_op_info_begin(), bundle_op_info_end());
  }

                                                       
  bool hasOperandBundles() const { return getNumOperandBundles() != 0; }

                                                                    
  unsigned getBundleOperandsStartIndex() const {
    assert(hasOperandBundles() && "Don't call otherwise!");
    return bundle_op_info_begin()->Begin;
  }

                                                                   
  unsigned getBundleOperandsEndIndex() const {
    assert(hasOperandBundles() && "Don't call otherwise!");
    return bundle_op_info_end()[-1].End;
  }

                                                                     
  bool isBundleOperand(unsigned Idx) const {
    return hasOperandBundles() && Idx >= getBundleOperandsStartIndex() &&
           Idx < getBundleOperandsEndIndex();
  }

                                                                    
                                                     
  unsigned getNumTotalBundleOperands() const {
    if (!hasOperandBundles())
      return 0;

    unsigned Begin = getBundleOperandsStartIndex();
    unsigned End = getBundleOperandsEndIndex();

    assert(Begin <= End && "Should be!");
    return End - Begin;
  }

                                                    
  OperandBundleUse getOperandBundleAt(unsigned Index) const {
    assert(Index < getNumOperandBundles() && "Index out of bounds!");
    return operandBundleFromBundleOpInfo(*(bundle_op_info_begin() + Index));
  }

                                                                        
                       
  unsigned countOperandBundlesOfType(StringRef Name) const {
    unsigned Count = 0;
    for (unsigned i = 0, e = getNumOperandBundles(); i != e; ++i)
      if (getOperandBundleAt(i).getTagName() == Name)
        Count++;

    return Count;
  }

                                                                      
                       
  unsigned countOperandBundlesOfType(uint32_t ID) const {
    unsigned Count = 0;
    for (unsigned i = 0, e = getNumOperandBundles(); i != e; ++i)
      if (getOperandBundleAt(i).getTagID() == ID)
        Count++;

    return Count;
  }

                                                   
     
                                                                        
                                                         
  Optional<OperandBundleUse> getOperandBundle(StringRef Name) const {
    assert(countOperandBundlesOfType(Name) < 2 && "Precondition violated!");

    for (unsigned i = 0, e = getNumOperandBundles(); i != e; ++i) {
      OperandBundleUse U = getOperandBundleAt(i);
      if (U.getTagName() == Name)
        return U;
    }

    return None;
  }

                                                     
     
                                                                        
                                                         
  Optional<OperandBundleUse> getOperandBundle(uint32_t ID) const {
    assert(countOperandBundlesOfType(ID) < 2 && "Precondition violated!");

    for (unsigned i = 0, e = getNumOperandBundles(); i != e; ++i) {
      OperandBundleUse U = getOperandBundleAt(i);
      if (U.getTagID() == ID)
        return U;
    }

    return None;
  }

                                                                        
                                    
     
                                                                             
                                                                
                                                                          
                                                                   
  void getOperandBundlesAsDefs(SmallVectorImpl<OperandBundleDef> &Defs) const {
    for (unsigned i = 0, e = getNumOperandBundles(); i != e; ++i)
      Defs.emplace_back(getOperandBundleAt(i));
  }

                                                               
     
                                                                              
                     
  OperandBundleUse getOperandBundleForOperand(unsigned OpIdx) const {
    return operandBundleFromBundleOpInfo(getBundleOpInfoForOperand(OpIdx));
  }

                                                                      
                             
  bool hasReadingOperandBundles() const {
                                                                            
                                                                              
                      
    return hasOperandBundles();
  }

                                                                      
                            
  bool hasClobberingOperandBundles() const {
    for (auto &BOI : bundle_op_infos()) {
      if (BOI.Tag->second == LLVMContext::OB_deopt ||
          BOI.Tag->second == LLVMContext::OB_funclet)
        continue;

                                                                        
                          
      return true;
    }

    return false;
  }

                                                                 
                     
  bool bundleOperandHasAttr(unsigned OpIdx,  Attribute::AttrKind A) const {
    auto &BOI = getBundleOpInfoForOperand(OpIdx);
    auto OBU = operandBundleFromBundleOpInfo(BOI);
    return OBU.operandHasAttr(OpIdx - BOI.Begin, A);
  }

                                                                     
                                                                       
                        
  bool hasIdenticalOperandBundleSchema(
      const OperandBundleUser<InstrTy, OpIteratorTy> &Other) const {
    if (getNumOperandBundles() != Other.getNumOperandBundles())
      return false;

    return std::equal(bundle_op_info_begin(), bundle_op_info_end(),
                      Other.bundle_op_info_begin());
  }

                                                                      
                                                     
  bool hasOperandBundlesOtherThan(ArrayRef<uint32_t> IDs) const {
    for (unsigned i = 0, e = getNumOperandBundles(); i != e; ++i) {
      uint32_t ID = getOperandBundleAt(i).getTagID();
      if (!is_contained(IDs, ID))
        return true;
    }
    return false;
  }

protected:
                                                                      
                               
  bool isFnAttrDisallowedByOpBundle(StringRef S) const {
                                                                               
                                                   
    return false;
  }

                                                                      
                               
  bool isFnAttrDisallowedByOpBundle(Attribute::AttrKind A) const {
    switch (A) {
    default:
      return false;

    case Attribute::InaccessibleMemOrArgMemOnly:
      return hasReadingOperandBundles();

    case Attribute::InaccessibleMemOnly:
      return hasReadingOperandBundles();

    case Attribute::ArgMemOnly:
      return hasReadingOperandBundles();

    case Attribute::ReadNone:
      return hasReadingOperandBundles();

    case Attribute::ReadOnly:
      return hasClobberingOperandBundles();
    }

    llvm_unreachable("switch has a default case!");
  }

                                                                       
                              
  struct BundleOpInfo {
                                           
                                              
    StringMapEntry<uint32_t> *Tag;

                                                                    
                      
    uint32_t Begin;

                                                                    
                    
    uint32_t End;

    bool operator==(const BundleOpInfo &Other) const {
      return Tag == Other.Tag && Begin == Other.Begin && End == Other.End;
    }
  };

                                                        
                       
  OperandBundleUse
  operandBundleFromBundleOpInfo(const BundleOpInfo &BOI) const {
    auto op_begin = static_cast<const InstrTy *>(this)->op_begin();
    ArrayRef<Use> Inputs(op_begin + BOI.Begin, op_begin + BOI.End);
    return OperandBundleUse(BOI.Tag, Inputs);
  }

  using bundle_op_iterator = BundleOpInfo *;
  using const_bundle_op_iterator = const BundleOpInfo *;

                                                                       
                                  
  bundle_op_iterator bundle_op_info_begin() {
    if (!static_cast<InstrTy *>(this)->hasDescriptor())
      return nullptr;

    uint8_t *BytesBegin = static_cast<InstrTy *>(this)->getDescriptor().begin();
    return reinterpret_cast<bundle_op_iterator>(BytesBegin);
  }

                                                                       
                                  
  const_bundle_op_iterator bundle_op_info_begin() const {
    auto *NonConstThis =
        const_cast<OperandBundleUser<InstrTy, OpIteratorTy> *>(this);
    return NonConstThis->bundle_op_info_begin();
  }

                                                                     
                                  
  bundle_op_iterator bundle_op_info_end() {
    if (!static_cast<InstrTy *>(this)->hasDescriptor())
      return nullptr;

    uint8_t *BytesEnd = static_cast<InstrTy *>(this)->getDescriptor().end();
    return reinterpret_cast<bundle_op_iterator>(BytesEnd);
  }

                                                                     
                                  
  const_bundle_op_iterator bundle_op_info_end() const {
    auto *NonConstThis =
        const_cast<OperandBundleUser<InstrTy, OpIteratorTy> *>(this);
    return NonConstThis->bundle_op_info_end();
  }

                                                                        
  iterator_range<bundle_op_iterator> bundle_op_infos() {
    return make_range(bundle_op_info_begin(), bundle_op_info_end());
  }

                                                                        
  iterator_range<const_bundle_op_iterator> bundle_op_infos() const {
    return make_range(bundle_op_info_begin(), bundle_op_info_end());
  }

                                                                     
                                                                             
                              
     
                                                                         
                                                   
  OpIteratorTy populateBundleOperandInfos(ArrayRef<OperandBundleDef> Bundles,
                                          const unsigned BeginIndex) {
    auto It = static_cast<InstrTy *>(this)->op_begin() + BeginIndex;
    for (auto &B : Bundles)
      It = std::copy(B.input_begin(), B.input_end(), It);

    auto *ContextImpl = static_cast<InstrTy *>(this)->getContext().pImpl;
    auto BI = Bundles.begin();
    unsigned CurrentIndex = BeginIndex;

    for (auto &BOI : bundle_op_infos()) {
      assert(BI != Bundles.end() && "Incorrect allocation?");

      BOI.Tag = ContextImpl->getOrInsertBundleTag(BI->getTag());
      BOI.Begin = CurrentIndex;
      BOI.End = CurrentIndex + BI->input_size();
      CurrentIndex = BOI.End;
      BI++;
    }

    assert(BI == Bundles.end() && "Incorrect allocation?");

    return It;
  }

                                                             
     
                                                                              
                     
  const BundleOpInfo &getBundleOpInfoForOperand(unsigned OpIdx) const {
    for (auto &BOI : bundle_op_infos())
      if (BOI.Begin <= OpIdx && OpIdx < BOI.End)
        return BOI;

    llvm_unreachable("Did not find operand bundle for operand!");
  }

                                                           
  static unsigned CountBundleInputs(ArrayRef<OperandBundleDef> Bundles) {
    unsigned Total = 0;
    for (auto &B : Bundles)
      Total += B.input_size();
    return Total;
  }
};

}                      
#pragma GCC diagnostic pop
#endif                        
