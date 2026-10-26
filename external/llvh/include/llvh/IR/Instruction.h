//===-- llvm/Instruction.h - Instruction class definition -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the Instruction class, which is the
// base class for all of the LLVM instructions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_INSTRUCTION_H
#define LLVM_IR_INSTRUCTION_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/IR/DebugLoc.h"
#include "llvh/IR/SymbolTableListTraits.h"
#include "llvh/IR/User.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <utility>

namespace llvh {

class BasicBlock;
class FastMathFlags;
class MDNode;
class Module;
struct AAMDNodes;

template <> struct ilist_alloc_traits<Instruction> {
  static inline void deleteNode(Instruction *V);
};

class Instruction : public User,
                    public ilist_node_with_parent<Instruction, BasicBlock> {
  BasicBlock *Parent;
  DebugLoc DbgLoc;                                                 

  enum {
                                                                              
                                                            
    HasMetadataBit = 1 << 15
  };

protected:
  ~Instruction();                                                      

public:
  Instruction(const Instruction &) = delete;
  Instruction &operator=(const Instruction &) = delete;

                                                                             
                                             
  Instruction       *user_back()       { return cast<Instruction>(*user_begin());}
  const Instruction *user_back() const { return cast<Instruction>(*user_begin());}

  inline const BasicBlock *getParent() const { return Parent; }
  inline       BasicBlock *getParent()       { return Parent; }

                                                                       
                                                        
     
                                                                         
                                                                        
  const Module *getModule() const;
  Module *getModule() {
    return const_cast<Module *>(
                           static_cast<const Instruction *>(this)->getModule());
  }

                                                      
     
                                                                       
                                         
  const Function *getFunction() const;
  Function *getFunction() {
    return const_cast<Function *>(
                         static_cast<const Instruction *>(this)->getFunction());
  }

                                                                              
                
  void removeFromParent();

                                                                                
     
                                                                       
  SymbolTableList<Instruction>::iterator eraseFromParent();

                                                                          
                                
  void insertBefore(Instruction *InsertPos);

                                                                             
                            
  void insertAfter(Instruction *InsertPos);

                                                                             
                                                                  
  void moveBefore(Instruction *MovePos);

                                                          
     
                                         
  void moveBefore(BasicBlock &BB, SymbolTableList<Instruction>::iterator I);

                                                                             
                                                                 
  void moveAfter(Instruction *MovePos);

                                                                                
                             
                                                                                

                                                                 
  unsigned getOpcode() const { return getValueID() - InstructionVal; }

  const char *getOpcodeName() const { return getOpcodeName(getOpcode()); }
  bool isTerminator() const { return isTerminator(getOpcode()); }
  bool isBinaryOp() const { return isBinaryOp(getOpcode()); }
  bool isIntDivRem() const { return isIntDivRem(getOpcode()); }
  bool isShift() { return isShift(getOpcode()); }
  bool isCast() const { return isCast(getOpcode()); }
  bool isFuncletPad() const { return isFuncletPad(getOpcode()); }
  bool isExceptionalTerminator() const {
    return isExceptionalTerminator(getOpcode());
  }

  static const char* getOpcodeName(unsigned OpCode);

  static inline bool isTerminator(unsigned OpCode) {
    return OpCode >= TermOpsBegin && OpCode < TermOpsEnd;
  }

  static inline bool isBinaryOp(unsigned Opcode) {
    return Opcode >= BinaryOpsBegin && Opcode < BinaryOpsEnd;
  }

  static inline bool isIntDivRem(unsigned Opcode) {
    return Opcode == UDiv || Opcode == SDiv || Opcode == URem || Opcode == SRem;
  }

                                                               
  static inline bool isShift(unsigned Opcode) {
    return Opcode >= Shl && Opcode <= AShr;
  }

                                                                           
  inline bool isLogicalShift() const {
    return getOpcode() == Shl || getOpcode() == LShr;
  }

                                                       
  inline bool isArithmeticShift() const {
    return getOpcode() == AShr;
  }

                                            
  static inline bool isBitwiseLogicOp(unsigned Opcode) {
    return Opcode == And || Opcode == Or || Opcode == Xor;
  }

                                        
  inline bool isBitwiseLogicOp() const {
    return isBitwiseLogicOp(getOpcode());
  }

                                                                  
  static inline bool isCast(unsigned OpCode) {
    return OpCode >= CastOpsBegin && OpCode < CastOpsEnd;
  }

                                                                        
  static inline bool isFuncletPad(unsigned OpCode) {
    return OpCode >= FuncletPadOpsBegin && OpCode < FuncletPadOpsEnd;
  }

                                                                               
  static inline bool isExceptionalTerminator(unsigned OpCode) {
    switch (OpCode) {
    case Instruction::CatchSwitch:
    case Instruction::CatchRet:
    case Instruction::CleanupRet:
    case Instruction::Invoke:
    case Instruction::Resume:
      return true;
    default:
      return false;
    }
  }

                                                                                
                           
                                                                                

                                                                      
  bool hasMetadata() const { return DbgLoc || hasMetadataHashEntry(); }

                                                                              
                     
  bool hasMetadataOtherThanDebugLoc() const {
    return hasMetadataHashEntry();
  }

                                                                  
                                                    
  MDNode *getMetadata(unsigned KindID) const {
    if (!hasMetadata()) return nullptr;
    return getMetadataImpl(KindID);
  }

                                                                  
                                                    
  MDNode *getMetadata(StringRef Kind) const {
    if (!hasMetadata()) return nullptr;
    return getMetadataImpl(Kind);
  }

                                                                              
                                                                            
                                                 
  void
  getAllMetadata(SmallVectorImpl<std::pair<unsigned, MDNode *>> &MDs) const {
    if (hasMetadata())
      getAllMetadataImpl(MDs);
  }

                                                                                
                     
  void getAllMetadataOtherThanDebugLoc(
      SmallVectorImpl<std::pair<unsigned, MDNode *>> &MDs) const {
    if (hasMetadataOtherThanDebugLoc())
      getAllMetadataOtherThanDebugLocImpl(MDs);
  }

                                                                           
                                                                                
                                                    
  void getAAMetadata(AAMDNodes &N, bool Merge = false) const;

                                                                                
                                                                             
  void setMetadata(unsigned KindID, MDNode *Node);
  void setMetadata(StringRef Kind, MDNode *Node);

                                                                             
                                                                          
                                          
  void copyMetadata(const Instruction &SrcInst,
                    ArrayRef<unsigned> WL = ArrayRef<unsigned>());

                                                                             
                                                                       
               
  void swapProfMetadata();

                                                           
        
                                                                           
                                             
  void dropUnknownNonDebugMetadata(ArrayRef<unsigned> KnownIDs);
  void dropUnknownNonDebugMetadata() {
    return dropUnknownNonDebugMetadata(None);
  }
  void dropUnknownNonDebugMetadata(unsigned ID1) {
    return dropUnknownNonDebugMetadata(makeArrayRef(ID1));
  }
  void dropUnknownNonDebugMetadata(unsigned ID1, unsigned ID2) {
    unsigned IDs[] = {ID1, ID2};
    return dropUnknownNonDebugMetadata(IDs);
  }
        

                                                                         
  void setAAMetadata(const AAMDNodes &N);

                                                                       
                                                             
                                                                 
  bool extractProfMetadata(uint64_t &TrueVal, uint64_t &FalseVal) const;

                                                   
                                                                   
                                             
  bool extractProfTotalWeight(uint64_t &TotalVal) const;

                                                                   
  void updateProfWeight(uint64_t S, uint64_t T);

                                                            
  void setProfWeight(uint64_t W);

                                                              
  void setDebugLoc(DebugLoc Loc) { DbgLoc = std::move(Loc); }

                                                            
  const DebugLoc &getDebugLoc() const { return DbgLoc; }

                                                                              
                                                                              
  void setHasNoUnsignedWrap(bool b = true);

                                                                              
                                                                              
  void setHasNoSignedWrap(bool b = true);

                                                                                
                                                                              
  void setIsExact(bool b = true);

                                                         
  bool hasNoUnsignedWrap() const;

                                                       
  bool hasNoSignedWrap() const;

                                                                               
                               
  void dropPoisonGeneratingFlags();

                                              
  bool isExact() const;

                                                                            
                                                                            
                
  void setFast(bool B);

                                                                            
                                                                               
                
  void setHasAllowReassoc(bool B);

                                                                         
                                                                            
                
  void setHasNoNaNs(bool B);

                                                                         
                                                                            
                
  void setHasNoInfs(bool B);

                                                                              
                                                                               
                
  void setHasNoSignedZeros(bool B);

                                                                               
                                                                               
                
  void setHasAllowReciprocal(bool B);

                                                                           
                                                                              
                               
  void setHasApproxFunc(bool B);

                                                                       
                                                                            
                                                  
  void setFastMathFlags(FastMathFlags FMF);

                                                                             
                                                                            
                                                  
  void copyFastMathFlags(FastMathFlags FMF);

                                                    
  bool isFast() const;

                                                            
  bool hasAllowReassoc() const;

                                                
  bool hasNoNaNs() const;

                                                
  bool hasNoInfs() const;

                                                        
  bool hasNoSignedZeros() const;

                                                         
  bool hasAllowReciprocal() const;

                                                       
  bool hasAllowContract() const;

                                                                   
  bool hasApproxFunc() const;

                                                                                
                                                                              
                  
  FastMathFlags getFastMathFlags() const;

                              
  void copyFastMathFlags(const Instruction *I);

                                                                             
                                                
  void copyIRFlags(const Value *V, bool IncludeWrapFlags = true);

                                                                            
                             
  void andIRFlags(const Value *V);

                                                                     
                                                                            
                                                                            
                                                                         
                                                              
                                                                          
                                                                   
                                                                       
                                                               
                                                                       
                                                                      
                                                                          
                      
  void applyMergedLocation(const DILocation *LocA, const DILocation *LocB);

private:
                                                                       
  bool hasMetadataHashEntry() const {
    return (getSubclassDataFromValue() & HasMetadataBit) != 0;
  }

                                               
  MDNode *getMetadataImpl(unsigned KindID) const;
  MDNode *getMetadataImpl(StringRef Kind) const;
  void
  getAllMetadataImpl(SmallVectorImpl<std::pair<unsigned, MDNode *>> &) const;
  void getAllMetadataOtherThanDebugLocImpl(
      SmallVectorImpl<std::pair<unsigned, MDNode *>> &) const;
                                                               
  void clearMetadataHashEntries();

public:
                                                                                
                                   
                                                                                

                                                    
     
                                                                       
     
                                                                        
     
  bool isAssociative() const LLVM_READONLY;
  static bool isAssociative(unsigned Opcode) {
    return Opcode == And || Opcode == Or || Opcode == Xor ||
           Opcode == Add || Opcode == Mul;
  }

                                                    
     
                                                            
     
                                                                              
                          
     
  bool isCommutative() const { return isCommutative(getOpcode()); }
  static bool isCommutative(unsigned Opcode) {
    switch (Opcode) {
    case Add: case FAdd:
    case Mul: case FMul:
    case And: case Or: case Xor:
      return true;
    default:
      return false;
  }
  }

                                                   
     
                                                   
     
                                                       
     
  bool isIdempotent() const { return isIdempotent(getOpcode()); }
  static bool isIdempotent(unsigned Opcode) {
    return Opcode == And || Opcode == Or;
  }

                                                  
     
                                                    
     
                                                                            
                                                    
     
                                             
     
  bool isNilpotent() const { return isNilpotent(getOpcode()); }
  static bool isNilpotent(unsigned Opcode) {
    return Opcode == Xor;
  }

                                                        
  bool mayWriteToMemory() const;

                                                      
  bool mayReadFromMemory() const;

                                                               
  bool mayReadOrWriteMemory() const {
    return mayReadFromMemory() || mayWriteToMemory();
  }

                                                                           
             
  bool isAtomic() const;

                                                               
  bool hasAtomicLoad() const;

                                                              
  bool hasAtomicStore() const;

                                                             
  bool mayThrow() const;

                                                                              
                                                                        
  bool isFenceLike() const {
    switch (getOpcode()) {
    default:
      return false;
                                                                             
                                                      
    case Instruction::Fence:
    case Instruction::CatchPad:
    case Instruction::CatchRet:
    case Instruction::Call:
    case Instruction::Invoke:
      return true;
    }
  }

                                                           
     
                                                                     
                                                                           
                                                                            
                                                                    
  bool mayHaveSideEffects() const { return mayWriteToMemory() || mayThrow(); }

                                                                            
     
                                                                             
                                                                             
                                                                               
                        
  bool isSafeToRemove() const;

                                                              
  bool isEHPad() const {
    switch (getOpcode()) {
    case Instruction::CatchSwitch:
    case Instruction::CatchPad:
    case Instruction::CleanupPad:
    case Instruction::LandingPad:
      return true;
    default:
      return false;
    }
  }

                                                                          
                                                                
  const Instruction *getNextNonDebugInstruction() const;
  Instruction *getNextNonDebugInstruction() {
    return const_cast<Instruction *>(
        static_cast<const Instruction *>(this)->getNextNonDebugInstruction());
  }

                                                                              
                    
                                       
                                     
     
  Instruction *clone() const;

                                                                          
                                                                               
                                    
  bool isIdenticalTo(const Instruction *I) const;

                                                            
                                                                              
                                        
  bool isIdenticalToWhenDefined(const Instruction *I) const;

                                                                             
                                                    
  enum OperationEquivalenceFlags {
                                                            
    CompareIgnoringAlignment = 1<<0,
                                                                       
                      
    CompareUsingScalarTypes = 1<<1
  };

                                                                             
                                                                              
                                                                                
                                                                              
                   
                                                                         
                      
                                                                    
  bool isSameOperationAs(const Instruction *I, unsigned flags = 0) const;

                                                                                
                                                                               
                                                      
  bool isUsedOutsideOfBlock(const BasicBlock *BB) const;

                                                                                
                           
  unsigned getNumSuccessors() const;

                                                                            
  BasicBlock *getSuccessor(unsigned Idx) const;

                                                                         
                                       
  void setSuccessor(unsigned Idx, BasicBlock *BB);

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() >= Value::InstructionVal;
  }

                                                                          
                           
    
  enum TermOps {                                      
#define  FIRST_TERM_INST(N)             TermOpsBegin = N,
#define HANDLE_TERM_INST(N, OPC, CLASS) OPC = N,
#define   LAST_TERM_INST(N)             TermOpsEnd = N+1
#include "llvh/IR/Instruction.def"
  };

  enum BinaryOps {
#define  FIRST_BINARY_INST(N)             BinaryOpsBegin = N,
#define HANDLE_BINARY_INST(N, OPC, CLASS) OPC = N,
#define   LAST_BINARY_INST(N)             BinaryOpsEnd = N+1
#include "llvh/IR/Instruction.def"
  };

  enum MemoryOps {
#define  FIRST_MEMORY_INST(N)             MemoryOpsBegin = N,
#define HANDLE_MEMORY_INST(N, OPC, CLASS) OPC = N,
#define   LAST_MEMORY_INST(N)             MemoryOpsEnd = N+1
#include "llvh/IR/Instruction.def"
  };

  enum CastOps {
#define  FIRST_CAST_INST(N)             CastOpsBegin = N,
#define HANDLE_CAST_INST(N, OPC, CLASS) OPC = N,
#define   LAST_CAST_INST(N)             CastOpsEnd = N+1
#include "llvh/IR/Instruction.def"
  };

  enum FuncletPadOps {
#define  FIRST_FUNCLETPAD_INST(N)             FuncletPadOpsBegin = N,
#define HANDLE_FUNCLETPAD_INST(N, OPC, CLASS) OPC = N,
#define   LAST_FUNCLETPAD_INST(N)             FuncletPadOpsEnd = N+1
#include "llvh/IR/Instruction.def"
  };

  enum OtherOps {
#define  FIRST_OTHER_INST(N)             OtherOpsBegin = N,
#define HANDLE_OTHER_INST(N, OPC, CLASS) OPC = N,
#define   LAST_OTHER_INST(N)             OtherOpsEnd = N+1
#include "llvh/IR/Instruction.def"
  };

private:
  friend class SymbolTableListTraits<Instruction>;

                                                                                
                                           
  void setValueSubclassData(unsigned short D) {
    Value::setValueSubclassData(D);
  }

  unsigned short getSubclassDataFromValue() const {
    return Value::getSubclassDataFromValue();
  }

  void setHasMetadataHashEntry(bool V) {
    setValueSubclassData((getSubclassDataFromValue() & ~HasMetadataBit) |
                         (V ? HasMetadataBit : 0));
  }

  void setParent(BasicBlock *P);

protected:
                                                                     
                                                          

                                               
  void setInstructionSubclassData(unsigned short D) {
    assert((D & HasMetadataBit) == 0 && "Out of range value put into field");
    setValueSubclassData((getSubclassDataFromValue() & HasMetadataBit) | D);
  }

  unsigned getSubclassDataFromInstruction() const {
    return getSubclassDataFromValue() & ~HasMetadataBit;
  }

  Instruction(Type *Ty, unsigned iType, Use *Ops, unsigned NumOps,
              Instruction *InsertBefore = nullptr);
  Instruction(Type *Ty, unsigned iType, Use *Ops, unsigned NumOps,
              BasicBlock *InsertAtEnd);

private:
                                        
  Instruction *cloneImpl() const;
};

inline void ilist_alloc_traits<Instruction>::deleteNode(Instruction *V) {
  V->deleteValue();
}

}                      

#endif                         
