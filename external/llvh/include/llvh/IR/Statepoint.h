//===- llvm/IR/Statepoint.h - gc.statepoint utilities -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains utility functions and a wrapper class analogous to
// CallSite for accessing the fields of gc.statepoint, gc.relocate,
// gc.result intrinsics; and some general utilities helpful when dealing with
// gc.statepoint.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_STATEPOINT_H
#define LLVM_IR_STATEPOINT_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/BasicBlock.h"
#include "llvh/IR/CallSite.h"
#include "llvh/IR/Constants.h"
#include "llvh/IR/Function.h"
#include "llvh/IR/Instruction.h"
#include "llvh/IR/Instructions.h"
#include "llvh/IR/IntrinsicInst.h"
#include "llvh/IR/Intrinsics.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/MathExtras.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace llvh {

                                                                          
                                      
enum class StatepointFlags {
  None = 0,
  GCTransition = 1,                                                         
                                                                    
                                                                           
                                                                                
                                                                              
                                                                             
                                                                          
                                                                    
  DeoptLiveIn = 2,

  MaskAll = 3                                              
};

class GCRelocateInst;
class GCResultInst;

bool isStatepoint(ImmutableCallSite CS);
bool isStatepoint(const Value *V);
bool isStatepoint(const Value &V);

bool isGCRelocate(ImmutableCallSite CS);
bool isGCRelocate(const Value *V);

bool isGCResult(ImmutableCallSite CS);
bool isGCResult(const Value *V);

                                                               
                                                                
                                                                   
                                                                
                                                                    
                          
template <typename FunTy, typename InstructionTy, typename ValueTy,
          typename CallSiteTy>
class StatepointBase {
  CallSiteTy StatepointCS;

protected:
  explicit StatepointBase(InstructionTy *I) {
    if (isStatepoint(I)) {
      StatepointCS = CallSiteTy(I);
      assert(StatepointCS && "isStatepoint implies CallSite");
    }
  }

  explicit StatepointBase(CallSiteTy CS) {
    if (isStatepoint(CS))
      StatepointCS = CS;
  }

public:
  using arg_iterator = typename CallSiteTy::arg_iterator;

  enum {
    IDPos = 0,
    NumPatchBytesPos = 1,
    CalledFunctionPos = 2,
    NumCallArgsPos = 3,
    FlagsPos = 4,
    CallArgsBeginPos = 5,
  };

  void *operator new(size_t, unsigned) = delete;
  void *operator new(size_t s) = delete;

  explicit operator bool() const {
                                                                 
    return (bool)StatepointCS;
  }

                                     
  CallSiteTy getCallSite() const {
    assert(*this && "check validity first!");
    return StatepointCS;
  }

  uint64_t getFlags() const {
    return cast<ConstantInt>(getCallSite().getArgument(FlagsPos))
        ->getZExtValue();
  }

                                                    
  uint64_t getID() const {
    const Value *IDVal = getCallSite().getArgument(IDPos);
    return cast<ConstantInt>(IDVal)->getZExtValue();
  }

                                                                           
  uint32_t getNumPatchBytes() const {
    const Value *NumPatchBytesVal = getCallSite().getArgument(NumPatchBytesPos);
    uint64_t NumPatchBytes =
      cast<ConstantInt>(NumPatchBytesVal)->getZExtValue();
    assert(isInt<32>(NumPatchBytes) && "should fit in 32 bits!");
    return NumPatchBytes;
  }

                                                        
  ValueTy *getCalledValue() const {
    return getCallSite().getArgument(CalledFunctionPos);
  }

  InstructionTy *getInstruction() const {
    return getCallSite().getInstruction();
  }

                                                                          
                                             
  FunTy *getCalledFunction() const {
    return dyn_cast<Function>(getCalledValue());
  }

                                                     
  FunTy *getCaller() const { return getCallSite().getCaller(); }

                                                
  bool doesNotThrow() const {
    Function *F = getCalledFunction();
    return getCallSite().doesNotThrow() || (F ? F->doesNotThrow() : false);
  }

                                                                      
                 
  Type *getActualReturnType() const {
    auto *FTy = cast<FunctionType>(
        cast<PointerType>(getCalledValue()->getType())->getElementType());
    return FTy->getReturnType();
  }

                                                            
  int getNumCallArgs() const {
    const Value *NumCallArgsVal = getCallSite().getArgument(NumCallArgsPos);
    return cast<ConstantInt>(NumCallArgsVal)->getZExtValue();
  }

  size_t arg_size() const { return getNumCallArgs(); }
  typename CallSiteTy::arg_iterator arg_begin() const {
    assert(CallArgsBeginPos <= (int)getCallSite().arg_size());
    return getCallSite().arg_begin() + CallArgsBeginPos;
  }
  typename CallSiteTy::arg_iterator arg_end() const {
    auto I = arg_begin() + arg_size();
    assert((getCallSite().arg_end() - I) >= 0);
    return I;
  }

  ValueTy *getArgument(unsigned Index) {
    assert(Index < arg_size() && "out of bounds!");
    return *(arg_begin() + Index);
  }

                                      
  iterator_range<arg_iterator> call_args() const {
    return make_range(arg_begin(), arg_end());
  }

                                                                    
  bool paramHasAttr(unsigned i, Attribute::AttrKind A) const {
    Function *F = getCalledFunction();
    return getCallSite().paramHasAttr(i + CallArgsBeginPos, A) ||
          (F ? F->getAttributes().hasAttribute(i, A) : false);
  }

                                   
  int getNumTotalGCTransitionArgs() const {
    const Value *NumGCTransitionArgs = *arg_end();
    return cast<ConstantInt>(NumGCTransitionArgs)->getZExtValue();
  }
  typename CallSiteTy::arg_iterator gc_transition_args_begin() const {
    auto I = arg_end() + 1;
    assert((getCallSite().arg_end() - I) >= 0);
    return I;
  }
  typename CallSiteTy::arg_iterator gc_transition_args_end() const {
    auto I = gc_transition_args_begin() + getNumTotalGCTransitionArgs();
    assert((getCallSite().arg_end() - I) >= 0);
    return I;
  }

                                               
  iterator_range<arg_iterator> gc_transition_args() const {
    return make_range(gc_transition_args_begin(), gc_transition_args_end());
  }

                                                             
                             
  int getNumTotalVMSArgs() const {
    const Value *NumVMSArgs = *gc_transition_args_end();
    return cast<ConstantInt>(NumVMSArgs)->getZExtValue();
  }

  typename CallSiteTy::arg_iterator deopt_begin() const {
    auto I = gc_transition_args_end() + 1;
    assert((getCallSite().arg_end() - I) >= 0);
    return I;
  }
  typename CallSiteTy::arg_iterator deopt_end() const {
    auto I = deopt_begin() + getNumTotalVMSArgs();
    assert((getCallSite().arg_end() - I) >= 0);
    return I;
  }

                                          
  iterator_range<arg_iterator> deopt_operands() const {
    return make_range(deopt_begin(), deopt_end());
  }

  typename CallSiteTy::arg_iterator gc_args_begin() const {
    return deopt_end();
  }
  typename CallSiteTy::arg_iterator gc_args_end() const {
    return getCallSite().arg_end();
  }

  unsigned gcArgsStartIdx() const {
    return gc_args_begin() - getInstruction()->op_begin();
  }

                                    
  iterator_range<arg_iterator> gc_args() const {
    return make_range(gc_args_begin(), gc_args_end());
  }

                                                            
                                                                     
                                                                   
                     
  std::vector<const GCRelocateInst *> getRelocates() const;

                                                                          
                                                                                
                                
  const GCResultInst *getGCResult() const {
    for (auto *U : getInstruction()->users())
      if (auto *GRI = dyn_cast<GCResultInst>(U))
        return GRI;
    return nullptr;
  }

#ifndef NDEBUG
                                                                        
                                                                       
                                    
  void verify() {
    assert(getNumCallArgs() >= 0 &&
           "number of arguments to actually callee can't be negative");

                                                                  
    (void)arg_begin();
    (void)arg_end();
    (void)gc_transition_args_begin();
    (void)gc_transition_args_end();
    (void)deopt_begin();
    (void)deopt_end();
    (void)gc_args_begin();
    (void)gc_args_end();
  }
#endif
};

                                                            
                       
class ImmutableStatepoint
    : public StatepointBase<const Function, const Instruction, const Value,
                            ImmutableCallSite> {
  using Base =
      StatepointBase<const Function, const Instruction, const Value,
                     ImmutableCallSite>;

public:
  explicit ImmutableStatepoint(const Instruction *I) : Base(I) {}
  explicit ImmutableStatepoint(ImmutableCallSite CS) : Base(CS) {}
};

                                                             
                       
class Statepoint
    : public StatepointBase<Function, Instruction, Value, CallSite> {
  using Base = StatepointBase<Function, Instruction, Value, CallSite>;

public:
  explicit Statepoint(Instruction *I) : Base(I) {}
  explicit Statepoint(CallSite CS) : Base(CS) {}
};

                                                                          
                                                                            
class GCProjectionInst : public IntrinsicInst {
public:
  static bool classof(const IntrinsicInst *I) {
    return I->getIntrinsicID() == Intrinsic::experimental_gc_relocate ||
      I->getIntrinsicID() == Intrinsic::experimental_gc_result;
  }

  static bool classof(const Value *V) {
    return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
  }

                                                                    
                                                              
  bool isTiedToInvoke() const {
    const Value *Token = getArgOperand(0);

    return isa<LandingPadInst>(Token) || isa<InvokeInst>(Token);
  }

                                                               
  const Instruction *getStatepoint() const {
    const Value *Token = getArgOperand(0);

                                                                           
                                           
    if (!isa<LandingPadInst>(Token)) {
      assert(isStatepoint(Token));
      return cast<Instruction>(Token);
    }

                                                                   
    const BasicBlock *InvokeBB =
        cast<Instruction>(Token)->getParent()->getUniquePredecessor();

    assert(InvokeBB && "safepoints should have unique landingpads");
    assert(InvokeBB->getTerminator() &&
           "safepoint block should be well formed");
    assert(isStatepoint(InvokeBB->getTerminator()));

    return InvokeBB->getTerminator();
  }
};

                                                  
class GCRelocateInst : public GCProjectionInst {
public:
  static bool classof(const IntrinsicInst *I) {
    return I->getIntrinsicID() == Intrinsic::experimental_gc_relocate;
  }

  static bool classof(const Value *V) {
    return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
  }

                                                             
                                                          
                                            
  unsigned getBasePtrIndex() const {
    return cast<ConstantInt>(getArgOperand(1))->getZExtValue();
  }

                                                                   
                                                                       
  unsigned getDerivedPtrIndex() const {
    return cast<ConstantInt>(getArgOperand(2))->getZExtValue();
  }

  Value *getBasePtr() const {
    ImmutableCallSite CS(getStatepoint());
    return *(CS.arg_begin() + getBasePtrIndex());
  }

  Value *getDerivedPtr() const {
    ImmutableCallSite CS(getStatepoint());
    return *(CS.arg_begin() + getDerivedPtrIndex());
  }
};

                                                
class GCResultInst : public GCProjectionInst {
public:
  static bool classof(const IntrinsicInst *I) {
    return I->getIntrinsicID() == Intrinsic::experimental_gc_result;
  }

  static bool classof(const Value *V) {
    return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
  }
};

template <typename FunTy, typename InstructionTy, typename ValueTy,
          typename CallSiteTy>
std::vector<const GCRelocateInst *>
StatepointBase<FunTy, InstructionTy, ValueTy, CallSiteTy>::getRelocates()
    const {

  std::vector<const GCRelocateInst *> Result;

  CallSiteTy StatepointCS = getCallSite();

                                                                         
                                                                             
                                   
  for (const User *U : getInstruction()->users())
    if (auto *Relocate = dyn_cast<GCRelocateInst>(U))
      Result.push_back(Relocate);

  if (!StatepointCS.isInvoke())
    return Result;

                                                                                
  LandingPadInst *LandingPad =
      cast<InvokeInst>(getInstruction())->getLandingPadInst();

                                                                  
  for (const User *LandingPadUser : LandingPad->users()) {
    if (auto *Relocate = dyn_cast<GCRelocateInst>(LandingPadUser))
      Result.push_back(Relocate);
  }
  return Result;
}

                                                                     
                                                                              
                                                                               
                                                                             
struct StatepointDirectives {
  Optional<uint32_t> NumPatchBytes;
  Optional<uint64_t> StatepointID;

  static const uint64_t DefaultStatepointID = 0xABCDEF00;
  static const uint64_t DeoptBundleStatepointID = 0xABCDEF0F;
};

                                                                              
       
StatepointDirectives parseStatepointDirectivesFromAttrs(AttributeList AS);

                                                                      
              
bool isStatepointDirectiveAttr(Attribute Attr);

}                      

#endif                        
