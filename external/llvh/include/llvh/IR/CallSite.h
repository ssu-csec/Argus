//===- CallSite.h - Abstract Call & Invoke instrs ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the CallSite class, which is a handy wrapper for code that
// wants to treat Call and Invoke instructions in a generic way. When in non-
// mutation context (e.g. an analysis) ImmutableCallSite should be used.
// Finally, when some degree of customization is necessary between these two
// extremes, CallSiteBase<> can be supplied with fine-tuned parameters.
//
// NOTE: These classes are supposed to have "value semantics". So they should be
// passed by value, not by reference; they should not be "new"ed or "delete"d.
// They are efficiently copyable, assignable and constructable, with cost
// equivalent to copying a pointer (notice that they have only a single data
// member). The internal representation carries a flag which indicates which of
// the two variants is enclosed. This allows for cheaper checks when various
// accessors of CallSite are employed.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_CALLSITE_H
#define LLVM_IR_CALLSITE_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/PointerIntPair.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/CallingConv.h"
#include "llvh/IR/Function.h"
#include "llvh/IR/InstrTypes.h"
#include "llvh/IR/Instruction.h"
#include "llvh/IR/Instructions.h"
#include "llvh/IR/Use.h"
#include "llvh/IR/User.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include <cassert>
#include <cstdint>
#include <iterator>

namespace llvh {

namespace Intrinsic {
enum ID : unsigned;
}

template <typename FunTy = const Function,
          typename BBTy = const BasicBlock,
          typename ValTy = const Value,
          typename UserTy = const User,
          typename UseTy = const Use,
          typename InstrTy = const Instruction,
          typename CallTy = const CallInst,
          typename InvokeTy = const InvokeInst,
          typename IterTy = User::const_op_iterator>
class CallSiteBase {
protected:
  PointerIntPair<InstrTy*, 1, bool> I;

  CallSiteBase() = default;
  CallSiteBase(CallTy *CI) : I(CI, true) { assert(CI); }
  CallSiteBase(InvokeTy *II) : I(II, false) { assert(II); }
  explicit CallSiteBase(ValTy *II) { *this = get(II); }

private:
                                                                             
                                                                               
                                                                             
  static CallSiteBase get(ValTy *V) {
    if (InstrTy *II = dyn_cast<InstrTy>(V)) {
      if (II->getOpcode() == Instruction::Call)
        return CallSiteBase(static_cast<CallTy*>(II));
      else if (II->getOpcode() == Instruction::Invoke)
        return CallSiteBase(static_cast<InvokeTy*>(II));
    }
    return CallSiteBase();
  }

public:
                                                                              
                                                                                
  bool isCall() const { return I.getInt(); }

                                              
  bool isInvoke() const { return getInstruction() && !I.getInt(); }

  InstrTy *getInstruction() const { return I.getPointer(); }
  InstrTy *operator->() const { return I.getPointer(); }
  explicit operator bool() const { return I.getPointer(); }

                                                   
  BBTy* getParent() const { return getInstruction()->getParent(); }

                                                          
  ValTy *getCalledValue() const {
    assert(getInstruction() && "Not a call or invoke instruction!");
    return *getCallee();
  }

                                                                          
                                             
  FunTy *getCalledFunction() const {
    return dyn_cast<FunTy>(getCalledValue());
  }

                                                      
  bool isIndirectCall() const {
    const Value *V = getCalledValue();
    if (!V)
      return false;
    if (isa<FunTy>(V) || isa<Constant>(V))
      return false;
    if (const CallInst *CI = dyn_cast<CallInst>(getInstruction())) {
      if (CI->isInlineAsm())
        return false;
    }
    return true;
  }

                                            
  void setCalledFunction(Value *V) {
    assert(getInstruction() && "Not a call or invoke instruction!");
    *getCallee() = V;
  }

                                                                       
                                                                  
                                                         
  Intrinsic::ID getIntrinsicID() const {
    if (auto *F = getCalledFunction())
      return F->getIntrinsicID();
                                                                     
                                                         
    return static_cast<Intrinsic::ID>(0);
  }

                                                                               
  bool isCallee(Value::const_user_iterator UI) const {
    return isCallee(&UI.getUse());
  }

                                                             
  bool isCallee(const Use *U) const { return getCallee() == U; }

                                                                          
  bool isArgOperand(Value::const_user_iterator UI) const {
    return isArgOperand(&UI.getUse());
  }

                                                                     
  bool isArgOperand(const Use *U) const {
    assert(getInstruction() == U->getUser());
    return arg_begin() <= U && U < arg_end();
  }

                                                                       
  bool isBundleOperand(Value::const_user_iterator UI) const {
    return isBundleOperand(&UI.getUse());
  }

                                                                  
  bool isBundleOperand(const Use *U) const {
    assert(getInstruction() == U->getUser());
    if (!hasOperandBundles())
      return false;
    unsigned OperandNo = U - (*this)->op_begin();
    return getBundleOperandsStartIndex() <= OperandNo &&
           OperandNo < getBundleOperandsEndIndex();
  }

                                                                     
  bool isDataOperand(Value::const_user_iterator UI) const {
    return isDataOperand(&UI.getUse());
  }

                                                                
  bool isDataOperand(const Use *U) const {
    return data_operands_begin() <= U && U < data_operands_end();
  }

  ValTy *getArgument(unsigned ArgNo) const {
    assert(arg_begin() + ArgNo < arg_end() && "Argument # out of range!");
    return *(arg_begin() + ArgNo);
  }

  void setArgument(unsigned ArgNo, Value* newVal) {
    assert(getInstruction() && "Not a call or invoke instruction!");
    assert(arg_begin() + ArgNo < arg_end() && "Argument # out of range!");
    getInstruction()->setOperand(ArgNo, newVal);
  }

                                                                              
                                                       
  unsigned getArgumentNo(Value::const_user_iterator I) const {
    return getArgumentNo(&I.getUse());
  }

                                                                              
         
  unsigned getArgumentNo(const Use *U) const {
    assert(getInstruction() && "Not a call or invoke instruction!");
    assert(isArgOperand(U) && "Argument # out of range!");
    return U - arg_begin();
  }

                                                                            
                
  using arg_iterator = IterTy;

  iterator_range<IterTy> args() const {
    return make_range(arg_begin(), arg_end());
  }
  bool arg_empty() const { return arg_end() == arg_begin(); }
  unsigned arg_size() const { return unsigned(arg_end() - arg_begin()); }

                                                                              
                                                          
  unsigned getDataOperandNo(Value::const_user_iterator UI) const {
    return getDataOperandNo(&UI.getUse());
  }

                                                                      
                        
  unsigned getDataOperandNo(const Use *U) const {
    assert(getInstruction() && "Not a call or invoke instruction!");
    assert(isDataOperand(U) && "Data operand # out of range!");
    return U - data_operands_begin();
  }

                                                                               
                  
  using data_operand_iterator = IterTy;

                                                                             
                                                                                
                                                                          
                                                                             
                             

  IterTy data_operands_begin() const {
    assert(getInstruction() && "Not a call or invoke instruction!");
    return (*this)->op_begin();
  }
  IterTy data_operands_end() const {
    assert(getInstruction() && "Not a call or invoke instruction!");
    return (*this)->op_end() - (isCall() ? 1 : 3);
  }
  iterator_range<IterTy> data_ops() const {
    return make_range(data_operands_begin(), data_operands_end());
  }
  bool data_operands_empty() const {
    return data_operands_end() == data_operands_begin();
  }
  unsigned data_operands_size() const {
    return std::distance(data_operands_begin(), data_operands_end());
  }

                                                                       
  Type *getType() const { return (*this)->getType(); }

                                                    
  FunTy *getCaller() const { return (*this)->getParent()->getParent(); }

                                                                              
                             
  bool isMustTailCall() const {
    return isCall() && cast<CallInst>(getInstruction())->isMustTailCall();
  }

                                                       
  bool isTailCall() const {
    return isCall() && cast<CallInst>(getInstruction())->isTailCall();
  }

#define CALLSITE_DELEGATE_GETTER(METHOD) \
  InstrTy *II = getInstruction();    \
  return isCall()                        \
    ? cast<CallInst>(II)->METHOD         \
    : cast<InvokeInst>(II)->METHOD

#define CALLSITE_DELEGATE_SETTER(METHOD) \
  InstrTy *II = getInstruction();    \
  if (isCall())                          \
    cast<CallInst>(II)->METHOD;          \
  else                                   \
    cast<InvokeInst>(II)->METHOD

  unsigned getNumArgOperands() const {
    CALLSITE_DELEGATE_GETTER(getNumArgOperands());
  }

  ValTy *getArgOperand(unsigned i) const {
    CALLSITE_DELEGATE_GETTER(getArgOperand(i));
  }

  ValTy *getReturnedArgOperand() const {
    CALLSITE_DELEGATE_GETTER(getReturnedArgOperand());
  }

  bool isInlineAsm() const {
    if (isCall())
      return cast<CallInst>(getInstruction())->isInlineAsm();
    return false;
  }

                                             
  CallingConv::ID getCallingConv() const {
    CALLSITE_DELEGATE_GETTER(getCallingConv());
  }
                                             
  void setCallingConv(CallingConv::ID CC) {
    CALLSITE_DELEGATE_SETTER(setCallingConv(CC));
  }

  FunctionType *getFunctionType() const {
    CALLSITE_DELEGATE_GETTER(getFunctionType());
  }

  void mutateFunctionType(FunctionType *Ty) const {
    CALLSITE_DELEGATE_SETTER(mutateFunctionType(Ty));
  }

                                               
  AttributeList getAttributes() const {
    CALLSITE_DELEGATE_GETTER(getAttributes());
  }
                                               
  void setAttributes(AttributeList PAL) {
    CALLSITE_DELEGATE_SETTER(setAttributes(PAL));
  }

  void addAttribute(unsigned i, Attribute::AttrKind Kind) {
    CALLSITE_DELEGATE_SETTER(addAttribute(i, Kind));
  }

  void addAttribute(unsigned i, Attribute Attr) {
    CALLSITE_DELEGATE_SETTER(addAttribute(i, Attr));
  }

  void addParamAttr(unsigned ArgNo, Attribute::AttrKind Kind) {
    CALLSITE_DELEGATE_SETTER(addParamAttr(ArgNo, Kind));
  }

  void removeAttribute(unsigned i, Attribute::AttrKind Kind) {
    CALLSITE_DELEGATE_SETTER(removeAttribute(i, Kind));
  }

  void removeAttribute(unsigned i, StringRef Kind) {
    CALLSITE_DELEGATE_SETTER(removeAttribute(i, Kind));
  }

  void removeParamAttr(unsigned ArgNo, Attribute::AttrKind Kind) {
    CALLSITE_DELEGATE_SETTER(removeParamAttr(ArgNo, Kind));
  }

                                                           
  bool hasFnAttr(Attribute::AttrKind Kind) const {
    CALLSITE_DELEGATE_GETTER(hasFnAttr(Kind));
  }

                                                           
  bool hasFnAttr(StringRef Kind) const {
    CALLSITE_DELEGATE_GETTER(hasFnAttr(Kind));
  }

                                                               
  bool hasRetAttr(Attribute::AttrKind Kind) const {
    CALLSITE_DELEGATE_GETTER(hasRetAttr(Kind));
  }

                                                                    
  bool paramHasAttr(unsigned ArgNo, Attribute::AttrKind Kind) const {
    CALLSITE_DELEGATE_GETTER(paramHasAttr(ArgNo, Kind));
  }

  Attribute getAttribute(unsigned i, Attribute::AttrKind Kind) const {
    CALLSITE_DELEGATE_GETTER(getAttribute(i, Kind));
  }

  Attribute getAttribute(unsigned i, StringRef Kind) const {
    CALLSITE_DELEGATE_GETTER(getAttribute(i, Kind));
  }

                                                                              
                         
     
                                                                               
                                                                             
                                                                             
                     
  bool dataOperandHasImpliedAttr(unsigned i, Attribute::AttrKind Kind) const {
    CALLSITE_DELEGATE_GETTER(dataOperandHasImpliedAttr(i, Kind));
  }

                                                
  unsigned getRetAlignment() const {
    CALLSITE_DELEGATE_GETTER(getRetAlignment());
  }

                                                                
  unsigned getParamAlignment(unsigned ArgNo) const {
    CALLSITE_DELEGATE_GETTER(getParamAlignment(ArgNo));
  }

                                                                         
                  
  uint64_t getDereferenceableBytes(unsigned i) const {
    CALLSITE_DELEGATE_GETTER(getDereferenceableBytes(i));
  }

                                                                       
                            
  uint64_t getDereferenceableOrNullBytes(unsigned i) const {
    CALLSITE_DELEGATE_GETTER(getDereferenceableOrNullBytes(i));
  }

                                                                     
  bool returnDoesNotAlias() const {
    CALLSITE_DELEGATE_GETTER(returnDoesNotAlias());
  }

                                                                           
  bool isNoBuiltin() const {
    CALLSITE_DELEGATE_GETTER(isNoBuiltin());
  }

                                                                       
  bool isStrictFP() const {
    CALLSITE_DELEGATE_GETTER(isStrictFP());
  }

                                                    
  bool isNoInline() const {
    CALLSITE_DELEGATE_GETTER(isNoInline());
  }
  void setIsNoInline(bool Value = true) {
    CALLSITE_DELEGATE_SETTER(setIsNoInline(Value));
  }

                                                   
  bool doesNotAccessMemory() const {
    CALLSITE_DELEGATE_GETTER(doesNotAccessMemory());
  }
  void setDoesNotAccessMemory() {
    CALLSITE_DELEGATE_SETTER(setDoesNotAccessMemory());
  }

                                                                 
  bool onlyReadsMemory() const {
    CALLSITE_DELEGATE_GETTER(onlyReadsMemory());
  }
  void setOnlyReadsMemory() {
    CALLSITE_DELEGATE_SETTER(setOnlyReadsMemory());
  }

                                                                  
  bool doesNotReadMemory() const {
    CALLSITE_DELEGATE_GETTER(doesNotReadMemory());
  }
  void setDoesNotReadMemory() {
    CALLSITE_DELEGATE_SETTER(setDoesNotReadMemory());
  }

                                                                        
                       
  bool onlyAccessesArgMemory() const {
    CALLSITE_DELEGATE_GETTER(onlyAccessesArgMemory());
  }
  void setOnlyAccessesArgMemory() {
    CALLSITE_DELEGATE_SETTER(setOnlyAccessesArgMemory());
  }

                                                              
                               
  bool onlyAccessesInaccessibleMemory() const {
    CALLSITE_DELEGATE_GETTER(onlyAccessesInaccessibleMemory());
  }
  void setOnlyAccessesInaccessibleMemory() {
    CALLSITE_DELEGATE_SETTER(setOnlyAccessesInaccessibleMemory());
  }

                                                              
                                                                     
  bool onlyAccessesInaccessibleMemOrArgMem() const {
    CALLSITE_DELEGATE_GETTER(onlyAccessesInaccessibleMemOrArgMem());
  }
  void setOnlyAccessesInaccessibleMemOrArgMem() {
    CALLSITE_DELEGATE_SETTER(setOnlyAccessesInaccessibleMemOrArgMem());
  }

                                          
  bool doesNotReturn() const {
    CALLSITE_DELEGATE_GETTER(doesNotReturn());
  }
  void setDoesNotReturn() {
    CALLSITE_DELEGATE_SETTER(setDoesNotReturn());
  }

                                          
  bool doesNotThrow() const {
    CALLSITE_DELEGATE_GETTER(doesNotThrow());
  }
  void setDoesNotThrow() {
    CALLSITE_DELEGATE_SETTER(setDoesNotThrow());
  }

                                              
  bool cannotDuplicate() const {
    CALLSITE_DELEGATE_GETTER(cannotDuplicate());
  }
  void setCannotDuplicate() {
    CALLSITE_DELEGATE_SETTER(setCannotDuplicate());
  }

                                          
  bool isConvergent() const {
    CALLSITE_DELEGATE_GETTER(isConvergent());
  }
  void setConvergent() {
    CALLSITE_DELEGATE_SETTER(setConvergent());
  }
  void setNotConvergent() {
    CALLSITE_DELEGATE_SETTER(setNotConvergent());
  }

  unsigned getNumOperandBundles() const {
    CALLSITE_DELEGATE_GETTER(getNumOperandBundles());
  }

  bool hasOperandBundles() const {
    CALLSITE_DELEGATE_GETTER(hasOperandBundles());
  }

  unsigned getBundleOperandsStartIndex() const {
    CALLSITE_DELEGATE_GETTER(getBundleOperandsStartIndex());
  }

  unsigned getBundleOperandsEndIndex() const {
    CALLSITE_DELEGATE_GETTER(getBundleOperandsEndIndex());
  }

  unsigned getNumTotalBundleOperands() const {
    CALLSITE_DELEGATE_GETTER(getNumTotalBundleOperands());
  }

  OperandBundleUse getOperandBundleAt(unsigned Index) const {
    CALLSITE_DELEGATE_GETTER(getOperandBundleAt(Index));
  }

  Optional<OperandBundleUse> getOperandBundle(StringRef Name) const {
    CALLSITE_DELEGATE_GETTER(getOperandBundle(Name));
  }

  Optional<OperandBundleUse> getOperandBundle(uint32_t ID) const {
    CALLSITE_DELEGATE_GETTER(getOperandBundle(ID));
  }

  unsigned countOperandBundlesOfType(uint32_t ID) const {
    CALLSITE_DELEGATE_GETTER(countOperandBundlesOfType(ID));
  }

  bool isBundleOperand(unsigned Idx) const {
    CALLSITE_DELEGATE_GETTER(isBundleOperand(Idx));
  }

  IterTy arg_begin() const {
    CALLSITE_DELEGATE_GETTER(arg_begin());
  }

  IterTy arg_end() const {
    CALLSITE_DELEGATE_GETTER(arg_end());
  }

#undef CALLSITE_DELEGATE_GETTER
#undef CALLSITE_DELEGATE_SETTER

  void getOperandBundlesAsDefs(SmallVectorImpl<OperandBundleDef> &Defs) const {
    const Instruction *II = getInstruction();
                                                                                
                                       
    if (isCall())
      cast<CallInst>(II)->getOperandBundlesAsDefs(Defs);
    else
      cast<InvokeInst>(II)->getOperandBundlesAsDefs(Defs);
  }

                                                          
  bool doesNotCapture(unsigned OpNo) const {
    return dataOperandHasImpliedAttr(OpNo + 1, Attribute::NoCapture);
  }

                                                         
  bool isByValArgument(unsigned ArgNo) const {
    return paramHasAttr(ArgNo, Attribute::ByVal);
  }

                                                             
  bool isInAllocaArgument(unsigned ArgNo) const {
    return paramHasAttr(ArgNo, Attribute::InAlloca);
  }

                                                                         
  bool isByValOrInAllocaArgument(unsigned ArgNo) const {
    return paramHasAttr(ArgNo, Attribute::ByVal) ||
           paramHasAttr(ArgNo, Attribute::InAlloca);
  }

                                                                                
                                  
  bool hasInAllocaArgument() const {
    return !arg_empty() && paramHasAttr(arg_size() - 1, Attribute::InAlloca);
  }

  bool doesNotAccessMemory(unsigned OpNo) const {
    return dataOperandHasImpliedAttr(OpNo + 1, Attribute::ReadNone);
  }

  bool onlyReadsMemory(unsigned OpNo) const {
    return dataOperandHasImpliedAttr(OpNo + 1, Attribute::ReadOnly) ||
           dataOperandHasImpliedAttr(OpNo + 1, Attribute::ReadNone);
  }

  bool doesNotReadMemory(unsigned OpNo) const {
    return dataOperandHasImpliedAttr(OpNo + 1, Attribute::WriteOnly) ||
           dataOperandHasImpliedAttr(OpNo + 1, Attribute::ReadNone);
  }

                                                              
                                                                           
                                                                     
  bool isReturnNonNull() const {
    if (hasRetAttr(Attribute::NonNull))
      return true;
    else if (getDereferenceableBytes(AttributeList::ReturnIndex) > 0 &&
             !NullPointerIsDefined(getCaller(),
                                   getType()->getPointerAddressSpace()))
      return true;

    return false;
  }

                                                                             
                          
  bool hasArgument(const Value *Arg) const {
    for (arg_iterator AI = this->arg_begin(), E = this->arg_end(); AI != E;
         ++AI)
      if (AI->get() == Arg)
        return true;
    return false;
  }

private:
  IterTy getCallee() const {
    if (isCall())               
      return cast<CallInst>(getInstruction())->op_end() - 1;
    else                       
      return cast<InvokeInst>(getInstruction())->op_end() - 3;
  }
};

class CallSite : public CallSiteBase<Function, BasicBlock, Value, User, Use,
                                     Instruction, CallInst, InvokeInst,
                                     User::op_iterator> {
public:
  CallSite() = default;
  CallSite(CallSiteBase B) : CallSiteBase(B) {}
  CallSite(CallInst *CI) : CallSiteBase(CI) {}
  CallSite(InvokeInst *II) : CallSiteBase(II) {}
  explicit CallSite(Instruction *II) : CallSiteBase(II) {}
  explicit CallSite(Value *V) : CallSiteBase(V) {}

  bool operator==(const CallSite &CS) const { return I == CS.I; }
  bool operator!=(const CallSite &CS) const { return I != CS.I; }
  bool operator<(const CallSite &CS) const {
    return getInstruction() < CS.getInstruction();
  }

private:
  friend struct DenseMapInfo<CallSite>;

  User::op_iterator getCallee() const;
};

template <> struct DenseMapInfo<CallSite> {
  using BaseInfo = DenseMapInfo<decltype(CallSite::I)>;

  static CallSite getEmptyKey() {
    CallSite CS;
    CS.I = BaseInfo::getEmptyKey();
    return CS;
  }

  static CallSite getTombstoneKey() {
    CallSite CS;
    CS.I = BaseInfo::getTombstoneKey();
    return CS;
  }

  static unsigned getHashValue(const CallSite &CS) {
    return BaseInfo::getHashValue(CS.I);
  }

  static bool isEqual(const CallSite &LHS, const CallSite &RHS) {
    return LHS == RHS;
  }
};

                                                    
class ImmutableCallSite : public CallSiteBase<> {
public:
  ImmutableCallSite() = default;
  ImmutableCallSite(const CallInst *CI) : CallSiteBase(CI) {}
  ImmutableCallSite(const InvokeInst *II) : CallSiteBase(II) {}
  explicit ImmutableCallSite(const Instruction *II) : CallSiteBase(II) {}
  explicit ImmutableCallSite(const Value *V) : CallSiteBase(V) {}
  ImmutableCallSite(CallSite CS) : CallSiteBase(CS.getInstruction()) {}
};

}                      

#endif                      
