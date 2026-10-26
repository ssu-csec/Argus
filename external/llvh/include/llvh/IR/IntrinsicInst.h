//===-- llvm/IntrinsicInst.h - Intrinsic Instruction Wrappers ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines classes that make it really easy to deal with intrinsic
// functions with the isa/dyncast family of functions.  In particular, this
// allows you to do things like:
//
//     if (MemCpyInst *MCI = dyn_cast<MemCpyInst>(Inst))
//        ... MCI->getDest() ... MCI->getSource() ...
//
// All intrinsic function calls are instances of the call instruction, so these
// are all subclasses of the CallInst class.  Note that none of these classes
// has state or virtual methods, which is an important part of this gross/neat
// hack working.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_INTRINSICINST_H
#define LLVM_IR_INTRINSICINST_H

#include "llvh/IR/Constants.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/Function.h"
#include "llvh/IR/GlobalVariable.h"
#include "llvh/IR/Instructions.h"
#include "llvh/IR/Intrinsics.h"
#include "llvh/IR/Metadata.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include <cassert>
#include <cstdint>

namespace llvh {

                                                                  
                                                                                
                             
  class IntrinsicInst : public CallInst {
  public:
    IntrinsicInst() = delete;
    IntrinsicInst(const IntrinsicInst &) = delete;
    IntrinsicInst &operator=(const IntrinsicInst &) = delete;

                                                  
    Intrinsic::ID getIntrinsicID() const {
      return getCalledFunction()->getIntrinsicID();
    }

                                                                        
    static bool classof(const CallInst *I) {
      if (const Function *CF = I->getCalledFunction())
        return CF->isIntrinsic();
      return false;
    }
    static bool classof(const Value *V) {
      return isa<CallInst>(V) && classof(cast<CallInst>(V));
    }
  };

                                                              
  class DbgInfoIntrinsic : public IntrinsicInst {
  public:
                             
          
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::dbg_declare:
      case Intrinsic::dbg_value:
      case Intrinsic::dbg_addr:
      case Intrinsic::dbg_label:
        return true;
      default: return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
          
  };

                                                                            
  class DbgVariableIntrinsic : public DbgInfoIntrinsic {
  public:
                                                                              
                                                                      
                                        
    Value *getVariableLocation(bool AllowNullOp = true) const;

                                                                             
                                                                      
    bool isAddressOfVariable() const {
      return getIntrinsicID() != Intrinsic::dbg_value;
    }

    DILocalVariable *getVariable() const {
      return cast<DILocalVariable>(getRawVariable());
    }

    DIExpression *getExpression() const {
      return cast<DIExpression>(getRawExpression());
    }

    Metadata *getRawVariable() const {
      return cast<MetadataAsValue>(getArgOperand(1))->getMetadata();
    }

    Metadata *getRawExpression() const {
      return cast<MetadataAsValue>(getArgOperand(2))->getMetadata();
    }

                                                                                
                     
    Optional<uint64_t> getFragmentSizeInBits() const;

                             
          
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::dbg_declare:
      case Intrinsic::dbg_value:
      case Intrinsic::dbg_addr:
        return true;
      default: return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
          
  };

                                                       
  class DbgDeclareInst : public DbgVariableIntrinsic {
  public:
    Value *getAddress() const { return getVariableLocation(); }

                             
          
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::dbg_declare;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
          
  };

                                                    
  class DbgAddrIntrinsic : public DbgVariableIntrinsic {
  public:
    Value *getAddress() const { return getVariableLocation(); }

                             
          
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::dbg_addr;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                     
  class DbgValueInst : public DbgVariableIntrinsic {
  public:
    Value *getValue() const {
      return getVariableLocation(                    false);
    }

                             
          
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::dbg_value;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
          
  };

                                                     
  class DbgLabelInst : public DbgInfoIntrinsic {
  public:
    DILabel *getLabel() const {
      return cast<DILabel>(getRawLabel());
    }

    Metadata *getRawLabel() const {
      return cast<MetadataAsValue>(getArgOperand(0))->getMetadata();
    }

                                                                         
          
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::dbg_label;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
          
  };

                                                                              
  class ConstrainedFPIntrinsic : public IntrinsicInst {
  public:
    enum RoundingMode {
      rmInvalid,
      rmDynamic,
      rmToNearest,
      rmDownward,
      rmUpward,
      rmTowardZero
    };

    enum ExceptionBehavior {
      ebInvalid,
      ebIgnore,
      ebMayTrap,
      ebStrict
    };

    bool isUnaryOp() const;
    bool isTernaryOp() const;
    RoundingMode getRoundingMode() const;
    ExceptionBehavior getExceptionBehavior() const;

                                                                        
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::experimental_constrained_fadd:
      case Intrinsic::experimental_constrained_fsub:
      case Intrinsic::experimental_constrained_fmul:
      case Intrinsic::experimental_constrained_fdiv:
      case Intrinsic::experimental_constrained_frem:
      case Intrinsic::experimental_constrained_fma:
      case Intrinsic::experimental_constrained_sqrt:
      case Intrinsic::experimental_constrained_pow:
      case Intrinsic::experimental_constrained_powi:
      case Intrinsic::experimental_constrained_sin:
      case Intrinsic::experimental_constrained_cos:
      case Intrinsic::experimental_constrained_exp:
      case Intrinsic::experimental_constrained_exp2:
      case Intrinsic::experimental_constrained_log:
      case Intrinsic::experimental_constrained_log10:
      case Intrinsic::experimental_constrained_log2:
      case Intrinsic::experimental_constrained_rint:
      case Intrinsic::experimental_constrained_nearbyint:
        return true;
      default: return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                                  
                     
                                                              
                                  
  template <typename Derived> class MemIntrinsicBase : public IntrinsicInst {
  private:
    enum { ARG_DEST = 0, ARG_LENGTH = 2 };

  public:
    Value *getRawDest() const {
      return const_cast<Value *>(getArgOperand(ARG_DEST));
    }
    const Use &getRawDestUse() const { return getArgOperandUse(ARG_DEST); }
    Use &getRawDestUse() { return getArgOperandUse(ARG_DEST); }

    Value *getLength() const {
      return const_cast<Value *>(getArgOperand(ARG_LENGTH));
    }
    const Use &getLengthUse() const { return getArgOperandUse(ARG_LENGTH); }
    Use &getLengthUse() { return getArgOperandUse(ARG_LENGTH); }

                                                                
                                                                       
                                                                          
    Value *getDest() const { return getRawDest()->stripPointerCasts(); }

    unsigned getDestAddressSpace() const {
      return cast<PointerType>(getRawDest()->getType())->getAddressSpace();
    }

    unsigned getDestAlignment() const { return getParamAlignment(ARG_DEST); }

                                                       
    void setDest(Value *Ptr) {
      assert(getRawDest()->getType() == Ptr->getType() &&
             "setDest called with pointer of wrong type!");
      setArgOperand(ARG_DEST, Ptr);
    }

    void setDestAlignment(unsigned Align) {
      removeParamAttr(ARG_DEST, Attribute::Alignment);
      if (Align > 0)
        addParamAttr(ARG_DEST,
                     Attribute::getWithAlignment(getContext(), Align));
    }

    void setLength(Value *L) {
      assert(getLength()->getType() == L->getType() &&
             "setLength called with value of wrong type!");
      setArgOperand(ARG_LENGTH, L);
    }
  };

                                                                           
                     
  template <class BaseCL> class MemTransferBase : public BaseCL {
  private:
    enum { ARG_SOURCE = 1 };

  public:
                                                
    Value *getRawSource() const {
      return const_cast<Value *>(BaseCL::getArgOperand(ARG_SOURCE));
    }
    const Use &getRawSourceUse() const {
      return BaseCL::getArgOperandUse(ARG_SOURCE);
    }
    Use &getRawSourceUse() { return BaseCL::getArgOperandUse(ARG_SOURCE); }

                                                                  
                                                                           
                                            
    Value *getSource() const { return getRawSource()->stripPointerCasts(); }

    unsigned getSourceAddressSpace() const {
      return cast<PointerType>(getRawSource()->getType())->getAddressSpace();
    }

    unsigned getSourceAlignment() const {
      return BaseCL::getParamAlignment(ARG_SOURCE);
    }

    void setSource(Value *Ptr) {
      assert(getRawSource()->getType() == Ptr->getType() &&
             "setSource called with pointer of wrong type!");
      BaseCL::setArgOperand(ARG_SOURCE, Ptr);
    }

    void setSourceAlignment(unsigned Align) {
      BaseCL::removeParamAttr(ARG_SOURCE, Attribute::Alignment);
      if (Align > 0)
        BaseCL::addParamAttr(ARG_SOURCE, Attribute::getWithAlignment(
                                             BaseCL::getContext(), Align));
    }
  };

                                                                  
                     
  template <class BaseCL> class MemSetBase : public BaseCL {
  private:
    enum { ARG_VALUE = 1 };

  public:
    Value *getValue() const {
      return const_cast<Value *>(BaseCL::getArgOperand(ARG_VALUE));
    }
    const Use &getValueUse() const {
      return BaseCL::getArgOperandUse(ARG_VALUE);
    }
    Use &getValueUse() { return BaseCL::getArgOperandUse(ARG_VALUE); }

    void setValue(Value *Val) {
      assert(getValue()->getType() == Val->getType() &&
             "setValue called with value of wrong type!");
      BaseCL::setArgOperand(ARG_VALUE, Val);
    }
  };

                                                                          
                                                             
  class AtomicMemIntrinsic : public MemIntrinsicBase<AtomicMemIntrinsic> {
  private:
    enum { ARG_ELEMENTSIZE = 3 };

  public:
    Value *getRawElementSizeInBytes() const {
      return const_cast<Value *>(getArgOperand(ARG_ELEMENTSIZE));
    }

    ConstantInt *getElementSizeInBytesCst() const {
      return cast<ConstantInt>(getRawElementSizeInBytes());
    }

    uint32_t getElementSizeInBytes() const {
      return getElementSizeInBytesCst()->getZExtValue();
    }

    void setElementSizeInBytes(Constant *V) {
      assert(V->getType() == Type::getInt8Ty(getContext()) &&
             "setElementSizeInBytes called with value of wrong type!");
      setArgOperand(ARG_ELEMENTSIZE, V);
    }

    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memcpy_element_unordered_atomic:
      case Intrinsic::memmove_element_unordered_atomic:
      case Intrinsic::memset_element_unordered_atomic:
        return true;
      default:
        return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                   
                                              
  class AtomicMemSetInst : public MemSetBase<AtomicMemIntrinsic> {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::memset_element_unordered_atomic;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                          
                                                      
  class AtomicMemTransferInst : public MemTransferBase<AtomicMemIntrinsic> {
  public:
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memcpy_element_unordered_atomic:
      case Intrinsic::memmove_element_unordered_atomic:
        return true;
      default:
        return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                       
                                               
  class AtomicMemCpyInst : public AtomicMemTransferInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::memcpy_element_unordered_atomic;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                        
                                                
  class AtomicMemMoveInst : public AtomicMemTransferInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::memmove_element_unordered_atomic;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                              
  class MemIntrinsic : public MemIntrinsicBase<MemIntrinsic> {
  private:
    enum { ARG_VOLATILE = 3 };

  public:
    ConstantInt *getVolatileCst() const {
      return cast<ConstantInt>(
          const_cast<Value *>(getArgOperand(ARG_VOLATILE)));
    }

    bool isVolatile() const {
      return !getVolatileCst()->isZero();
    }

    void setVolatile(Constant *V) { setArgOperand(ARG_VOLATILE, V); }

                                                                        
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memcpy:
      case Intrinsic::memmove:
      case Intrinsic::memset:
        return true;
      default: return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                 
  class MemSetInst : public MemSetBase<MemIntrinsic> {
  public:
                                                                        
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::memset;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                          
  class MemTransferInst : public MemTransferBase<MemIntrinsic> {
  public:
                                                                        
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::memcpy ||
             I->getIntrinsicID() == Intrinsic::memmove;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                 
  class MemCpyInst : public MemTransferInst {
  public:
                                                                        
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::memcpy;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                  
  class MemMoveInst : public MemTransferInst {
  public:
                                                                        
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::memmove;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                                    
                                          
                                                             
                                    
  class AnyMemIntrinsic : public MemIntrinsicBase<AnyMemIntrinsic> {
  public:
    bool isVolatile() const {
                                                       
      if (auto *MI = dyn_cast<MemIntrinsic>(this))
        return MI->isVolatile();
      return false;
    }

    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memcpy:
      case Intrinsic::memmove:
      case Intrinsic::memset:
      case Intrinsic::memcpy_element_unordered_atomic:
      case Intrinsic::memmove_element_unordered_atomic:
      case Intrinsic::memset_element_unordered_atomic:
        return true;
      default:
        return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                
                                              
                     
  class AnyMemSetInst : public MemSetBase<AnyMemIntrinsic> {
  public:
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memset:
      case Intrinsic::memset_element_unordered_atomic:
        return true;
      default:
        return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                   
                                                      
                             
  class AnyMemTransferInst : public MemTransferBase<AnyMemIntrinsic> {
  public:
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memcpy:
      case Intrinsic::memmove:
      case Intrinsic::memcpy_element_unordered_atomic:
      case Intrinsic::memmove_element_unordered_atomic:
        return true;
      default:
        return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                
                                               
                      
  class AnyMemCpyInst : public AnyMemTransferInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memcpy:
      case Intrinsic::memcpy_element_unordered_atomic:
        return true;
      default:
        return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                 
                                                
                       
  class AnyMemMoveInst : public AnyMemTransferInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      switch (I->getIntrinsicID()) {
      case Intrinsic::memmove:
      case Intrinsic::memmove_element_unordered_atomic:
        return true;
      default:
        return false;
      }
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                  
  class VAStartInst : public IntrinsicInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::vastart;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }

    Value *getArgList() const { return const_cast<Value*>(getArgOperand(0)); }
  };

                                                
  class VAEndInst : public IntrinsicInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::vaend;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }

    Value *getArgList() const { return const_cast<Value*>(getArgOperand(0)); }
  };

                                                 
  class VACopyInst : public IntrinsicInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::vacopy;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }

    Value *getDest() const { return const_cast<Value*>(getArgOperand(0)); }
    Value *getSrc() const { return const_cast<Value*>(getArgOperand(1)); }
  };

                                                             
  class InstrProfIncrementInst : public IntrinsicInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::instrprof_increment;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }

    GlobalVariable *getName() const {
      return cast<GlobalVariable>(
          const_cast<Value *>(getArgOperand(0))->stripPointerCasts());
    }

    ConstantInt *getHash() const {
      return cast<ConstantInt>(const_cast<Value *>(getArgOperand(1)));
    }

    ConstantInt *getNumCounters() const {
      return cast<ConstantInt>(const_cast<Value *>(getArgOperand(2)));
    }

    ConstantInt *getIndex() const {
      return cast<ConstantInt>(const_cast<Value *>(getArgOperand(3)));
    }

    Value *getStep() const;
  };

  class InstrProfIncrementInstStep : public InstrProfIncrementInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::instrprof_increment_step;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }
  };

                                                                 
  class InstrProfValueProfileInst : public IntrinsicInst {
  public:
    static bool classof(const IntrinsicInst *I) {
      return I->getIntrinsicID() == Intrinsic::instrprof_value_profile;
    }
    static bool classof(const Value *V) {
      return isa<IntrinsicInst>(V) && classof(cast<IntrinsicInst>(V));
    }

    GlobalVariable *getName() const {
      return cast<GlobalVariable>(
          const_cast<Value *>(getArgOperand(0))->stripPointerCasts());
    }

    ConstantInt *getHash() const {
      return cast<ConstantInt>(const_cast<Value *>(getArgOperand(1)));
    }

    Value *getTargetValue() const {
      return cast<Value>(const_cast<Value *>(getArgOperand(2)));
    }

    ConstantInt *getValueKind() const {
      return cast<ConstantInt>(const_cast<Value *>(getArgOperand(3)));
    }

                                    
    ConstantInt *getIndex() const {
      return cast<ConstantInt>(const_cast<Value *>(getArgOperand(4)));
    }
  };

}                      

#endif                           
