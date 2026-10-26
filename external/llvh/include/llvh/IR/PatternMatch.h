//===- PatternMatch.h - Match on the LLVM IR --------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides a simple and efficient mechanism for performing general
// tree-based pattern matches on the LLVM IR. The power of these routines is
// that it allows you to write concise patterns that are expressive and easy to
// understand. The other major advantage of this is that it allows you to
// trivially capture/bind elements in the pattern to variables. For example,
// you can do something like this:
//
//  Value *Exp = ...
//  Value *X, *Y;  ConstantInt *C1, *C2;      // (X & C1) | (Y & C2)
//  if (match(Exp, m_Or(m_And(m_Value(X), m_ConstantInt(C1)),
//                      m_And(m_Value(Y), m_ConstantInt(C2))))) {
//    ... Pattern is matched and variables are bound ...
//  }
//
// This is primarily useful to things like the instruction combiner, but can
// also be useful for static analysis tools or code generators.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_PATTERNMATCH_H
#define LLVM_IR_PATTERNMATCH_H

#include "llvh/ADT/APFloat.h"
#include "llvh/ADT/APInt.h"
#include "llvh/IR/CallSite.h"
#include "llvh/IR/Constant.h"
#include "llvh/IR/Constants.h"
#include "llvh/IR/InstrTypes.h"
#include "llvh/IR/Instruction.h"
#include "llvh/IR/Instructions.h"
#include "llvh/IR/Intrinsics.h"
#include "llvh/IR/Operator.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include <cstdint>

namespace llvh {
namespace PatternMatch {

template <typename Val, typename Pattern> bool match(Val *V, const Pattern &P) {
  return const_cast<Pattern &>(P).match(V);
}

template <typename SubPattern_t> struct OneUse_match {
  SubPattern_t SubPattern;

  OneUse_match(const SubPattern_t &SP) : SubPattern(SP) {}

  template <typename OpTy> bool match(OpTy *V) {
    return V->hasOneUse() && SubPattern.match(V);
  }
};

template <typename T> inline OneUse_match<T> m_OneUse(const T &SubPattern) {
  return SubPattern;
}

template <typename Class> struct class_match {
  template <typename ITy> bool match(ITy *V) { return isa<Class>(V); }
};

                                           
inline class_match<Value> m_Value() { return class_match<Value>(); }

                                                      
inline class_match<BinaryOperator> m_BinOp() {
  return class_match<BinaryOperator>();
}

                                                  
inline class_match<CmpInst> m_Cmp() { return class_match<CmpInst>(); }

                                                 
inline class_match<ConstantInt> m_ConstantInt() {
  return class_match<ConstantInt>();
}

                                      
inline class_match<UndefValue> m_Undef() { return class_match<UndefValue>(); }

                                              
inline class_match<Constant> m_Constant() { return class_match<Constant>(); }

                        
template <typename LTy, typename RTy> struct match_combine_or {
  LTy L;
  RTy R;

  match_combine_or(const LTy &Left, const RTy &Right) : L(Left), R(Right) {}

  template <typename ITy> bool match(ITy *V) {
    if (L.match(V))
      return true;
    if (R.match(V))
      return true;
    return false;
  }
};

template <typename LTy, typename RTy> struct match_combine_and {
  LTy L;
  RTy R;

  match_combine_and(const LTy &Left, const RTy &Right) : L(Left), R(Right) {}

  template <typename ITy> bool match(ITy *V) {
    if (L.match(V))
      if (R.match(V))
        return true;
    return false;
  }
};

                                                
template <typename LTy, typename RTy>
inline match_combine_or<LTy, RTy> m_CombineOr(const LTy &L, const RTy &R) {
  return match_combine_or<LTy, RTy>(L, R);
}

                                                
template <typename LTy, typename RTy>
inline match_combine_and<LTy, RTy> m_CombineAnd(const LTy &L, const RTy &R) {
  return match_combine_and<LTy, RTy>(L, R);
}

struct apint_match {
  const APInt *&Res;

  apint_match(const APInt *&R) : Res(R) {}

  template <typename ITy> bool match(ITy *V) {
    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      Res = &CI->getValue();
      return true;
    }
    if (V->getType()->isVectorTy())
      if (const auto *C = dyn_cast<Constant>(V))
        if (auto *CI = dyn_cast_or_null<ConstantInt>(C->getSplatValue())) {
          Res = &CI->getValue();
          return true;
        }
    return false;
  }
};
                                                             
                                                              
                                   
struct apfloat_match {
  const APFloat *&Res;
  apfloat_match(const APFloat *&R) : Res(R) {}
  template <typename ITy> bool match(ITy *V) {
    if (auto *CI = dyn_cast<ConstantFP>(V)) {
      Res = &CI->getValueAPF();
      return true;
    }
    if (V->getType()->isVectorTy())
      if (const auto *C = dyn_cast<Constant>(V))
        if (auto *CI = dyn_cast_or_null<ConstantFP>(C->getSplatValue())) {
          Res = &CI->getValueAPF();
          return true;
        }
    return false;
  }
};

                                                               
                                             
inline apint_match m_APInt(const APInt *&Res) { return Res; }

                                                              
                                               
inline apfloat_match m_APFloat(const APFloat *&Res) { return Res; }

template <int64_t Val> struct constantint_match {
  template <typename ITy> bool match(ITy *V) {
    if (const auto *CI = dyn_cast<ConstantInt>(V)) {
      const APInt &CIV = CI->getValue();
      if (Val >= 0)
        return CIV == static_cast<uint64_t>(Val);
                                                                             
                                                                             
                                      
      return -CIV == -Val;
    }
    return false;
  }
};

                                              
template <int64_t Val> inline constantint_match<Val> m_ConstantInt() {
  return constantint_match<Val>();
}

                                                                               
                                  
                                                         
template <typename Predicate> struct cst_pred_ty : public Predicate {
  template <typename ITy> bool match(ITy *V) {
    if (const auto *CI = dyn_cast<ConstantInt>(V))
      return this->isValue(CI->getValue());
    if (V->getType()->isVectorTy()) {
      if (const auto *C = dyn_cast<Constant>(V)) {
        if (const auto *CI = dyn_cast_or_null<ConstantInt>(C->getSplatValue()))
          return this->isValue(CI->getValue());

                                                                     
        unsigned NumElts = V->getType()->getVectorNumElements();
        assert(NumElts != 0 && "Constant vector with no elements?");
        for (unsigned i = 0; i != NumElts; ++i) {
          Constant *Elt = C->getAggregateElement(i);
          if (!Elt)
            return false;
          if (isa<UndefValue>(Elt))
            continue;
          auto *CI = dyn_cast<ConstantInt>(Elt);
          if (!CI || !this->isValue(CI->getValue()))
            return false;
        }
        return true;
      }
    }
    return false;
  }
};

                                                                       
                                                             
template <typename Predicate> struct api_pred_ty : public Predicate {
  const APInt *&Res;

  api_pred_ty(const APInt *&R) : Res(R) {}

  template <typename ITy> bool match(ITy *V) {
    if (const auto *CI = dyn_cast<ConstantInt>(V))
      if (this->isValue(CI->getValue())) {
        Res = &CI->getValue();
        return true;
      }
    if (V->getType()->isVectorTy())
      if (const auto *C = dyn_cast<Constant>(V))
        if (auto *CI = dyn_cast_or_null<ConstantInt>(C->getSplatValue()))
          if (this->isValue(CI->getValue())) {
            Res = &CI->getValue();
            return true;
          }

    return false;
  }
};

                                                                       
                                                 
                                                         
template <typename Predicate> struct cstfp_pred_ty : public Predicate {
  template <typename ITy> bool match(ITy *V) {
    if (const auto *CF = dyn_cast<ConstantFP>(V))
      return this->isValue(CF->getValueAPF());
    if (V->getType()->isVectorTy()) {
      if (const auto *C = dyn_cast<Constant>(V)) {
        if (const auto *CF = dyn_cast_or_null<ConstantFP>(C->getSplatValue()))
          return this->isValue(CF->getValueAPF());

                                                                     
        unsigned NumElts = V->getType()->getVectorNumElements();
        assert(NumElts != 0 && "Constant vector with no elements?");
        for (unsigned i = 0; i != NumElts; ++i) {
          Constant *Elt = C->getAggregateElement(i);
          if (!Elt)
            return false;
          if (isa<UndefValue>(Elt))
            continue;
          auto *CF = dyn_cast<ConstantFP>(Elt);
          if (!CF || !this->isValue(CF->getValueAPF()))
            return false;
        }
        return true;
      }
    }
    return false;
  }
};

                                                                               
  
                                                                              
                                                                              
                                                                                
                
  
                                                                               

struct is_all_ones {
  bool isValue(const APInt &C) { return C.isAllOnesValue(); }
};
                                                 
                                                                 
inline cst_pred_ty<is_all_ones> m_AllOnes() {
  return cst_pred_ty<is_all_ones>();
}

struct is_maxsignedvalue {
  bool isValue(const APInt &C) { return C.isMaxSignedValue(); }
};
                                                                              
                      
                                                                 
inline cst_pred_ty<is_maxsignedvalue> m_MaxSignedValue() {
  return cst_pred_ty<is_maxsignedvalue>();
}
inline api_pred_ty<is_maxsignedvalue> m_MaxSignedValue(const APInt *&V) {
  return V;
}

struct is_negative {
  bool isValue(const APInt &C) { return C.isNegative(); }
};
                                                  
                                                                 
inline cst_pred_ty<is_negative> m_Negative() {
  return cst_pred_ty<is_negative>();
}
inline api_pred_ty<is_negative> m_Negative(const APInt *&V) {
  return V;
}

struct is_nonnegative {
  bool isValue(const APInt &C) { return C.isNonNegative(); }
};
                                                     
                                                                 
inline cst_pred_ty<is_nonnegative> m_NonNegative() {
  return cst_pred_ty<is_nonnegative>();
}
inline api_pred_ty<is_nonnegative> m_NonNegative(const APInt *&V) {
  return V;
}

struct is_one {
  bool isValue(const APInt &C) { return C.isOneValue(); }
};
                                                                
                                                                 
inline cst_pred_ty<is_one> m_One() {
  return cst_pred_ty<is_one>();
}

struct is_zero_int {
  bool isValue(const APInt &C) { return C.isNullValue(); }
};
                                                                
                                                                 
inline cst_pred_ty<is_zero_int> m_ZeroInt() {
  return cst_pred_ty<is_zero_int>();
}

struct is_zero {
  template <typename ITy> bool match(ITy *V) {
    auto *C = dyn_cast<Constant>(V);
    return C && (C->isNullValue() || cst_pred_ty<is_zero_int>().match(C));
  }
};
                                                                     
                                                                 
inline is_zero m_Zero() {
  return is_zero();
}

struct is_power2 {
  bool isValue(const APInt &C) { return C.isPowerOf2(); }
};
                                          
                                                                 
inline cst_pred_ty<is_power2> m_Power2() {
  return cst_pred_ty<is_power2>();
}
inline api_pred_ty<is_power2> m_Power2(const APInt *&V) {
  return V;
}

struct is_power2_or_zero {
  bool isValue(const APInt &C) { return !C || C.isPowerOf2(); }
};
                                                         
                                                                 
inline cst_pred_ty<is_power2_or_zero> m_Power2OrZero() {
  return cst_pred_ty<is_power2_or_zero>();
}
inline api_pred_ty<is_power2_or_zero> m_Power2OrZero(const APInt *&V) {
  return V;
}

struct is_sign_mask {
  bool isValue(const APInt &C) { return C.isSignMask(); }
};
                                                             
                                                                 
inline cst_pred_ty<is_sign_mask> m_SignMask() {
  return cst_pred_ty<is_sign_mask>();
}

struct is_lowbit_mask {
  bool isValue(const APInt &C) { return C.isMask(); }
};
                                                            
                                                                 
inline cst_pred_ty<is_lowbit_mask> m_LowBitMask() {
  return cst_pred_ty<is_lowbit_mask>();
}

struct is_nan {
  bool isValue(const APFloat &C) { return C.isNaN(); }
};
                                                                             
                                                                 
inline cstfp_pred_ty<is_nan> m_NaN() {
  return cstfp_pred_ty<is_nan>();
}

struct is_any_zero_fp {
  bool isValue(const APFloat &C) { return C.isZero(); }
};
                                                          
                                                                 
inline cstfp_pred_ty<is_any_zero_fp> m_AnyZeroFP() {
  return cstfp_pred_ty<is_any_zero_fp>();
}

struct is_pos_zero_fp {
  bool isValue(const APFloat &C) { return C.isPosZero(); }
};
                                         
                                                                 
inline cstfp_pred_ty<is_pos_zero_fp> m_PosZeroFP() {
  return cstfp_pred_ty<is_pos_zero_fp>();
}

struct is_neg_zero_fp {
  bool isValue(const APFloat &C) { return C.isNegZero(); }
};
                                         
                                                                 
inline cstfp_pred_ty<is_neg_zero_fp> m_NegZeroFP() {
  return cstfp_pred_ty<is_neg_zero_fp>();
}

                                                                               

template <typename Class> struct bind_ty {
  Class *&VR;

  bind_ty(Class *&V) : VR(V) {}

  template <typename ITy> bool match(ITy *V) {
    if (auto *CV = dyn_cast<Class>(V)) {
      VR = CV;
      return true;
    }
    return false;
  }
};

                                            
inline bind_ty<Value> m_Value(Value *&V) { return V; }
inline bind_ty<const Value> m_Value(const Value *&V) { return V; }

                                                   
inline bind_ty<Instruction> m_Instruction(Instruction *&I) { return I; }
                                                      
inline bind_ty<BinaryOperator> m_BinOp(BinaryOperator *&I) { return I; }

                                                         
inline bind_ty<ConstantInt> m_ConstantInt(ConstantInt *&CI) { return CI; }

                                                      
inline bind_ty<Constant> m_Constant(Constant *&C) { return C; }

                                                        
inline bind_ty<ConstantFP> m_ConstantFP(ConstantFP *&C) { return C; }

                             
struct specificval_ty {
  const Value *Val;

  specificval_ty(const Value *V) : Val(V) {}

  template <typename ITy> bool match(ITy *V) { return V == Val; }
};

                                                
inline specificval_ty m_Specific(const Value *V) { return V; }

                                                              
                                             
template <typename Class> struct deferredval_ty {
  Class *const &Val;

  deferredval_ty(Class *const &V) : Val(V) {}

  template <typename ITy> bool match(ITy *const V) { return V == Val; }
};

                                                   
inline deferredval_ty<Value> m_Deferred(Value *const &V) { return V; }
inline deferredval_ty<const Value> m_Deferred(const Value *const &V) {
  return V;
}

                                                                       
               
struct specific_fpval {
  double Val;

  specific_fpval(double V) : Val(V) {}

  template <typename ITy> bool match(ITy *V) {
    if (const auto *CFP = dyn_cast<ConstantFP>(V))
      return CFP->isExactlyValue(Val);
    if (V->getType()->isVectorTy())
      if (const auto *C = dyn_cast<Constant>(V))
        if (auto *CFP = dyn_cast_or_null<ConstantFP>(C->getSplatValue()))
          return CFP->isExactlyValue(Val);
    return false;
  }
};

                                                                     
                       
inline specific_fpval m_SpecificFP(double V) { return specific_fpval(V); }

                                                               
inline specific_fpval m_FPOne() { return m_SpecificFP(1.0); }

struct bind_const_intval_ty {
  uint64_t &VR;

  bind_const_intval_ty(uint64_t &V) : VR(V) {}

  template <typename ITy> bool match(ITy *V) {
    if (const auto *CV = dyn_cast<ConstantInt>(V))
      if (CV->getValue().ule(UINT64_MAX)) {
        VR = CV->getZExtValue();
        return true;
      }
    return false;
  }
};

                                                                     
         
struct specific_intval {
  uint64_t Val;

  specific_intval(uint64_t V) : Val(V) {}

  template <typename ITy> bool match(ITy *V) {
    const auto *CI = dyn_cast<ConstantInt>(V);
    if (!CI && V->getType()->isVectorTy())
      if (const auto *C = dyn_cast<Constant>(V))
        CI = dyn_cast_or_null<ConstantInt>(C->getSplatValue());

    return CI && CI->getValue() == Val;
  }
};

                                                                       
              
inline specific_intval m_SpecificInt(uint64_t V) { return specific_intval(V); }

                                                                   
                                    
inline bind_const_intval_ty m_ConstantInt(uint64_t &V) { return V; }

                                                                                
                                   
  
template <typename LHS_t, typename RHS_t, bool Commutable = false>
struct AnyBinaryOp_match {
  LHS_t L;
  RHS_t R;

                                                                        
                                     
  AnyBinaryOp_match(const LHS_t &LHS, const RHS_t &RHS) : L(LHS), R(RHS) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *I = dyn_cast<BinaryOperator>(V))
      return (L.match(I->getOperand(0)) && R.match(I->getOperand(1))) ||
             (Commutable && L.match(I->getOperand(1)) &&
              R.match(I->getOperand(0)));
    return false;
  }
};

template <typename LHS, typename RHS>
inline AnyBinaryOp_match<LHS, RHS> m_BinOp(const LHS &L, const RHS &R) {
  return AnyBinaryOp_match<LHS, RHS>(L, R);
}

                                                                                
                                          
  

template <typename LHS_t, typename RHS_t, unsigned Opcode,
          bool Commutable = false>
struct BinaryOp_match {
  LHS_t L;
  RHS_t R;

                                                                        
                                     
  BinaryOp_match(const LHS_t &LHS, const RHS_t &RHS) : L(LHS), R(RHS) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (V->getValueID() == Value::InstructionVal + Opcode) {
      auto *I = cast<BinaryOperator>(V);
      return (L.match(I->getOperand(0)) && R.match(I->getOperand(1))) ||
             (Commutable && L.match(I->getOperand(1)) &&
              R.match(I->getOperand(0)));
    }
    if (auto *CE = dyn_cast<ConstantExpr>(V))
      return CE->getOpcode() == Opcode &&
             ((L.match(CE->getOperand(0)) && R.match(CE->getOperand(1))) ||
              (Commutable && L.match(CE->getOperand(1)) &&
               R.match(CE->getOperand(0))));
    return false;
  }
};

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Add> m_Add(const LHS &L,
                                                        const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Add>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::FAdd> m_FAdd(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::FAdd>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Sub> m_Sub(const LHS &L,
                                                        const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Sub>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::FSub> m_FSub(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::FSub>(L, R);
}

                                     
template <typename RHS>
inline BinaryOp_match<cstfp_pred_ty<is_neg_zero_fp>, RHS, Instruction::FSub>
m_FNeg(const RHS &X) {
  return m_FSub(m_NegZeroFP(), X);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Mul> m_Mul(const LHS &L,
                                                        const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Mul>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::FMul> m_FMul(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::FMul>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::UDiv> m_UDiv(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::UDiv>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::SDiv> m_SDiv(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::SDiv>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::FDiv> m_FDiv(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::FDiv>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::URem> m_URem(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::URem>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::SRem> m_SRem(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::SRem>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::FRem> m_FRem(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::FRem>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::And> m_And(const LHS &L,
                                                        const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::And>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Or> m_Or(const LHS &L,
                                                      const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Or>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Xor> m_Xor(const LHS &L,
                                                        const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Xor>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Shl> m_Shl(const LHS &L,
                                                        const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Shl>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::LShr> m_LShr(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::LShr>(L, R);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::AShr> m_AShr(const LHS &L,
                                                          const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::AShr>(L, R);
}

template <typename LHS_t, typename RHS_t, unsigned Opcode,
          unsigned WrapFlags = 0>
struct OverflowingBinaryOp_match {
  LHS_t L;
  RHS_t R;

  OverflowingBinaryOp_match(const LHS_t &LHS, const RHS_t &RHS)
      : L(LHS), R(RHS) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *Op = dyn_cast<OverflowingBinaryOperator>(V)) {
      if (Op->getOpcode() != Opcode)
        return false;
      if (WrapFlags & OverflowingBinaryOperator::NoUnsignedWrap &&
          !Op->hasNoUnsignedWrap())
        return false;
      if (WrapFlags & OverflowingBinaryOperator::NoSignedWrap &&
          !Op->hasNoSignedWrap())
        return false;
      return L.match(Op->getOperand(0)) && R.match(Op->getOperand(1));
    }
    return false;
  }
};

template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Add,
                                 OverflowingBinaryOperator::NoSignedWrap>
m_NSWAdd(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Add,
                                   OverflowingBinaryOperator::NoSignedWrap>(
      L, R);
}
template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Sub,
                                 OverflowingBinaryOperator::NoSignedWrap>
m_NSWSub(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Sub,
                                   OverflowingBinaryOperator::NoSignedWrap>(
      L, R);
}
template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Mul,
                                 OverflowingBinaryOperator::NoSignedWrap>
m_NSWMul(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Mul,
                                   OverflowingBinaryOperator::NoSignedWrap>(
      L, R);
}
template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Shl,
                                 OverflowingBinaryOperator::NoSignedWrap>
m_NSWShl(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Shl,
                                   OverflowingBinaryOperator::NoSignedWrap>(
      L, R);
}

template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Add,
                                 OverflowingBinaryOperator::NoUnsignedWrap>
m_NUWAdd(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Add,
                                   OverflowingBinaryOperator::NoUnsignedWrap>(
      L, R);
}
template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Sub,
                                 OverflowingBinaryOperator::NoUnsignedWrap>
m_NUWSub(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Sub,
                                   OverflowingBinaryOperator::NoUnsignedWrap>(
      L, R);
}
template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Mul,
                                 OverflowingBinaryOperator::NoUnsignedWrap>
m_NUWMul(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Mul,
                                   OverflowingBinaryOperator::NoUnsignedWrap>(
      L, R);
}
template <typename LHS, typename RHS>
inline OverflowingBinaryOp_match<LHS, RHS, Instruction::Shl,
                                 OverflowingBinaryOperator::NoUnsignedWrap>
m_NUWShl(const LHS &L, const RHS &R) {
  return OverflowingBinaryOp_match<LHS, RHS, Instruction::Shl,
                                   OverflowingBinaryOperator::NoUnsignedWrap>(
      L, R);
}

                                                                                
                                                
  
template <typename LHS_t, typename RHS_t, typename Predicate>
struct BinOpPred_match : Predicate {
  LHS_t L;
  RHS_t R;

  BinOpPred_match(const LHS_t &LHS, const RHS_t &RHS) : L(LHS), R(RHS) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *I = dyn_cast<Instruction>(V))
      return this->isOpType(I->getOpcode()) && L.match(I->getOperand(0)) &&
             R.match(I->getOperand(1));
    if (auto *CE = dyn_cast<ConstantExpr>(V))
      return this->isOpType(CE->getOpcode()) && L.match(CE->getOperand(0)) &&
             R.match(CE->getOperand(1));
    return false;
  }
};

struct is_shift_op {
  bool isOpType(unsigned Opcode) { return Instruction::isShift(Opcode); }
};

struct is_right_shift_op {
  bool isOpType(unsigned Opcode) {
    return Opcode == Instruction::LShr || Opcode == Instruction::AShr;
  }
};

struct is_logical_shift_op {
  bool isOpType(unsigned Opcode) {
    return Opcode == Instruction::LShr || Opcode == Instruction::Shl;
  }
};

struct is_bitwiselogic_op {
  bool isOpType(unsigned Opcode) {
    return Instruction::isBitwiseLogicOp(Opcode);
  }
};

struct is_idiv_op {
  bool isOpType(unsigned Opcode) {
    return Opcode == Instruction::SDiv || Opcode == Instruction::UDiv;
  }
};

                             
template <typename LHS, typename RHS>
inline BinOpPred_match<LHS, RHS, is_shift_op> m_Shift(const LHS &L,
                                                      const RHS &R) {
  return BinOpPred_match<LHS, RHS, is_shift_op>(L, R);
}

                                     
template <typename LHS, typename RHS>
inline BinOpPred_match<LHS, RHS, is_right_shift_op> m_Shr(const LHS &L,
                                                          const RHS &R) {
  return BinOpPred_match<LHS, RHS, is_right_shift_op>(L, R);
}

                                     
template <typename LHS, typename RHS>
inline BinOpPred_match<LHS, RHS, is_logical_shift_op>
m_LogicalShift(const LHS &L, const RHS &R) {
  return BinOpPred_match<LHS, RHS, is_logical_shift_op>(L, R);
}

                                     
template <typename LHS, typename RHS>
inline BinOpPred_match<LHS, RHS, is_bitwiselogic_op>
m_BitwiseLogic(const LHS &L, const RHS &R) {
  return BinOpPred_match<LHS, RHS, is_bitwiselogic_op>(L, R);
}

                                        
template <typename LHS, typename RHS>
inline BinOpPred_match<LHS, RHS, is_idiv_op> m_IDiv(const LHS &L,
                                                    const RHS &R) {
  return BinOpPred_match<LHS, RHS, is_idiv_op>(L, R);
}

                                                                                
                                       
  
template <typename SubPattern_t> struct Exact_match {
  SubPattern_t SubPattern;

  Exact_match(const SubPattern_t &SP) : SubPattern(SP) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *PEO = dyn_cast<PossiblyExactOperator>(V))
      return PEO->isExact() && SubPattern.match(V);
    return false;
  }
};

template <typename T> inline Exact_match<T> m_Exact(const T &SubPattern) {
  return SubPattern;
}

                                                                                
                               
  

template <typename LHS_t, typename RHS_t, typename Class, typename PredicateTy,
          bool Commutable = false>
struct CmpClass_match {
  PredicateTy &Predicate;
  LHS_t L;
  RHS_t R;

                                                                        
                                     
  CmpClass_match(PredicateTy &Pred, const LHS_t &LHS, const RHS_t &RHS)
      : Predicate(Pred), L(LHS), R(RHS) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *I = dyn_cast<Class>(V))
      if ((L.match(I->getOperand(0)) && R.match(I->getOperand(1))) ||
          (Commutable && L.match(I->getOperand(1)) &&
           R.match(I->getOperand(0)))) {
        Predicate = I->getPredicate();
        return true;
      }
    return false;
  }
};

template <typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, CmpInst, CmpInst::Predicate>
m_Cmp(CmpInst::Predicate &Pred, const LHS &L, const RHS &R) {
  return CmpClass_match<LHS, RHS, CmpInst, CmpInst::Predicate>(Pred, L, R);
}

template <typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, ICmpInst, ICmpInst::Predicate>
m_ICmp(ICmpInst::Predicate &Pred, const LHS &L, const RHS &R) {
  return CmpClass_match<LHS, RHS, ICmpInst, ICmpInst::Predicate>(Pred, L, R);
}

template <typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, FCmpInst, FCmpInst::Predicate>
m_FCmp(FCmpInst::Predicate &Pred, const LHS &L, const RHS &R) {
  return CmpClass_match<LHS, RHS, FCmpInst, FCmpInst::Predicate>(Pred, L, R);
}

                                                                                
                                                                        
  

                                                        
template <typename T0, unsigned Opcode> struct OneOps_match {
  T0 Op1;

  OneOps_match(const T0 &Op1) : Op1(Op1) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (V->getValueID() == Value::InstructionVal + Opcode) {
      auto *I = cast<Instruction>(V);
      return Op1.match(I->getOperand(0));
    }
    return false;
  }
};

                                                        
template <typename T0, typename T1, unsigned Opcode> struct TwoOps_match {
  T0 Op1;
  T1 Op2;

  TwoOps_match(const T0 &Op1, const T1 &Op2) : Op1(Op1), Op2(Op2) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (V->getValueID() == Value::InstructionVal + Opcode) {
      auto *I = cast<Instruction>(V);
      return Op1.match(I->getOperand(0)) && Op2.match(I->getOperand(1));
    }
    return false;
  }
};

                                                        
template <typename T0, typename T1, typename T2, unsigned Opcode>
struct ThreeOps_match {
  T0 Op1;
  T1 Op2;
  T2 Op3;

  ThreeOps_match(const T0 &Op1, const T1 &Op2, const T2 &Op3)
      : Op1(Op1), Op2(Op2), Op3(Op3) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (V->getValueID() == Value::InstructionVal + Opcode) {
      auto *I = cast<Instruction>(V);
      return Op1.match(I->getOperand(0)) && Op2.match(I->getOperand(1)) &&
             Op3.match(I->getOperand(2));
    }
    return false;
  }
};

                       
template <typename Cond, typename LHS, typename RHS>
inline ThreeOps_match<Cond, LHS, RHS, Instruction::Select>
m_Select(const Cond &C, const LHS &L, const RHS &R) {
  return ThreeOps_match<Cond, LHS, RHS, Instruction::Select>(C, L, R);
}

                                                 
                                  
template <int64_t L, int64_t R, typename Cond>
inline ThreeOps_match<Cond, constantint_match<L>, constantint_match<R>,
                      Instruction::Select>
m_SelectCst(const Cond &C) {
  return m_Select(C, m_ConstantInt<L>(), m_ConstantInt<R>());
}

                              
template <typename Val_t, typename Elt_t, typename Idx_t>
inline ThreeOps_match<Val_t, Elt_t, Idx_t, Instruction::InsertElement>
m_InsertElement(const Val_t &Val, const Elt_t &Elt, const Idx_t &Idx) {
  return ThreeOps_match<Val_t, Elt_t, Idx_t, Instruction::InsertElement>(
      Val, Elt, Idx);
}

                               
template <typename Val_t, typename Idx_t>
inline TwoOps_match<Val_t, Idx_t, Instruction::ExtractElement>
m_ExtractElement(const Val_t &Val, const Idx_t &Idx) {
  return TwoOps_match<Val_t, Idx_t, Instruction::ExtractElement>(Val, Idx);
}

                              
template <typename V1_t, typename V2_t, typename Mask_t>
inline ThreeOps_match<V1_t, V2_t, Mask_t, Instruction::ShuffleVector>
m_ShuffleVector(const V1_t &v1, const V2_t &v2, const Mask_t &m) {
  return ThreeOps_match<V1_t, V2_t, Mask_t, Instruction::ShuffleVector>(v1, v2,
                                                                        m);
}

                     
template <typename OpTy>
inline OneOps_match<OpTy, Instruction::Load> m_Load(const OpTy &Op) {
  return OneOps_match<OpTy, Instruction::Load>(Op);
}

                      
template <typename ValueOpTy, typename PointerOpTy>
inline TwoOps_match<ValueOpTy, PointerOpTy, Instruction::Store>
m_Store(const ValueOpTy &ValueOp, const PointerOpTy &PointerOp) {
  return TwoOps_match<ValueOpTy, PointerOpTy, Instruction::Store>(ValueOp,
                                                                  PointerOp);
}

                                                                                
                                
  

template <typename Op_t, unsigned Opcode> struct CastClass_match {
  Op_t Op;

  CastClass_match(const Op_t &OpMatch) : Op(OpMatch) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *O = dyn_cast<Operator>(V))
      return O->getOpcode() == Opcode && Op.match(O->getOperand(0));
    return false;
  }
};

                    
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::BitCast> m_BitCast(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::BitCast>(Op);
}

                     
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::PtrToInt> m_PtrToInt(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::PtrToInt>(Op);
}

                  
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::Trunc> m_Trunc(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::Trunc>(Op);
}

                 
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::SExt> m_SExt(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::SExt>(Op);
}

                 
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::ZExt> m_ZExt(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::ZExt>(Op);
}

template <typename OpTy>
inline match_combine_or<CastClass_match<OpTy, Instruction::ZExt>,
                        CastClass_match<OpTy, Instruction::SExt>>
m_ZExtOrSExt(const OpTy &Op) {
  return m_CombineOr(m_ZExt(Op), m_SExt(Op));
}

                   
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::UIToFP> m_UIToFP(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::UIToFP>(Op);
}

                   
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::SIToFP> m_SIToFP(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::SIToFP>(Op);
}

                   
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::FPTrunc> m_FPTrunc(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::FPTrunc>(Op);
}

                 
template <typename OpTy>
inline CastClass_match<OpTy, Instruction::FPExt> m_FPExt(const OpTy &Op) {
  return CastClass_match<OpTy, Instruction::FPExt>(Op);
}

                                                                                
                             
  

struct br_match {
  BasicBlock *&Succ;

  br_match(BasicBlock *&Succ) : Succ(Succ) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *BI = dyn_cast<BranchInst>(V))
      if (BI->isUnconditional()) {
        Succ = BI->getSuccessor(0);
        return true;
      }
    return false;
  }
};

inline br_match m_UnconditionalBr(BasicBlock *&Succ) { return br_match(Succ); }

template <typename Cond_t> struct brc_match {
  Cond_t Cond;
  BasicBlock *&T, *&F;

  brc_match(const Cond_t &C, BasicBlock *&t, BasicBlock *&f)
      : Cond(C), T(t), F(f) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (auto *BI = dyn_cast<BranchInst>(V))
      if (BI->isConditional() && Cond.match(BI->getCondition())) {
        T = BI->getSuccessor(0);
        F = BI->getSuccessor(1);
        return true;
      }
    return false;
  }
};

template <typename Cond_t>
inline brc_match<Cond_t> m_Br(const Cond_t &C, BasicBlock *&T, BasicBlock *&F) {
  return brc_match<Cond_t>(C, T, F);
}

                                                                                
                                                                           
  

template <typename CmpInst_t, typename LHS_t, typename RHS_t, typename Pred_t,
          bool Commutable = false>
struct MaxMin_match {
  LHS_t L;
  RHS_t R;

                                                                        
                                     
  MaxMin_match(const LHS_t &LHS, const RHS_t &RHS) : L(LHS), R(RHS) {}

  template <typename OpTy> bool match(OpTy *V) {
                                                             
    auto *SI = dyn_cast<SelectInst>(V);
    if (!SI)
      return false;
    auto *Cmp = dyn_cast<CmpInst_t>(SI->getCondition());
    if (!Cmp)
      return false;
                                                                              
                                                                       
    Value *TrueVal = SI->getTrueValue();
    Value *FalseVal = SI->getFalseValue();
    Value *LHS = Cmp->getOperand(0);
    Value *RHS = Cmp->getOperand(1);
    if ((TrueVal != LHS || FalseVal != RHS) &&
        (TrueVal != RHS || FalseVal != LHS))
      return false;
    typename CmpInst_t::Predicate Pred =
        LHS == TrueVal ? Cmp->getPredicate() : Cmp->getInversePredicate();
                                                                         
    if (!Pred_t::match(Pred))
      return false;
                                   
    return (L.match(LHS) && R.match(RHS)) ||
           (Commutable && L.match(RHS) && R.match(LHS));
  }
};

                                                       
struct smax_pred_ty {
  static bool match(ICmpInst::Predicate Pred) {
    return Pred == CmpInst::ICMP_SGT || Pred == CmpInst::ICMP_SGE;
  }
};

                                                       
struct smin_pred_ty {
  static bool match(ICmpInst::Predicate Pred) {
    return Pred == CmpInst::ICMP_SLT || Pred == CmpInst::ICMP_SLE;
  }
};

                                                         
struct umax_pred_ty {
  static bool match(ICmpInst::Predicate Pred) {
    return Pred == CmpInst::ICMP_UGT || Pred == CmpInst::ICMP_UGE;
  }
};

                                                         
struct umin_pred_ty {
  static bool match(ICmpInst::Predicate Pred) {
    return Pred == CmpInst::ICMP_ULT || Pred == CmpInst::ICMP_ULE;
  }
};

                                                        
struct ofmax_pred_ty {
  static bool match(FCmpInst::Predicate Pred) {
    return Pred == CmpInst::FCMP_OGT || Pred == CmpInst::FCMP_OGE;
  }
};

                                                        
struct ofmin_pred_ty {
  static bool match(FCmpInst::Predicate Pred) {
    return Pred == CmpInst::FCMP_OLT || Pred == CmpInst::FCMP_OLE;
  }
};

                                                          
struct ufmax_pred_ty {
  static bool match(FCmpInst::Predicate Pred) {
    return Pred == CmpInst::FCMP_UGT || Pred == CmpInst::FCMP_UGE;
  }
};

                                                          
struct ufmin_pred_ty {
  static bool match(FCmpInst::Predicate Pred) {
    return Pred == CmpInst::FCMP_ULT || Pred == CmpInst::FCMP_ULE;
  }
};

template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, smax_pred_ty> m_SMax(const LHS &L,
                                                             const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, smax_pred_ty>(L, R);
}

template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, smin_pred_ty> m_SMin(const LHS &L,
                                                             const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, smin_pred_ty>(L, R);
}

template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, umax_pred_ty> m_UMax(const LHS &L,
                                                             const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, umax_pred_ty>(L, R);
}

template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, umin_pred_ty> m_UMin(const LHS &L,
                                                             const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, umin_pred_ty>(L, R);
}

                                                       
                                                                            
                                                                               
                                                                               
                                                                        
                                                                         
   
                                                              
                                                         
template <typename LHS, typename RHS>
inline MaxMin_match<FCmpInst, LHS, RHS, ofmax_pred_ty> m_OrdFMax(const LHS &L,
                                                                 const RHS &R) {
  return MaxMin_match<FCmpInst, LHS, RHS, ofmax_pred_ty>(L, R);
}

                                                       
                                                                            
                                                                               
                                                                               
                                                                        
                                                                         
   
                                                              
                                                         
template <typename LHS, typename RHS>
inline MaxMin_match<FCmpInst, LHS, RHS, ofmin_pred_ty> m_OrdFMin(const LHS &L,
                                                                 const RHS &R) {
  return MaxMin_match<FCmpInst, LHS, RHS, ofmin_pred_ty>(L, R);
}

                                                         
                                                                            
                                                                               
                                                                               
                                                                        
                                                                         
   
                                                              
                                                         
template <typename LHS, typename RHS>
inline MaxMin_match<FCmpInst, LHS, RHS, ufmax_pred_ty>
m_UnordFMax(const LHS &L, const RHS &R) {
  return MaxMin_match<FCmpInst, LHS, RHS, ufmax_pred_ty>(L, R);
}

                                                         
                                                                            
                                                                               
                                                                               
                                                                        
                                                                         
   
                                                               
                                                          
template <typename LHS, typename RHS>
inline MaxMin_match<FCmpInst, LHS, RHS, ufmin_pred_ty>
m_UnordFMin(const LHS &L, const RHS &R) {
  return MaxMin_match<FCmpInst, LHS, RHS, ufmin_pred_ty>(L, R);
}

                                                                                
                                                          
  

template <typename LHS_t, typename RHS_t, typename Sum_t>
struct UAddWithOverflow_match {
  LHS_t L;
  RHS_t R;
  Sum_t S;

  UAddWithOverflow_match(const LHS_t &L, const RHS_t &R, const Sum_t &S)
      : L(L), R(R), S(S) {}

  template <typename OpTy> bool match(OpTy *V) {
    Value *ICmpLHS, *ICmpRHS;
    ICmpInst::Predicate Pred;
    if (!m_ICmp(Pred, m_Value(ICmpLHS), m_Value(ICmpRHS)).match(V))
      return false;

    Value *AddLHS, *AddRHS;
    auto AddExpr = m_Add(m_Value(AddLHS), m_Value(AddRHS));

                                 
    if (Pred == ICmpInst::ICMP_ULT)
      if (AddExpr.match(ICmpLHS) && (ICmpRHS == AddLHS || ICmpRHS == AddRHS))
        return L.match(AddLHS) && R.match(AddRHS) && S.match(ICmpLHS);

                                 
    if (Pred == ICmpInst::ICMP_UGT)
      if (AddExpr.match(ICmpRHS) && (ICmpLHS == AddLHS || ICmpLHS == AddRHS))
        return L.match(AddLHS) && R.match(AddRHS) && S.match(ICmpRHS);

    return false;
  }
};

                                                                         
   
                                                                                
                                                
template <typename LHS_t, typename RHS_t, typename Sum_t>
UAddWithOverflow_match<LHS_t, RHS_t, Sum_t>
m_UAddWithOverflow(const LHS_t &L, const RHS_t &R, const Sum_t &S) {
  return UAddWithOverflow_match<LHS_t, RHS_t, Sum_t>(L, R, S);
}

template <typename Opnd_t> struct Argument_match {
  unsigned OpI;
  Opnd_t Val;

  Argument_match(unsigned OpIdx, const Opnd_t &V) : OpI(OpIdx), Val(V) {}

  template <typename OpTy> bool match(OpTy *V) {
    CallSite CS(V);
    return CS.isCall() && Val.match(CS.getArgument(OpI));
  }
};

                      
template <unsigned OpI, typename Opnd_t>
inline Argument_match<Opnd_t> m_Argument(const Opnd_t &Op) {
  return Argument_match<Opnd_t>(OpI, Op);
}

                       
struct IntrinsicID_match {
  unsigned ID;

  IntrinsicID_match(Intrinsic::ID IntrID) : ID(IntrID) {}

  template <typename OpTy> bool match(OpTy *V) {
    if (const auto *CI = dyn_cast<CallInst>(V))
      if (const auto *F = CI->getCalledFunction())
        return F->getIntrinsicID() == ID;
    return false;
  }
};

                                                                   
                                                                              
                                                                             
                                                      
template <typename T0 = void, typename T1 = void, typename T2 = void,
          typename T3 = void, typename T4 = void, typename T5 = void,
          typename T6 = void, typename T7 = void, typename T8 = void,
          typename T9 = void, typename T10 = void>
struct m_Intrinsic_Ty;
template <typename T0> struct m_Intrinsic_Ty<T0> {
  using Ty = match_combine_and<IntrinsicID_match, Argument_match<T0>>;
};
template <typename T0, typename T1> struct m_Intrinsic_Ty<T0, T1> {
  using Ty =
      match_combine_and<typename m_Intrinsic_Ty<T0>::Ty, Argument_match<T1>>;
};
template <typename T0, typename T1, typename T2>
struct m_Intrinsic_Ty<T0, T1, T2> {
  using Ty =
      match_combine_and<typename m_Intrinsic_Ty<T0, T1>::Ty,
                        Argument_match<T2>>;
};
template <typename T0, typename T1, typename T2, typename T3>
struct m_Intrinsic_Ty<T0, T1, T2, T3> {
  using Ty =
      match_combine_and<typename m_Intrinsic_Ty<T0, T1, T2>::Ty,
                        Argument_match<T3>>;
};

                                    
                                            
template <Intrinsic::ID IntrID> inline IntrinsicID_match m_Intrinsic() {
  return IntrinsicID_match(IntrID);
}

template <Intrinsic::ID IntrID, typename T0>
inline typename m_Intrinsic_Ty<T0>::Ty m_Intrinsic(const T0 &Op0) {
  return m_CombineAnd(m_Intrinsic<IntrID>(), m_Argument<0>(Op0));
}

template <Intrinsic::ID IntrID, typename T0, typename T1>
inline typename m_Intrinsic_Ty<T0, T1>::Ty m_Intrinsic(const T0 &Op0,
                                                       const T1 &Op1) {
  return m_CombineAnd(m_Intrinsic<IntrID>(Op0), m_Argument<1>(Op1));
}

template <Intrinsic::ID IntrID, typename T0, typename T1, typename T2>
inline typename m_Intrinsic_Ty<T0, T1, T2>::Ty
m_Intrinsic(const T0 &Op0, const T1 &Op1, const T2 &Op2) {
  return m_CombineAnd(m_Intrinsic<IntrID>(Op0, Op1), m_Argument<2>(Op2));
}

template <Intrinsic::ID IntrID, typename T0, typename T1, typename T2,
          typename T3>
inline typename m_Intrinsic_Ty<T0, T1, T2, T3>::Ty
m_Intrinsic(const T0 &Op0, const T1 &Op1, const T2 &Op2, const T3 &Op3) {
  return m_CombineAnd(m_Intrinsic<IntrID>(Op0, Op1, Op2), m_Argument<3>(Op3));
}

                                             
template <typename Opnd0>
inline typename m_Intrinsic_Ty<Opnd0>::Ty m_BitReverse(const Opnd0 &Op0) {
  return m_Intrinsic<Intrinsic::bitreverse>(Op0);
}

template <typename Opnd0>
inline typename m_Intrinsic_Ty<Opnd0>::Ty m_BSwap(const Opnd0 &Op0) {
  return m_Intrinsic<Intrinsic::bswap>(Op0);
}

template <typename Opnd0>
inline typename m_Intrinsic_Ty<Opnd0>::Ty m_FAbs(const Opnd0 &Op0) {
  return m_Intrinsic<Intrinsic::fabs>(Op0);
}

template <typename Opnd0>
inline typename m_Intrinsic_Ty<Opnd0>::Ty m_FCanonicalize(const Opnd0 &Op0) {
  return m_Intrinsic<Intrinsic::canonicalize>(Op0);
}

template <typename Opnd0, typename Opnd1>
inline typename m_Intrinsic_Ty<Opnd0, Opnd1>::Ty m_FMin(const Opnd0 &Op0,
                                                        const Opnd1 &Op1) {
  return m_Intrinsic<Intrinsic::minnum>(Op0, Op1);
}

template <typename Opnd0, typename Opnd1>
inline typename m_Intrinsic_Ty<Opnd0, Opnd1>::Ty m_FMax(const Opnd0 &Op0,
                                                        const Opnd1 &Op1) {
  return m_Intrinsic<Intrinsic::maxnum>(Op0, Op1);
}

                                                                                
                                                                         
  

                                                              
template <typename LHS, typename RHS>
inline AnyBinaryOp_match<LHS, RHS, true> m_c_BinOp(const LHS &L, const RHS &R) {
  return AnyBinaryOp_match<LHS, RHS, true>(L, R);
}

                                                                      
                                
template <typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, ICmpInst, ICmpInst::Predicate, true>
m_c_ICmp(ICmpInst::Predicate &Pred, const LHS &L, const RHS &R) {
  return CmpClass_match<LHS, RHS, ICmpInst, ICmpInst::Predicate, true>(Pred, L,
                                                                       R);
}

                                                   
template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Add, true> m_c_Add(const LHS &L,
                                                                const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Add, true>(L, R);
}

                                                   
template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Mul, true> m_c_Mul(const LHS &L,
                                                                const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Mul, true>(L, R);
}

                                                    
template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::And, true> m_c_And(const LHS &L,
                                                                const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::And, true>(L, R);
}

                                                   
template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Or, true> m_c_Or(const LHS &L,
                                                              const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Or, true>(L, R);
}

                                                    
template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::Xor, true> m_c_Xor(const LHS &L,
                                                                const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::Xor, true>(L, R);
}

                                  
template <typename ValTy>
inline BinaryOp_match<cst_pred_ty<is_zero_int>, ValTy, Instruction::Sub>
m_Neg(const ValTy &V) {
  return m_Sub(m_ZeroInt(), V);
}

                                                  
template <typename ValTy>
inline BinaryOp_match<ValTy, cst_pred_ty<is_all_ones>, Instruction::Xor, true>
m_Not(const ValTy &V) {
  return m_c_Xor(V, m_AllOnes());
}

                                                     
template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, smin_pred_ty, true>
m_c_SMin(const LHS &L, const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, smin_pred_ty, true>(L, R);
}
                                                     
template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, smax_pred_ty, true>
m_c_SMax(const LHS &L, const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, smax_pred_ty, true>(L, R);
}
                                                    
template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, umin_pred_ty, true>
m_c_UMin(const LHS &L, const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, umin_pred_ty, true>(L, R);
}
                                                    
template <typename LHS, typename RHS>
inline MaxMin_match<ICmpInst, LHS, RHS, umax_pred_ty, true>
m_c_UMax(const LHS &L, const RHS &R) {
  return MaxMin_match<ICmpInst, LHS, RHS, umax_pred_ty, true>(L, R);
}

                                                  
template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::FAdd, true>
m_c_FAdd(const LHS &L, const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::FAdd, true>(L, R);
}

                                                  
template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, Instruction::FMul, true>
m_c_FMul(const LHS &L, const RHS &R) {
  return BinaryOp_match<LHS, RHS, Instruction::FMul, true>(L, R);
}

template <typename Opnd_t> struct Signum_match {
  Opnd_t Val;
  Signum_match(const Opnd_t &V) : Val(V) {}

  template <typename OpTy> bool match(OpTy *V) {
    unsigned TypeSize = V->getType()->getScalarSizeInBits();
    if (TypeSize == 0)
      return false;

    unsigned ShiftWidth = TypeSize - 1;
    Value *OpL = nullptr, *OpR = nullptr;

                                                     
      
                                            
      
                                                              
      
                                           
      
                     

    auto LHS = m_AShr(m_Value(OpL), m_SpecificInt(ShiftWidth));
    auto RHS = m_LShr(m_Neg(m_Value(OpR)), m_SpecificInt(ShiftWidth));
    auto Signum = m_Or(LHS, RHS);

    return Signum.match(V) && OpL == OpR && Val.match(OpL);
  }
};

                             
   
               
                      
                      
                      
template <typename Val_t> inline Signum_match<Val_t> m_Signum(const Val_t &V) {
  return Signum_match<Val_t>(V);
}

}                              
}                      

#endif                          
