/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "instsimplify"

#include "hermes/Optimizer/Scalar/InstSimplify.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/IREval.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseSet.h"

using namespace hermes;

STATISTIC(NumSimp, "Number of instructions simplified");

namespace {

constexpr Type kNullOrUndef =
    Type::unionTy(Type::createUndefined(), Type::createNull());

                                                                            
                             
bool notNaN(Value *value) {
                             
  if (!value->getType().canBeNumber()) {
    return true;
  }

                                             
  if (auto *literalNumber = llvh::dyn_cast<LiteralNumber>(value)) {
    return !std::isnan(literalNumber->getValue());
  }

                                                     
  return false;
}

template <typename T>
Value *reduceAsNumberLike(T *asNumber) {
  IRBuilder builder(asNumber->getParent()->getParent());
  auto *op = asNumber->getSingleOperand();

                                                                
  if (auto *lit = llvh::dyn_cast<Literal>(op)) {
    if (auto *result = evalToNumber(builder, lit)) {
      return result;
    }
  }

                                                         
  if (op->getType().isNumberType()) {
    return op;
  }

                                                               
  return asNumber;
}

Value *reduceAsNumber(AsNumberInst *asNumber) {
  return reduceAsNumberLike(asNumber);
}

Value *reduceAsNumeric(AsNumericInst *asNumeric) {
  auto *op = asNumeric->getSingleOperand();
  if (op->getType().isBigIntType()) {
    return op;
  }

  return reduceAsNumberLike(asNumeric);
}

Value *reduceAsInt32(AsInt32Inst *asInt32) {
  IRBuilder builder(asInt32->getParent()->getParent());
  auto *op = asInt32->getSingleOperand();

                                                                
  if (auto *lit = llvh::dyn_cast<Literal>(op)) {
    if (auto *result = evalToInt32(builder, lit)) {
      return result;
    }
  }

#ifdef HERMES_RUN_WASM
  if (op->getType().isInt32Type()) {
    return op;
  }
#endif

                                                      
  return asInt32;
}

Value *simplifyUnOp(UnaryOperatorInst *unary) {
  IRBuilder builder(unary->getParent()->getParent());

  auto kind = unary->getOperatorKind();
  auto *op = unary->getSingleOperand();
  Type t = op->getType();

                                                                 
  if (auto *lit = llvh::dyn_cast<Literal>(op)) {
    if (auto result = evalUnaryOperator(kind, builder, lit)) {
      return result;
    }
  }

  using OpKind = UnaryOperatorInst::OpKind;

                                               
  switch (kind) {
    case OpKind::TypeofKind:
      if (t.isNullType()) {
        return builder.getLiteralString("object");
      }
      if (t.isNumberType()) {
        return builder.getLiteralString("number");
      }
      if (t.isUndefinedType()) {
        return builder.getLiteralString("undefined");
      }
      if (t.isBooleanType()) {
        return builder.getLiteralString("boolean");
      }
      if (t.isStringType()) {
        return builder.getLiteralString("string");
      }
      if (t.isRegExpType()) {
        return builder.getLiteralString("object");
      }
      if (t.isClosureType()) {
        return builder.getLiteralString("function");
      }
      break;

    case OpKind::BangKind:
      if (op->getType().isSubsetOf(kNullOrUndef)) {
        return builder.getLiteralBool(true);
      }
      break;

    case OpKind::PlusKind:
                                   
      builder.setInsertionPoint(unary);
      return reduceAsNumber(builder.createAsNumberInst(op));

    default:
      break;
  }

  return nullptr;
}

Value *simplifyBinOp(BinaryOperatorInst *binary) {
  IRBuilder builder(binary->getParent()->getParent());

  Value *lhs = binary->getLeftHandSide();
  Value *rhs = binary->getRightHandSide();
  auto kind = binary->getOperatorKind();

                                                       
  auto *litLhs = llvh::dyn_cast<Literal>(lhs);
  auto *litRhs = llvh::dyn_cast<Literal>(rhs);
  if (litLhs && litRhs) {
    if (auto result = evalBinaryOperator(kind, builder, litLhs, litRhs)) {
      return result;
    }
  }

                                                                         
                                                                               
  Type leftTy = lhs->getType();
  Type rightTy = rhs->getType();
  const bool primitiveTypes = leftTy.isPrimitive() && rightTy.isPrimitive();

                                                                          
                                                                             
                                                                             
                     
                                                                              
                                              
  const bool identicalForEquality = primitiveTypes && lhs == rhs && notNaN(lhs);

                                                                       
                                                                           
                                                                        
                 
                                                                               
                                                                          
                                                                            
                                                                            
  bool identicalForRelational =
      identicalForEquality && !leftTy.canBeUndefined();

  using OpKind = BinaryOperatorInst::OpKind;

  switch (kind) {
    case OpKind::EqualKind:      
                                          
      if (identicalForEquality) {
        return builder.getLiteralBool(true);
      }

                                                                          
                                   
      if (leftTy.isKnownPrimitiveType() && rightTy == leftTy) {
        builder.setInsertionPoint(binary);
        return builder.createBinaryOperatorInst(
            lhs, rhs, OpKind::StrictlyEqualKind);
      }
      break;

    case OpKind::NotEqualKind:      
                                               
      if (identicalForEquality) {
        return builder.getLiteralBool(false);
      }

                                                                              
                                   
      if (leftTy.isKnownPrimitiveType() && rightTy == leftTy) {
        builder.setInsertionPoint(binary);
        return builder.createBinaryOperatorInst(
            lhs, rhs, OpKind::StrictlyNotEqualKind);
      }
      break;

    case OpKind::StrictlyEqualKind:       
                                                  
      if (identicalForEquality) {
        return builder.getLiteralBool(true);
      }

                                                             
      if (leftTy.isPrimitive() && rightTy.isPrimitive()) {
        if (Type::intersectTy(leftTy, rightTy).isNoType()) {
          return builder.getLiteralBool(false);
        }
      }
      break;

    case OpKind::StrictlyNotEqualKind:        
                                               
      if (identicalForEquality) {
        return builder.getLiteralBool(false);
      }
      break;

    case OpKind::LessThanKind:     
                                   
      if (identicalForRelational) {
        return builder.getLiteralBool(false);
      }
      break;

    case OpKind::LessThanOrEqualKind:      
                                   
      if (identicalForRelational) {
        return builder.getLiteralBool(true);
      }
      break;

    case OpKind::GreaterThanKind:     
                                   
      if (identicalForRelational) {
        return builder.getLiteralBool(false);
      }
      break;

    case OpKind::GreaterThanOrEqualKind:      
                                   
      if (identicalForRelational) {
        return builder.getLiteralBool(true);
      }
      break;

    case OpKind::AddKind:
                                                     
      if (llvh::isa<LiteralString>(lhs) &&
          cast<LiteralString>(lhs)->getValue().str() == "") {
        builder.setInsertionPoint(binary);
        return builder.createAddEmptyStringInst(rhs);
      } else if (
          llvh::isa<LiteralString>(rhs) &&
          cast<LiteralString>(rhs)->getValue().str() == "") {
        builder.setInsertionPoint(binary);
        return builder.createAddEmptyStringInst(lhs);
      }
      break;

    case OpKind::OrKind: {     
                                               
      Value *nonzeroOp = nullptr;
      if (llvh::isa<LiteralNumber>(lhs) &&
          cast<LiteralNumber>(lhs)->getValue() == 0) {
        nonzeroOp = rhs;
      } else if (
          llvh::isa<LiteralNumber>(rhs) &&
          cast<LiteralNumber>(rhs)->getValue() == 0) {
        nonzeroOp = lhs;
      }
      if (nonzeroOp) {
        builder.setInsertionPoint(binary);
        return reduceAsInt32(builder.createAsInt32Inst(nonzeroOp));
      }
      break;
    }

    default:
      break;
  }

  return nullptr;
}

Value *simplifyPhiInst(PhiInst *P) {
                                                                             
                                                                              
                                                                               
                            
  Value *incoming = nullptr;
  for (int i = 0, e = P->getNumEntries(); i < e; i++) {
    auto E = P->getEntry(i);
                         
    if (E.first == P)
      continue;

                                    
    if (!incoming) {
      incoming = E.first;
      continue;
    }

                                            
    if (incoming != E.first)
      return nullptr;
  }

                                                                          
                        
  if (incoming) {
    P->replaceAllUsesWith(incoming);
    P->eraseFromParent();
  }

  return nullptr;
}

Value *simplifyCondBranchInst(CondBranchInst *CBI) {
  auto *cond = CBI->getCondition();

                                                                           
                          
    
                
                           
    
          
    
                
                           
    
  if (auto *U = llvh::dyn_cast<UnaryOperatorInst>(cond)) {
    if (U->getSideEffect() == SideEffectKind::None &&
        U->getOperatorKind() == UnaryOperatorInst::OpKind::BangKind) {
                            
      CBI->setOperand(U->getSingleOperand(), 0);
                                     
      Value *BB1 = CBI->getOperand(1);
      Value *BB2 = CBI->getOperand(2);
      CBI->setOperand(BB1, 2);
      CBI->setOperand(BB2, 1);
      return CBI;
    }
  }
  return nullptr;
}

                                                               
                                                       
Value *getKnownReturnValue(Function *F, CallInst *callSite) {
  IRBuilder builder(F);
  llvh::DenseSet<Value *> returnValues;

  for (auto &BB : F->getBasicBlockList()) {
    auto *term = BB.getTerminator();
    auto *ret = llvh::dyn_cast<ReturnInst>(term);
    if (!ret)
      continue;

    returnValues.insert(ret->getValue());
  }

                                                             
                                                                
                                                                
  if (returnValues.size() != 1)
    return nullptr;

  Value *v = *returnValues.begin();

                                                  
  if (llvh::isa<Literal>(v))
    return v;

                                                             
                             
  if (auto *P = llvh::dyn_cast<Parameter>(v)) {
                                         
    if (P->isThisParameter())
      return nullptr;

    unsigned idx = P->getIndexInParamList();

                                                     
    if (idx >= callSite->getNumArguments() - 1)
      return builder.getLiteralUndefined();

                                                              
                        
    return callSite->getArgument(idx + 1);
  }

                                           
  return nullptr;
}

Value *simplifyCallInst(CallInst *CI) {
  if (!CI->hasUsers() || llvh::isa<ConstructInst>(CI))
    return nullptr;

  if (Function *F = getCallee(CI->getCallee())) {
    if (Value *V = getKnownReturnValue(F, CI)) {
      CI->replaceAllUsesWith(V);
      return CI;
    }
  }

  return nullptr;
}

Value *simplifyAsNumber(AsNumberInst *asNumber) {
  Value *reduced = reduceAsNumber(asNumber);
  return reduced == asNumber ? nullptr : reduced;
}

bool isUnaryIncOrDec(Value *value) {
  if (auto *unOp = llvh::dyn_cast<UnaryOperatorInst>(value)) {
    switch (unOp->getOperatorKind()) {
      default:
        break;
      case UnaryOperatorInst::OpKind::IncKind:
      case UnaryOperatorInst::OpKind::DecKind:
        return true;
    }
  }

  return false;
}

Value *simplifyAsNumeric(AsNumericInst *asNumeric) {
                                                                              
  Value *reduced = asNumeric;

  if (asNumeric->hasOneUser()) {
    if (isUnaryIncOrDec(*asNumeric->users_begin())) {
                                                                                
                                           
      reduced = asNumeric->getSingleOperand();
    }
  }

  if (reduced == asNumeric) {
                                                                          
               
    reduced = reduceAsNumeric(asNumeric);
  }

  return reduced == asNumeric ? nullptr : reduced;
}

Value *simplifyAsInt32(AsInt32Inst *asInt32) {
  Value *reduced = reduceAsInt32(asInt32);
  return (reduced == asInt32) ? nullptr : reduced;
}

Value *simplifyAddEmptyString(AddEmptyStringInst *AES) {
  IRBuilder builder(AES->getParent()->getParent());
  auto *op = AES->getSingleOperand();

                                                                
  if (auto *lit = llvh::dyn_cast<Literal>(op)) {
    if (auto *result = evalToString(builder, lit)) {
      return result;
    }
  }

                                                         
  if (op->getType().isStringType()) {
    return op;
  }

  return nullptr;
}

Value *simplifyCoerceThisNS(CoerceThisNSInst *coerce) {
  auto *operand = coerce->getSingleOperand();

                                            
  if (operand->getType().isSubsetOf(kNullOrUndef)) {
    IRBuilder builder(coerce->getParent()->getParent());
    builder.setInsertionPoint(coerce);
    return builder.getGlobalObject();
  }

                           
  if (operand->getType().isObjectType())
    return operand;

  return nullptr;
}

                                    
                    
                                                        
                                                          
                                                     
                                                        
OptValue<Value *> simplifyThrowIfEmpty(ThrowIfEmptyInst *TIE) {
                                                                        
                
  if (!TIE->getCheckedValue()->getType().canBeEmpty())
    return TIE->getCheckedValue();
  return nullptr;
}

                                         
                    
                                                        
                                                          
                                                     
                                                        
OptValue<Value *> simplifyInstruction(Instruction *I) {
                                                 
  switch (I->getKind()) {
    case ValueKind::BinaryOperatorInstKind:
      return simplifyBinOp(cast<BinaryOperatorInst>(I));
    case ValueKind::UnaryOperatorInstKind:
      return simplifyUnOp(cast<UnaryOperatorInst>(I));
    case ValueKind::AsNumberInstKind:
      return simplifyAsNumber(cast<AsNumberInst>(I));
    case ValueKind::AsNumericInstKind:
      return simplifyAsNumeric(cast<AsNumericInst>(I));
    case ValueKind::AsInt32InstKind:
      return simplifyAsInt32(cast<AsInt32Inst>(I));
    case ValueKind::AddEmptyStringInstKind:
      return simplifyAddEmptyString(cast<AddEmptyStringInst>(I));
    case ValueKind::PhiInstKind:
      return simplifyPhiInst(cast<PhiInst>(I));
    case ValueKind::CondBranchInstKind:
      return simplifyCondBranchInst(cast<CondBranchInst>(I));
    case ValueKind::CallInstKind:
      return simplifyCallInst(cast<CallInst>(I));
    case ValueKind::CoerceThisNSInstKind:
      return simplifyCoerceThisNS(cast<CoerceThisNSInst>(I));
    case ValueKind::ThrowIfEmptyInstKind:
      return simplifyThrowIfEmpty(cast<ThrowIfEmptyInst>(I));

    default:
                                                  
      return nullptr;
  }
}

}             

bool InstSimplify::runOnFunction(Function *F) {
  bool changed = false;
  IRBuilder::InstructionDestroyer destroyer;

                                                            
  PostOrderAnalysis PO(F);
  for (BasicBlock *BB : llvh::reverse(PO)) {
                            
    for (auto instIter = BB->begin(), e = BB->end(); instIter != e;) {
      Instruction *II = &*instIter;
      ++instIter;

      auto optNewVal = simplifyInstruction(II);
      if (optNewVal.hasValue()) {
        auto newVal = optNewVal.getValue();
        if (!newVal)
          continue;

        changed = true;
        NumSimp++;

                                       
        if (II == newVal)
          continue;

                                                                         
                                                
        II->replaceAllUsesWith(newVal);
      } else {
        changed = true;
        NumSimp++;
      }
      destroyer.add(II);
    }
  }

  return changed;
}

std::unique_ptr<Pass> hermes::createInstSimplify() {
  return std::make_unique<InstSimplify>();
}

#undef DEBUG_TYPE
