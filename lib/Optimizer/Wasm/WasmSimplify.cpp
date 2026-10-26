/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifdef HERMES_RUN_WASM
#define DEBUG_TYPE "wasmsimplify"
#include "hermes/Optimizer/Wasm/WasmSimplify.h"

#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Wasm/WasmIntrinsics.h"
#include "hermes/Support/Statistic.h"

#include "llvh/Support/Debug.h"

using namespace hermes;
using llvh::dbgs;
using llvh::isa;

STATISTIC(NumWasmSimp, "Number of Wasm ops simplified");

namespace {

Value *simplifyAsUint32(Value *operand) {
  auto *binary = llvh::dyn_cast<BinaryOperatorInst>(operand);
  if (!binary)
    return operand;

  if (binary->getOperatorKind() !=
      BinaryOperatorInst::OpKind::UnsignedRightShiftKind)
    return operand;

  auto *lhs = binary->getLeftHandSide();
  auto *rhs = binary->getRightHandSide();
  auto *amount = llvh::dyn_cast<LiteralNumber>(rhs);
                                                                    
  if (!amount || amount->asUInt32() != 0 || !lhs->getType().isIntegerType())
    return operand;

  return lhs;
}

OptValue<Value *> simplifyBinOpWasm(BinaryOperatorInst *binary) {
  auto kind = binary->getOperatorKind();

  Value *lhs = binary->getLeftHandSide();
  Value *rhs = binary->getRightHandSide();

  Type leftTy = lhs->getType();

  if (!(lhs->getType().isIntegerType() && rhs->getType().isIntegerType()))
    return llvh::None;

  IRBuilder builder(binary->getParent()->getParent());

  llvh::SmallVector<Value *, 2> args{};
  args.push_back(lhs);
  args.push_back(rhs);

  using OpKind = BinaryOperatorInst::OpKind;
  hermes::CallIntrinsicInst *intrinsic = nullptr;
  builder.setInsertionPoint(binary);

  switch (kind) {
    case OpKind::AddKind:
      intrinsic =
          builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_add32, args);
      break;
    case OpKind::SubtractKind:
      intrinsic =
          builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_sub32, args);
      break;
    case OpKind::DivideKind:
                                                       
      if (leftTy.isInt32Type()) {
        intrinsic = builder.createCallIntrinsicInst(
            WasmIntrinsics::__uasm_divi32, args);
      } else {
                                         
        auto lhs_pealed = simplifyAsUint32(lhs);
        auto rhs_pealed = simplifyAsUint32(rhs);
        args.clear();
        args.push_back(lhs_pealed);
        args.push_back(rhs_pealed);
        intrinsic = builder.createCallIntrinsicInst(
            WasmIntrinsics::__uasm_divu32, args);
      }
      break;

    default:
                                              
      return llvh::None;
      break;
  }
  intrinsic->setType(Type::createInt32());
  return intrinsic;
}

                                             
                                                                      
                              
OptValue<Value *> simplifyLoad(LoadPropertyInst *load) {
  auto *loadHeapInst = llvh::dyn_cast<LoadFrameInst>(load->getObject());
  if (!loadHeapInst)
    return llvh::None;
  auto heapStr = loadHeapInst->getLoadVariable()->getName().str();
  if (!heapStr.startswith("HEAP"))
    return llvh::None;
  LLVM_DEBUG(llvh::dbgs() << "found a heap access to " << heapStr << "\n");

                                                    
  auto *addrInst = llvh::dyn_cast<BinaryOperatorInst>(load->getProperty());
  if (!addrInst)
    return llvh::None;
  if (addrInst->getOperatorKind() != BinaryOperatorInst::OpKind::RightShiftKind)
    return llvh::None;
  auto *addr = addrInst->getLeftHandSide();
  auto *amount = llvh::dyn_cast<LiteralNumber>(addrInst->getRightHandSide());
  if (!amount)
    return llvh::None;

                             
  IRBuilder builder(load->getParent()->getParent());
  builder.setInsertionPoint(load);
  llvh::SmallVector<Value *, 2> args{};
  args.push_back(load->getObject());
  args.push_back(addr);

  hermes::CallIntrinsicInst *intrinsic = nullptr;
  if (heapStr == "HEAP8") {
    if (amount->asUInt32() != 0)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_loadi8, args);
  } else if (heapStr == "HEAPU8") {
    if (amount->asUInt32() != 0)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_loadu8, args);
  } else if (heapStr == "HEAP16") {
    if (amount->asUInt32() != 1)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_loadi16, args);
  } else if (heapStr == "HEAPU16") {
    if (amount->asUInt32() != 1)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_loadu16, args);
  } else if (heapStr == "HEAP32") {
    if (amount->asUInt32() != 2)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_loadi32, args);
  } else if (heapStr == "HEAPU32") {
    if (amount->asUInt32() != 2)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_loadu32, args);
  } else {
                                                      
    return llvh::None;
  }
  intrinsic->setType(Type::createInt32());
  return intrinsic;
};

OptValue<Value *> simplifyStore(StorePropertyInst *store) {
  auto *loadHeapInst = llvh::dyn_cast<LoadFrameInst>(store->getObject());
  if (!loadHeapInst)
    return llvh::None;
  auto heapStr = loadHeapInst->getLoadVariable()->getName().str();
  if (!heapStr.startswith("HEAP"))
    return llvh::None;
  LLVM_DEBUG(llvh::dbgs() << "found a heap access to " << heapStr << "\n");

                                                    
  auto *addrInst = llvh::dyn_cast<BinaryOperatorInst>(store->getProperty());
  if (!addrInst)
    return llvh::None;
  if (addrInst->getOperatorKind() != BinaryOperatorInst::OpKind::RightShiftKind)
    return llvh::None;
  auto *addr = addrInst->getLeftHandSide();
  auto *amount = llvh::dyn_cast<LiteralNumber>(addrInst->getRightHandSide());
  if (!amount)
    return llvh::None;

                              
  IRBuilder builder(store->getParent()->getParent());
  builder.setInsertionPoint(store);
  llvh::SmallVector<Value *, 3> args{};
  args.push_back(store->getObject());
  args.push_back(addr);
  args.push_back(store->getStoredValue());

  hermes::CallIntrinsicInst *intrinsic = nullptr;
  if (heapStr == "HEAP8" || heapStr == "HEAPU8") {
    if (amount->asUInt32() != 0)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_store8, args);
  } else if (heapStr == "HEAP16" || heapStr == "HEAPU16") {
    if (amount->asUInt32() != 1)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_store16, args);
  } else if (heapStr == "HEAP32" || heapStr == "HEAPU32") {
    if (amount->asUInt32() != 2)
      return llvh::None;
    intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_store32, args);
  } else {
                                                      
    return llvh::None;
  }
  return intrinsic;
};

OptValue<Value *> simplifyCall(CallInst *call) {
  auto *loadHeapInst = llvh::dyn_cast<LoadFrameInst>(call->getCallee());
  if (!loadHeapInst)
    return llvh::None;
  auto heapStr = loadHeapInst->getLoadVariable()->getName().str();

  IRBuilder builder(call->getParent()->getParent());
  builder.setInsertionPoint(call);
  llvh::SmallVector<Value *, 2> args{};

  if (heapStr == "Math_imul") {
                      
    if (call->getNumArguments() != 3)
      return llvh::None;
    Value *lhs = call->getArgument(1);
    Value *rhs = call->getArgument(2);
                                    
    if (!(lhs->getType().isIntegerType() && rhs->getType().isIntegerType()))
      return llvh::None;
    args.push_back(lhs);
    args.push_back(rhs);
    auto intrinsic =
        builder.createCallIntrinsicInst(WasmIntrinsics::__uasm_mul32, args);
    intrinsic->setType(Type::createInt32());
    return intrinsic;
  }

  return llvh::None;
}

                                                        
                         
                    
                                                           
                                                     
                                                     
OptValue<Value *> wasmSimplifyInstruction(Instruction *I) {
                                                 
  switch (I->getKind()) {
    case ValueKind::BinaryOperatorInstKind:
      return simplifyBinOpWasm(cast<BinaryOperatorInst>(I));
    case ValueKind::LoadPropertyInstKind:
      return simplifyLoad(cast<LoadPropertyInst>(I));
    case ValueKind::StorePropertyInstKind:
      return simplifyStore(cast<StorePropertyInst>(I));
    case ValueKind::CallInstKind:
      return simplifyCall(cast<CallInst>(I));
    default:
                                                      
      return llvh::None;
  }
}

}             

bool WasmSimplify::runOnFunction(Function *F) {
  bool changed = false;
  IRBuilder::InstructionDestroyer destroyer;

                                    
  for (BasicBlock &BB : *F) {
                            
    for (auto instIter = BB.begin(), e = BB.end(); instIter != e;) {
      Instruction *II = &*instIter;
      ++instIter;

                                                             
      auto optNewVal = wasmSimplifyInstruction(II);

                                                      
      if (!optNewVal.hasValue())
        continue;

      auto newVal = optNewVal.getValue();
      changed = true;
      NumWasmSimp++;

                                                                       
                     
      if (newVal) {
        II->replaceAllUsesWith(newVal);
      }
                                                                             
                     
      destroyer.add(II);
    }
  }

  return changed;
}

#undef DEBUG_TYPE
#endif
