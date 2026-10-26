/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/TraverseLiteralStrings.h"
#include "hermes/IR/Instrs.h"

#include <functional>

namespace {

using namespace hermes;

                                                                           
                                                                             
               
bool isIdOperand(Instruction *I, unsigned idx) {
#define CASE_WITH_PROP_IDX(INSN) \
  case ValueKind::INSN##Kind:    \
    return idx == INSN::PropertyIdx

  switch (I->getKind()) {
    CASE_WITH_PROP_IDX(DeletePropertyInst);
    CASE_WITH_PROP_IDX(LoadPropertyInst);
    CASE_WITH_PROP_IDX(StoreNewOwnPropertyInst);
    CASE_WITH_PROP_IDX(StorePropertyInst);
    CASE_WITH_PROP_IDX(TryLoadGlobalPropertyInst);
    CASE_WITH_PROP_IDX(TryStoreGlobalPropertyInst);
    CASE_WITH_PROP_IDX(ThrowIfHasRestrictedGlobalPropertyInst);

    case ValueKind::HBCAllocObjectFromBufferInstKind:
                                                                        
                                            
      return (idx - HBCAllocObjectFromBufferInst::FirstKeyIdx) % 2 == 0;

    default:
      return false;
  }
#undef CASE
}

}             

namespace hermes {
namespace hbc {

void traverseFunctions(
    Module *M,
    std::function<bool(Function *)> shouldVisitFunction,
    std::function<void(llvh::StringRef)> traversal,
    std::function<void(llvh::StringRef)> functionSourceTraversal,
    bool stripFunctionNames) {
  for (auto &F : *M) {
    if (!shouldVisitFunction(&F)) {
      continue;
    }
    if (!stripFunctionNames) {
      traversal(F.getOriginalOrInferredName().str());
    }
                                                                            
                                                                             
                                          
    if (!F.isGlobalScope()) {
                                                                        
      if (auto source = F.getSourceRepresentationStr()) {
        functionSourceTraversal(*source);
      }
    }
  }
}

void traverseCJSModuleNames(
    Module *M,
    std::function<bool(Function *)> shouldVisitFunction,
    std::function<void(llvh::StringRef)> traversal) {
  for (auto &F : *M) {
    if (!shouldVisitFunction(&F)) {
      continue;
    }

    if (auto *cjsModule = M->findCJSModule(&F)) {
      traversal(cjsModule->filename.str());
    }
  }
}

void traverseLiteralStrings(
    Module *M,
    std::function<bool(Function *)> shouldVisitFunction,
    std::function<void(llvh::StringRef, bool)> traversal) {
                                     
  for (auto *prop : M->getGlobalProperties()) {
    if (prop->isDeclared()) {
      traversal(prop->getName()->getValue().str(),                    true);
    }
  }

                    
  for (auto &F : *M) {
    if (!shouldVisitFunction(&F)) {
      continue;
    }

    for (auto &BB : F) {
                                   
      for (auto &I : BB) {
        for (int i = 0, e = I.getNumOperands(); i < e; i++) {
          auto *op = I.getOperand(i);
          if (auto *str = llvh::dyn_cast<LiteralString>(op)) {
            traversal(str->getValue().str(), isIdOperand(&I, i));
          }
        }
      }
    }
  }
}

}                 
}                    
