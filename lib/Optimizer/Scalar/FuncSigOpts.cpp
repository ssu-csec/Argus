/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "funcsigopts"

#include "hermes/Optimizer/Scalar/FuncSigOpts.h"
#include "hermes/Optimizer/Scalar/Utils.h"

#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/Support/Debug.h"

STATISTIC(NumParamOpt, "Number of parameters optimized");
STATISTIC(NumArgsOpt, "Number of arguments optimized");

using namespace hermes;
using llvh::dbgs;

                                                                         
               
static bool capturesArgumentVector(Function *F) {
  for (auto &BB : *F) {
    for (auto &I : BB) {
      if (llvh::isa<CreateArgumentsInst>(I))
        return true;
      if (auto *CB = llvh::dyn_cast<CallBuiltinInst>(&I)) {
        if (CB->getBuiltinIndex() == BuiltinMethod::HermesBuiltin_copyRestArgs)
          return true;
      }
    }
  }

  return false;
}

                                                          
                                       
static bool performFSO(Function *F, std::vector<Function *> &worklist) {
  LLVM_DEBUG(dbgs() << "-- Inspecting " << F->getInternalNameStr() << "\n");

  if (capturesArgumentVector(F))
    return false;

                                                                        
                                                                
                                                                          
                                                              
  if (llvh::isa<GeneratorFunction>(F) || llvh::isa<AsyncFunction>(F))
    return false;

  IRBuilder builder(F);

  llvh::SmallVector<CallInst *, 8> callsites;
  if (!getCallSites(F, callsites))
    return false;

  LLVM_DEBUG(dbgs() << "-- Has " << callsites.size() << " call sites\n");

  unsigned numFormalParam = F->getParameters().size();

                                                                   
                                                                         
                                            
  Literal *undef = builder.getLiteralUndefined();
  llvh::SmallVector<std::pair<Literal *, bool>, 8> args(
      numFormalParam, {undef, false});

                                                     
  llvh::SmallVector<std::pair<CallInst *, unsigned>, 8> unusedParams;

                        
  for (CallInst *caller : callsites) {
                                        
    for (unsigned i = 0; i < numFormalParam; i++) {
                                                                             
                               
      Value *arg = undef;
      if (i < caller->getNumArguments() - 1)
        arg = caller->getArgument(i + 1);

      auto *L = llvh::dyn_cast<Literal>(arg);
      if (L) {
        LLVM_DEBUG(
            dbgs() << "-- Found literal for argument " << i << ": "
                   << L->getKindStr() << ".\n");
      }

                                                                    
      if (!args[i].second) {
        args[i] = {L, true};
        continue;
      }

                                                                             
                                            
      Literal *prev = args[i].first;
      if (prev != L) {
        LLVM_DEBUG(
            dbgs() << "-- Found disagreement for argument " << i << "\n");
        LLVM_DEBUG(
            dbgs() << "-- Previous value is "
                   << (prev ? prev->getKindStr() : "nullptr") << ".\n");
        args[i] = {nullptr, true};
      }
    }

                                                  
                                                                         
    for (unsigned i = 1, e = caller->getNumArguments(); i < e; i++) {
                                                                              
                                          
      if (i > numFormalParam || !F->getParameters()[i - 1]->hasUsers()) {
        unusedParams.push_back({caller, i});
      }
    }
  }

  LLVM_DEBUG(dbgs() << "-- Found " << unusedParams.size() << " unused args.\n");

  bool changed = false;

  unsigned paramIdx = 0;
  for (auto *P : F->getParameters()) {
    LLVM_DEBUG(dbgs() << "-- Inspecting param " << P->getName().str() << ".\n");

    if (Literal *L = args[paramIdx].first) {
      LLVM_DEBUG(
          dbgs() << "-- Found literal " << L->getKindStr() << " for param "
                 << P->getName().str() << ".\n");
      P->replaceAllUsesWith(L);
      changed = true;
      NumParamOpt++;
    }

    paramIdx++;
  }

  llvh::DenseSet<Function *> toRedo;

                                             
  for (auto &arg : unusedParams) {
    auto *prevArg = arg.first->getArgument(arg.second);
    if (!llvh::isa<Literal>(prevArg))
      toRedo.insert(arg.first->getParent()->getParent());

    arg.first->setArgument(undef, arg.second);
    NumArgsOpt++;
  }

  for (auto *fRedo : toRedo) {
    worklist.push_back(fRedo);
  }

  return changed;
}

bool FuncSigOpts::runOnModule(Module *M) {
  bool changed = false;

  std::vector<Function *> worklist;

  for (auto &F : *M) {
    if (M->findCJSModule(&F)) {
                                                                 
      continue;
    }

    worklist.push_back(&F);
  }

                           
  while (worklist.size()) {
    Function *F = worklist.back();
    worklist.pop_back();
    changed |= performFSO(F, worklist);
  }

  return changed;
}

std::unique_ptr<Pass> hermes::createFuncSigOpts() {
  return std::make_unique<FuncSigOpts>();
}

#undef DEBUG_TYPE
