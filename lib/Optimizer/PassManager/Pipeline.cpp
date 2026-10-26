/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Optimizer/PassManager/Pipeline.h"

#include "hermes/Optimizer/PassManager/PassManager.h"
#include "hermes/Optimizer/Scalar/Auditor.h"
#include "hermes/Optimizer/Scalar/DCE.h"
#include "hermes/Optimizer/Scalar/ScopeTransformations.h"
#include "hermes/Optimizer/Scalar/SimplifyCFG.h"
#include "hermes/Optimizer/Scalar/TypeInference.h"
#include "hermes/Optimizer/Taint/TaintAnalysis.h"
#include "hermes/Optimizer/Wasm/EmitWasmIntrinsics.h"
#include "hermes/Optimizer/Wasm/WasmSimplify.h"

#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"

#define DEBUG_TYPE "pipeline"

using llvh::dbgs;

bool hermes::runCustomOptimizationPasses(
    Module &M,
    const std::vector<std::string> &Opts) {
  LLVM_DEBUG(dbgs() << "Optimizing with custom pipeline...\n");
  PassManager PM{M.getContext().getCodeGenerationSettings()};

                                 
  for (auto P : Opts) {
    if (!PM.addPassForName(P)) {
      return false;
    }
  }
                           
  PM.run(&M);
  return true;
}

void hermes::runFullOptimizationPasses(Module &M) {
  LLVM_DEBUG(dbgs() << "Running -O3 optimizations...\n");
  PassManager PM{M.getContext().getCodeGenerationSettings()};

                                                                    
  PM.addPass<TaintAnalysis>();

                                 
  if (M.getContext().getCodeGenerationSettings().enableBlockScoping) {
    PM.addPass<ScopeMerger>();
  }

                                                           
  PM.addInstSimplify();
  PM.addResolveStaticRequire();
                                                                            
                                                                              
  PM.addDCE();

  PM.addTypeInference();
  PM.addSimplifyCFG();
  PM.addSimpleStackPromotion();
  PM.addMem2Reg();
  PM.addSimpleStackPromotion();
  PM.addInlining();
  PM.addSimpleStackPromotion();
  PM.addInstSimplify();
  PM.addDCE();
  PM.addSimpleStackPromotion();

#ifdef HERMES_RUN_WASM
  if (M.getContext().getUseUnsafeIntrinsics()) {
    PM.addTypeInference();
    PM.addPass<WasmSimplify>();
  }
#endif                   

                                                                             
  PM.addTypeInference();
  PM.addCSE();
  PM.addSimplifyCFG();

  PM.addInstSimplify();
  PM.addFuncSigOpts();
  PM.addDCE();
  PM.addSimplifyCFG();
  PM.addMem2Reg();
  PM.addAuditor();

  PM.addTypeInference();

                                                                
  PM.addHoistStartGenerator();

#ifdef HERMES_RUN_WASM
                                                             
  if (M.getContext().getUseUnsafeIntrinsics()) {
    PM.addPass<EmitWasmIntrinsics>();
  }
#endif                   

                           
  PM.run(&M);
}

void hermes::runDebugOptimizationPasses(Module &M) {
  LLVM_DEBUG(dbgs() << "Running -Og optimizations...\n");
  PassManager PM{M.getContext().getCodeGenerationSettings()};

                                                                    
  PM.addPass<TaintAnalysis>();

  PM.addInstSimplify();
  PM.addResolveStaticRequire();

                                                                
  PM.addHoistStartGenerator();

#ifdef HERMES_RUN_WASM
                                                             
  if (M.getContext().getUseUnsafeIntrinsics()) {
    PM.addPass<EmitWasmIntrinsics>();
  }
#endif                   

                           
  PM.run(&M);
}

#ifdef HERMES_RUN_WASM
void hermes::runNoOptimizationPasses(Module &M) {
  LLVM_DEBUG(dbgs() << "Running -O0 optimizations...\n");

                                          
  PassManager PM{M.getContext().getCodeGenerationSettings()};
  PM.addPass<TaintAnalysis>();

                                                             
  if (M.getContext().getUseUnsafeIntrinsics()) {
    PM.addPass<EmitWasmIntrinsics>();
  }
  
  PM.run(&M);
}
#else
void hermes::runNoOptimizationPasses(Module &M) {
  LLVM_DEBUG(dbgs() << "Running -O0 optimizations...\n");
  
                                          
  PassManager PM{M.getContext().getCodeGenerationSettings()};
  PM.addPass<TaintAnalysis>();
  PM.run(&M);
}
#endif                   

#undef DEBUG_TYPE
