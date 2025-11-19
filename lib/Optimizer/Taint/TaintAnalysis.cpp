/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
#define DEBUG_TYPE "taintanalysis"
#include "hermes/Optimizer/Taint/TaintAnalysis.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"

using namespace hermes;
using llvh::dbgs;
using llvh::outs;

bool TaintAnalysis::runOnModule(Module *M) {
    // Print a separator for better readability
    outs() << "\n";
    outs() << "========================================\n";
    outs() << "=== Hermes IR Dump\n";
    outs() << "========================================\n\n";

    // Module statistics
    unsigned numFunctions = 0;
    unsigned numBasicBlocks = 0;
    unsigned numInstructions = 0;
  
    for (auto &F : *M) {
        numFunctions++;
        for (auto &BB : F) {
        numBasicBlocks++;
        numInstructions += BB.getInstList().size();
        }
    }
  
    outs() << "Module Statistics:\n";
    outs() << "  Functions:     " << numFunctions << "\n";
    outs() << "  Basic Blocks:  " << numBasicBlocks << "\n";
    outs() << "  Instructions:  " << numInstructions << "\n";
    outs() << "\n";
  
    // Print each function with detailed information
    for (auto &F : *M) {
        outs() << "========================================\n";
        outs() << "Function: " << F.getInternalName() << "\n";
        outs() << "  Scope: " << (F.isGlobalScope() ? "Global" : "Local") << "\n";
        outs() << "  Strict Mode: " << (F.isStrictMode() ? "Yes" : "No") << "\n";
        outs() << "  Parameters: " << F.getParameters().size() << "\n";
        outs() << "  Basic Blocks: " << F.getBasicBlockList().size() << "\n";
        outs() << "----------------------------------------\n";
    
        // Dump function IR
        F.dump(outs());
        outs() << "\n";
    }

    // Print end separator
    outs() << "\n";
    outs() << "========================================\n";
    outs() << "=== End of IR Dump\n";
    outs() << "========================================\n\n";

    // Alternative: Print each function separately with more details
    /*
    for (auto &F : *M) {
        outs() << "Function: " << F.getInternalName() << "\n";
        outs() << "----------------------------------------\n";
        F.dump(outs());
        outs() << "\n";
    }
    */

    // Return false because this pass does not modify the IR
    return false;
}

std::unique_ptr<Pass> hermes::createTaintAnalysis() {
    return std::make_unique<TaintAnalysis>();
}

#undef DEBUG_TYPE