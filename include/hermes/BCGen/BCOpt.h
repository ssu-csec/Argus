/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_BCOPT_H
#define HERMES_BCGEN_BCOPT_H

#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/PassManager/Pass.h"
#include "hermes/Optimizer/PassManager/PassManager.h"

namespace hermes {
class RegisterAllocator;

                                                                 
class MovElimination : public FunctionPass {
 public:
  explicit MovElimination(RegisterAllocator &RA)
      : FunctionPass("MovElimination"), RA_(RA) {}
  ~MovElimination() override = default;

  bool runOnFunction(Function *F) override;

 private:
  RegisterAllocator &RA_;
};

}                    

#endif
