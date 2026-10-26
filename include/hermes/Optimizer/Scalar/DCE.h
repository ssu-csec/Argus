/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_DCE_H
#define HERMES_OPTIMIZER_SCALAR_DCE_H

#include "hermes/IR/IR.h"
#include "hermes/Optimizer/PassManager/Pass.h"

namespace hermes {

                                      
class DCE : public ModulePass {
 public:
  explicit DCE() : hermes::ModulePass("DCE") {}
  ~DCE() override = default;

  bool runOnModule(Module *M) override;
};

}                    

#endif                                 
