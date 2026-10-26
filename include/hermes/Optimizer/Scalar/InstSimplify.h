/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_INSTSIMPLIFY_H
#define HERMES_OPTIMIZER_SCALAR_INSTSIMPLIFY_H

#include "hermes/IR/IR.h"
#include "hermes/Optimizer/PassManager/Pass.h"

namespace hermes {

                                           
class InstSimplify : public FunctionPass {
 public:
  explicit InstSimplify() : FunctionPass("InstSimplify") {}
  ~InstSimplify() override = default;

  bool runOnFunction(Function *F) override;
};

}                    

#endif                                          
