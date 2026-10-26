/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifdef HERMES_RUN_WASM
#ifndef HERMES_OPTIMIZER_EMITWASMINTRINSICS_H
#define HERMES_OPTIMIZER_EMITWASMINTRINSICS_H

#include "hermes/Optimizer/PassManager/Pass.h"

namespace hermes {

                                                                            
                            
class EmitWasmIntrinsics : public FunctionPass {
 public:
  explicit EmitWasmIntrinsics() : FunctionPass("EmitWasmIntrinsics") {}

  bool runOnFunction(Function *F) override;
};

}                    

#endif                                         
#endif                   
