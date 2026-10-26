/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_PASSES_OPTENVIRONMENTINIT_H
#define HERMES_BCGEN_HBC_PASSES_OPTENVIRONMENTINIT_H

#include "hermes/Optimizer/PassManager/Pass.h"

namespace hermes {
namespace hbc {

                                                                            
                                                                              
class OptEnvironmentInit : public FunctionPass {
 public:
  explicit OptEnvironmentInit() : FunctionPass("OptEnvironmentInit") {}

  bool runOnFunction(Function *F) override;
};

}                 
}                    

#endif                                                
