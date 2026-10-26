/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_SIMPLE_CALLGRAPH_PROVIDER_H
#define HERMES_OPTIMIZER_SCALAR_SIMPLE_CALLGRAPH_PROVIDER_H

#include "hermes/Optimizer/Scalar/CallGraphProvider.h"

namespace hermes {

class Function;

                                                                        
                                                                     
                                            
class SimpleCallGraphProvider : public CallGraphProvider {
  void initCallRelationships(Function *F);

 public:
  SimpleCallGraphProvider(Function *F) {
    initCallRelationships(F);
  }
};
}                    

#endif                                                       
