/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IR_IRVERIFIER_H
#define HERMES_IR_IRVERIFIER_H

#include "hermes/IR/IR.h"
#include "llvh/Support/raw_ostream.h"

using llvh::raw_ostream;

namespace hermes {

class Module;

enum class VerificationMode {
                                    
  IR_VALID,
                                                                       
  IR_OPTIMIZED
};

                                     
   
                                                                      
                                                                        
                                                                       
                                                                     
                                        
bool verifyModule(
    const Module &M,
    raw_ostream *OS = nullptr,
    VerificationMode mode = VerificationMode::IR_VALID);

}                    

#endif
