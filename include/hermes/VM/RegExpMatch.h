/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_REGEXPMATCH_H
#define HERMES_VM_REGEXPMATCH_H

#include "hermes/Support/OptValue.h"

#include "llvh/ADT/SmallVector.h"

namespace hermes {
namespace vm {

                                       
struct RegExpMatchRange {
                                               
  uint32_t location;

                                        
  uint32_t length;
};

                                                                              
                                                     
                                                           
using RegExpMatch = llvh::SmallVector<OptValue<RegExpMatchRange>, 4>;

}                
}                    

#endif
