/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_INTERPRETERSTATE_H
#define HERMES_VM_INTERPRETERSTATE_H
#include <cstdint>

#include "CallResult.h"

namespace hermes {
namespace vm {

class CodeBlock;

                                                                       
                                                                  
struct InterpreterState {
                               
  CodeBlock *codeBlock{nullptr};

                                                                            
              
  uint32_t offset{0};

  InterpreterState() {}

  InterpreterState(CodeBlock *codeBlock, uint32_t offset)
      : codeBlock(codeBlock), offset(offset) {}

  InterpreterState(const InterpreterState &) = default;
  InterpreterState &operator=(const InterpreterState &) = default;

  bool operator==(const InterpreterState &other) const {
    return codeBlock == other.codeBlock && offset == other.offset;
  }
  bool operator!=(const InterpreterState &other) const {
    return !(*this == other);
  }
};
}                
}                    

#endif
