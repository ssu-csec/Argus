/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_SIMPLEBYTECODEBUILDER_H
#define HERMES_BCGEN_HBC_SIMPLEBYTECODEBUILDER_H

#include "hermes/BCGen/HBC/BytecodeFileFormat.h"
#include "hermes/BCGen/HBC/BytecodeInstructionGenerator.h"
#include "hermes/Public/Buffer.h"

#include <memory>
#include <vector>

namespace hermes {
namespace hbc {
                                                                          
                                                                               
class SimpleBytecodeBuilder {
                                                                        
                                                                            
                                         
  struct SimpleFunction {
                                                                          
                   
    uint32_t offset{};
                                              
    uint32_t paramCount;
                          
    uint32_t frameSize;
                    
    std::vector<opcode_atom_t> opcodes;

    SimpleFunction(
        uint32_t paramCount,
        uint32_t frameSize,
        std::vector<opcode_atom_t> &&opcodes)
        : paramCount(paramCount),
          frameSize(frameSize),
          opcodes(std::move(opcodes)) {
      assert(paramCount > 0 && "paramCount must include 'this'");
    }
  };

                                                                        
                      
  std::vector<SimpleFunction> functions_{};

 public:
                                                                      
                 
  void addFunction(
      uint32_t paramCount,
      uint32_t frameSize,
      std::vector<opcode_atom_t> &&opcodes) {
    functions_.emplace_back(paramCount, frameSize, std::move(opcodes));
  }

                                                                              
  std::unique_ptr<Buffer> generateBytecodeBuffer();
};
}                 
}                    

#endif                                            
