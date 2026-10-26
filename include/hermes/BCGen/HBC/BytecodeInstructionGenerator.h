/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_BYTECODELIST_H
#define HERMES_BCGEN_HBC_BYTECODELIST_H

#include "hermes/Support/Conversions.h"

#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace hbc {

                                                          
using param_t = int64_t;

                                                                                
                    
using offset_t = uint32_t;

                                                                               
                                                                                
                                            
using opcode_atom_t = uint8_t;

enum Operator {
                                  
         
         
      
#define DEFINE_OPCODE(name) name##Op,
#include "hermes/BCGen/HBC/BytecodeList.def"
};

class BytecodeInstructionGenerator {
 protected:
                        
  std::vector<opcode_atom_t> opcodes_{};

                                                                          
                                                  
  bool encodingError_{};

 public:
                                                                          
  bool hasEncodingError() const {
    return encodingError_;
  }

                                                          
  offset_t getCurrentLocation() {
    return opcodes_.size();
  }

  offset_t emitOpcode(Operator op) {
    auto loc = getCurrentLocation();
    emitUInt8(op);
    return loc;
  }
                                                                               
  void emitOperand(param_t t, int size) {
    while (size--) {
      opcodes_.push_back((opcode_atom_t)t);
      t >>= 8;
    }
  }

                                                                        
  std::vector<opcode_atom_t> acquireBytecode() {
    return std::move(opcodes_);
  }

                                               
                                        
                                       
      
                                                    
                                                                        
                                                          
#define DEFINE_OPERAND_TYPE(name, ctype)                  \
  void emit##name(param_t value) {                        \
    encodingError_ |= ((param_t)(ctype)value) != value && \
        !std::is_floating_point<ctype>::value;            \
    emitOperand(value, sizeof(ctype));                    \
  }
#include "hermes/BCGen/HBC/BytecodeList.def"

                                          
                                    
                                                
      
#define DEFINE_OPCODE_0(name)        \
  offset_t emit##name() {            \
    auto loc = emitOpcode(name##Op); \
    return loc;                      \
  };
#define DEFINE_OPCODE_1(name, t1)    \
  offset_t emit##name(param_t p1) {  \
    auto loc = emitOpcode(name##Op); \
    emit##t1(p1);                    \
    return loc;                      \
  };
#define DEFINE_OPCODE_2(name, t1, t2)           \
  offset_t emit##name(param_t p1, param_t p2) { \
    auto loc = emitOpcode(name##Op);            \
    emit##t1(p1);                               \
    emit##t2(p2);                               \
    return loc;                                 \
  };
#define DEFINE_OPCODE_3(name, t1, t2, t3)                   \
  offset_t emit##name(param_t p1, param_t p2, param_t p3) { \
    auto loc = emitOpcode(name##Op);                        \
    emit##t1(p1);                                           \
    emit##t2(p2);                                           \
    emit##t3(p3);                                           \
    return loc;                                             \
  };
#define DEFINE_OPCODE_4(name, t1, t2, t3, t4)                           \
  offset_t emit##name(param_t p1, param_t p2, param_t p3, param_t p4) { \
    auto loc = emitOpcode(name##Op);                                    \
    emit##t1(p1);                                                       \
    emit##t2(p2);                                                       \
    emit##t3(p3);                                                       \
    emit##t4(p4);                                                       \
    return loc;                                                         \
  };
#define DEFINE_OPCODE_5(name, t1, t2, t3, t4, t5)                   \
  offset_t emit##name(                                              \
      param_t p1, param_t p2, param_t p3, param_t p4, param_t p5) { \
    auto loc = emitOpcode(name##Op);                                \
    emit##t1(p1);                                                   \
    emit##t2(p2);                                                   \
    emit##t3(p3);                                                   \
    emit##t4(p4);                                                   \
    emit##t5(p5);                                                   \
    return loc;                                                     \
  };
#define DEFINE_OPCODE_6(name, t1, t2, t3, t4, t5, t6) \
  offset_t emit##name(                                \
      param_t p1,                                     \
      param_t p2,                                     \
      param_t p3,                                     \
      param_t p4,                                     \
      param_t p5,                                     \
      param_t p6) {                                   \
    auto loc = emitOpcode(name##Op);                  \
    emit##t1(p1);                                     \
    emit##t2(p2);                                     \
    emit##t3(p3);                                     \
    emit##t4(p4);                                     \
    emit##t5(p5);                                     \
    emit##t6(p6);                                     \
    return loc;                                       \
  };
#include "hermes/BCGen/HBC/BytecodeList.def"

                                                          
                                                        
                 
  offset_t emitLoadConstDoubleDirect(param_t dst, double value) {
                                                                   
                                                               
    if (LLVM_UNLIKELY(std::isnan(value))) {
      static_assert(
          sizeof(double) == sizeof(uint64_t), "double better be 64 bits");
      static constexpr uint64_t qnan = 0xfff8000000000000;
      return emitLoadConstDouble(dst, qnan);
    }
    return emitLoadConstDouble(dst, llvh::DoubleToBits(value));
  }
};
}                 
}                    
#pragma GCC diagnostic pop

#endif
