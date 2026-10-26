/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                                              
                            
                                                                                
#ifndef HERMES_INST_INSTDECODE_H
#define HERMES_INST_INSTDECODE_H

#include "hermes/Inst/Inst.h"

namespace llvh {
class raw_ostream;
}

namespace hermes {
namespace inst {

                                                        
enum class OperandType : uint8_t {
#define DEFINE_OPERAND_TYPE(name, type) name,
#include "hermes/BCGen/HBC/BytecodeList.def"
};

inline constexpr bool isOperandTypeFloating(OperandType opType) {
  return opType == OperandType::Double;
}
inline constexpr bool isOperandTypeInteger(OperandType opType) {
  return !isOperandTypeFloating(opType);
}

                                                           
constexpr unsigned INST_MAX_OPERANDS = 6;

                                                                           
                                 
struct InstMetaData {
                             
  OpCode opCode;
                                              
  uint8_t size;
                         
  uint8_t numOperands;
                               
  OperandType operandType[INST_MAX_OPERANDS];
};

                                                           
union OperandValue {
  double floating;
  int64_t integer;

                                                                               
  template <typename T>
  inline void set(T val) {
    if (std::is_integral<T>::value)
      integer = (int64_t)val;
    else
      floating = (double)val;
  }
};

                                                                              
                                                                            
                
struct DecodedInstruction {
  InstMetaData meta;
  OperandValue operandValue[INST_MAX_OPERANDS];
};

                                                           
uint8_t getInstSize(OpCode opCode);

                                                            
uint8_t getOperandSize(OperandType type);

                                                  
llvh::StringRef getOpCodeString(OpCode opCode);

                                                            
InstMetaData getInstMetaData(OpCode opCode);

                                                                           
DecodedInstruction decodeInstruction(const Inst *inst);

                                                                            
                                                               
bool isCallType(OpCode opcode);

llvh::raw_ostream &operator<<(
    llvh::raw_ostream &OS,
    const DecodedInstruction &decoded);

                                                   
void dumpOperand(llvh::raw_ostream &OS, OperandType type, OperandValue value);

}                  
}                    

#endif                            
