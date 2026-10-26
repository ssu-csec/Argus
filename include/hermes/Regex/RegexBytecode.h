/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_REGEX_REGEXBYTECODE_H
#define HERMES_REGEX_REGEXBYTECODE_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/Support/Casting.h"

#include <cstdint>
#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace regex {

                                           
#define REOP(code) code,
enum class Opcode : uint8_t {
#include "hermes/Regex/RegexOpcodes.def"
};

                                                         
using JumpTarget32 = uint32_t;

                                                                  
using MatchConstraintSet = uint8_t;

                                                          
                                                                             
                          
LLVM_PACKED_START

                                                                                
                                                                
struct Insn {
  Opcode opcode;
};

struct GoalInsn : public Insn {};
struct LeftAnchorInsn : public Insn {};
struct RightAnchorInsn : public Insn {};
struct MatchAnyInsn : public Insn {};
struct U16MatchAnyInsn : public Insn {};
struct MatchAnyButNewlineInsn : public Insn {};
struct U16MatchAnyButNewlineInsn : public Insn {};
struct MatchChar8Insn : public Insn {
  char c;
};

                                                                              
struct MatchChar16Insn : public Insn {
  char16_t c;
};

                                                                
struct U16MatchChar32Insn : public Insn {
  uint32_t c;
};

                                                                        
struct MatchCharICase8Insn : public Insn {
  char c;
};

                                                                              
struct MatchCharICase16Insn : public Insn {
  char16_t c;
};

                                                                        
             
struct U16MatchCharICase32Insn : public Insn {
  uint32_t c;
};

struct AlternationInsn : public Insn {
                                                                         
                                                                                
                                                          
  JumpTarget32 secondaryBranch;
  MatchConstraintSet primaryConstraints;
  MatchConstraintSet secondaryConstraints;
};
struct Jump32Insn : public Insn {
  JumpTarget32 target;
};

struct BackRefInsn : public Insn {
  uint16_t mexp;
};

                                                                            
                                                                            
struct BracketRange32 {
  uint32_t start;
  uint32_t end;
};

                                                                                
                                                        
struct BracketInsn : public Insn {
                                                           
  uint32_t rangeCount;
                                                 
  uint8_t negate : 1;

                                                                               
                                                                             
                          
  uint8_t positiveCharClasses : 3;
  uint8_t negativeCharClasses : 3;

                                                                    
  uint32_t totalWidth() const {
    return sizeof(*this) + rangeCount * sizeof(BracketRange32);
  }
};

                                                                      
                                                                     
struct U16BracketInsn : public BracketInsn {};

struct MatchNChar8Insn : public Insn {
                                                      
  uint8_t charCount;

                                                                
  uint32_t totalWidth() const {
    return sizeof(*this) + charCount * sizeof(char);
  }
};

struct MatchNCharICase8Insn : public Insn {
                                                      
  uint8_t charCount;

                                                                
  uint32_t totalWidth() const {
    return sizeof(*this) + charCount * sizeof(char);
  }
};

                                                                  
static_assert(
    sizeof(BracketInsn) == 6,
    "BracketInsn should take up 6 byte total");

struct WordBoundaryInsn : public Insn {
                                                          
  bool invert;
};

                                                                              
                                                                           
                      
struct BeginMarkedSubexpressionInsn : public Insn {
  uint16_t mexp;
};
struct EndMarkedSubexpressionInsn : public Insn {
  uint16_t mexp;
};

                                                                          
                                                         
struct LookaroundInsn : public Insn {
                                                          
  bool invert;
                                                           
  bool forwards;
                                                             
  MatchConstraintSet constraints;
                                                                      
  uint16_t mexpBegin;
  uint16_t mexpEnd;
                                           
  JumpTarget32 continuation;
};

                                                                         
                                                                         
                                                                         
                                                                               
                  
struct BeginLoopInsn : public Insn {
                                                                              
                         
  uint32_t loopId;

                                     
                                                                      
  uint32_t min;
  uint32_t max;

                                                                           
  uint16_t mexpBegin;
  uint16_t mexpEnd;

                                                       
  bool greedy;

                                                         
  MatchConstraintSet loopeeConstraints;

                                        
  JumpTarget32 notTakenTarget;
};

                                                                     
                                         
struct EndLoopInsn : public Insn {
  JumpTarget32 target;
};

                                                                             
                                 
                                        
                     
                                                     
struct BeginSimpleLoopInsn : public Insn {
                                                                         
                                                      

                                                         
  MatchConstraintSet loopeeConstraints;

                                        
  JumpTarget32 notTakenTarget;
};

                                                                            
                                               
struct EndSimpleLoopInsn : public Insn {
  JumpTarget32 target;
};

                                                                              
                                            
struct Width1LoopInsn : public Insn {
                                                                              
                         
  uint32_t loopId;

                                     
                                                                      
  uint32_t min;
  uint32_t max;

                                                       
  bool greedy;

                                        
  JumpTarget32 notTakenTarget;
};

                                                                
struct RegexBytecodeHeader {
                               
  uint16_t markedCount;

                      
  uint16_t loopCount;

                                               
  uint8_t syntaxFlags;

                                                       
  MatchConstraintSet constraints;
};

LLVM_PACKED_END;

                                                                    
template <typename Instruction>
struct OpcodeFor {};

#define REOP(Code)                                \
  template <>                                     \
  struct OpcodeFor<Code##Insn> {                  \
    static constexpr Opcode value = Opcode::Code; \
  };
#include "hermes/Regex/RegexOpcodes.def"

                                                               
class RegexBytecodeStream {
                                                  
  std::vector<uint8_t> bytes_;

                                             
  bool acquired_ = false;

 public:
                                                                   
                                                                              
                               
  template <typename Instruction>
  class InstructionWrapper {
    std::vector<uint8_t> *const bytes_;
    const uint32_t offset_;

   public:
    Instruction *operator->() {
      Insn *base = reinterpret_cast<Insn *>(&bytes_->at(offset_));
      return llvh::cast<Instruction>(base);
    }

    InstructionWrapper(std::vector<uint8_t> *bytes, uint32_t offset)
        : bytes_(bytes), offset_(offset) {}
  };

                          
                                                                            
             
  template <typename Instruction>
  InstructionWrapper<Instruction> emit() {
    size_t startSize = bytes_.size();
    bytes_.resize(startSize + sizeof(Instruction), 0);
    Insn *insn = reinterpret_cast<Insn *>(&bytes_[startSize]);
    insn->opcode = OpcodeFor<Instruction>::value;
    return InstructionWrapper<Instruction>(&bytes_, startSize);
  }

                            
  void emitBracketRange(BracketRange32 range) {
    const uint8_t *rangeBytes = reinterpret_cast<const uint8_t *>(&range);
    bytes_.insert(bytes_.end(), rangeBytes, rangeBytes + sizeof(range));
  }

                                                                            
  void emitChar8(char c) {
    bytes_.push_back((uint8_t)c);
  }

                                                                       
                                                              
  uint32_t currentOffset() const {
    return bytes_.size() - sizeof(RegexBytecodeHeader);
  }

                                                                       
  std::vector<uint8_t> acquireBytecode() {
    assert(!acquired_ && "Bytecode already acquired");
    acquired_ = true;
    return std::move(bytes_);
  }

                                                             
  RegexBytecodeStream(const RegexBytecodeHeader &header) {
    const uint8_t *headerBytes = reinterpret_cast<const uint8_t *>(&header);
    bytes_.insert(bytes_.end(), headerBytes, headerBytes + sizeof header);
  }
};

}                   
}                    

namespace llvh {
                                                                         
                                                                       
                                                                         
                                                                               
                   
template <typename To, typename From>
struct isa_impl<
    To,
    From,
    typename std::enable_if<
        std::is_same<hermes::regex::Insn, From>::value &&
        std::is_base_of<hermes::regex::Insn, To>::value>::type> {
  static inline bool doit(const From &val) {
    return val.opcode == hermes::regex::OpcodeFor<To>::value;
  }
};
}                  
#pragma GCC diagnostic pop

#endif                                
