/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_BYTECODEDISASSEMBLER_H
#define HERMES_BCGEN_HBC_BYTECODEDISASSEMBLER_H

#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/BCGen/HBC/DisassemblyOptions.h"
#include "hermes/BCGen/HBC/SerializedLiteralGenerator.h"
#include "hermes/Inst/Inst.h"
#include "hermes/Inst/InstDecode.h"

#include <unordered_map>

namespace llvh {
class raw_ostream;
}                  

namespace hermes {
namespace hbc {

using llvh::raw_ostream;
using BigIntID = uint32_t;
using StringID = uint32_t;

                                                                           
                          
template <typename T>
void decodeOperand(const uint8_t *operandBuf, T *val) {
  using param_t = int64_t;
  param_t ret = 0;
  for (unsigned i = 0; i < sizeof(T); ++i) {
    ret |= ((param_t)operandBuf[i]) << (i * 8);
  }

  if (std::is_same<T, double>::value) {
    *val = llvh::BitsToDouble(ret);
  } else {
    *val = ret;
  }
}

template <typename... Ts>
std::string formatString(const char *format, Ts... args) {
  size_t size =
      snprintf(nullptr, 0, format, args...) + 1;                        
  std::unique_ptr<char[]> buf(new char[size]);
  snprintf(buf.get(), size, format, args...);
  return std::string(
      buf.get(), buf.get() + size - 1);                                 
}

                                                                      
std::pair<int, SerializedLiteralGenerator::TagType> checkBufferTag(
    const unsigned char *buff);

                                                   
class BytecodeVisitor {
 protected:
  std::shared_ptr<hbc::BCProvider> bcProvider_{};
  unsigned funcId_{0};

 protected:
                                                  
                                                 
                                                                  
  virtual void beforeStart(unsigned funcId, const uint8_t *bytecodeStart) {}

                                                  
  virtual void afterStart() {}

                                                    
                                               
                                                      
                                               
  virtual void
  preVisitInstruction(inst::OpCode opcode, const uint8_t *ip, int length) {}

                                                   
                                               
                                                      
                                               
  virtual void
  postVisitInstruction(inst::OpCode opcode, const uint8_t *ip, int length) {}

                                                                
                                                  
                                                               
                                                       
  virtual void
  visitSwitchImmTargets(uint32_t jmpIdx, int32_t offset, const uint8_t *dest) {}

                                    
                                                      
                                                      
                                                              
                                                    
  virtual void visitOperand(
      const uint8_t *ip,
      inst::OperandType operandType,
      const uint8_t *operandBuf,
      int operandIndex) {}

                                                                      
  void visitInstructionsInBody(
      const uint8_t *bytecodeStart,
      const uint8_t *bytecodeEnd,
      bool visitSwitchImmTargets);

 public:
  BytecodeVisitor(std::shared_ptr<hbc::BCProvider> bcProvider)
      : bcProvider_(bcProvider) {}

  virtual ~BytecodeVisitor() = default;

                                                            
  void visitInstructionsInFunction(unsigned funcId);
};

using JumpTargetsTy = std::unordered_map<const void *, unsigned>;

                                                                           
class JumpTargetsVisitor : public BytecodeVisitor {
 private:
  unsigned funcId_ = 0;
  const uint8_t *bytecodeStart_ = nullptr;

  unsigned labelNumber_{0};
                                                                                
  std::vector<inst::Inst const *> switchInsts_{};
                                              
  JumpTargetsTy jumpTargets_{};

 private:
  void createOrSetLabel(const void *dest) {
    auto res = jumpTargets_.emplace(dest, 0);
    if (res.second)
      res.first->second = ++labelNumber_;
  }

 protected:
  void beforeStart(unsigned funcId, const uint8_t *bytecodeStart) override {
    funcId_ = funcId;
    bytecodeStart_ = bytecodeStart;
  }

  void afterStart() override;

  void preVisitInstruction(inst::OpCode opcode, const uint8_t *ip, int length)
      override;

  void visitSwitchImmTargets(
      uint32_t jmpIdx,
      int32_t offset,
      const uint8_t *dest) override {
    createOrSetLabel(dest);
  }

  void visitOperand(
      const uint8_t *ip,
      inst::OperandType operandType,
      const uint8_t *operandBuf,
      int operandIndex) override;

 public:
  JumpTargetsVisitor(std::shared_ptr<hbc::BCProvider> bcProvider)
      : BytecodeVisitor(bcProvider) {}

  JumpTargetsTy &getJumpTargets() {
    return jumpTargets_;
  }
  std::vector<inst::Inst const *> &getSwitchIntructions() {
    return switchInsts_;
  }
};

                                                     
                                           
                                   
                                             
class PrettyDisassembleVisitor : public BytecodeVisitor {
 private:
  inst::OpCode opcode_;
  JumpTargetsTy &jumpTargets_;
  const uint8_t *bytecodeStart_ = nullptr;
  uint32_t funcVirtualOffset_{0};

 protected:
  raw_ostream &os_;
  DisassemblyOptions options_;

 private:
                                                                                
                                                                              
              
  void dumpOperandString(StringID stringID, raw_ostream &OS);

                                                                        
                                                                   
  void dumpOperandBigInt(BigIntID bigintID, raw_ostream &OS);

                                                             
  void dumpOperandFunction(unsigned functionID, raw_ostream &OS);

 protected:
  void beforeStart(unsigned funcId, const uint8_t *bytecodeStart);
  void preVisitInstruction(inst::OpCode opcode, const uint8_t *ip, int length);
  void
  postVisitInstruction(inst::OpCode opcode, const uint8_t *ip, int length) {
    os_ << "\n";
  }
  void visitOperand(
      const uint8_t *ip,
      inst::OperandType operandType,
      const uint8_t *operandBuf,
      int operandIndex);

                                               
  virtual unsigned getIndentation();

                                                                         
  void printSourceLineForOffset(uint32_t opcodeOffset);

 public:
  PrettyDisassembleVisitor(
      std::shared_ptr<hbc::BCProvider> bcProvider,
      JumpTargetsTy &jumpTargets,
      raw_ostream &os,
      DisassemblyOptions options = DisassemblyOptions::None)
      : BytecodeVisitor(bcProvider),
        jumpTargets_(jumpTargets),
        os_(os),
        options_(options) {}

  JumpTargetsTy &getJumpTargets() {
    return jumpTargets_;
  }
};

class BytecodeSectionWalker {
 private:
                                                  
  const uint8_t *bytecodeStart_{nullptr};
  std::shared_ptr<hbc::BCProviderFromBuffer> bcProvider_{};
  llvh::raw_ostream &os_;

  std::vector<const char *> sectionNames_{};
  std::vector<const uint8_t *> sectionStarts_{};
  std::vector<const uint8_t *> sectionEnds_{};

                                                                          
                                                                      
  template <typename T>
  void addSection(const char *sectionName, const T *start, const T *end) {
    sectionNames_.push_back(sectionName);
    sectionStarts_.push_back(reinterpret_cast<const uint8_t *>(start));
    sectionEnds_.push_back(reinterpret_cast<const uint8_t *>(end));
  }

 public:
                                                                        
                                              
                                           
                                 
                                             
  BytecodeSectionWalker(
      const uint8_t *bytecodeStart,
      std::shared_ptr<hbc::BCProviderFromBuffer> bcProvider,
      llvh::raw_ostream &os);

                                                                      
                                                                         
                                                                    
  void printSectionRanges(bool human);
};

                                              
                                                                    
class BytecodeDisassembler {
 private:
  std::shared_ptr<hbc::BCProvider> bcProvider_{};

                                        
  DisassemblyOptions options_{DisassemblyOptions::Pretty};

                                                 
  void disassembleBytecodeFileHeader(raw_ostream &OS);

                                                            
  void disassembleFunctionRaw(unsigned funcId, raw_ostream &OS);

                                                                            
                                 
  void disassembleFunctionPretty(unsigned funcId, raw_ostream &OS);

                                              
  void disassembleStringStorage(raw_ostream &OS);

                                                             
  void disassembleArrayBuffer(raw_ostream &OS);

                                              
  void disassembleBigIntStorage(raw_ostream &OS);

                                                              
  void disassembleObjectBuffer(raw_ostream &OS);

                                                          
                                 
  void disassembleCJSModuleTable(raw_ostream &OS);

                                                               
                                 
  void disassembleFunctionSourceTable(raw_ostream &OS);

                                                                  
  void disassembleExceptionHandlers(unsigned funcId, raw_ostream &OS);

                                                                  
  void disassembleExceptionHandlersPretty(
      unsigned funcId,
      const JumpTargetsTy &jumpTargets,
      raw_ostream &OS);

                                                                 
  void disassembleRegexs(raw_ostream &OS);

                                                                               
                                                                         
                                                                          
  std::vector<std::pair<uint32_t, uint32_t>> generateRegexStringIDMap();

 public:
  explicit BytecodeDisassembler(std::shared_ptr<hbc::BCProvider> bcProvider)
      : bcProvider_(bcProvider) {}

                                         
  void setOptions(DisassemblyOptions options) {
    options_ = options;
  }

                                                     
  DisassemblyOptions getOptions() const {
    return options_;
  }

                                                            
  void disassembleFunction(unsigned funcId, raw_ostream &OS) {
    if ((options_ & DisassemblyOptions::Pretty) == DisassemblyOptions::Pretty) {
      disassembleFunctionPretty(funcId, OS);
    } else {
      disassembleFunctionRaw(funcId, OS);
    }
  }

                                                                          
  void disassemble(raw_ostream &OS);

  uint32_t getFunctionCount() const {
    return bcProvider_->getFunctionCount();
  }

                                                                         
                                                                               
  uint32_t fuzzyHashBytecode(
      unsigned funcId,
      bool useStrings = true,
      bool useIntConstants = true);
};

}                 
}                    

#endif                                           
