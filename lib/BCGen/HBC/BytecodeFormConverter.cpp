/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/BytecodeFormConverter.h"

#include "hermes/BCGen/HBC/Bytecode.h"
#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/Inst/Inst.h"
#include "hermes/Inst/InstDecode.h"
#include "hermes/Support/Algorithms.h"
#include "hermes/Support/MemoryBuffer.h"

using namespace hermes;
using namespace hermes::hbc;
using namespace hermes::inst;
using llvh::MutableArrayRef;

namespace {

                                                     
template <BytecodeForm TargetForm>
class BytecodeFormConverter {
                                                                             
           
  struct Adjuster {
                                                                               
                                                                       
                                                                              
                                                         
    uint64_t current_{0};

                                        
                                       
    template <typename T>
    T apply(T value) {
      static_assert(
          std::is_unsigned<T>::value, "Can only process unsigned types");
      uint64_t result;
      if (TargetForm == BytecodeForm::Delta) {
        result = value - current_;
        current_ = value;
      } else {
        result = value + current_;
        current_ = result;
      }
      return result;
    }

                                                  
    template <typename T>
    void operator()(T &value) {
      value = apply(value);
    }
  };

                                                      
  MutableArrayRef<uint8_t> bytes_;

                                                      
  MutableBytecodeFileFields fields_;

                                           
  std::unique_ptr<BCProviderFromBuffer> bcProvider_;

                                            
  void processInstructions() {
                                                                           
                                                
    Adjuster adjDeclareGlobalVar;
    Adjuster adjCreateClosure;
    Adjuster adjCreateClosureLong;
    Adjuster adjNewArrayWithBuffer;
    Adjuster adjNewArrayWithBufferLong;
                                                                             
                                                                              
#define ADJUST(adjuster, field) field = (adjuster).apply(field)
    for (uint32_t func = 0; func < bcProvider_->getFunctionCount(); ++func) {
      RuntimeFunctionHeader header = bcProvider_->getFunctionHeader(func);
                                                           
      uint8_t *bytecodeStart = &bytes_[header.offset()];
      uint8_t *bytecodeEnd = bytecodeStart + header.bytecodeSizeInBytes();
      uint8_t *cursor = bytecodeStart;
      while (cursor < bytecodeEnd) {
        auto *ip = reinterpret_cast<inst::Inst *>(cursor);
        switch (ip->opCode) {
          case OpCode::NewArrayWithBuffer:
            ADJUST(adjNewArrayWithBuffer, ip->iNewArrayWithBuffer.op4);
            break;
          case OpCode::NewArrayWithBufferLong:
            ADJUST(adjNewArrayWithBufferLong, ip->iNewArrayWithBufferLong.op4);
            break;
          case OpCode::CreateClosure:
            ADJUST(adjCreateClosure, ip->iCreateClosure.op3);
            break;
          case OpCode::CreateClosureLongIndex:
            ADJUST(adjCreateClosureLong, ip->iCreateClosureLongIndex.op3);
            break;
          case OpCode::DeclareGlobalVar:
            ADJUST(adjDeclareGlobalVar, ip->iDeclareGlobalVar.op1);
            break;
          default:
            break;
        }
        cursor += getInstSize(ip->opCode);
      }
#undef ADJUST
    }
  }

                                                     
  void processOverflowFunctionHeaders() {
                                                                             
                                                                          
                          
    Adjuster overflowOffsetAdj;
    for (SmallFuncHeader &sfh : fields_.functionHeaders) {
      if (sfh.flags.overflowed) {
        FunctionHeader *fh = reinterpret_cast<FunctionHeader *>(
            &bytes_[sfh.getLargeHeaderOffset()]);
        overflowOffsetAdj(fh->offset);
      }
    }
  }

                                            
  void processFunctionHeaders() {
    Adjuster offsetAdj;
    for (SmallFuncHeader &sfh : fields_.functionHeaders) {
      sfh.offset = offsetAdj.apply(sfh.offset);
    }
  }

                                                  
  void processStringTable() {
    Adjuster offsetAdj;
    for (SmallStringTableEntry &entry : fields_.stringTableEntries) {
      entry.offset = offsetAdj.apply(entry.offset);
    }
  }

                                                           
  void processOverflowStringTable() {
    Adjuster offsetAdj;
    for (OverflowStringTableEntry &entry : fields_.stringTableOverflowEntries) {
      entry.offset = offsetAdj.apply(entry.offset);
    }
  }

                           
  void processMagicNumber() {
    fields_.header->magic =
        (TargetForm == BytecodeForm::Delta ? DELTA_MAGIC : MAGIC);
  }

 public:
                                                                                
                                             
  explicit BytecodeFormConverter(
      MutableArrayRef<uint8_t> bytes,
      MutableBytecodeFileFields &fields,
      BytecodeForm sourceForm)
      : bytes_(bytes), fields_(fields) {
    auto res = hbc::BCProviderFromBuffer::createBCProviderFromBuffer(
        std::make_unique<Buffer>(bytes.data(), bytes.size()), sourceForm);
    if (!res.first) {
      hermes_fatal(res.second.c_str());
    }
    bcProvider_ = std::move(res.first);
  }

                             
  void perform() {
                                                      
    using Step = void (BytecodeFormConverter::*)(void);
    Step steps[] = {
        &BytecodeFormConverter::processMagicNumber,
        &BytecodeFormConverter::processInstructions,
        &BytecodeFormConverter::processOverflowFunctionHeaders,
        &BytecodeFormConverter::processFunctionHeaders,
        &BytecodeFormConverter::processStringTable,
        &BytecodeFormConverter::processOverflowStringTable

    };
                                                                            
                                                                               
                                                                            
                                                              
    if (TargetForm == BytecodeForm::Execution) {
      std::reverse(std::begin(steps), std::end(steps));
    }
    for (auto step : steps) {
      (this->*step)();
    }
    hbc::BCProviderFromBuffer::updateBytecodeHash(bytes_);
  }
};

}             

bool hermes::hbc::convertBytecodeToForm(
    MutableArrayRef<uint8_t> buffer,
    BytecodeForm targetForm,
    std::string *outError) {
  BytecodeForm sourceForm =
      (targetForm == BytecodeForm::Delta ? BytecodeForm::Execution
                                         : BytecodeForm::Delta);
  MutableBytecodeFileFields fields;
  if (!fields.populateFromBuffer(buffer, outError, sourceForm)) {
    return false;
  }

  if (targetForm == BytecodeForm::Delta) {
    BytecodeFormConverter<BytecodeForm::Delta> conv(buffer, fields, sourceForm);
    conv.perform();
  } else {
    BytecodeFormConverter<BytecodeForm::Execution> conv(
        buffer, fields, sourceForm);
    conv.perform();
  }
  return true;
}
