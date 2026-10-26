/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/SerializedLiteralGenerator.h"
#include "hermes/BCGen/HBC/BytecodeGenerator.h"
#include "llvh/Support/Endian.h"

namespace hermes {
namespace hbc {

namespace {
void appendTagToBuffer(
    std::vector<unsigned char> &buff,
    SerializedLiteralGenerator::TagType tag,
    int seqLength) {
  if (seqLength > 15) {
    buff.push_back((tag | 0x80) | (seqLength >> 8));
    buff.push_back(seqLength & 0xffff);
  } else {
    buff.push_back(tag + seqLength);
  }
}

                                                                    
template <typename value_type>
void serializeValueToBuffer(
    value_type value,
    std::vector<unsigned char> &buff) {
                                                                  
                                                                    
                                                         
                                                                    
                      
  buff.resize(buff.size() + sizeof(value_type));
  llvh::support::endian::write<value_type, 1>(
      buff.data() + buff.size() - sizeof(value_type),
      value,
      llvh::support::endianness::little);
}

template <>
void serializeValueToBuffer(double value, std::vector<unsigned char> &buff) {
                                                                  
                                                                    
                                                         
                                                                    
                      
  buff.resize(buff.size() + sizeof(double));
                                                                 
                                                             
  if (LLVM_UNLIKELY(std::isnan(value))) {
    static_assert(
        sizeof(double) == sizeof(uint64_t), "double better be 64 bits");
    static constexpr uint64_t qnan = 0xfff8000000000000;
    llvh::support::endian::write<uint64_t, 1>(
        buff.data() + buff.size() - sizeof(uint64_t),
        qnan,
        llvh::support::endianness::little);
  } else {
    llvh::support::endian::write<double, 1>(
        buff.data() + buff.size() - sizeof(double),
        value,
        llvh::support::endianness::little);
  }
}
}             

void SerializedLiteralGenerator::serializeBuffer(
    llvh::ArrayRef<Literal *> literals,
    std::vector<unsigned char> &buff,
    bool isKeyBuffer) {
                                                
  TagType lastTag = NumberTag;

                                                           
  TagType newTag = NumberTag;

                                                                       
                                                             
  std::vector<unsigned char> tmpSeqBuffer;

                                                   
  size_t seqLength = 0;

  for (size_t i = 0, buffSize = literals.size(); i < buffSize; ++i) {
                                           
                                                                     
                            
                                                                            
                                                                        
                                                                         
                                                                          
                                                                             
                                                                         
                                                       
    switch (literals[i]->getKind()) {
      case ValueKind::LiteralNumberKind:
        newTag = llvh::cast<LiteralNumber>(literals[i])
                     ->isIntTypeRepresentible<int32_t>()
            ? IntegerTag
            : NumberTag;
        break;
      case ValueKind::LiteralStringKind: {
        auto str = llvh::cast<LiteralString>(literals[i])->getValue().str();
        int ind =
            isKeyBuffer ? BMGen_.getIdentifierID(str) : BMGen_.getStringID(str);

        if (ind > UINT16_MAX) {
          newTag = LongStringTag;
        } else if (ind > UINT8_MAX) {
          newTag = ShortStringTag;
        } else {
          newTag = ByteStringTag;
        }
        break;
      }
      case ValueKind::LiteralBoolKind:
        newTag = llvh::cast<LiteralBool>(literals[i])->getValue() ? TrueTag
                                                                  : FalseTag;
        break;
      case ValueKind::LiteralNullKind:
        newTag = NullTag;
        break;
      default:
        hermes_fatal("Invalid Literal Kind");
    }

    if (newTag != lastTag || seqLength == SequenceMax) {
      if (seqLength > 0) {
        appendTagToBuffer(buff, lastTag, seqLength);
        buff.insert(buff.end(), tmpSeqBuffer.begin(), tmpSeqBuffer.end());
        tmpSeqBuffer.resize(0);
      }
      lastTag = newTag;
      seqLength = 0;
    }
    seqLength++;

    switch (literals[i]->getKind()) {
      case ValueKind::LiteralNumberKind: {
        auto litNum = llvh::cast<LiteralNumber>(literals[i]);
        if (llvh::Optional<int> intPointer =
                litNum->isIntTypeRepresentible<int32_t>()) {
          int n = intPointer.getValue();
          serializeValueToBuffer<uint32_t>(n, tmpSeqBuffer);
        } else {
          double num = litNum->getValue();
          serializeValueToBuffer<double>(num, tmpSeqBuffer);
        }
        break;
      }
      case ValueKind::LiteralStringKind: {
                                                                            
                                                    
        auto str = llvh::cast<LiteralString>(literals[i])->getValue().str();
        auto stringID =
            isKeyBuffer ? BMGen_.getIdentifierID(str) : BMGen_.getStringID(str);

        if (stringID > UINT16_MAX) {
          serializeValueToBuffer<uint32_t>(stringID, tmpSeqBuffer);
        } else if (stringID > UINT8_MAX) {
          serializeValueToBuffer<uint16_t>(stringID, tmpSeqBuffer);
        } else {
          serializeValueToBuffer<uint8_t>(stringID, tmpSeqBuffer);
        }
        break;
      }
      case ValueKind::LiteralBoolKind:
      case ValueKind::LiteralNullKind:
                   
        break;
      default:
        hermes_fatal("Invalid Literal Kind");
    }
  }
                                                                   
  appendTagToBuffer(buff, lastTag, seqLength);
  buff.insert(buff.end(), tmpSeqBuffer.begin(), tmpSeqBuffer.end());
}

}                 
}                    
