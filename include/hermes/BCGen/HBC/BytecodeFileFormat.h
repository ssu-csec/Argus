/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_BYTECODEFILEFORMAT_H
#define HERMES_BCGEN_HBC_BYTECODEFILEFORMAT_H

#include "hermes/BCGen/HBC/BytecodeVersion.h"
#include "hermes/BCGen/HBC/StringKind.h"
#include "hermes/Regex/RegexSerialization.h"
#include "hermes/Support/BigIntSupport.h"
#include "hermes/Support/Compiler.h"
#include "hermes/Support/SHA1.h"
#include "hermes/Support/StringTableEntry.h"

#include <cassert>
#include <cstdint>
#include <cstring>

namespace hermes {
namespace hbc {

                                                                          
const static uint64_t MAGIC = 0x1F1903C103BC1FC6;

                                                                         
                                                                        
const static uint64_t DELTA_MAGIC = ~MAGIC;

                                                    
static constexpr uint8_t PROPERTY_CACHING_DISABLED = 0;

                                            
static constexpr size_t BYTECODE_ALIGNMENT = alignof(uint32_t);

                  
enum class BytecodeForm {
                                                                          
  Execution,

                                                                       
  Delta,
};

                                                                           
            
union BytecodeOptions {
  struct {
    bool staticBuiltins : 1;
    bool cjsModulesStaticallyResolved : 1;
    bool hasAsync : 1;
  };
  uint8_t _flags;

  BytecodeOptions() : _flags(0) {}
};

                                                                 
static_assert(
    sizeof(BytecodeOptions) == 1,
    "BytecodeOptions should take up 1 byte total");

   
                         
   
LLVM_PACKED_START
struct BytecodeFileHeader {
  uint64_t magic;
  uint32_t version;
  uint8_t sourceHash[SHA1_NUM_BYTES];
  uint32_t fileLength;                                            
  uint32_t globalCodeIndex;
  uint32_t functionCount;
  uint32_t stringKindCount;                                  
  uint32_t identifierCount;                                            
  uint32_t stringCount;                                          
  uint32_t overflowStringCount;                                            
  uint32_t stringStorageSize;                                         
  uint32_t bigIntCount;                                          
  uint32_t bigIntStorageSize;                              
  uint32_t regExpCount;
  uint32_t regExpStorageSize;
  uint32_t arrayBufferSize;
  uint32_t objKeyBufferSize;
  uint32_t objValueBufferSize;
  uint32_t segmentID;                           
  uint32_t cjsModuleCount;                      
  uint32_t functionSourceCount;                                         
  uint32_t debugInfoOffset;
  BytecodeOptions options;

                                                                             
                                      
  uint8_t padding[19];

  BytecodeFileHeader(
      uint64_t magic,
      uint32_t version,
      const SHA1 &sourceHash,
      uint32_t fileLength,
      uint32_t globalCodeIndex,
      uint32_t functionCount,
      uint32_t stringKindCount,
      uint32_t identifierCount,
      uint32_t stringCount,
      uint32_t overflowStringCount,
      uint32_t stringStorageSize,
      uint32_t bigIntCount,
      uint32_t bigIntStorageSize,
      uint32_t regExpCount,
      uint32_t regExpStorageSize,
      uint32_t arrayBufferSize,
      uint32_t objKeyBufferSize,
      uint32_t objValueBufferSize,
      uint32_t segmentID,
      uint32_t cjsModuleCount,
      uint32_t functionSourceCount,
      uint32_t debugInfoOffset,
      BytecodeOptions options)
      : magic(magic),
        version(version),
        sourceHash(),
        fileLength(fileLength),
        globalCodeIndex(globalCodeIndex),
        functionCount(functionCount),
        stringKindCount(stringKindCount),
        identifierCount(identifierCount),
        stringCount(stringCount),
        overflowStringCount(overflowStringCount),
        stringStorageSize(stringStorageSize),
        bigIntCount(bigIntCount),
        bigIntStorageSize(bigIntStorageSize),
        regExpCount(regExpCount),
        regExpStorageSize(regExpStorageSize),
        arrayBufferSize(arrayBufferSize),
        objKeyBufferSize(objKeyBufferSize),
        objValueBufferSize(objValueBufferSize),
        segmentID(segmentID),
        cjsModuleCount(cjsModuleCount),
        functionSourceCount(functionSourceCount),
        debugInfoOffset(debugInfoOffset),
        options(options) {
    std::copy(sourceHash.begin(), sourceHash.end(), this->sourceHash);
    std::fill(padding, padding + sizeof(padding), 0);
  }
};

   
                                                                    
                                                                 
   
struct BytecodeFileFooter {
  uint8_t fileHash[SHA1_NUM_BYTES];                                        

                                                                          
                                       

  BytecodeFileFooter(const SHA1 &fileHash) {
    std::copy(fileHash.begin(), fileHash.end(), this->fileHash);
  }
};

                                                                          
                                                                               
                       
struct SmallStringTableEntry {
                                                                            
                        
                                     
                                                           
                                                  
                                                                             
                                                                      
  uint32_t isUTF16 : 1;
  uint32_t offset : 23;
  uint32_t length : 8;

  static constexpr uint32_t INVALID_OFFSET = (1 << 23);
  static constexpr uint32_t INVALID_LENGTH = (1 << 8) - 1;

  bool isOverflowed() const {
    return length == INVALID_LENGTH;
  }

                                                                            
                                             
  SmallStringTableEntry(
      const StringTableEntry &entry,
      uint32_t overflowOffset) {
    isUTF16 = entry.isUTF16();
    if (entry.getOffset() < INVALID_OFFSET &&
        entry.getLength() < INVALID_LENGTH) {
      offset = entry.getOffset();
      length = entry.getLength();
    } else {
      assert(overflowOffset < INVALID_OFFSET);
      offset = overflowOffset;
      length = INVALID_LENGTH;
    }
  }
};

                                                                 
static_assert(
    sizeof(SmallStringTableEntry) == 4,
    "SmallStringTableEntry should take up 4 bytes total");

                                                                                
struct OverflowStringTableEntry {
  uint32_t offset;
  uint32_t length;

  OverflowStringTableEntry(uint32_t offset, uint32_t length)
      : offset(offset), length(length) {}
};

union FunctionHeaderFlag {
  enum {
    ProhibitCall = 0,
    ProhibitConstruct = 1,
    ProhibitNone = 2,
  };

  struct {
                                                                             
    uint8_t prohibitInvoke : 2;
    bool strictMode : 1;
    bool hasExceptionHandler : 1;
    bool hasDebugInfo : 1;
    bool overflowed : 1;
    bool derivedConstructor : 1;
    bool asyncGenerator : 1;
  };
  uint8_t flags;

  FunctionHeaderFlag() {
    flags = 0;
    prohibitInvoke = ProhibitNone;
  }

                                                                           
            
  bool isCallProhibited(bool construct) const {
    return prohibitInvoke == (uint8_t)construct;
  }
};

                                                                 
static_assert(
    sizeof(FunctionHeaderFlag) == 1,
    "FunctionHeaderFlag should take up 1 byte total");

                                                                      
                                                                    
                                                                               
                            
#define FUNC_HEADER_FIELDS(V)                    \
                                                 \
  V(uint32_t, uint32_t, offset, 25)              \
  V(uint32_t, uint32_t, paramCount, 7)           \
                                                 \
  V(uint32_t, uint32_t, bytecodeSizeInBytes, 15) \
  V(uint32_t, uint32_t, functionName, 17)        \
                                                 \
  V(uint32_t, uint32_t, infoOffset, 25)          \
  V(uint32_t, uint32_t, frameSize, 7)            \
                                                 \
  V(uint32_t, uint8_t, environmentSize, 8)       \
  V(uint8_t, uint8_t, highestReadCacheIndex, 8)  \
  V(uint8_t, uint8_t, highestWriteCacheIndex, 8)

   
                          
   
struct FunctionHeader {
                                                               
#define DECLARE_FIELD(api_type, store_type, name, bits) api_type name;
  FUNC_HEADER_FIELDS(DECLARE_FIELD)
#undef DECLARE_FIELD

  FunctionHeaderFlag flags{};

 public:
  FunctionHeader(
      uint32_t size,
      uint32_t paramCount,
      uint32_t frameSize,
      uint32_t envSize,
      uint32_t functionNameID,
      uint8_t hiRCacheIndex,
      uint8_t hiWCacheIndex)
      : offset(0),
        paramCount(paramCount),
        bytecodeSizeInBytes(size),
        functionName(functionNameID),
        infoOffset(0),
        frameSize(frameSize),
        environmentSize(envSize),
        highestReadCacheIndex(hiRCacheIndex),
        highestWriteCacheIndex(hiWCacheIndex) {}
};

                                                           
                                                            
                                      
                                                                
                                                      
                                                                  
                                                                 
                                                        

struct SmallFuncHeader {
                                                                         
#define DECLARE_BITFIELD(api_type, store_type, name, bits) \
  store_type name : bits;
  FUNC_HEADER_FIELDS(DECLARE_BITFIELD)
#undef DECLARE_BITFIELD

  FunctionHeaderFlag flags{};

                                                                  
                                                                  
  SmallFuncHeader(const FunctionHeader &large) {
    std::memset(this, 0, sizeof(SmallFuncHeader));                       
    flags = large.flags;
#define CHECK_COPY_FIELD(api_type, store_type, name, bits) \
  if (large.name > (1U << bits) - 1) {                     \
    setLargeHeaderOffset(large.infoOffset);                \
    return;                                                \
  }                                                        \
  name = large.name;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
    FUNC_HEADER_FIELDS(CHECK_COPY_FIELD)
#pragma GCC diagnostic pop
#undef CHECK_COPY_FIELD
    assert(!flags.overflowed);
  }

  void setLargeHeaderOffset(uint32_t largeHeaderOffset) {
    flags.overflowed = true;
                                                                       
    offset = largeHeaderOffset & 0xffff;
    infoOffset = largeHeaderOffset >> 16;
  }

  uint32_t getLargeHeaderOffset() const {
    assert(flags.overflowed);
    return (infoOffset << 16) | offset;
  }
};

                                                                            
                                                                       
static_assert(
    sizeof(BytecodeFileHeader) % 32 == 0,
    "BytecodeFileHeader size should be cache friendly");

static_assert(
    32 % sizeof(SmallFuncHeader) == 0,
    "SmallFuncHeader size should be cache friendly");

struct ExceptionHandlerTableHeader {
  uint32_t count;
};

                                                                         
                                                
struct HBCExceptionHandlerInfo {
  uint32_t start;
  uint32_t end;
  uint32_t target;
};

                                             
struct DebugInfoHeader {
                                             
  uint32_t filenameCount;
                                            
  uint32_t filenameStorageSize;

                             
  uint32_t fileRegionCount;
                                                             
  uint32_t scopeDescDataOffset;
                                                                  
  uint32_t textifiedCalleeOffset;
                                                        
  uint32_t stringTableOffset;
                                     
  uint32_t debugDataSize;
};

                                                          
struct DebugFileRegion {
  uint32_t fromAddress;
  uint32_t filenameId;
  uint32_t sourceMappingUrlId;
};

LLVM_PACKED_END

                                                   
                                                                  
template <typename Visitor>
void visitBytecodeSegmentsInOrder(Visitor &visitor) {
  visitor.visitFunctionHeaders();
  visitor.visitStringKinds();
  visitor.visitIdentifierHashes();
  visitor.visitSmallStringTable();
  visitor.visitOverflowStringTable();
  visitor.visitStringStorage();
  visitor.visitArrayBuffer();
  visitor.visitObjectKeyBuffer();
  visitor.visitObjectValueBuffer();
  visitor.visitBigIntTable();
  visitor.visitBigIntStorage();
  visitor.visitRegExpTable();
  visitor.visitRegExpStorage();
  visitor.visitCJSModuleTable();
  visitor.visitFunctionSourceTable();
}

                                                                            
                                                                           
                                                                              
                                                                              
                                                                               
                                                                             
                                              
template <bool Mutable>
struct BytecodeFileFields {
  template <typename T>
  using Pointer = typename std::conditional<Mutable, T *, const T *>::type;

  template <typename T>
  using Array = typename std::
      conditional<Mutable, llvh::MutableArrayRef<T>, llvh::ArrayRef<T>>::type;

                      
  Pointer<BytecodeFileHeader> header{nullptr};

                                                                      
  Array<hbc::SmallFuncHeader> functionHeaders;

                                             
  Array<hbc::SmallStringTableEntry> stringTableEntries{};

                                                                         
  Array<StringKind::Entry> stringKinds{};

                                    
  Array<uint32_t> identifierHashes{};

                                                  
  Array<hbc::OverflowStringTableEntry> stringTableOverflowEntries{};

                                                   
  Array<uint8_t> stringStorage;

                                
  Array<uint8_t> arrayBuffer;

                             
  Array<uint8_t> objKeyBuffer;

                               
  Array<uint8_t> objValueBuffer;

                              
  Array<bigint::BigIntTableEntry> bigIntTable;

                                  
  Array<uint8_t> bigIntStorage;

                              
  Array<RegExpTableEntry> regExpTable;

                                  
  Array<uint8_t> regExpStorage;

                          
  Array<std::pair<uint32_t, uint32_t>> cjsModuleTable;

                                   
  Array<std::pair<uint32_t, uint32_t>> cjsModuleTableStatic;

                                            
  Array<std::pair<uint32_t, uint32_t>> functionSourceTable;

                                                                        
                                                                              
                                             
                                                                       
                                       
                                                               
  bool populateFromBuffer(
      Array<uint8_t> bytes,
      std::string *outError,
      BytecodeForm form = BytecodeForm::Execution);
};

using ConstBytecodeFileFields = BytecodeFileFields<false>;
using MutableBytecodeFileFields = BytecodeFileFields<true>;

}                 
}                    

#endif                                         
