/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_BYTECODE_H
#define HERMES_BCGEN_HBC_BYTECODE_H

#include "llvh/ADT/ArrayRef.h"

#include "hermes/BCGen/HBC/BytecodeFileFormat.h"
#include "hermes/BCGen/HBC/BytecodeInstructionGenerator.h"
#include "hermes/BCGen/HBC/BytecodeStream.h"
#include "hermes/BCGen/HBC/DebugInfo.h"
#include "hermes/BCGen/HBC/StringKind.h"
#include "hermes/IRGen/IRGen.h"
#include "hermes/Regex/RegexSerialization.h"
#include "hermes/Support/BigIntSupport.h"
#include "hermes/Support/StringTableEntry.h"
#include "hermes/Utils/Options.h"

#include <memory>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
class SourceMapGenerator;

namespace hbc {

using llvh::ArrayRef;

                                                                               
class BytecodeFunction {
                                                                                
                                                                              
                  
                                                                               
                                     
                                                                               
                                                                         
             
  const std::vector<opcode_atom_t> opcodesAndJumpTables_;

                                                           
  FunctionHeader header_;

                                             
  DebugOffsets debugOffsets_{};

                                 
  std::vector<HBCExceptionHandlerInfo> exceptions_;

                                                                  
  std::unique_ptr<LazyCompilationData> lazyCompilationData_{};

 public:
                                                                            
  explicit BytecodeFunction(
      std::vector<opcode_atom_t> &&opcodesAndJumpTables,
      FunctionHeader &&header,
      std::vector<HBCExceptionHandlerInfo> &&exceptionHandlers)
      : opcodesAndJumpTables_(std::move(opcodesAndJumpTables)),
        header_(std::move(header)),
        exceptions_(std::move(exceptionHandlers)) {}

  const FunctionHeader &getHeader() const {
    return header_;
  }

  FunctionHeaderFlag &mutableFlags() {
    return header_.flags;
  }

  void setOffset(uint32_t offset) {
    header_.offset = offset;
  }
  uint32_t getOffset() const {
    return header_.offset;
  }

  void setInfoOffset(uint32_t offset) {
    header_.infoOffset = offset;
  }

  bool isStrictMode() const {
    return header_.flags.strictMode;
  }

                                                                              
             
  ArrayRef<opcode_atom_t> getOpcodeArray() const {
    return opcodesAndJumpTables_;
  }

                                                                           
                                                           
  ArrayRef<opcode_atom_t> getOpcodesOnly() const {
    return {opcodesAndJumpTables_.data(), header_.bytecodeSizeInBytes};
  }

                                                                               
                                                                      
  ArrayRef<uint32_t> getJumpTablesOnly() const;

  bool hasExceptionHandlers() const {
    return exceptions_.size() > 0;
  }

  uint32_t getExceptionHandlerCount() const {
    return exceptions_.size();
  }

  ArrayRef<HBCExceptionHandlerInfo> getExceptionHandlers() const {
    return exceptions_;
  }

  bool hasDebugInfo() const {
    return debugOffsets_.sourceLocations != DebugOffsets::NO_OFFSET ||
        debugOffsets_.scopeDescData != DebugOffsets::NO_OFFSET;
  }

  const DebugOffsets *getDebugOffsets() const {
    return &debugOffsets_;
  }

  void setDebugOffsets(DebugOffsets offsets) {
    debugOffsets_ = offsets;
    header_.flags.hasDebugInfo = hasDebugInfo();
  }

  LazyCompilationData *getLazyCompilationData() const {
    return lazyCompilationData_.get();
  }

  void setLazyCompilationData(std::unique_ptr<LazyCompilationData> data) {
    lazyCompilationData_ = std::move(data);
  }

                                                             
  bool isLazy() const {
    return (bool)lazyCompilationData_;
  }
};

                                                                             
class BytecodeModule {
  using FunctionList = std::vector<std::unique_ptr<BytecodeFunction>>;
  using SerializableBufferTy = std::vector<unsigned char>;

                                   
  FunctionList functions_{};

                                                                            
            
  uint32_t globalFunctionIndex_{};

                                                                         
  std::vector<StringKind::Entry> stringKinds_;

                                                                        
                                      
  std::vector<uint32_t> identifierHashes_;

                                                                           
                                        
  std::vector<StringTableEntry> stringTable_;

                                                     
  std::vector<unsigned char> stringStorage_;

                                                                          
                          
  std::vector<bigint::BigIntTableEntry> bigIntTable_;

                                           
  std::vector<uint8_t> bigIntStorage_;

                                 
  std::vector<unsigned char> regExpStorage_;

                                                                             
                          
  std::vector<RegExpTableEntry> regExpTable_;

                                                          
  DebugInfo debugInfo_;

                         
  SerializableBufferTy arrayBuffer_;

                              
  SerializableBufferTy objKeyBuffer_;

                                
  SerializableBufferTy objValBuffer_;

                                                          
                                                                          
                                                                           
                                  
  uint32_t segmentID_;

                                                                         
                                                   
  std::vector<std::pair<uint32_t, uint32_t>> cjsModuleTable_{};

                                                                         
                                                        
                                                        
  std::vector<std::pair<uint32_t, uint32_t>> cjsModuleTableStatic_{};

                                                                       
                                                                              
                                                                      
                                                                      
  std::vector<std::pair<uint32_t, uint32_t>> functionSourceTable_{};

                                                                             
              
  BytecodeOptions options_{};

 public:
                                
  explicit BytecodeModule(
      uint32_t functionCount,
      std::vector<StringKind::Entry> &&stringKinds,
      std::vector<uint32_t> &&identifierHashes,
      std::vector<StringTableEntry> &&stringTable,
      std::vector<unsigned char> &&stringStorage,
      std::vector<bigint::BigIntTableEntry> &&bigIntTable,
      std::vector<uint8_t> &&bigIntStorage,
      std::vector<RegExpTableEntry> &&regExpTable,
      std::vector<unsigned char> &&regExpStorage,
      uint32_t globalFunctionIndex,
      std::vector<unsigned char> &&arrayBuffer,
      std::vector<unsigned char> &&objKeyBuffer,
      std::vector<unsigned char> &&objValBuffer,
      uint32_t segmentID,
      std::vector<std::pair<uint32_t, uint32_t>> &&cjsModuleTable,
      std::vector<std::pair<uint32_t, uint32_t>> &&cjsModuleTableStatic,
      std::vector<std::pair<uint32_t, uint32_t>> &&functionSourceTable,
      BytecodeOptions options)
      : globalFunctionIndex_(globalFunctionIndex),
        stringKinds_(std::move(stringKinds)),
        identifierHashes_(std::move(identifierHashes)),
        stringTable_(std::move(stringTable)),
        stringStorage_(std::move(stringStorage)),
        bigIntTable_(std::move(bigIntTable)),
        bigIntStorage_(std::move(bigIntStorage)),
        regExpStorage_(std::move(regExpStorage)),
        regExpTable_(std::move(regExpTable)),
        arrayBuffer_(std::move(arrayBuffer)),
        objKeyBuffer_(std::move(objKeyBuffer)),
        objValBuffer_(std::move(objValBuffer)),
        segmentID_(segmentID),
        cjsModuleTable_(std::move(cjsModuleTable)),
        cjsModuleTableStatic_(std::move(cjsModuleTableStatic)),
        functionSourceTable_(std::move(functionSourceTable)),
        options_(options) {
    functions_.resize(functionCount);
  }

                                                                 
  explicit BytecodeModule(uint32_t functionCount) {
    functions_.resize(functionCount);
  }

  const FunctionList &getFunctionTable() const {
    return functions_;
  }
  uint32_t getNumFunctions() const {
    return functions_.size();
  }

  uint32_t getGlobalFunctionIndex() const {
    return globalFunctionIndex_;
  }

                                                            
  void setFunction(uint32_t index, std::unique_ptr<BytecodeFunction> F);

  BytecodeFunction &getFunction(unsigned index);

  BytecodeFunction &getGlobalCode() {
    return getFunction(globalFunctionIndex_);
  }

  llvh::ArrayRef<StringKind::Entry> getStringKinds() const {
    return stringKinds_;
  }

                                        
  uint32_t getIdentifierCount() const {
    return identifierHashes_.size();
  }

  llvh::ArrayRef<uint32_t> getIdentifierHashes() const {
    return identifierHashes_;
  }

  uint32_t getStringTableSize() const {
    return stringTable_.size();
  }

  StringTableEntry::StringTableRefTy getStringTable() const {
    return stringTable_;
  }

  uint32_t getStringStorageSize() const {
    return stringStorage_.size();
  }

  StringTableEntry::StringStorageRefTy getStringStorage() const {
    return stringStorage_;
  }

  llvh::ArrayRef<bigint::BigIntTableEntry> getBigIntTable() const {
    return bigIntTable_;
  }

  llvh::ArrayRef<uint8_t> getBigIntStorage() const {
    return bigIntStorage_;
  }

  llvh::ArrayRef<RegExpTableEntry> getRegExpTable() const {
    return regExpTable_;
  }

  llvh::ArrayRef<unsigned char> getRegExpStorage() const {
    return regExpStorage_;
  }

  uint32_t getSegmentID() const {
    return segmentID_;
  }

  llvh::ArrayRef<std::pair<uint32_t, uint32_t>> getCJSModuleTable() const {
    return cjsModuleTable_;
  }

  llvh::ArrayRef<std::pair<uint32_t, uint32_t>> getCJSModuleTableStatic()
      const {
    return cjsModuleTableStatic_;
  }

  llvh::ArrayRef<std::pair<uint32_t, uint32_t>> getFunctionSourceTable() const {
    return functionSourceTable_;
  }

  DebugInfo &getDebugInfo() {
    return debugInfo_;
  }

  void setDebugInfo(DebugInfo info) {
    debugInfo_ = std::move(info);
  }

  uint32_t getArrayBufferSize() const {
    return arrayBuffer_.size();
  }

  ArrayRef<unsigned char> getArrayBuffer() const {
    return arrayBuffer_;
  }

                                                          
  uint32_t getObjectKeyBufferSize() const {
    return objKeyBuffer_.size();
  }

                                                            
  uint32_t getObjectValueBufferSize() const {
    return objValBuffer_.size();
  }

                                                                    
                                                                    
  std::pair<ArrayRef<unsigned char>, ArrayRef<unsigned char>> getObjectBuffer()
      const {
    return {
        ArrayRef<unsigned char>(objKeyBuffer_),
        ArrayRef<unsigned char>(objValBuffer_)};
  }

                                                                           
                                                                          
  std::pair<ArrayRef<unsigned char>, ArrayRef<unsigned char>>
  getObjectBufferAtOffset(unsigned keyIdx, unsigned valIdx) const {
    return {
        ArrayRef<unsigned char>(objKeyBuffer_).slice(keyIdx),
        ArrayRef<unsigned char>(objValBuffer_).slice(valIdx)};
  }

                                                                      
  void populateSourceMap(SourceMapGenerator *sourceMap) const;

  BytecodeOptions getBytecodeOptions() const {
    return options_;
  }
};

}                 
}                    
#pragma GCC diagnostic pop

#endif
