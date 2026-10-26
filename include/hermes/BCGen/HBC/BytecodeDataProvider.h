/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_BYTECODEDATAPROVIDER_H
#define HERMES_BCGEN_HBC_BYTECODEDATAPROVIDER_H

#include "hermes/BCGen/HBC/BytecodeFileFormat.h"
#include "hermes/BCGen/HBC/DebugInfo.h"
#include "hermes/Public/Buffer.h"
#include "hermes/Regex/RegexSerialization.h"
#include "hermes/SourceMap/SourceMapGenerator.h"
#include "hermes/Support/BigIntSupport.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/Support/PageAccessTracker.h"
#include "hermes/Support/StringTableEntry.h"

#include "llvh/ADT/ArrayRef.h"

#include <atomic>
#include <thread>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

namespace hermes {
namespace hbc {
class BCProviderBase;
class BCProviderFromBuffer;

                                                                           
                                                                         
#ifdef HERMESVM_LEAN
using BCProvider = BCProviderFromBuffer;
#else
using BCProvider = BCProviderBase;
#endif

using StringID = uint32_t;

                                                                       
                                                              
class RuntimeFunctionHeader {
                                             
  const char *ptr_;

 public:
  explicit RuntimeFunctionHeader(const hbc::SmallFuncHeader *smallHeader)
      : ptr_(reinterpret_cast<const char *>(smallHeader)) {
    assert(!isLarge());
  }
  explicit RuntimeFunctionHeader(const hbc::FunctionHeader *large)
      : ptr_(reinterpret_cast<const char *>(large) + 1) {
    assert(isLarge());
  }

#define HEADER_FIELD_ACCESSOR(api_type, store_type, name, bits) \
  api_type name() const {                                       \
    if (LLVM_UNLIKELY(isLarge()))                               \
      return asLarge()->name;                                   \
    else                                                        \
      return asSmall()->name;                                   \
  }
  FUNC_HEADER_FIELDS(HEADER_FIELD_ACCESSOR)
  HEADER_FIELD_ACCESSOR(
      hbc::FunctionHeaderFlag,
      hbc::FunctionHeaderFlag,
      flags,
      8)
#undef HEADER_FIELD_ACCESSOR

 private:
  bool isLarge() const {
    return reinterpret_cast<uintptr_t>(ptr_) & 1;
  }

  const hbc::SmallFuncHeader *asSmall() const {
    assert(!isLarge());
    return reinterpret_cast<const hbc::SmallFuncHeader *>(ptr_);
  }

  const hbc::FunctionHeader *asLarge() const {
    assert(isLarge());
    return reinterpret_cast<const hbc::FunctionHeader *>(ptr_ - 1);
  }
};

static_assert(
    std::is_trivially_copyable<RuntimeFunctionHeader>::value,
    "RuntimeFunctionHeader should be trivially copyable");

                                                                   
                                                                      
                                                                     
                                                           
class BCProviderBase {
 protected:
                                                                             
              
  BytecodeOptions options_{};

                          
  uint32_t functionCount_{};

                        
  uint32_t globalFunctionIndex_{};

                                                             
  uint32_t stringCount_{};
  llvh::ArrayRef<StringKind::Entry> stringKinds_{};
  llvh::ArrayRef<uint32_t> identifierHashes_{};
  llvh::ArrayRef<unsigned char> stringStorage_{};

  llvh::ArrayRef<unsigned char> arrayBuffer_{};
  llvh::ArrayRef<unsigned char> objKeyBuffer_{};
  llvh::ArrayRef<unsigned char> objValueBuffer_{};

  llvh::ArrayRef<bigint::BigIntTableEntry> bigIntTable_{};
  llvh::ArrayRef<unsigned char> bigIntStorage_{};

  llvh::ArrayRef<RegExpTableEntry> regExpTable_{};
  llvh::ArrayRef<unsigned char> regExpStorage_{};

                                                          
  uint32_t segmentID_;

                                                                         
                                                                  
  llvh::ArrayRef<std::pair<uint32_t, uint32_t>> cjsModuleTable_{};

                                                                         
                                                                       
  llvh::ArrayRef<std::pair<uint32_t, uint32_t>> cjsModuleTableStatic_{};

                                                                         
                                                                 
  llvh::ArrayRef<std::pair<uint32_t, uint32_t>> functionSourceTable_{};

                                                                            
                                                                         
                                                                    
  const hbc::DebugInfo *debugInfo_{};

                                                                
                                                   
  std::string errstr_{};

                                                                            
  virtual void createDebugInfo() = 0;

 public:
                                            
  BytecodeOptions getBytecodeOptions() const {
    return options_;
  }
  uint32_t getFunctionCount() const {
    return functionCount_;
  }
  uint32_t getGlobalFunctionIndex() const {
    return globalFunctionIndex_;
  }
  uint32_t getStringCount() const {
    return stringCount_;
  }
  uint32_t getBigIntCount() const {
    return bigIntTable_.size();
  }
  llvh::ArrayRef<StringKind::Entry> getStringKinds() const {
    return stringKinds_;
  }
  llvh::ArrayRef<uint32_t> getIdentifierHashes() const {
    return identifierHashes_;
  }
  llvh::ArrayRef<unsigned char> getStringStorage() const {
    return stringStorage_;
  }
  llvh::ArrayRef<unsigned char> getArrayBuffer() const {
    return arrayBuffer_;
  }
  llvh::ArrayRef<unsigned char> getObjectKeyBuffer() const {
    return objKeyBuffer_;
  }
  llvh::ArrayRef<unsigned char> getObjectValueBuffer() const {
    return objValueBuffer_;
  }
  llvh::ArrayRef<bigint::BigIntTableEntry> getBigIntTable() const {
    return bigIntTable_;
  }
  llvh::ArrayRef<unsigned char> getBigIntStorage() const {
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
  const std::string getErrorStr() const {
    return errstr_;
  }

  virtual StringTableEntry getStringTableEntry(uint32_t index) const = 0;

  llvh::StringRef getStringRefFromID(StringID stringID) const {
    auto entry = getStringTableEntry(stringID);
    return llvh::StringRef(
        (const char *)getStringStorage().begin() + entry.getOffset(),
        entry.getLength());
  }

                                                  
  const hbc::DebugInfo *getDebugInfo() const {
    if (!debugInfo_) {
      const_cast<BCProviderBase *>(this)->createDebugInfo();
    }
    return debugInfo_;
  }

                                                                                
  virtual llvh::ArrayRef<uint8_t> getEpilogue() const {
    return llvh::ArrayRef<uint8_t>();
  }

                                                                  
  virtual SHA1 getSourceHash() const {
    return SHA1{};
  }

                                           
  virtual RuntimeFunctionHeader getFunctionHeader(
      uint32_t functionID) const = 0;

                                           
  virtual const uint8_t *getBytecode(uint32_t functionID) const = 0;

                                                                      
  virtual llvh::ArrayRef<hbc::HBCExceptionHandlerInfo> getExceptionTable(
      uint32_t functionID) const = 0;

                                                                    
  virtual const hbc::DebugOffsets *getDebugOffsets(
      uint32_t functionID) const = 0;

                                                                             
                
  llvh::Optional<SourceMapTextLocation> getLocationForAddress(
      uint32_t funcId,
      uint32_t offsetInFunction) const;

  virtual ~BCProviderBase() = default;

                                                          
  virtual bool isFunctionLazy(uint32_t functionID) const = 0;

                                                    
  virtual bool isLazy() const = 0;

                                                                           
  virtual void startWarmup(uint8_t percent) {}

                                                           
  virtual void madvise(oscompat::MAdvice advice) {}

                                                                            
                                                                     
  virtual void adviseStringTableSequential() {}

                                                                            
                                                                        
  virtual void adviseStringTableRandom() {}

                                                                            
                                                                  
  virtual void willNeedStringTable() {}

                                                                               
                                                                                
  virtual void startPageAccessTracker() {}

                                                                 
  virtual volatile PageAccessTracker *getPageAccessTracker() {
    return nullptr;
  }

                                                                     
  virtual llvh::ArrayRef<uint8_t> getRawBuffer() const {
    return llvh::ArrayRef<uint8_t>();
  }

                                                                        
                                                                        
                                            
  int32_t findCatchTargetOffset(uint32_t functionID, uint32_t exceptionOffset)
      const;

                                                                      
                                                                              
                                                                           
                                                                          
                                                                            
  uint32_t getVirtualOffsetForFunction(uint32_t functionID) const;
};

                                                                       
                                                                             
                                                                           
                                                         
class BCProviderFromBuffer final : public BCProviderBase {
                                     
  std::unique_ptr<const Buffer> buffer_;

                                                                 
  const uint8_t *bufferPtr_;

                               
  const hbc::SmallFuncHeader *functionHeaders_{};

                                   
                                                                             
                           
  const hbc::SmallStringTableEntry *stringTableEntries_{};

                                            
  llvh::ArrayRef<OverflowStringTableEntry> overflowStringTableEntries_{};

                                                
  uint32_t debugInfoOffset_{};

                                                                             
  llvh::Optional<std::thread> warmupThread_;

                                                              
  std::atomic<bool> warmupAbortFlag_;

  std::unique_ptr<volatile PageAccessTracker> tracker_;

                               
  const uint8_t *end_;

                                                                          
  void stopWarmup();

  explicit BCProviderFromBuffer(
      std::unique_ptr<const Buffer> buffer,
      BytecodeForm form);

  void createDebugInfo() override;

                                                                            
                                                                             
                                                        
  std::pair<
      llvh::ArrayRef<hbc::HBCExceptionHandlerInfo>,
      const hbc::DebugOffsets *>
  getExceptionTableAndDebugOffsets(uint32_t functionID) const;

 public:
  static std::pair<std::unique_ptr<BCProviderFromBuffer>, std::string>
  createBCProviderFromBuffer(
      std::unique_ptr<const Buffer> buffer,
      BytecodeForm form = BytecodeForm::Execution) {
    auto ret = std::unique_ptr<BCProviderFromBuffer>(
        new BCProviderFromBuffer(std::move(buffer), form));
    auto errstr = ret->getErrorStr();
    return {errstr.empty() ? std::move(ret) : nullptr, errstr};
  }

                                                   
  static bool isBytecodeStream(llvh::ArrayRef<uint8_t> aref) {
    const auto *header =
        reinterpret_cast<const hbc::BytecodeFileHeader *>(aref.data());
    return (
        aref.size() >= sizeof(hbc::BytecodeFileHeader) &&
        header->magic == hbc::MAGIC);
  }

                                                     
  static bool isBytecodeStream(const Buffer &buffer) {
    return isBytecodeStream(
        llvh::ArrayRef<uint8_t>(buffer.data(), buffer.size()));
  }

                                                                          
                                                                         
                                                                         
                                                                
  static void prefetch(llvh::ArrayRef<uint8_t> aref);

                                                     
  static llvh::ArrayRef<uint8_t> getEpilogueFromBytecode(
      llvh::ArrayRef<uint8_t> buffer);

  static SHA1 getSourceHashFromBytecode(llvh::ArrayRef<uint8_t> buffer);

                                                                           
                                    
  static bool bytecodeStreamSanityCheck(
      llvh::ArrayRef<uint8_t> aref,
      std::string *errorMessage = nullptr);

                                                                             
                                            
  static bool bytecodeHashIsValid(llvh::ArrayRef<uint8_t> aref);

                                                                            
                                         
  static void updateBytecodeHash(llvh::MutableArrayRef<uint8_t> aref);

                                                     
                                                            
  const llvh::ArrayRef<hbc::SmallFuncHeader> getSmallFunctionHeaders() const {
    return llvh::ArrayRef<hbc::SmallFuncHeader>(
        functionHeaders_, functionCount_);
  }

  RuntimeFunctionHeader getFunctionHeader(uint32_t functionID) const override {
    const hbc::SmallFuncHeader &smallHeader = functionHeaders_[functionID];
    if (LLVM_UNLIKELY(smallHeader.flags.overflowed)) {
      auto large = reinterpret_cast<const hbc::FunctionHeader *>(
          bufferPtr_ + smallHeader.getLargeHeaderOffset());
      return RuntimeFunctionHeader(large);
    } else {
      return RuntimeFunctionHeader(&smallHeader);
    }
  }

                                                             
                                                                      
  llvh::ArrayRef<SmallStringTableEntry> getSmallStringTableEntries() const {
    return llvh::makeArrayRef(stringTableEntries_, stringCount_);
  }

                                                             
                                                         
  llvh::ArrayRef<OverflowStringTableEntry> getOverflowStringTableEntries()
      const {
    return overflowStringTableEntries_;
  }

  StringTableEntry getStringTableEntry(uint32_t index) const override {
    auto &smallHeader = stringTableEntries_[index];
    if (LLVM_UNLIKELY(smallHeader.isOverflowed())) {
      auto overflow = overflowStringTableEntries_[smallHeader.offset];
      StringTableEntry entry(
          overflow.offset, overflow.length, smallHeader.isUTF16);
      return entry;
    }
    StringTableEntry entry(
        smallHeader.offset, smallHeader.length, smallHeader.isUTF16);
    return entry;
  }

  const uint8_t *getBytecode(uint32_t functionID) const override {
    return bufferPtr_ + getFunctionHeader(functionID).offset();
  }

  llvh::ArrayRef<hbc::HBCExceptionHandlerInfo> getExceptionTable(
      uint32_t functionID) const override {
    return getExceptionTableAndDebugOffsets(functionID).first;
  }

  const hbc::DebugOffsets *getDebugOffsets(uint32_t functionID) const override {
    return getExceptionTableAndDebugOffsets(functionID).second;
  }

  llvh::ArrayRef<uint8_t> getEpilogue() const override;
  SHA1 getSourceHash() const override;

  void startWarmup(uint8_t percent) override;

  void madvise(oscompat::MAdvice advice) override;
  void adviseStringTableSequential() override;
  void adviseStringTableRandom() override;
  void willNeedStringTable() override;

  void startPageAccessTracker() override;

  volatile PageAccessTracker *getPageAccessTracker() override {
    return tracker_.get();
  }

  llvh::ArrayRef<uint8_t> getRawBuffer() const override {
    return llvh::ArrayRef<uint8_t>(bufferPtr_, buffer_->size());
  }

  ~BCProviderFromBuffer() override {
    stopWarmup();
    delete debugInfo_;
  }

  bool isFunctionLazy(uint32_t functionID) const override {
    return false;
  }

  bool isLazy() const override {
    return false;
  }
};

}                 
}                    
#pragma GCC diagnostic pop

#endif                                           
