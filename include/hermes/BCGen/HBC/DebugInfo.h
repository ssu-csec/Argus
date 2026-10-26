/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_DEBUGINFO_H
#define HERMES_BCGEN_HBC_DEBUGINFO_H

#include "hermes/BCGen/HBC/BytecodeFileFormat.h"
#include "hermes/BCGen/HBC/ConsecutiveStringStorage.h"
#include "hermes/BCGen/HBC/StreamVector.h"
#include "hermes/BCGen/HBC/UniquingFilenameTable.h"
#include "hermes/Public/DebuggerTypes.h"
#include "hermes/Support/LEB128.h"
#include "hermes/Support/OptValue.h"
#include "hermes/Support/StringTable.h"
#include "hermes/Support/UTF8.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/Format.h"

#include <string>
#include <vector>

namespace llvh {
class raw_ostream;
}                  

namespace hermes {
class SourceMapGenerator;
namespace hbc {

                                                                      
struct DebugSourceLocation {
  static constexpr uint32_t NO_REG = UINT32_MAX;
                                            
  uint32_t address{0};
                                              
  uint32_t filenameId{0};
                                                    
                                               
  uint32_t sourceMappingUrlId{facebook::hermes::debugger::kInvalidBreakpoint};
                             
  uint32_t line{0};
                               
  uint32_t column{0};
                                                           
                                                                          
                                                                              
  uint32_t statement{0};
                                                                       
                                                                      
                                              
  uint32_t scopeAddress{0};
                                                                
  uint32_t envReg{NO_REG};

  DebugSourceLocation() {}

  DebugSourceLocation(
      uint32_t address,
      uint32_t filenameId,
      uint32_t line,
      uint32_t column,
      uint32_t statement,
      uint32_t scopeAddress,
      uint32_t envReg)
      : address(address),
        filenameId(filenameId),
        line(line),
        column(column),
        statement(statement),
        scopeAddress(scopeAddress),
        envReg(envReg) {}

  bool operator==(const DebugSourceLocation &rhs) const {
    return address == rhs.address && filenameId == rhs.filenameId &&
        line == rhs.line && column == rhs.column &&
        statement == rhs.statement && scopeAddress == rhs.scopeAddress &&
        envReg == rhs.envReg;
  }

  bool operator!=(const DebugSourceLocation &rhs) const {
    return !(*this == rhs);
  }
};

                                    
struct DebugScopeDescriptor {
                                                                              
                               
  struct Flags {
                                                             
    explicit Flags(uint32_t bits = 0);

                                     
    uint32_t toUint32() const;

                                                                                
                                    
    bool isInnerScope;

                                                                                
    bool isDynamic;

   private:
    enum class Bits {
      InnerScope,
      Dynamic,
    };
  };

                                                                              
                              
  OptValue<unsigned> parentOffset;

  Flags flags;

                                                
  llvh::SmallVector<llvh::StringRef, 4> names;
};

                                                                          
             
struct DebugTextifiedCallee {
                                            
  uint32_t address{0};
                                                                               
  Identifier textifiedCallee;
};

                                                       
struct DebugOffsets {
                                                             
                            
  uint32_t sourceLocations = NO_OFFSET;

                                                                          
  uint32_t scopeDescData = NO_OFFSET;

                                                                          
  uint32_t textifiedCallees = NO_OFFSET;

                                          
  static constexpr uint32_t NO_OFFSET = UINT32_MAX;

                   
  DebugOffsets() = default;
  DebugOffsets(uint32_t src, uint32_t scopeDesc, uint32_t tCallee)
      : sourceLocations(src),
        scopeDescData(scopeDesc),
        textifiedCallees(tCallee) {}
};

                                                                            
struct DebugSearchResult {
                                                          
  uint32_t functionIndex{0};

                                                      
                                                 
  uint32_t bytecodeOffset{0};

                                            
  uint32_t line{0};

                                              
  uint32_t column{0};

  DebugSearchResult() {}

  DebugSearchResult(
      uint32_t functionIndex,
      uint32_t bytecodeOffset,
      uint32_t line,
      uint32_t column)
      : functionIndex(functionIndex),
        bytecodeOffset(bytecodeOffset),
        line(line),
        column(column) {}
};

                                            
class DebugInfo {
 public:
  using DebugFileRegionList = llvh::SmallVector<DebugFileRegion, 1>;

 private:
                                                                            
  std::vector<StringTableEntry> filenameTable_{};

                                   
  std::vector<unsigned char> filenameStorage_{};

  DebugFileRegionList files_{};
  uint32_t scopeDescDataOffset_ = 0;
  uint32_t textifiedCalleeOffset_ = 0;
  uint32_t stringTableOffset_ = 0;
  StreamVector<uint8_t> data_{};

                                       
  OptValue<uint32_t> getFilenameForAddress(uint32_t debugOffset) const;

                                                                                
                                 
  llvh::StringRef decodeString(
      uint32_t *inoutOffset,
      llvh::ArrayRef<uint8_t> data) const;

 public:
  explicit DebugInfo() = default;
               DebugInfo(DebugInfo &&that) = default;

  explicit DebugInfo(
      ConsecutiveStringStorage &&filenameStrings,
      DebugFileRegionList &&files,
      uint32_t scopeDescDataOffset,
      uint32_t textifiedCalleeOffset,
      uint32_t stringTableOffset,
      StreamVector<uint8_t> &&data)
      : filenameTable_(filenameStrings.acquireStringTable()),
        filenameStorage_(filenameStrings.acquireStringStorage()),
        files_(std::move(files)),
        scopeDescDataOffset_(scopeDescDataOffset),
        textifiedCalleeOffset_(textifiedCalleeOffset),
        stringTableOffset_(stringTableOffset),
        data_(std::move(data)) {}

  explicit DebugInfo(
      std::vector<StringTableEntry> &&filenameStrings,
      std::vector<unsigned char> &&filenameStorage,
      DebugFileRegionList &&files,
      uint32_t scopeDescDataOffset,
      uint32_t textifiedCalleeOffset,
      uint32_t stringTableOffset,
      StreamVector<uint8_t> &&data)
      : filenameTable_(std::move(filenameStrings)),
        filenameStorage_(std::move(filenameStorage)),
        files_(std::move(files)),
        scopeDescDataOffset_(scopeDescDataOffset),
        textifiedCalleeOffset_(textifiedCalleeOffset),
        stringTableOffset_(stringTableOffset),
        data_(std::move(data)) {}

  DebugInfo &operator=(DebugInfo &&that) = default;

  const DebugFileRegionList &viewFiles() const {
    return files_;
  }
  const StreamVector<uint8_t> &viewData() const {
    return data_;
  }
  llvh::ArrayRef<StringTableEntry> getFilenameTable() const {
    return filenameTable_;
  }
  llvh::ArrayRef<unsigned char> getFilenameStorage() const {
    return filenameStorage_;
  }

                                                                    
  std::string getFilenameByID(uint32_t id) const {
    assert(id < filenameTable_.size() && "Filename ID out of bounds");
    std::string utf8Storage;
    return getStringFromEntry(filenameTable_[id], filenameStorage_, utf8Storage)
        .str();
  }

  uint32_t scopeDescDataOffset() const {
    return scopeDescDataOffset_;
  }

  uint32_t textifiedCalleeOffset() const {
    return textifiedCalleeOffset_;
  }

  uint32_t stringTableOffset() const {
    return stringTableOffset_;
  }

                                                                         
             
  OptValue<DebugSourceLocation> getLocationForAddress(
      uint32_t debugOffset,
      uint32_t offsetInFunction) const;

                                                                             
                                                  
  OptValue<llvh::StringRef> getTextifiedCalleeUTF8(
      uint32_t debugOffset,
      uint32_t offsetInFunction) const;

                                                         
                                                                             
                                                                              
                                                                   
  OptValue<DebugSearchResult> getAddressForLocation(
      uint32_t filenameId,
      uint32_t targetLine,
      OptValue<uint32_t> targetColumn) const;

                                                                            
                                                            
  DebugScopeDescriptor getScopeDescriptor(uint32_t offset) const;

                                                                               
                                                                            
           
  OptValue<uint32_t> getParentFunctionId(uint32_t offset) const;

                                                             
  uint32_t getSourceLocationsDataSizeBytes() const {
    return scopeDescDataOffset_ - 0;
  }

                                                             
  uint32_t getScopeDescDataSizeBytes() const {
    return textifiedCalleeOffset_ - scopeDescDataOffset_;
  }

                                                             
  uint32_t getTextifiedCalleesDataSizeBytes() const {
    return stringTableOffset_ - textifiedCalleeOffset_;
  }

                                                         
  uint32_t getStringTableSizeBytes() const {
    return data_.size() - stringTableOffset_;
  }

 private:
  // clang-format off
  /// Accessors for portions of data_, which looks like this:
  /// [sourceLocations][scopeDescData][textifiedCallee][stringTable]
  ///                  |              |                ^ stringTableOffset_
  ///                  |              ^ textifiedCalleeOffset_
  ///                  ^ scopeDescDataOffset_
  // clang-format on

                                                                 
  llvh::ArrayRef<uint8_t> sourceLocationsData() const {
    return data_.getData().slice(0, getSourceLocationsDataSizeBytes());
  }

                                                               
  llvh::ArrayRef<uint8_t> scopeDescData() const {
    return data_.getData().slice(
        scopeDescDataOffset_, getScopeDescDataSizeBytes());
  }

                                                                       
  llvh::ArrayRef<uint8_t> textifiedCalleeData() const {
    return data_.getData().slice(
        textifiedCalleeOffset_, getTextifiedCalleesDataSizeBytes());
  }

                                                                  
  llvh::ArrayRef<uint8_t> stringTableData() const {
    return data_.getData().slice(stringTableOffset_);
  }

  void disassembleFilenames(llvh::raw_ostream &OS) const;
  void disassembleFilesAndOffsets(llvh::raw_ostream &OS) const;
  void disassembleScopeDescData(llvh::raw_ostream &OS) const;
  void disassembleTextifiedCallee(llvh::raw_ostream &OS) const;
  void disassembleStringTable(llvh::raw_ostream &OS) const;

 public:
  void disassemble(llvh::raw_ostream &OS) const {
    disassembleFilenames(OS);
    disassembleFilesAndOffsets(OS);
    disassembleScopeDescData(OS);
    disassembleTextifiedCallee(OS);
    disassembleStringTable(OS);
  }

#ifndef HERMESVM_LEAN
                                                                        
                                                                            
                                                                           
                                                                             
                                          
  void populateSourceMap(
      SourceMapGenerator *sourceMap,
      std::vector<uint32_t> &&functionOffsets,
      uint32_t segmentID) const;
#endif
};

class DebugInfoGenerator {
 private:
                                                                           
     
                                                                              
                                                                                
                                                                             
                                                                            
                                                                     
                                          
     
                                                               
  static constexpr uint32_t kMostCommonEntryOffset = 0;

  bool validData{true};

                                      
  std::vector<uint8_t> sourcesData_{};

                                   
                                                                            
  ConsecutiveStringStorage filenameStrings_;

                                                               
  DebugInfo::DebugFileRegionList files_{};

                                   
  std::vector<uint8_t> scopeDescData_;

                                        
  std::vector<uint8_t> textifiedCallees_;

                                                                               
                                                                            
                            
  std::vector<uint8_t> stringTable_;

                                           
  llvh::DenseMap<UniqueString *, uint32_t> stringTableIndex_;

  int32_t delta(uint32_t to, uint32_t from) {
    int64_t diff = (int64_t)to - from;
                                                                              
                                                           
    assert(
        diff <= INT32_MAX && diff >= INT32_MIN &&
        "uint32_t delta too large when encoding debug info");
    return (int32_t)diff;
  }

                                                                 
                                                                   
  void appendString(std::vector<uint8_t> &data, Identifier str);

                                                      
                                                                           
                                                   
  DebugInfoGenerator(const DebugInfoGenerator &) = delete;
  DebugInfoGenerator &operator=(const DebugInfoGenerator &) = delete;

 public:
  explicit DebugInfoGenerator(UniquingFilenameTable &&filenameTable);

  DebugInfoGenerator(DebugInfoGenerator &&) = default;

  uint32_t appendSourceLocations(
      const DebugSourceLocation &start,
      uint32_t functionIndex,
      llvh::ArrayRef<DebugSourceLocation> offsets);

                                                                    
                                             
     
                                                               
     
                                                                                
     
                                                                   
  uint32_t appendScopeDesc(
      OptValue<uint32_t> parentScopeID,
      DebugScopeDescriptor::Flags flags,
      llvh::ArrayRef<Identifier> names);

                                                                               
                                                   
  uint32_t appendTextifiedCalleeData(
      llvh::ArrayRef<DebugTextifiedCallee> textifiedCallees);

                                              
  DebugInfo serializeWithMove();
};

}                 
}                    
#endif                                
