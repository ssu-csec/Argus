/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_BYTECODEGENERATOR_H
#define HERMES_BCGEN_HBC_BYTECODEGENERATOR_H

#include "llvh/ADT/DenseMap.h"

#include "hermes/BCGen/Exceptions.h"
#include "hermes/BCGen/HBC/Bytecode.h"
#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/BCGen/HBC/BytecodeInstructionGenerator.h"
#include "hermes/BCGen/HBC/ConsecutiveStringStorage.h"
#include "hermes/BCGen/HBC/DebugInfo.h"
#include "hermes/BCGen/HBC/SerializedLiteralGenerator.h"
#include "hermes/BCGen/HBC/UniquingFilenameTable.h"
#include "hermes/BCGen/HBC/UniquingStringLiteralTable.h"
#include "hermes/IR/IR.h"
#include "hermes/Regex/RegexSerialization.h"
#include "hermes/Support/BigIntSupport.h"
#include "hermes/Support/Conversions.h"
#include "hermes/Support/OptValue.h"
#include "llvh/ADT/SetVector.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {
namespace hbc {
using llvh::DenseMap;
using llvh::SmallVector;
using std::move;
using std::unique_ptr;

const char *const kStrippedFunctionName = "function-name-stripped";

                                                            
                                                            
                                                                  
                                          
template <typename T>
class AllocationTable {
  DenseMap<T, unsigned> indexMap_{};
  SmallVector<T, 8> elements_{};

 public:
  unsigned allocate(T val) {
    auto it = indexMap_.find(val);
    if (it != indexMap_.end()) {
      return it->second;
    }
    auto nextId = indexMap_.size();
    indexMap_[val] = nextId;
    elements_.push_back(val);
    return nextId;
  }

  const ArrayRef<T> getElements() const {
    return elements_;
  }
};

class BytecodeModuleGenerator;

                                             
                                                                       
class BytecodeFunctionGenerator : public BytecodeInstructionGenerator {
                                   
  BytecodeModuleGenerator &BMGen_;

                              
  std::vector<HBCExceptionHandlerInfo> exceptionHandlers_{};

                                                                         
  uint32_t frameSize_{0};

  DebugSourceLocation sourceLocation_;
  std::vector<DebugSourceLocation> debugLocations_{};

                                                   
  std::vector<DebugTextifiedCallee> textifiedCallees_;

                                                                         
  OptValue<uint32_t> lexicalParentID_{};

                                                   
  bool lazyFunctions_{false};

                                                                 
  uint32_t bytecodeSize_{0};

                                                                            
                                 
  bool complete_{false};

                                                               
  uint8_t highestReadCacheIndex_{0};
  uint8_t highestWriteCacheIndex_{0};

                                               
                                                                        
                                                           
  std::vector<uint32_t> jumpTable_{};

  explicit BytecodeFunctionGenerator(
      BytecodeModuleGenerator &BMGen,
      uint32_t frameSize)
      : BytecodeInstructionGenerator(), BMGen_(BMGen), frameSize_(frameSize) {}

 public:
  static std::unique_ptr<BytecodeFunctionGenerator> create(
      BytecodeModuleGenerator &BMGen,
      uint32_t frameSize) {
    return std::unique_ptr<BytecodeFunctionGenerator>(
        new BytecodeFunctionGenerator(BMGen, frameSize));
  }

                                 
                                                                     
                                                                   
                                                                     
                                                                      
                                               
  std::unique_ptr<BytecodeFunction> generateBytecodeFunction(
      Function::DefinitionKind definitionKind,
      ValueKind valueKind,
      bool strictMode,
      uint32_t paramCount,
      uint32_t environmentSize,
      uint32_t nameID = 0);

  unsigned getFunctionID(Function *F);

  unsigned getScopeDescID(ScopeDesc *S);

                                                                              
               
  unsigned getBigIntID(LiteralBigInt *value) const;

                                                                              
               
  unsigned getStringID(LiteralString *value) const;

                                                                              
                                                                        
  unsigned getIdentifierID(LiteralString *value) const;

                                               
                                                   
  uint32_t addBigInt(bigint::ParsedBigInt bigint);

                                                 
                                                   
  uint32_t addRegExp(CompiledRegExp *regexp);

                                         
                                      
  uint32_t addFilename(llvh::StringRef filename);

  void addExceptionHandler(HBCExceptionHandlerInfo info);

                                                         
  void setSourceLocation(const DebugSourceLocation &location) {
    assert(
        !complete_ &&
        "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
    sourceLocation_ = location;
  }

  const DebugSourceLocation &getSourceLocation() const {
    return sourceLocation_;
  }

                                                                               
                                                  
  void patchDebugSourceLocations(
      const llvh::DenseMap<unsigned, unsigned> &scopeDescOffsetMap);

                                    
  void addDebugSourceLocation(const DebugSourceLocation &info);
  const std::vector<DebugSourceLocation> &getDebugLocations() const {
    return debugLocations_;
  }

  bool hasDebugInfo() const {
    return !debugLocations_.empty() || !textifiedCallees_.empty();
  }

                                                                          
  void addDebugTextfiedCallee(const DebugTextifiedCallee &tCallee) {
    textifiedCallees_.emplace_back(tCallee);
  }

  llvh::ArrayRef<DebugTextifiedCallee> getTextifiedCallees() const {
    return textifiedCallees_;
  }

                                                                     
                                                                         
  void shrinkJump(offset_t loc);

                                                                    
                     
  void updateJumpTarget(offset_t loc, int newVal, int bytes);

                                                                    
                      
                                            
                                                            
                                                                             
               
  void
  updateJumpTableOffset(offset_t loc, uint32_t jumpTableOffset, uint32_t cs);

                                                                     
  inline void longToShortJump(offset_t loc) {
    switch (opcodes_[loc]) {
#define DEFINE_JUMP_LONG_VARIANT(shortName, longName) \
  case longName##Op:                                  \
    opcodes_[loc] = shortName##Op;                    \
    break;
#include "hermes/BCGen/HBC/BytecodeList.def"
      default:
        llvm_unreachable("Unknown jump opcode");
    }
  }

                                    
  uint32_t getFrameSize() const {
    return frameSize_;
  }

  void setHighestReadCacheIndex(uint8_t sz) {
    assert(
        !complete_ &&
        "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
    this->highestReadCacheIndex_ = sz;
  }
  void setHighestWriteCacheIndex(uint8_t sz) {
    assert(
        !complete_ &&
        "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
    this->highestWriteCacheIndex_ = sz;
  }

                                                   
  void setJumpTable(std::vector<uint32_t> &&jumpTable);

                                                   
  void bytecodeGenerationComplete();

  friend class HBCISel;
  friend class BytecodeModuleGenerator;
};

                                             
                                                      
class BytecodeModuleGenerator {
 public:
  using LiteralOffset = std::pair<uint32_t, uint32_t>;
  using LiteralOffsetMapTy = llvh::DenseMap<const Instruction *, LiteralOffset>;

 private:
                                                 
  AllocationTable<Function *> functionIDMap_{};

                                                  
  AllocationTable<ScopeDesc *> scopeDescIDMap_{};

                                                                                
  llvh::SetVector<ScopeDesc *> newScopeDescs_;

                                                                            
           
  llvh::DenseMap<unsigned, unsigned> scopeDescIDAddr_{};

  unsigned serializeScopeChain(
      StringTable &st,
      DebugInfoGenerator &debugInfoGen,
      ScopeDesc *s);

                                                                  
  DenseMap<Function *, std::unique_ptr<BytecodeFunctionGenerator>>
      functionGenerators_{};

                                                                          
             
  StringLiteralTable stringTable_{};

                                        
  bigint::UniquingBigIntTable bigIntTable_{};

                                          
  UniquingRegExpTable regExpTable_;

                                                                             
                                                                          
  UniquingFilenameTable filenameTable_{};

                             
  uint32_t segmentID_{0};

                                                                           
                                                   
  std::vector<std::pair<uint32_t, uint32_t>> cjsModules_;

                                                                         
                                                 
  std::vector<std::pair<uint32_t, uint32_t>> cjsModulesStatic_;

                                                                          
                                              
  std::vector<std::pair<uint32_t, uint32_t>> functionSourceTable_;

                                                            
                                                                 
  std::vector<unsigned char> arrayBuffer_{};

                                                        
                                                                
  std::vector<unsigned char> objKeyBuffer_{};

                                                          
                                                                
  std::vector<unsigned char> objValBuffer_{};

                                                                            
                                                          
                                                         
  LiteralOffsetMapTy literalOffsetMap_{};

                                              
  BytecodeGenerationOptions options_;

                                                   
  bool lazyFunctions_{false};

                                                    
  bool asyncFunctions_{false};

                                                     
                                                                    
                                                                     
                                                      
  bool valid_{true};

                                                                    
  int entryPointIndex_{-1};

 public:
                                                                               
  BytecodeModuleGenerator(
      BytecodeGenerationOptions options = BytecodeGenerationOptions::defaults())
      : options_(options) {}

                                                                            
  unsigned addFunction(Function *F);

                                                                              
  unsigned addScopeDesc(ScopeDesc *S);

                                              
  void setFunctionGenerator(
      Function *F,
      unique_ptr<BytecodeFunctionGenerator> BFG);

                                                                   
  int getEntryPointIndex() const {
    return entryPointIndex_;
  }

                                                                   
  void setEntryPointIndex(int index) {
    entryPointIndex_ = index;
  }

                                                                          
                                                                             
                                
  unsigned getBigIntID(llvh::StringRef str) const;

                                                                          
                                                                             
                                
  unsigned getStringID(llvh::StringRef str) const;

                                                                              
                                                                          
                                                                               
                                           
  unsigned getIdentifierID(llvh::StringRef str) const;

                                                                           
                                                                            
                                                                        
                
  void initializeStringTable(StringLiteralTable stringTable);

                                               
                                                   
  uint32_t addBigInt(bigint::ParsedBigInt bigint);

                                                                               
                                            
                                                                         
                                                                                
                                                                        
                   
  void initializeSerializedLiterals(
      std::vector<unsigned char> &&arrayBuffer,
      std::vector<unsigned char> &&keyBuffer,
      std::vector<unsigned char> &&valBuffer,
      LiteralOffsetMapTy &&offsetMap);

                                                 
                                                   
  uint32_t addRegExp(CompiledRegExp *regexp);

                                         
                                      
  uint32_t addFilename(llvh::StringRef str);

                                         
  void setSegmentID(uint32_t id) {
    segmentID_ = id;
  }

                                           
  void addCJSModule(uint32_t functionID, uint32_t nameID);

                                                               
                                                                          
  void addCJSModuleStatic(uint32_t moduleID, uint32_t functionID);

                                                
                                                  
                                                                                
  void addFunctionSource(uint32_t functionID, uint32_t stringID);

                                                                        
                                               
                                                 
                                                                           
                                                                           
                                                                           
                 
                                                                             
                                                                
                                                                            
                                                                           
                                                                    
                                 
  uint32_t serializeBuffer(
      ArrayRef<Literal *> literals,
      std::vector<unsigned char> &buff,
      bool isKeyBuffer);

                                                                                
                                                                           
                                                                            
                                                   
  LiteralOffset serializedLiteralOffsetFor(const Instruction *inst) {
    assert(
        literalOffsetMap_.count(inst) &&
        "instruction has no serialized literal");
    return literalOffsetMap_[inst];
  }

                               
  std::unique_ptr<BytecodeModule> generate();
};
}                 
}                    

#endif                                        
