/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_ISEL_H
#define HERMES_BCGEN_HBC_ISEL_H

#include "hermes/BCGen/Exceptions.h"
#include "hermes/BCGen/HBC/BytecodeGenerator.h"
#include "hermes/BCGen/HBC/HVMRegisterAllocator.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/IR.h"
#include "hermes/Utils/Dumper.h"
#include "hermes/Utils/Options.h"

#include "llvh/ADT/DenseMap.h"

namespace hermes {
namespace hbc {

                                                      
struct FileAndSourceMapId {
                                                                 
  uint32_t filenameId;
                                                      
                                
  uint32_t sourceMappingUrlId;
};

                                                 
                                                                         
                   
using FileAndSourceMapIdCache =
    llvh::SmallDenseMap<unsigned, FileAndSourceMapId>;

class HBCISel {
  struct Relocation {
    enum RelocationType {
                                 
      JumpType = 0,
                                
      LongJumpType,
                      
      BasicBlockType,
                            
      CatchType,
                   
      DebugInfo,
                         
      TextifiedCallee,
                            
      JumpTableDispatch,
    };

                                                
    offset_t loc;
                               
    RelocationType type;
                                                                        
                                                                            
                                                                 
                                                                       
    Value *pointer;
  };

                                                                      
  struct SwitchImmInfo {
                                 
    uint32_t offset;

                                                        
    BasicBlock *defaultTarget;

                                    
                                                                                
         
    std::vector<BasicBlock *> table;
  };

                                         
  Function *F_;

                                                     
  BytecodeFunctionGenerator *BCFGen_;

                             
  HVMRegisterAllocator &RA_;

                                                                              
                                       
  FunctionScopeAnalysis &scopeAnalysis_;

                                                                                
                                                                        
                              
  ScopeRegisterAnalysis &SRA_;

                                                                        
                                                                        
                                          
  DenseMap<BasicBlock *, std::pair<offset_t, BasicBlock *>> basicBlockMap_{};

                                                                      
  DenseSet<const BasicBlock *> asyncBreakChecks_{};

                                                                     
                                        
  SmallVector<Relocation, 8> relocations_{};

                                                                 
  DenseMap<Instruction *, offset_t> debugInstructionOffset_{};

                                                               
  CatchInfoMap catchInfoMap_{};

                                  
  const BytecodeGenerationOptions &bytecodeGenerationOptions_;

                                                                     
  llvh::DenseMap<SwitchImmInst *, SwitchImmInfo> switchImmInfo_{};
  using switchInfoEntry =
      llvh::DenseMap<SwitchImmInst *, SwitchImmInfo>::iterator::value_type;

                                                           
  Identifier protoIdent_{};

                                         
  unsigned encodeValue(Value *);

                                             
  void resolveRelocations();

                                                       
  void registerLongJump(offset_t loc, BasicBlock *target);

                                                 
  void registerSwitchImm(offset_t loc, SwitchImmInst *target);

                                     
  void resolveExceptionHandlers();

                                                            
  void generateJumpTable();

                                                         
                                                                            
  bool getDebugSourceLocation(
      SourceErrorManager &manager,
      SMLoc loc,
      DebugSourceLocation *out);

                                                                             
                                                       
  FileAndSourceMapId obtainFileAndSourceMapId(
      SourceErrorManager &sm,
      unsigned bufId);

                                
  void addDebugSourceLocationInfo(SourceMapGenerator *outSourceMap);
  void addDebugTextifiedCalleeInfo();

                                                         
  void populatePropertyCachingInfo();

                                                                           
  void initialize();

                                                 
  void emitMovIfNeeded(param_t dest, param_t src);

                                                                       
  void emitUnreachableIfDebug();

                                                                          
  void verifyCall(CallInst *Inst);

                                            
  uint8_t lastPropertyReadCacheIndex_{0};
  uint8_t lastPropertyWriteCacheIndex_{0};

                                                                         
  llvh::DenseMap<unsigned           , uint8_t> propertyReadCacheIndexForId_;
  llvh::DenseMap<unsigned           , uint8_t> propertyWriteCacheIndexForId_;

                                                                         
                                              
  uint8_t acquirePropertyReadCacheIndex(unsigned id);
  uint8_t acquirePropertyWriteCacheIndex(unsigned id);

                                                             
  FileAndSourceMapIdCache &fileAndSourceMapIdCache_;
                                                                           
                                            
  FileAndSourceMapIdCache::value_type *lastFoundFileSourceMapId_ = nullptr;

 public:
            
                                                    
                                 
  HBCISel(
      Function *F,
      BytecodeFunctionGenerator *BCFGen,
      HVMRegisterAllocator &RA,
      FunctionScopeAnalysis &scopeAnalysis,
      ScopeRegisterAnalysis &SRA,
      const BytecodeGenerationOptions &options,
      FileAndSourceMapIdCache &debugIdCache)
      : F_(F),
        BCFGen_(BCFGen),
        RA_(RA),
        scopeAnalysis_(scopeAnalysis),
        SRA_(SRA),
        bytecodeGenerationOptions_(options),
        fileAndSourceMapIdCache_(debugIdCache) {
    protoIdent_ = F->getContext().getIdentifier("__proto__");
  }

                                                                           
                                            
#define INCLUDE_HBC_INSTRS
#define DEF_VALUE(CLASS, PARENT) \
  void generate##CLASS(CLASS *Inst, BasicBlock *next);
#include "hermes/IR/ValueKinds.def"
#undef DEF_VALUE
#undef MARK_VALUE
#undef INCLUDE_HBC_INSTRS

                                                                             
                                                                                
                                                   
  void generate(BasicBlock *BB, BasicBlock *next);

                                                  
  void generate(Instruction *ii, BasicBlock *next);

                                                    
  void generate(SourceMapGenerator *outSourceMap);
};

}                 
}                    

#endif
