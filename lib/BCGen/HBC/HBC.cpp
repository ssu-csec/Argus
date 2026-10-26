/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/HBC.h"

#include "hermes/BCGen/BCOpt.h"
#include "hermes/BCGen/HBC/BytecodeGenerator.h"
#include "hermes/BCGen/HBC/BytecodeStream.h"
#include "hermes/BCGen/HBC/ISel.h"
#include "hermes/BCGen/HBC/Passes.h"
#include "hermes/BCGen/HBC/Passes/FuncCallNOpts.h"
#include "hermes/BCGen/HBC/Passes/InsertProfilePoint.h"
#include "hermes/BCGen/HBC/Passes/LowerBuiltinCalls.h"
#include "hermes/BCGen/HBC/Passes/OptEnvironmentInit.h"
#include "hermes/BCGen/HBC/TraverseLiteralStrings.h"
#include "hermes/BCGen/Lowering.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/IRVerifier.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/PassManager/Pass.h"
#include "hermes/Optimizer/PassManager/PassManager.h"
#include "hermes/Support/PerfSection.h"
#include "hermes/Support/UTF8.h"

#define DEBUG_TYPE "hbc-backend"

using namespace hermes;
using namespace hbc;

namespace {

                                                                            
                                                                              
                                                                             
                                              
const unsigned kFastRegisterAllocationThreshold = 250;

                                                                               
                                                                              
                     
const uint64_t kRegisterAllocationMemoryLimit = 10L * 1024 * 1024;

void lowerIR(Module *M, const BytecodeGenerationOptions &options) {
  if (M->isLowered())
    return;

  PassManager PM{M->getContext().getCodeGenerationSettings()};
  PM.addPass<LowerLoadStoreFrameInst>();
  if (options.optimizationEnabled) {
                                                             
    PM.addPass<OptEnvironmentInit>();
  }
                                                                              
                                           
  PM.addPass<LowerExponentiationOperator>();
                                                                    
  PM.addPass<LowerBuiltinCalls>();
                                                                       
                                                            
  PM.addPass<LowerNumericProperties>();
  PM.addPass<LowerConstruction>();
  PM.addPass<LowerArgumentsArray>();
  PM.addPass<LimitAllocArray>(UINT16_MAX);
  PM.addPass<DedupReifyArguments>();
  PM.addPass<LowerSwitchIntoJumpTables>();
  PM.addPass<SwitchLowering>();
  PM.addPass<LoadConstants>();
  PM.addPass<LoadParameters>();
  if (options.optimizationEnabled) {
                                                                              
                                   
    PM.addPass<LowerAllocObject>();
                                                                       
    PM.addPass<LowerCondBranch>();
                              
    PM.addPass<FuncCallNOpts>();
                                              
    PM.addCodeMotion();
                                          
    PM.addCSE();
                                     
    PM.addDCE();
  }

                                                                
  PM.addHoistStartGenerator();

  PM.run(M);
  M->setLowered(true);

  if (options.verifyIR &&
      verifyModule(*M, &llvh::errs(), VerificationMode::IR_VALID)) {
    M->dump();
    hermes_fatal("IR verification failed");
  }
}

                                  
                                                                          
                                    
UniquingStringLiteralAccumulator stringAccumulatorFromBCProvider(
    const BCProviderBase &bcProvider) {
  uint32_t count = bcProvider.getStringCount();

  std::vector<StringTableEntry> entries;
  std::vector<bool> isIdentifier;

  entries.reserve(count);
  isIdentifier.reserve(count);

  {
    unsigned i = 0;
    for (auto kindEntry : bcProvider.getStringKinds()) {
      bool isIdentRun = kindEntry.kind() != StringKind::String;
      for (unsigned j = 0; j < kindEntry.count(); ++j, ++i) {
        entries.push_back(bcProvider.getStringTableEntry(i));
        isIdentifier.push_back(isIdentRun);
      }
    }

    assert(i == count && "Did not initialise every string");
  }

  auto strStorage = bcProvider.getStringStorage();
  ConsecutiveStringStorage css{std::move(entries), strStorage.vec()};

  return UniquingStringLiteralAccumulator{
      std::move(css), std::move(isIdentifier)};
}

                                                                            
                                                                    
                                                                               
                                     
                 
                                                       
                                                                              
                          
                                                                     
                                                                            
class UniquedStringVector {
 public:
                      
  void push_back(llvh::StringRef str) {
    indexInSet_.push_back(set_.insert(str));
  }

                                                                            
                                          
  size_t size() const {
    return indexInSet_.size();
  }

                                                                             
             
  StringSetVector::const_iterator beginSet() const {
    return set_.begin();
  }
                                                                           
             
  StringSetVector::const_iterator endSet() const {
    return set_.end();
  }

                                                                               
                            
  uint32_t indexInSet(size_t insertionIndex) const {
    return indexInSet_[insertionIndex];
  }

 private:
                                                
  StringSetVector set_{};
                                                                              
            
  std::vector<uint32_t> indexInSet_{};
};

                                                                         
                                                          
                            
class LiteralBufferBuilder {
 public:
                  
                                        
                                                                          
                                                                              
                                              
                                                      
                                                                     
  LiteralBufferBuilder(
      Module *m,
      const std::function<bool(Function const *)> &shouldVisitFunction,
      BytecodeModuleGenerator &bmGen,
      bool optimize)
      : M_(m),
        shouldVisitFunction_(shouldVisitFunction),
        bmGen_(bmGen),
        optimize_(optimize),
        literalGenerator_(bmGen) {}

                                                                               
                                          
  void generate();

 private:
                                                                         
                                                                                
                  
  void traverse();

                                                       

  void serializeLiteralFor(AllocArrayInst *AAI);
  void serializeLiteralFor(HBCAllocObjectFromBufferInst *AOFB);

                                                                               
              
                                                                             
          
  void serializeInto(
      UniquedStringVector &dest,
      llvh::ArrayRef<Literal *> elements,
      bool isKeyBuffer);

 private:
                               
  Module *const M_;
                                                                               
                                                                               
  const std::function<bool(const Function *)> &shouldVisitFunction_;
                                         
  BytecodeModuleGenerator &bmGen_;
                                                     
  bool const optimize_;

                                     
  SerializedLiteralGenerator literalGenerator_;

                                                                            
                                         
  std::vector<unsigned char> tempBuffer_{};

                                                 
  UniquedStringVector arrays_{};

                                                                              
                                        
  std::vector<const Instruction *> arraysInst_{};

                                                                      
  UniquedStringVector objKeys_{};

                                                                        
  UniquedStringVector objVals_{};

                                                                              
                                                  
  std::vector<const Instruction *> objInst_{};
};

void LiteralBufferBuilder::generate() {
  traverse();

                                                                
  ConsecutiveStringStorage arrayStorage{
      arrays_.beginSet(), arrays_.endSet(), std::true_type{}, optimize_};
  ConsecutiveStringStorage keyStorage{
      objKeys_.beginSet(), objKeys_.endSet(), std::true_type{}, optimize_};
  ConsecutiveStringStorage valStorage{
      objVals_.beginSet(), objVals_.endSet(), std::true_type{}, optimize_};

                             
  BytecodeModuleGenerator::LiteralOffsetMapTy literalOffsetMap{};

                              
  auto arrayView = const_cast<const ConsecutiveStringStorage &>(arrayStorage)
                       .getStringTableView();
  for (size_t i = 0, e = arraysInst_.size(); i != e; ++i) {
    assert(
        literalOffsetMap.count(arraysInst_[i]) == 0 &&
        "instruction literal can't be serialized twice");
    uint32_t arrayIndexInSet = arrays_.indexInSet(i);
    literalOffsetMap[arraysInst_[i]] = BytecodeModuleGenerator::LiteralOffset{
        arrayView[arrayIndexInSet].getOffset(), UINT32_MAX};
  }

                                                               
  auto keyView = const_cast<const ConsecutiveStringStorage &>(keyStorage)
                     .getStringTableView();
  auto valView = const_cast<const ConsecutiveStringStorage &>(valStorage)
                     .getStringTableView();
  for (size_t i = 0, e = objInst_.size(); i != e; ++i) {
    assert(
        literalOffsetMap.count(objInst_[i]) == 0 &&
        "instruction literal can't be serialized twice");
    uint32_t keyIndexInSet = objKeys_.indexInSet(i);
    uint32_t valIndexInSet = objVals_.indexInSet(i);
    literalOffsetMap[objInst_[i]] = BytecodeModuleGenerator::LiteralOffset{
        keyView[keyIndexInSet].getOffset(), valView[valIndexInSet].getOffset()};
  }

  bmGen_.initializeSerializedLiterals(
      arrayStorage.acquireStringStorage(),
      keyStorage.acquireStringStorage(),
      valStorage.acquireStringStorage(),
      std::move(literalOffsetMap));
}

void LiteralBufferBuilder::traverse() {
  for (auto &F : *M_) {
    if (!shouldVisitFunction_(&F))
      continue;

    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *AAI = dyn_cast<AllocArrayInst>(&I)) {
          serializeLiteralFor(AAI);
        } else if (auto *AOFB = dyn_cast<HBCAllocObjectFromBufferInst>(&I)) {
          serializeLiteralFor(AOFB);
        }
      }
    }
  }
}

void LiteralBufferBuilder::serializeInto(
    UniquedStringVector &dest,
    llvh::ArrayRef<Literal *> elements,
    bool isKeyBuffer) {
  tempBuffer_.clear();
  literalGenerator_.serializeBuffer(elements, tempBuffer_, isKeyBuffer);
  dest.push_back(
      llvh::StringRef((const char *)tempBuffer_.data(), tempBuffer_.size()));
}

void LiteralBufferBuilder::serializeLiteralFor(AllocArrayInst *AAI) {
  SmallVector<Literal *, 8> elements;
  for (unsigned i = 0, e = AAI->getElementCount(); i < e; ++i) {
    elements.push_back(cast<Literal>(AAI->getArrayElement(i)));
  }

  serializeInto(arrays_, elements, false);
  arraysInst_.push_back(AAI);
}

void LiteralBufferBuilder::serializeLiteralFor(
    HBCAllocObjectFromBufferInst *AOFB) {
  unsigned e = AOFB->getKeyValuePairCount();
  if (!e)
    return;

  SmallVector<Literal *, 8> objKeys;
  SmallVector<Literal *, 8> objVals;
  for (unsigned ind = 0; ind != e; ++ind) {
    auto keyValuePair = AOFB->getKeyValuePair(ind);
    objKeys.push_back(cast<Literal>(keyValuePair.first));
    objVals.push_back(cast<Literal>(keyValuePair.second));
  }

  serializeInto(objKeys_, objKeys, true);
  serializeInto(objVals_, objVals, false);
  assert(
      objKeys_.size() == objVals_.size() &&
      "objKeys_ and objVals_ must be the same size");
  objInst_.push_back(AOFB);
}
};             

std::unique_ptr<BytecodeModule> hbc::generateBytecodeModule(
    Module *M,
    Function *entryPoint,
    const BytecodeGenerationOptions &options,
    hermes::OptValue<uint32_t> segment,
    SourceMapGenerator *sourceMapGen,
    std::unique_ptr<BCProviderBase> baseBCProvider) {
  return generateBytecodeModule(
      M,
      entryPoint,
      entryPoint,
      options,
      segment,
      sourceMapGen,
      std::move(baseBCProvider));
}

                                                                       
                                                                     
                                                                       
static inline void appendUnicodeToStorage(
    uint32_t cp,
    llvh::SmallVectorImpl<char> &storage) {
                                                        
                                                             
  char buf[8];
  char *d = buf;
                                                                             
                                                             
  if (LLVM_LIKELY(cp < 0x10000)) {
    hermes::encodeUTF8(d, cp);
  } else {
    assert(cp <= UNICODE_MAX_VALUE && "invalid Unicode value");
    cp -= 0x10000;
    hermes::encodeUTF8(d, UTF16_HIGH_SURROGATE + ((cp >> 10) & 0x3FF));
    hermes::encodeUTF8(d, UTF16_LOW_SURROGATE + (cp & 0x3FF));
  }
  storage.append(buf, d);
}

std::unique_ptr<BytecodeModule> hbc::generateBytecodeModule(
    Module *M,
    Function *lexicalTopLevel,
    Function *entryPoint,
    const BytecodeGenerationOptions &options,
    hermes::OptValue<uint32_t> segment,
    SourceMapGenerator *sourceMapGen,
    std::unique_ptr<BCProviderBase> baseBCProvider) {
  PerfSection perf("Bytecode Generation");
  lowerIR(M, options);

  if (options.format == DumpLIR)
    M->dump();

  BytecodeModuleGenerator BMGen(options);

  if (segment) {
    BMGen.setSegmentID(*segment);
  }
                                                                              
                
  llvh::DenseSet<Function *> functionsToGenerate = segment
      ? M->getFunctionsInSegment(*segment)
      : llvh::DenseSet<Function *>{};

                                                       
  std::function<bool(const Function *)> shouldGenerate;
  if (segment) {
    shouldGenerate = [entryPoint, &functionsToGenerate](const Function *f) {
      return f == entryPoint || functionsToGenerate.count(f) > 0;
    };
  } else {
    shouldGenerate = [](const Function *) { return true; };
  }

                                                                  
                                                     
                                 
                                                                              
                                              
                                                              
                                                                               
                                                                               
                   
  llvh::DenseMap<llvh::StringRef, llvh::SmallVector<char, 32>>
      unicodeFunctionSources{};

  {                                                                  
                                                                             
                                  
    auto strings = baseBCProvider
        ? stringAccumulatorFromBCProvider(*baseBCProvider)
        : UniquingStringLiteralAccumulator{};

    auto addStringOrIdent = [&strings](llvh::StringRef str, bool isIdentifier) {
      strings.addString(str, isIdentifier);
    };

    auto addString = [&strings](llvh::StringRef str) {
      strings.addString(str,                    false);
    };

    traverseLiteralStrings(M, shouldGenerate, addStringOrIdent);

    if (options.stripFunctionNames) {
      addString(kStrippedFunctionName);
    }

                                                                        
                                                                               
                                                                                
                                                         
    auto addFunctionSource = [&strings,
                              &unicodeFunctionSources](llvh::StringRef str) {
      if (hermes::isAllASCII(str.begin(), str.end())) {
                                            
        strings.addString(str,                    false);
      } else {
        auto &storage = unicodeFunctionSources[str];
        if (!storage.empty())
          return;
        for (const char *cur = str.begin(), *e = str.end(); cur != e;
                                    ) {
          if (LLVM_UNLIKELY(isUTF8Start(*cur))) {
                                                                             
                      
            appendUnicodeToStorage(
                hermes::_decodeUTF8SlowPath<false>(
                    cur, [](const llvh::Twine &) {}),
                storage);
          } else {
            storage.push_back(*cur);
            ++cur;
          }
        }
        strings.addString(
            llvh::StringRef{storage.begin(), storage.size()},
                               false);
      }
    };

                                                                               
                                                  
    traverseFunctions(
        M,
        shouldGenerate,
        addString,
        addFunctionSource,
        options.stripFunctionNames);

    if (!M->getCJSModulesResolved()) {
      traverseCJSModuleNames(M, shouldGenerate, addString);
    }

    BMGen.initializeStringTable(
        UniquingStringLiteralAccumulator::toTable(
            std::move(strings), options.optimizationEnabled));
  }

                                             
  {
    LiteralBufferBuilder litBuilder{
        M, shouldGenerate, BMGen, options.optimizationEnabled};
    litBuilder.generate();
  }

                                                                      
  for (auto &F : *M) {
    if (!shouldGenerate(&F)) {
      continue;
    }

    unsigned index = BMGen.addFunction(&F);
    if (&F == entryPoint) {
      BMGen.setEntryPointIndex(index);
    }

    auto *cjsModule = M->findCJSModule(&F);
    if (cjsModule) {
      if (M->getCJSModulesResolved()) {
        BMGen.addCJSModuleStatic(cjsModule->id, index);
      } else {
        BMGen.addCJSModule(index, BMGen.getStringID(cjsModule->filename.str()));
      }
    }

                                                                   
    if (!F.isGlobalScope()) {
      if (auto source = F.getSourceRepresentationStr()) {
        auto it = unicodeFunctionSources.find(*source);
                                                                   
                                                                               
                                                                    
        if (it != unicodeFunctionSources.end()) {
          BMGen.addFunctionSource(
              index,
              BMGen.getStringID(
                  llvh::StringRef{it->second.begin(), it->second.size()}));
        } else {
          BMGen.addFunctionSource(index, BMGen.getStringID(*source));
        }
      }
    }
  }
  assert(BMGen.getEntryPointIndex() != -1 && "Entry point not added");

                                                     
  FunctionScopeAnalysis scopeAnalysis{lexicalTopLevel};

                                                    
  FileAndSourceMapIdCache debugCache{};

                                           
  for (auto &F : *M) {
    if (!shouldGenerate(&F)) {
      continue;
    }

    std::unique_ptr<BytecodeFunctionGenerator> funcGen;

    if (F.isLazy()) {
      funcGen = BytecodeFunctionGenerator::create(BMGen, 0);
    } else {
      HVMRegisterAllocator RA(&F);
      ScopeRegisterAnalysis SRA(&F, RA);
      if (!options.optimizationEnabled) {
        RA.setFastPassThreshold(kFastRegisterAllocationThreshold);
        RA.setMemoryLimit(kRegisterAllocationMemoryLimit);
      }
      PostOrderAnalysis PO(&F);
                                                                          
                           
      llvh::SmallVector<BasicBlock *, 16> order(PO.rbegin(), PO.rend());
      RA.allocate(order);

      if (options.format == DumpRA) {
        RA.dump();
      }

      PassManager PM{M->getContext().getCodeGenerationSettings()};
      PM.addPass<LowerStoreInstrs>(RA);
      PM.addPass<LowerCalls>(RA);
      if (options.optimizationEnabled) {
        PM.addPass<MovElimination>(RA);
        PM.addPass<RecreateCheapValues>(RA);
        PM.addPass<LoadConstantValueNumbering>(RA);
      }
      PM.addPass<SpillRegisters>(RA);
      if (options.basicBlockProfiling) {
                                                                          
                
        PM.addPass<InsertProfilePoint>();
      }
      PM.run(&F);

      if (options.format == DumpLRA)
        RA.dump();

      if (options.format == DumpPostRA)
        F.dump();

      funcGen =
          BytecodeFunctionGenerator::create(BMGen, RA.getMaxRegisterUsage());
      HBCISel hbciSel(
          &F, funcGen.get(), RA, scopeAnalysis, SRA, options, debugCache);
      hbciSel.generate(sourceMapGen);
    }

    if (funcGen->hasEncodingError()) {
      M->getContext().getSourceErrorManager().error(
          F.getSourceRange().Start, "Error encoding bytecode");
      return nullptr;
    }
    BMGen.setFunctionGenerator(&F, std::move(funcGen));
  }

  return BMGen.generate();
}

std::unique_ptr<BytecodeModule> hbc::generateBytecode(
    Module *M,
    raw_ostream &OS,
    const BytecodeGenerationOptions &options,
    const SHA1 &sourceHash,
    hermes::OptValue<uint32_t> segment,
    SourceMapGenerator *sourceMapGen,
    std::unique_ptr<BCProviderBase> baseBCProvider) {
  auto BM = generateBytecodeModule(
      M,
      M->getTopLevelFunction(),
      options,
      segment,
      sourceMapGen,
      std::move(baseBCProvider));

  if (!BM) {
    return {};
  }

  if (options.format == OutputFormatKind::EmitBundle) {
    assert(BM != nullptr);
    BytecodeSerializer BS{OS, options};
    BS.serialize(*BM, sourceHash);
  }
                                                                              
                             
  if (sourceMapGen)
    BM->populateSourceMap(sourceMapGen);
  return BM;
}

#undef DEBUG_TYPE
