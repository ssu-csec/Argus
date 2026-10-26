/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/BytecodeGenerator.h"

#include "hermes/FrontEndDefs/Builtins.h"

#include "llvh/ADT/SmallString.h"
#include "llvh/Support/Format.h"

#include <unordered_map>

namespace hermes {
namespace hbc {

unsigned BytecodeFunctionGenerator::getStringID(LiteralString *value) const {
  return BMGen_.getStringID(value->getValue().str());
}

unsigned BytecodeFunctionGenerator::getIdentifierID(
    LiteralString *value) const {
  return BMGen_.getIdentifierID(value->getValue().str());
}

uint32_t BytecodeFunctionGenerator::addBigInt(bigint::ParsedBigInt bigint) {
  assert(
      !complete_ &&
      "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
  return BMGen_.addBigInt(std::move(bigint));
}

uint32_t BytecodeFunctionGenerator::addRegExp(CompiledRegExp *regexp) {
  assert(
      !complete_ &&
      "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
  return BMGen_.addRegExp(regexp);
}

uint32_t BytecodeFunctionGenerator::addFilename(llvh::StringRef filename) {
  assert(
      !complete_ &&
      "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
  return BMGen_.addFilename(filename);
}

void BytecodeFunctionGenerator::addExceptionHandler(
    HBCExceptionHandlerInfo info) {
  assert(
      !complete_ &&
      "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
  exceptionHandlers_.push_back(info);
}

void BytecodeFunctionGenerator::patchDebugSourceLocations(
    const llvh::DenseMap<unsigned, unsigned> &scopeDescOffsetMap) {
  if (debugLocations_.empty()) {
    return;
  }

  auto offset = scopeDescOffsetMap.find(sourceLocation_.scopeAddress);
  assert(offset != scopeDescOffsetMap.end());
  sourceLocation_.scopeAddress = offset->second;
  for (DebugSourceLocation &dl : debugLocations_) {
    offset = scopeDescOffsetMap.find(dl.scopeAddress);
    assert(offset != scopeDescOffsetMap.end());
    dl.scopeAddress = offset->second;
  }
}

void BytecodeFunctionGenerator::addDebugSourceLocation(
    const DebugSourceLocation &info) {
  assert(
      !complete_ &&
      "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
                                                                               
                              
  if (!debugLocations_.empty() &&
      debugLocations_.back().address == info.address) {
    debugLocations_.back() = info;
  } else {
    debugLocations_.push_back(info);
  }
}

void BytecodeFunctionGenerator::setJumpTable(
    std::vector<uint32_t> &&jumpTable) {
  assert(
      !complete_ &&
      "Cannot modify BytecodeFunction after call to bytecodeGenerationComplete.");
  assert(!jumpTable.empty() && "invoked with no jump table");

  jumpTable_ = std::move(jumpTable);
}

std::unique_ptr<BytecodeFunction>
BytecodeFunctionGenerator::generateBytecodeFunction(
    Function::DefinitionKind definitionKind,
    ValueKind valueKind,
    bool strictMode,
    uint32_t paramCount,
    uint32_t environmentSize,
    uint32_t nameID) {
  if (!complete_) {
    bytecodeGenerationComplete();
  }

  FunctionHeader header{
      bytecodeSize_,
      paramCount,
      frameSize_,
      environmentSize,
      nameID,
      highestReadCacheIndex_,
      highestWriteCacheIndex_};

  switch (definitionKind) {
    case Function::DefinitionKind::ES6Arrow:
    case Function::DefinitionKind::ES6Method:
      header.flags.prohibitInvoke = FunctionHeaderFlag::ProhibitConstruct;
      break;
    case Function::DefinitionKind::ES6DerivedConstructor:
      header.flags.derivedConstructor = true;
      LLVM_FALLTHROUGH;
    case Function::DefinitionKind::ES6Constructor:
      header.flags.prohibitInvoke = FunctionHeaderFlag::ProhibitCall;
      break;
    default:
                                                                     
                                         
                                                                           
                                                                             
                                    
                                                                          
                                                                     
                                                                    
                                                                   
                                                
      header.flags.prohibitInvoke =
          (valueKind == ValueKind::GeneratorFunctionKind ||
           valueKind == ValueKind::AsyncFunctionKind)
          ? FunctionHeaderFlag::ProhibitConstruct
          : FunctionHeaderFlag::ProhibitNone;
      break;
  }

  header.flags.asyncGenerator = definitionKind == Function::DefinitionKind::ES6AsyncGenerator;
  header.flags.strictMode = strictMode;
  header.flags.hasExceptionHandler = exceptionHandlers_.size();

  return std::make_unique<BytecodeFunction>(
      std::move(opcodes_), std::move(header), std::move(exceptionHandlers_));
}

unsigned BytecodeFunctionGenerator::getFunctionID(Function *F) {
  return BMGen_.addFunction(F);
}

unsigned BytecodeFunctionGenerator::getScopeDescID(ScopeDesc *S) {
  return BMGen_.addScopeDesc(S);
}

void BytecodeFunctionGenerator::shrinkJump(offset_t loc) {
                                                    
                                                                      
  opcodes_.erase(opcodes_.begin() + loc, opcodes_.begin() + loc + 3);

                                                          
  longToShortJump(loc - 1);
}

void BytecodeFunctionGenerator::updateJumpTarget(
    offset_t loc,
    int newVal,
    int bytes) {
                                                                     
                                   
  for (; bytes; --bytes, ++loc) {
    opcodes_[loc] = (opcode_atom_t)(newVal);
    newVal >>= 8;
  }
}

void BytecodeFunctionGenerator::updateJumpTableOffset(
    offset_t loc,
    uint32_t jumpTableOffset,
    uint32_t instLoc) {
  assert(opcodes_.size() > instLoc && "invalid switchimm offset");

                                                                    
                 
  updateJumpTarget(
      loc,
      opcodes_.size() + jumpTableOffset * sizeof(uint32_t) - instLoc,
      sizeof(uint32_t));
}

void BytecodeFunctionGenerator::bytecodeGenerationComplete() {
  assert(!complete_ && "Can only call bytecodeGenerationComplete once");
  complete_ = true;
  bytecodeSize_ = opcodes_.size();

                                                                                
                                 
  if (!jumpTable_.empty()) {
    uint32_t alignedOpcodes = llvh::alignTo<sizeof(uint32_t)>(bytecodeSize_);
    uint32_t jumpTableBytes = jumpTable_.size() * sizeof(uint32_t);
    opcodes_.reserve(alignedOpcodes + jumpTableBytes);
    opcodes_.resize(alignedOpcodes, 0);
    const opcode_atom_t *jumpTableStart =
        reinterpret_cast<opcode_atom_t *>(jumpTable_.data());
    opcodes_.insert(
        opcodes_.end(), jumpTableStart, jumpTableStart + jumpTableBytes);
  }
}

unsigned BytecodeModuleGenerator::addFunction(Function *F) {
  lazyFunctions_ |= F->isLazy();
  asyncFunctions_ |= llvh::isa<AsyncFunction>(F) ||
      F->getDefinitionKind() == Function::DefinitionKind::ES6AsyncGenerator;
  return functionIDMap_.allocate(F);
}

unsigned BytecodeModuleGenerator::addScopeDesc(ScopeDesc *S) {
  if (S && S->hasFunction() &&
      S->getFunction()->getContext().getDebugInfoSetting() !=
          DebugInfoSetting::ALL) {
                                                                             
                                                                              
    S = nullptr;
  }

  newScopeDescs_.insert(S);
  return scopeDescIDMap_.allocate(S);
}

namespace {
                                                                         
            
static Identifier ensureUTF8Identifer(
    StringTable &st,
    Identifier name,
    std::string &nameUTF8Buffer) {
                                                                                
                                                               
  bool hasSurrogate = false;
  const char *it = name.str().begin();
  const char *nameEnd = name.str().end();
  while (it < nameEnd && !hasSurrogate) {
    constexpr bool allowSurrogates = false;
    decodeUTF8<allowSurrogates>(
        it, [&hasSurrogate](const llvh::Twine &) { hasSurrogate = true; });
  }

  if (hasSurrogate) {
    nameUTF8Buffer.clear();

                                                                                
                                             
    convertUTF8WithSurrogatesToUTF8WithReplacements(nameUTF8Buffer, name.str());
    name = st.getIdentifier(nameUTF8Buffer);
  }

  return name;
}
}             

unsigned BytecodeModuleGenerator::serializeScopeChain(
    StringTable &st,
    DebugInfoGenerator &debugInfoGen,
    ScopeDesc *S) {
  unsigned ID = addScopeDesc(S);
  auto it = scopeDescIDAddr_.find(ID);
  if (it != scopeDescIDAddr_.end()) {
    return it->second;
  }

  OptValue<unsigned> parentScopeOffset;
  DebugScopeDescriptor::Flags flags;
  llvh::SmallVector<Identifier, 4> names;
  if (S) {
    if (S->getParent() && S->getParent()->hasFunction()) {
      parentScopeOffset = serializeScopeChain(st, debugInfoGen, S->getParent());
    }
    flags.isInnerScope =
        S->hasFunction() && S->getFunction()->getFunctionScopeDesc() != S;

    flags.isDynamic = S->getDynamic();

                                                        
    std::string nameUTF8Buffer;
    for (Variable *V : S->getVariables()) {
      Identifier nameUTF8 =
          ensureUTF8Identifer(st, V->getName(), nameUTF8Buffer);
      names.push_back(nameUTF8);
    }
  }

  unsigned offset =
      debugInfoGen.appendScopeDesc(parentScopeOffset, flags, names);
  scopeDescIDAddr_[ID] = offset;
  return offset;
}

void BytecodeModuleGenerator::setFunctionGenerator(
    Function *F,
    unique_ptr<BytecodeFunctionGenerator> BFG) {
  assert(
      functionGenerators_.find(F) == functionGenerators_.end() &&
      "Adding same function twice.");
  assert(
      !BFG->hasEncodingError() && "Error should have been reported already.");
  functionGenerators_[F] = std::move(BFG);
}

unsigned BytecodeModuleGenerator::getStringID(llvh::StringRef str) const {
  return stringTable_.getStringID(str);
}

unsigned BytecodeModuleGenerator::getIdentifierID(llvh::StringRef str) const {
  return stringTable_.getIdentifierID(str);
}

void BytecodeModuleGenerator::initializeStringTable(
    StringLiteralTable stringTable) {
  assert(stringTable_.empty() && "String table must be empty");
  stringTable_ = std::move(stringTable);
}

uint32_t BytecodeModuleGenerator::addBigInt(bigint::ParsedBigInt bigint) {
  return bigIntTable_.addBigInt(std::move(bigint));
}

void BytecodeModuleGenerator::initializeSerializedLiterals(
    std::vector<unsigned char> &&arrayBuffer,
    std::vector<unsigned char> &&keyBuffer,
    std::vector<unsigned char> &&valBuffer,
    hermes::hbc::BytecodeModuleGenerator::LiteralOffsetMapTy &&offsetMap) {
  assert(
      arrayBuffer_.empty() && objKeyBuffer_.empty() && objValBuffer_.empty() &&
      literalOffsetMap_.empty() && "serialized literals already initialized");
  arrayBuffer_ = std::move(arrayBuffer);
  objKeyBuffer_ = std::move(keyBuffer);
  objValBuffer_ = std::move(valBuffer);
  literalOffsetMap_ = std::move(offsetMap);
}

uint32_t BytecodeModuleGenerator::addRegExp(CompiledRegExp *regexp) {
  return regExpTable_.addRegExp(regexp);
}

uint32_t BytecodeModuleGenerator::addFilename(llvh::StringRef filename) {
  return filenameTable_.addFilename(filename);
}

void BytecodeModuleGenerator::addCJSModule(
    uint32_t functionID,
    uint32_t nameID) {
  assert(
      cjsModulesStatic_.empty() &&
      "Statically resolved modules must be in cjsModulesStatic_");
  cjsModules_.push_back({nameID, functionID});
}

void BytecodeModuleGenerator::addCJSModuleStatic(
    uint32_t moduleID,
    uint32_t functionID) {
  assert(cjsModules_.empty() && "Unresolved modules must be in cjsModules_");
  cjsModulesStatic_.push_back({moduleID, functionID});
}

void BytecodeModuleGenerator::addFunctionSource(
    uint32_t functionID,
    uint32_t stringID) {
  functionSourceTable_.push_back({functionID, stringID});
}

std::unique_ptr<BytecodeModule> BytecodeModuleGenerator::generate() {
  assert(
      valid_ &&
      "BytecodeModuleGenerator::generate() cannot be called more than once");
  valid_ = false;

  assert(
      functionIDMap_.getElements().size() == functionGenerators_.size() &&
      "Missing functions.");

  auto kinds = stringTable_.getStringKinds();
  auto hashes = stringTable_.getIdentifierHashes();

  BytecodeOptions bytecodeOptions;
  bytecodeOptions.hasAsync = asyncFunctions_;
  bytecodeOptions.staticBuiltins = options_.staticBuiltinsEnabled;
  bytecodeOptions.cjsModulesStaticallyResolved = !cjsModulesStatic_.empty();
  std::unique_ptr<BytecodeModule> BM{new BytecodeModule(
      functionGenerators_.size(),
      std::move(kinds),
      std::move(hashes),
      stringTable_.acquireStringTable(),
      stringTable_.acquireStringStorage(),
      bigIntTable_.getEntryList(),
      bigIntTable_.getDigitsBuffer(),
      regExpTable_.getEntryList(),
      regExpTable_.getBytecodeBuffer(),
      entryPointIndex_,
      std::move(arrayBuffer_),
      std::move(objKeyBuffer_),
      std::move(objValBuffer_),
      segmentID_,
      std::move(cjsModules_),
      std::move(cjsModulesStatic_),
      std::move(functionSourceTable_),
      bytecodeOptions)};

  DebugInfoGenerator debugInfoGen{std::move(filenameTable_)};

  const uint32_t strippedFunctionNameId =
      options_.stripFunctionNames ? getStringID(kStrippedFunctionName) : 0;
  auto functions = functionIDMap_.getElements();
  for (unsigned i = 0, e = functions.size(); i < e; ++i) {
    auto *F = functions[i];
    auto &BFG = *functionGenerators_[F];

    uint32_t functionNameId = options_.stripFunctionNames
        ? strippedFunctionNameId
        : getStringID(functions[i]->getOriginalOrInferredName().str());

    std::unique_ptr<BytecodeFunction> func = BFG.generateBytecodeFunction(
        F->getDefinitionKind(),
        F->getKind(),
        F->isStrictMode(),
        F->getExpectedParamCountIncludingThis(),
        F->getFunctionScopeDesc()->getVariables().size(),
        functionNameId);

    if (F->isLazy()) {
      auto lazyData = std::make_unique<LazyCompilationData>();
      lazyData->context = F->getParent()->shareContext();
      lazyData->parentScope = F->getLazyScope();
      lazyData->span = F->getLazySource().functionRange;
      lazyData->nodeKind = F->getLazySource().nodeKind;
      lazyData->paramYield = F->getLazySource().paramYield;
      lazyData->paramAwait = F->getLazySource().paramAwait;
      lazyData->bufferId = F->getLazySource().bufferId;
      lazyData->originalName = F->getOriginalOrInferredName();
      lazyData->closureAlias = F->getLazyClosureAlias()
          ? F->getLazyClosureAlias()->getName()
          : Identifier();
      lazyData->strictMode = F->isStrictMode();
      func->setLazyCompilationData(std::move(lazyData));
    }

    if (BFG.hasDebugInfo()) {
                                                                               
                                                                           
                                                                       
                                                  
      for (uint32_t s = 0, end = newScopeDescs_.size(); s < end; ++s) {
        serializeScopeChain(
            F->getContext().getStringTable(), debugInfoGen, newScopeDescs_[s]);
      }

                                                                       
                                       
      newScopeDescs_.clear();

                                                                               
                                                                   
      BFG.patchDebugSourceLocations(scopeDescIDAddr_);

      uint32_t sourceLocOffset = debugInfoGen.appendSourceLocations(
          BFG.getSourceLocation(), i, BFG.getDebugLocations());
      uint32_t topLevelScopeDescDataOffset = serializeScopeChain(
          F->getContext().getStringTable(),
          debugInfoGen,
          F->getFunctionScopeDesc());
      uint32_t textifiedCalleesOffset =
          debugInfoGen.appendTextifiedCalleeData(BFG.getTextifiedCallees());
      func->setDebugOffsets(
          {sourceLocOffset,
           topLevelScopeDescDataOffset,
           textifiedCalleesOffset});
    }

    BM->setFunction(i, std::move(func));
  }

  BM->setDebugInfo(debugInfoGen.serializeWithMove());
  return BM;
}

}                 
}                    
