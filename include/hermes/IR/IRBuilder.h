/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IR_IRBUILDER_H
#define HERMES_IR_IRBUILDER_H

#include <string>
#include <utility>

#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"

#include "hermes/AST/Context.h"
#include "hermes/FrontEndDefs/Builtins.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Wasm/WasmIntrinsics.h"

namespace hermes {

                                                                             
                                                                        
                                                                          
                                                                             
                                                                          
class IRBuilder {
  IRBuilder(const IRBuilder &) = delete;
  void operator=(const IRBuilder &) = delete;

                                                                 
  Module *M;
                                                          
  BasicBlock::iterator InsertionPoint{};
                                             
  BasicBlock *Block{};

  SMLoc Location{};
  ScopeDesc *CurrentSourceLevelScope{};

 public:
  explicit IRBuilder(Module *Mod) : M(Mod), InsertionPoint(nullptr) {}
  explicit IRBuilder(Function *F)
      : M(F->getParent()), InsertionPoint(nullptr) {}

                                                                                
                                                                                
                                                                                

  enum class PropEnumerable { No = 0, Yes = 1 };

  Module *getModule() {
    return M;
  }

                                                                 
  BasicBlock *createBasicBlock(Function *Parent);

                                                     
                                                                  
                                                                            
                                                                             
  Function *createFunction(
      ScopeDesc *scopeDesc,
      Identifier OriginalName,
      Function::DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility = SourceVisibility::Default,
      SMRange sourceRange = SMRange{},
      bool isGlobal = false,
      Function *insertBefore = nullptr);

                                                     
  Function *createFunction(
      ScopeDesc *scopeDesc,
      llvh::StringRef OriginalName,
      Function::DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility = SourceVisibility::Default,
      SMRange sourceRange = SMRange{},
      bool isGlobal = false,
      Function *insertBefore = nullptr);

                                                          
                                                                  
                                                                            
                                                                             
  AsyncFunction *createAsyncFunction(
      ScopeDesc *scopeDesc,
      Identifier OriginalName,
      Function::DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility,
      SMRange sourceRange = SMRange{},
      Function *insertBefore = nullptr);

                                                              
                                                                  
                                                                            
                                                                             
  GeneratorFunction *createGeneratorFunction(
      ScopeDesc *scopeDesc,
      Identifier OriginalName,
      Function::DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility,
      SMRange sourceRange = SMRange{},
      Function *insertBefore = nullptr);

                                                                   
                                                                  
                                                                            
                                                                             
  GeneratorInnerFunction *createGeneratorInnerFunction(
      ScopeDesc *scopeDesc,
      Identifier OriginalName,
      Function::DefinitionKind definitionKind,
      bool strictMode,
      SMRange sourceRange = SMRange{},
      Function *insertBefore = nullptr);

                                                                  
  Function *createTopLevelFunction(
      ScopeDesc *scopeDesc,
      bool strictMode,
      SourceVisibility sourceVisibility = SourceVisibility::Default,
      SMRange sourceRange = SMRange{});

                                          
  GlobalObjectProperty *createGlobalObjectProperty(
      Identifier name,
      bool declared);
                                          
  GlobalObjectProperty *createGlobalObjectProperty(
      llvh::StringRef name,
      bool declared);

                                                         
  Parameter *createParameter(Function *Parent, Identifier Name);

                                                         
  Parameter *createParameter(Function *Parent, llvh::StringRef Name);

                                                     
                                          
  Parameter *createThisParameter(Function *Parent);

                                            
  Variable *createVariable(
      ScopeDesc *Parent,
      Variable::DeclKind declKind,
      Identifier Name);

                                            
  Variable *createVariable(
      ScopeDesc *Parent,
      Variable::DeclKind declKind,
      llvh::StringRef Name);

                                                    
  LiteralNumber *getLiteralNumber(double value);

                                         
  LiteralNumber *getLiteralPositiveZero();

                                         
  LiteralNumber *getLiteralNegativeZero();

                               
  LiteralNumber *getLiteralNaN();

                                                    
  LiteralBigInt *getLiteralBigInt(UniqueString *value);

                                                    
  LiteralString *getLiteralString(llvh::StringRef value);

                                                    
  LiteralString *getLiteralString(Identifier value);

                                                  
  LiteralBool *getLiteralBool(bool value);

                                   
  LiteralEmpty *getLiteralEmpty();

                                       
  LiteralUndefined *getLiteralUndefined();

                                
  LiteralNull *getLiteralNull();

                                    
  GlobalObject *getGlobalObject();

                                     
  EmptySentinel *getEmptySentinel();

                                            
  Identifier createIdentifier(llvh::StringRef str);

                                                                                
                                                                                
                                                                                

 private:
                                                                               
                                               
  void justInsert(Instruction *Inst);

                                                                           
                                                
  void insert(Instruction *Inst);

 public:
                                                                          
                                   
  void setInsertionBlock(BasicBlock *BB);

                                         
  BasicBlock *getInsertionBlock();

                                  
  Function *getFunction() {
    assert(Block && "Builder has no current function");
    return Block->getParent();
  }

                                                                          
                           
  void setInsertionPointAfter(Instruction *IP);

                                                                          
                                                                    
  void setInsertionPoint(Instruction *IP);

                                                  
  bool isInsertionPointValid();

                                                                               
                             
  void resetInsertionPoint();

  void setLocation(SMLoc loc) {
    Location = loc;
  }
  void clearLocation() {
    Location = SMLoc{};
  }
  SMLoc getLocation() const {
    return Location;
  }

  void setCurrentSourceLevelScope(ScopeDesc *sourceLevelScope) {
    CurrentSourceLevelScope = sourceLevelScope;
  }

                                                                           
                                                                             
                                                                              
  void transferInstructionToCurrentBlock(Instruction *inst);

                                                                                
                                                                                
                                                                                

                                                                           
                                                                                
                                             
                                                                           
  Instruction *cloneInst(
      const Instruction *source,
      llvh::ArrayRef<Value *> operands);

  BranchInst *createBranchInst(BasicBlock *Destination);

  CondBranchInst *
  createCondBranchInst(Value *Cond, BasicBlock *T, BasicBlock *F);

  ReturnInst *createReturnInst(Value *Val);

  AllocStackInst *createAllocStackInst(llvh::StringRef varName);

  AllocStackInst *createAllocStackInst(Identifier varName);

  AsNumberInst *createAsNumberInst(Value *val);

  AsNumericInst *createAsNumericInst(Value *val);

  AsInt32Inst *createAsInt32Inst(Value *val);

  AddEmptyStringInst *createAddEmptyStringInst(Value *val);

  ThrowIfHasRestrictedGlobalPropertyInst *
  createThrowIfHasRestrictedGlobalPropertyInst(llvh::StringRef property);

  CreateScopeInst *createCreateScopeInst(ScopeDesc *scopeDesc);

  CreateInnerScopeInst *createCreateInnerScopeInst(
      ScopeCreationInst *parentScope,
      ScopeDesc *scopeDesc);

  CreateFunctionInst *createCreateFunctionInst(
      Function *code,
      ScopeCreationInst *environment);

  LoadStackInst *createLoadStackInst(AllocStackInst *ptr);

  LoadFrameInst *createLoadFrameInst(Variable *ptr, ScopeCreationInst *scope);

  StoreStackInst *createStoreStackInst(Value *storedValue, AllocStackInst *ptr);

  StoreFrameInst *createStoreFrameInst(
      Value *storedValue,
      Variable *ptr,
      ScopeCreationInst *scope);

  CallInst *createCallInst(
      LiteralString *textifiedCallee,
      Value *callee,
      Value *thisValue,
      ArrayRef<Value *> args);

  HBCCallNInst *createHBCCallNInst(
      LiteralString *textifiedCallee,
      Value *callee,
      Value *thisValue,
      ArrayRef<Value *> args);

  ConstructInst *createConstructInst(
      Value *constructor,
      Value *newTarget,
      ArrayRef<Value *> args);

  CatchInst *createCatchInst();

  ThrowInst *createThrowInst(Value *thrownValue);

  CheckHasInstanceInst *createCheckHasInstanceInst(
      AllocStackInst *result,
      Value *left,
      Value *right,
      BasicBlock *onTrue,
      BasicBlock *onFalse);

  TryStartInst *createTryStartInst(
      BasicBlock *tryBodyBlock,
      BasicBlock *catchTargetBlock);

  TryEndInst *createTryEndInst();

  DeletePropertyInst *createDeletePropertyInst(Value *object, Value *property);

  LoadPropertyInst *createLoadPropertyInst(Value *object, Value *property);
  TryLoadGlobalPropertyInst *createTryLoadGlobalPropertyInst(
      LiteralString *property);
  TryLoadGlobalPropertyInst *createTryLoadGlobalPropertyInst(
      GlobalObjectProperty *property);

  StorePropertyInst *
  createStorePropertyInst(Value *storedValue, Value *object, Value *property);
  TryStoreGlobalPropertyInst *createTryStoreGlobalPropertyInst(
      Value *storedValue,
      LiteralString *property);
  TryStoreGlobalPropertyInst *createTryStoreGlobalPropertyInst(
      Value *storedValue,
      GlobalObjectProperty *property);
  StoreOwnPropertyInst *createStoreOwnPropertyInst(
      Value *storedValue,
      Value *object,
      Value *property,
      PropEnumerable isEnumerable);
  StoreNewOwnPropertyInst *createStoreNewOwnPropertyInst(
      Value *storedValue,
      Value *object,
      Literal *property,
      PropEnumerable isEnumerable);

  StoreGetterSetterInst *createStoreGetterSetterInst(
      Value *storedGetter,
      Value *storedSetter,
      Value *object,
      Value *property,
      PropEnumerable isEnumerable);
  DeletePropertyInst *createDeletePropertyInst(
      Value *object,
      llvh::StringRef property);

  LoadPropertyInst *createLoadPropertyInst(
      Value *object,
      llvh::StringRef property);
  TryLoadGlobalPropertyInst *createTryLoadGlobalPropertyInst(
      llvh::StringRef property);

  StorePropertyInst *createStorePropertyInst(
      Value *storedValue,
      Value *object,
      llvh::StringRef property);

  DeletePropertyInst *createDeletePropertyInst(
      Value *object,
      Identifier property);

  LoadPropertyInst *createLoadPropertyInst(Value *object, Identifier property);
  TryLoadGlobalPropertyInst *createTryLoadGlobalPropertyInst(
      Identifier property);

  StorePropertyInst *createStorePropertyInst(
      Value *storedValue,
      Value *object,
      Identifier property);
  TryStoreGlobalPropertyInst *createTryStoreGlobalPropertyInst(
      Value *storedValue,
      Identifier property);

  AllocObjectInst *createAllocObjectInst(
      uint32_t size,
      Value *parent = nullptr);

  AllocArrayInst *createAllocArrayInst(
      LiteralNumber *sizeHint,
      AllocArrayInst::ArrayValueList val_list);

  AllocArrayInst *createAllocArrayInst(
      AllocArrayInst::ArrayValueList val_list,
      unsigned sizeHint);

  CreateArgumentsInst *createCreateArgumentsInst();

  GetNewTargetInst *createGetNewTargetInst();

  ThrowIfEmptyInst *createThrowIfEmptyInst(Value *checkedValue);

  HBCGetGlobalObjectInst *createHBCGetGlobalObjectInst();

  CreateRegExpInst *createRegExpInst(Identifier pattern, Identifier flags);

  UnaryOperatorInst *createUnaryOperatorInst(
      Value *value,
      UnaryOperatorInst::OpKind opKind);

  DirectEvalInst *createDirectEvalInst(Value *operand, LiteralBool *isStrict);

  SwitchInst *createSwitchInst(
      Value *input,
      BasicBlock *defaultBlock,
      const SwitchInst::ValueListType &values,
      const SwitchInst::BasicBlockListType &blocks);

  PhiInst *createPhiInst(
      const PhiInst::ValueListType &values,
      const PhiInst::BasicBlockListType &blocks);

  PhiInst *createPhiInst();

  BinaryOperatorInst *createBinaryOperatorInst(
      Value *left,
      Value *right,
      BinaryOperatorInst::OpKind opKind);

  GetPNamesInst *createGetPNamesInst(
      Value *iteratorAddr,
      Value *baseAddr,
      Value *indexAddr,
      Value *sizeAddr,
      BasicBlock *onEmpty,
      BasicBlock *onSome);

  GetNextPNameInst *createGetNextPNameInst(
      Value *propertyAddr,
      Value *baseAddr,
      Value *indexAddr,
      Value *sizeAddr,
      Value *iteratorAddr,
      BasicBlock *onLast,
      BasicBlock *onSome);

  MovInst *createMovInst(Value *input);

  ImplicitMovInst *createImplicitMovInst(Value *input);

  CoerceThisNSInst *createCoerceThisNSInst(Value *input);

  DebuggerInst *createDebuggerInst();

  SaveAndYieldInst *createSaveAndYieldInst(
      Value *result,
      BasicBlock *nextBlock);

  CreateGeneratorInst *createCreateGeneratorInst(
      Function *innerFn,
      ScopeCreationInst *environment);

  StartGeneratorInst *createStartGeneratorInst();

  ResumeGeneratorInst *createResumeGeneratorInst(Value *isReturn);

                                                                                
                                                                                
                                                                                

  HBCResolveEnvironment *createHBCResolveEnvironment(
      ScopeDesc *originScopeDesc,
      ScopeDesc *targetScopeDesc);
  HBCStoreToEnvironmentInst *
  createHBCStoreToEnvironmentInst(Value *env, Value *toPut, Variable *var);
  HBCLoadFromEnvironmentInst *createHBCLoadFromEnvironmentInst(
      Value *env,
      Variable *var);

  SwitchImmInst *createSwitchImmInst(
      Value *input,
      BasicBlock *defaultBlock,
      LiteralNumber *minValue,
      LiteralNumber *size,
      const SwitchImmInst::ValueListType &values,
      const SwitchImmInst::BasicBlockListType &blocks);

  HBCLoadConstInst *createHBCLoadConstInst(Literal *value);

  HBCLoadParamInst *createHBCLoadParamInst(LiteralNumber *value);

  HBCCreateEnvironmentInst *createHBCCreateEnvironmentInst(
      ScopeDesc *scopeDesc);

  HBCCreateInnerEnvironmentInst *createHBCCreateInnerEnvironmentInst(
      ScopeCreationInst *parentScope,
      ScopeDesc *scopeDesc);

  HBCGetThisNSInst *createHBCGetThisNSInst();

  HBCGetArgumentsPropByValInst *createHBCGetArgumentsPropByValInst(
      Value *index,
      AllocStackInst *lazyReg);

  HBCGetArgumentsLengthInst *createHBCGetArgumentsLengthInst(
      AllocStackInst *lazyReg);

  HBCReifyArgumentsInst *createHBCReifyArgumentsInst(AllocStackInst *lazyReg);

  HBCCreateThisInst *createHBCCreateThisInst(Value *prototype, Value *closure);

  HBCConstructInst *createHBCConstructInst(
      Value *closure,
      Value *newTarget,
      Value *thisValue,
      ArrayRef<Value *> arguments);
  HBCGetConstructedObjectInst *createHBCGetConstructedObjectInst(
      HBCCreateThisInst *thisValue,
      HBCConstructInst *constructorReturnValue);
  HBCProfilePointInst *createHBCProfilePointInst(uint16_t pointIndex);

  CallBuiltinInst *createCallBuiltinInst(
      BuiltinMethod::Enum builtinIndex,
      ArrayRef<Value *> arguments);

  CallBuiltinInst *createCallBuiltinInstWithNewTarget(
      BuiltinMethod::Enum builtinIndex,
      Value *newTarget,
      ArrayRef<Value *> arguments);

  GetBuiltinClosureInst *createGetBuiltinClosureInst(
      BuiltinMethod::Enum builtinIndex);

#ifdef HERMES_RUN_WASM
  CallIntrinsicInst *createCallIntrinsicInst(
      WasmIntrinsics::Enum intrinsicsIndex,
      ArrayRef<Value *> arguments);
#endif

  HBCCallDirectInst *createHBCCallDirectInst(
      LiteralString *textifiedCallee,
      Function *callee,
      Value *thisValue,
      ArrayRef<Value *> arguments);

  HBCCreateFunctionInst *createHBCCreateFunctionInst(
      Function *function,
      Value *env);
  HBCSpillMovInst *createHBCSpillMovInst(Instruction *value);

  HBCCreateGeneratorInst *createHBCCreateGeneratorInst(
      Function *function,
      Value *env);

  HBCAllocObjectFromBufferInst *createHBCAllocObjectFromBufferInst(
      HBCAllocObjectFromBufferInst::ObjectPropertyMap prop_map,
      uint32_t size);

  CompareBranchInst *createCompareBranchInst(
      Value *left,
      Value *right,
      BinaryOperatorInst::OpKind opKind,
      BasicBlock *trueBlock,
      BasicBlock *falseBlock);

  IteratorBeginInst *createIteratorBeginInst(AllocStackInst *sourceOrNext);

  IteratorNextInst *createIteratorNextInst(
      AllocStackInst *iterator,
      AllocStackInst *sourceOrNext);

  IteratorCloseInst *createIteratorCloseInst(
      AllocStackInst *iterator,
      bool ignoreInnerException);

  UnreachableInst *createUnreachableInst();

                                                                               
                
  class ScopedLocationChange {
    ScopedLocationChange(const ScopedLocationChange &) = delete;
    void operator=(const ScopedLocationChange &) = delete;

    IRBuilder &builder_;
    SMLoc oldLocation_;

   public:
                                                                      
    explicit ScopedLocationChange(IRBuilder &builder, SMLoc location)
        : builder_(builder), oldLocation_(builder.getLocation()) {
      builder_.setLocation(location);
    }

                                                             
    ~ScopedLocationChange() {
      builder_.setLocation(oldLocation_);
    }
  };

                                                                                
                                                                                
                                                                                

                                                                               
                
  class SaveRestore {
    SaveRestore(const SaveRestore &) = delete;
    void operator=(const SaveRestore &) = delete;

    IRBuilder &Builder;
    BasicBlock *BB;
    SMLoc Location;

   public:
                                                                     
    explicit SaveRestore(IRBuilder &builder)
        : Builder(builder),
          BB(builder.getInsertionBlock()),
          Location(builder.getLocation()) {
      builder.clearLocation();
    }

                                                            
    ~SaveRestore() {
      Builder.setInsertionBlock(BB);
      Builder.setLocation(Location);
    }
  };

                                                                             
  class InstructionDestroyer {
    InstructionDestroyer(const InstructionDestroyer &) = delete;
    void operator=(const InstructionDestroyer &) = delete;

    llvh::SmallVector<Instruction *, 8> list{};

   public:
    explicit InstructionDestroyer() = default;

                                                                           
                                                                             
                  
    bool hasInstruction(Instruction *A) {
      return std::find(list.begin(), list.end(), A) != list.end();
    }

                                                                        
    void add(Instruction *A) {
#ifndef NDEBUG
      assert(!hasInstruction(A) && "Instruction already in list!");
#endif
      list.push_back(A);
    }

    ~InstructionDestroyer() {
      for (auto *I : list) {
        I->eraseFromParent();
      }
    }
  };
};

}                        

#endif
