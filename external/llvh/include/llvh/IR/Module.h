//===- llvm/Module.h - C++ class to represent a VM module -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// @file
/// Module.h This file contains the declarations for the Module class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_MODULE_H
#define LLVM_IR_MODULE_H

#include "llvh-c/Types.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/Comdat.h"
#include "llvh/IR/DataLayout.h"
#include "llvh/IR/Function.h"
#include "llvh/IR/GlobalAlias.h"
#include "llvh/IR/GlobalIFunc.h"
#include "llvh/IR/GlobalVariable.h"
#include "llvh/IR/Metadata.h"
#include "llvh/IR/SymbolTableListTraits.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/CodeGen.h"
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace llvh {

class Error;
class FunctionType;
class GVMaterializer;
class LLVMContext;
class MemoryBuffer;
class RandomNumberGenerator;
template <class PtrType> class SmallPtrSetImpl;
class StructType;

                                                                        
                                                                      
                                                                             
                                                                           
                                                                           
                                       
   
                                                                        
                                                                         
                                                                              
                                                                      
class Module {
                                
      
public:
                                                
  using GlobalListType = SymbolTableList<GlobalVariable>;
                                         
  using FunctionListType = SymbolTableList<Function>;
                                       
  using AliasListType = SymbolTableList<GlobalAlias>;
                                      
  using IFuncListType = SymbolTableList<GlobalIFunc>;
                                              
  using NamedMDListType = ilist<NamedMDNode>;
                                            
  using ComdatSymTabType = StringMap<Comdat>;

                                   
  using global_iterator = GlobalListType::iterator;
                                            
  using const_global_iterator = GlobalListType::const_iterator;

                             
  using iterator = FunctionListType::iterator;
                                    
  using const_iterator = FunctionListType::const_iterator;

                                    
  using reverse_iterator = FunctionListType::reverse_iterator;
                                             
  using const_reverse_iterator = FunctionListType::const_reverse_iterator;

                                 
  using alias_iterator = AliasListType::iterator;
                                        
  using const_alias_iterator = AliasListType::const_iterator;

                                 
  using ifunc_iterator = IFuncListType::iterator;
                                        
  using const_ifunc_iterator = IFuncListType::const_iterator;

                                   
  using named_metadata_iterator = NamedMDListType::iterator;
                                            
  using const_named_metadata_iterator = NamedMDListType::const_iterator;

                                                                       
  enum ModFlagBehavior {
                                                                               
                             
    Error = 1,

                                                                            
                                                                
    Warning = 2,

                                                                         
                                                                                
                                                                              
                                                                             
                                                                         
                                                                              
                                           
    Require = 3,

                                                                            
                                                                          
                                         
    Override = 4,

                                                                        
    Append = 5,

                                                                 
                                                                        
                                    
    AppendUnique = 6,

                                                                           
    Max = 7,

               
    ModFlagBehaviorFirstVal = Error,
    ModFlagBehaviorLastVal = Max
  };

                                                                           
                              
  static bool isValidModFlagBehavior(Metadata *MD, ModFlagBehavior &MFB);

  struct ModuleFlagEntry {
    ModFlagBehavior Behavior;
    MDString *Key;
    Metadata *Val;

    ModuleFlagEntry(ModFlagBehavior B, MDString *K, Metadata *V)
        : Behavior(B), Key(K), Val(V) {}
  };

      
                          
      
private:
  LLVMContext &Context;                                                    
                                                               
  GlobalListType GlobalList;                                             
  FunctionListType FunctionList;                                  
  AliasListType AliasList;                                      
  IFuncListType IFuncList;                                     
  NamedMDListType NamedMDList;                                         
  std::string GlobalScopeAsm;                                     
  ValueSymbolTable *ValSymTab;                                
  ComdatSymTabType ComdatSymTab;                               
  std::unique_ptr<MemoryBuffer>
  OwnedMemoryBuffer;                                                       
                                                                       
  std::unique_ptr<GVMaterializer>
  Materializer;                                                        
  std::string ModuleID;                                                        
  std::string SourceFileName;                                               
                                                           
  std::string TargetTriple;                                                     
                                                                               
  void *NamedMDSymTab;                                   
  DataLayout DL;                                                            

  friend class Constant;

      
                      
      
public:
                                                                            
                                                           
  explicit Module(StringRef ModuleID, LLVMContext& C);
                                                         
  ~Module();

      
                                
      

                                                                              
                                                
  const std::string &getModuleIdentifier() const { return ModuleID; }

                                                                    
                                                                        
                                       
  unsigned getInstructionCount();

                                                                     
                                                                         
                                                                    
                                   
  const std::string &getSourceFileName() const { return SourceFileName; }

                                        
     
                                                                              
                                           
  StringRef getName() const { return ModuleID; }

                                                                          
                                                               
  const std::string &getDataLayoutStr() const {
    return DL.getStringRepresentation();
  }

                                                           
  const DataLayout &getDataLayout() const;

                                                                         
                                                     
  const std::string &getTargetTriple() const { return TargetTriple; }

                                  
                                                                      
  LLVMContext &getContext() const { return Context; }

                                                  
                                                                           
  const std::string &getModuleInlineAsm() const { return GlobalScopeAsm; }

                                                                      
                                                                     
                                                                      
                                         
     
                                                                     
                                                                     
                                                                  
                                             
  std::unique_ptr<RandomNumberGenerator> createRNG(const Pass* P) const;

                                                                    
                
  bool shouldEmitInstrCountChangedRemark() {
    return getContext().getDiagHandlerPtr()->isAnalysisRemarkEnabled(
        "size-info");
  }

        
                                 
        

                                
  void setModuleIdentifier(StringRef ID) { ModuleID = ID; }

                                                 
  void setSourceFileName(StringRef Name) { SourceFileName = Name; }

                         
  void setDataLayout(StringRef Desc);
  void setDataLayout(const DataLayout &Other);

                            
  void setTargetTriple(StringRef T) { TargetTriple = T; }

                                                  
                                                                
  void setModuleInlineAsm(StringRef Asm) {
    GlobalScopeAsm = Asm;
    if (!GlobalScopeAsm.empty() && GlobalScopeAsm.back() != '\n')
      GlobalScopeAsm += '\n';
  }

                                                        
                                                                
  void appendModuleInlineAsm(StringRef Asm) {
    GlobalScopeAsm += Asm;
    if (!GlobalScopeAsm.empty() && GlobalScopeAsm.back() != '\n')
      GlobalScopeAsm += '\n';
  }

      
                                 
      

                                                                       
                                                                             
                        
  GlobalValue *getNamedValue(StringRef Name) const;

                                                                             
                                                        
  unsigned getMDKindID(StringRef Name) const;

                                                                                
                                     
  void getMDKindNames(SmallVectorImpl<StringRef> &Result) const;

                                                                             
                                                                              
                                             
  void getOperandBundleTags(SmallVectorImpl<StringRef> &Result) const;

                                                                               
           
  StructType *getTypeByName(StringRef Name) const;

  std::vector<StructType *> getIdentifiedStructTypes() const;

      
                            
      

                                                                     
                    
                                                                                
                                                                          
                                             
                                                                                
                                 
                                                                               
                                                                    
  Constant *getOrInsertFunction(StringRef Name, FunctionType *T,
                                AttributeList AttributeList);

  Constant *getOrInsertFunction(StringRef Name, FunctionType *T);

                                                                               
                                                                          
                                                                               
                                                                        
                                                                
                                                                   
  template<typename... ArgsTy>
  Constant *getOrInsertFunction(StringRef Name,
                                AttributeList AttributeList,
                                Type *RetTy, ArgsTy... Args)
  {
    SmallVector<Type*, sizeof...(ArgsTy)> ArgTys{Args...};
    return getOrInsertFunction(Name,
                               FunctionType::get(RetTy, ArgTys, false),
                               AttributeList);
  }

                                                
  template<typename... ArgsTy>
  Constant *getOrInsertFunction(StringRef Name, Type *RetTy, ArgsTy... Args) {
    return getOrInsertFunction(Name, AttributeList{}, RetTy, Args...);
  }

                                                                               
                         
  Function *getFunction(StringRef Name) const;

      
                                   
      

                                                                             
                                                                        
                                                                             
                             
  GlobalVariable *getGlobalVariable(StringRef Name) const {
    return getGlobalVariable(Name, false);
  }

  GlobalVariable *getGlobalVariable(StringRef Name, bool AllowInternal) const;

  GlobalVariable *getGlobalVariable(StringRef Name,
                                    bool AllowInternal = false) {
    return static_cast<const Module *>(this)->getGlobalVariable(Name,
                                                                AllowInternal);
  }

                                                                          
                                                                             
                        
  const GlobalVariable *getNamedGlobal(StringRef Name) const {
    return getGlobalVariable(Name, true);
  }
  GlobalVariable *getNamedGlobal(StringRef Name) {
    return const_cast<GlobalVariable *>(
                       static_cast<const Module *>(this)->getNamedGlobal(Name));
  }

                                                              
                                                                               
                                                                              
                                                      
                                                                             
                               
  Constant *getOrInsertGlobal(StringRef Name, Type *Ty);

      
                                
      

                                                                       
                                                                             
                        
  GlobalAlias *getNamedAlias(StringRef Name) const;

      
                                
      

                                                                       
                                                                             
                        
  GlobalIFunc *getNamedIFunc(StringRef Name) const;

      
                                  
      

                                                                              
                                                                                
  NamedMDNode *getNamedMetadata(const Twine &Name) const;

                                                                                
                                                                               
            
  NamedMDNode *getOrInsertNamedMetadata(StringRef Name);

                                                                  
  void eraseNamedMetadata(NamedMDNode *NMD);

      
                          
      

                                                                            
                                 
  Comdat *getOrInsertComdat(StringRef Name);

      
                                
      

                                                      
  void getModuleFlagsMetadata(SmallVectorImpl<ModuleFlagEntry> &Flags) const;

                                                                              
                  
  Metadata *getModuleFlag(StringRef Key) const;

                                                                               
                                                                  
  NamedMDNode *getModuleFlagsMetadata() const;

                                                                               
                                                                            
                    
  NamedMDNode *getOrInsertModuleFlagsMetadata();

                                                                                
                                                                        
  void addModuleFlag(ModFlagBehavior Behavior, StringRef Key, Metadata *Val);
  void addModuleFlag(ModFlagBehavior Behavior, StringRef Key, Constant *Val);
  void addModuleFlag(ModFlagBehavior Behavior, StringRef Key, uint32_t Val);
  void addModuleFlag(MDNode *Node);

      
                         
      

                                                                     
                                                                                
                                                                    
                                                                           
                                                                                
                                                                            
                         
  void setMaterializer(GVMaterializer *GVM);
                                                            
  GVMaterializer *getMaterializer() const { return Materializer.get(); }
  bool isMaterialized() const { return !getMaterializer(); }

                                              
  llvh::Error materialize(GlobalValue *GV);

                                                                            
                   
  llvh::Error materializeAll();

  llvh::Error materializeMetadata();

      
                                                                             
      

                                                           
  const GlobalListType   &getGlobalList() const       { return GlobalList; }
                                                
  GlobalListType         &getGlobalList()             { return GlobalList; }

  static GlobalListType Module::*getSublistAccess(GlobalVariable*) {
    return &Module::GlobalList;
  }

                                                    
  const FunctionListType &getFunctionList() const     { return FunctionList; }
                                         
  FunctionListType       &getFunctionList()           { return FunctionList; }
  static FunctionListType Module::*getSublistAccess(Function*) {
    return &Module::FunctionList;
  }

                                                  
  const AliasListType    &getAliasList() const        { return AliasList; }
                                       
  AliasListType          &getAliasList()              { return AliasList; }

  static AliasListType Module::*getSublistAccess(GlobalAlias*) {
    return &Module::AliasList;
  }

                                                 
  const IFuncListType    &getIFuncList() const        { return IFuncList; }
                                      
  IFuncListType          &getIFuncList()              { return IFuncList; }

  static IFuncListType Module::*getSublistAccess(GlobalIFunc*) {
    return &Module::IFuncList;
  }

                                                         
  const NamedMDListType  &getNamedMDList() const      { return NamedMDList; }
                                              
  NamedMDListType        &getNamedMDList()            { return NamedMDList; }

  static NamedMDListType Module::*getSublistAccess(NamedMDNode*) {
    return &Module::NamedMDList;
  }

                                                                      
  const ValueSymbolTable &getValueSymbolTable() const { return *ValSymTab; }
                                                                                
  ValueSymbolTable       &getValueSymbolTable()       { return *ValSymTab; }

                                                           
  const ComdatSymTabType &getComdatSymbolTable() const { return ComdatSymTab; }
                                                
  ComdatSymTabType &getComdatSymbolTable() { return ComdatSymTab; }

      
                                   
      

  global_iterator       global_begin()       { return GlobalList.begin(); }
  const_global_iterator global_begin() const { return GlobalList.begin(); }
  global_iterator       global_end  ()       { return GlobalList.end(); }
  const_global_iterator global_end  () const { return GlobalList.end(); }
  bool                  global_empty() const { return GlobalList.empty(); }

  iterator_range<global_iterator> globals() {
    return make_range(global_begin(), global_end());
  }
  iterator_range<const_global_iterator> globals() const {
    return make_range(global_begin(), global_end());
  }

      
                            
      

  iterator                begin()       { return FunctionList.begin(); }
  const_iterator          begin() const { return FunctionList.begin(); }
  iterator                end  ()       { return FunctionList.end();   }
  const_iterator          end  () const { return FunctionList.end();   }
  reverse_iterator        rbegin()      { return FunctionList.rbegin(); }
  const_reverse_iterator  rbegin() const{ return FunctionList.rbegin(); }
  reverse_iterator        rend()        { return FunctionList.rend(); }
  const_reverse_iterator  rend() const  { return FunctionList.rend(); }
  size_t                  size() const  { return FunctionList.size(); }
  bool                    empty() const { return FunctionList.empty(); }

  iterator_range<iterator> functions() {
    return make_range(begin(), end());
  }
  iterator_range<const_iterator> functions() const {
    return make_range(begin(), end());
  }

      
                         
      

  alias_iterator       alias_begin()            { return AliasList.begin(); }
  const_alias_iterator alias_begin() const      { return AliasList.begin(); }
  alias_iterator       alias_end  ()            { return AliasList.end();   }
  const_alias_iterator alias_end  () const      { return AliasList.end();   }
  size_t               alias_size () const      { return AliasList.size();  }
  bool                 alias_empty() const      { return AliasList.empty(); }

  iterator_range<alias_iterator> aliases() {
    return make_range(alias_begin(), alias_end());
  }
  iterator_range<const_alias_iterator> aliases() const {
    return make_range(alias_begin(), alias_end());
  }

      
                         
      

  ifunc_iterator       ifunc_begin()            { return IFuncList.begin(); }
  const_ifunc_iterator ifunc_begin() const      { return IFuncList.begin(); }
  ifunc_iterator       ifunc_end  ()            { return IFuncList.end();   }
  const_ifunc_iterator ifunc_end  () const      { return IFuncList.end();   }
  size_t               ifunc_size () const      { return IFuncList.size();  }
  bool                 ifunc_empty() const      { return IFuncList.empty(); }

  iterator_range<ifunc_iterator> ifuncs() {
    return make_range(ifunc_begin(), ifunc_end());
  }
  iterator_range<const_ifunc_iterator> ifuncs() const {
    return make_range(ifunc_begin(), ifunc_end());
  }

        
                                 
        

  using global_object_iterator =
      concat_iterator<GlobalObject, iterator, global_iterator>;
  using const_global_object_iterator =
      concat_iterator<const GlobalObject, const_iterator,
                      const_global_iterator>;

  iterator_range<global_object_iterator> global_objects() {
    return concat<GlobalObject>(functions(), globals());
  }
  iterator_range<const_global_object_iterator> global_objects() const {
    return concat<const GlobalObject>(functions(), globals());
  }

  global_object_iterator global_object_begin() {
    return global_objects().begin();
  }
  global_object_iterator global_object_end() { return global_objects().end(); }

  const_global_object_iterator global_object_begin() const {
    return global_objects().begin();
  }
  const_global_object_iterator global_object_end() const {
    return global_objects().end();
  }

  using global_value_iterator =
      concat_iterator<GlobalValue, iterator, global_iterator, alias_iterator,
                      ifunc_iterator>;
  using const_global_value_iterator =
      concat_iterator<const GlobalValue, const_iterator, const_global_iterator,
                      const_alias_iterator, const_ifunc_iterator>;

  iterator_range<global_value_iterator> global_values() {
    return concat<GlobalValue>(functions(), globals(), aliases(), ifuncs());
  }
  iterator_range<const_global_value_iterator> global_values() const {
    return concat<const GlobalValue>(functions(), globals(), aliases(),
                                     ifuncs());
  }

  global_value_iterator global_value_begin() { return global_values().begin(); }
  global_value_iterator global_value_end() { return global_values().end(); }

  const_global_value_iterator global_value_begin() const {
    return global_values().begin();
  }
  const_global_value_iterator global_value_end() const {
    return global_values().end();
  }

        
                                    
        

  named_metadata_iterator named_metadata_begin() { return NamedMDList.begin(); }
  const_named_metadata_iterator named_metadata_begin() const {
    return NamedMDList.begin();
  }

  named_metadata_iterator named_metadata_end() { return NamedMDList.end(); }
  const_named_metadata_iterator named_metadata_end() const {
    return NamedMDList.end();
  }

  size_t named_metadata_size() const { return NamedMDList.size();  }
  bool named_metadata_empty() const { return NamedMDList.empty(); }

  iterator_range<named_metadata_iterator> named_metadata() {
    return make_range(named_metadata_begin(), named_metadata_end());
  }
  iterator_range<const_named_metadata_iterator> named_metadata() const {
    return make_range(named_metadata_begin(), named_metadata_end());
  }

                                                                     
  class debug_compile_units_iterator {
    NamedMDNode *CUs;
    unsigned Idx;

    void SkipNoDebugCUs();

  public:
    using iterator_category = std::input_iterator_tag;
    using value_type = DICompileUnit *;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    explicit debug_compile_units_iterator(NamedMDNode *CUs, unsigned Idx)
        : CUs(CUs), Idx(Idx) {
      SkipNoDebugCUs();
    }

    debug_compile_units_iterator &operator++() {
      ++Idx;
      SkipNoDebugCUs();
      return *this;
    }

    debug_compile_units_iterator operator++(int) {
      debug_compile_units_iterator T(*this);
      ++Idx;
      return T;
    }

    bool operator==(const debug_compile_units_iterator &I) const {
      return Idx == I.Idx;
    }

    bool operator!=(const debug_compile_units_iterator &I) const {
      return Idx != I.Idx;
    }

    DICompileUnit *operator*() const;
    DICompileUnit *operator->() const;
  };

  debug_compile_units_iterator debug_compile_units_begin() const {
    auto *CUs = getNamedMetadata("llvm.dbg.cu");
    return debug_compile_units_iterator(CUs, 0);
  }

  debug_compile_units_iterator debug_compile_units_end() const {
    auto *CUs = getNamedMetadata("llvm.dbg.cu");
    return debug_compile_units_iterator(CUs, CUs ? CUs->getNumOperands() : 0);
  }

                                                                       
                                                                     
              
  iterator_range<debug_compile_units_iterator> debug_compile_units() const {
    auto *CUs = getNamedMetadata("llvm.dbg.cu");
    return make_range(
        debug_compile_units_iterator(CUs, 0),
        debug_compile_units_iterator(CUs, CUs ? CUs->getNumOperands() : 0));
  }
      

                                                                 
                                                                          
                                                                                
                                       
     
                                                                            
                                                                 
  void dropTriviallyDeadConstantArrays();

                                                                   
      

                                                           
                                                                               
                                                                             
                   
  void print(raw_ostream &OS, AssemblyAnnotationWriter *AAW,
             bool ShouldPreserveUseListOrder = false,
             bool IsForDebug = false) const;

                                                
  void dump() const;

                                                                                
                                                                              
                                                                       
                                                                             
                                                                           
                                                                
  void dropAllReferences();

      
                                                           
      

                                                                        
                   
  unsigned getNumberRegisterParameters() const;

                                                         
  unsigned getDwarfVersion() const;

                                                            
                                            
  unsigned getCodeViewFlag() const;

      
                                                              
      

                                                  
  PICLevel::Level getPICLevel() const;

                                              
  void setPICLevel(PICLevel::Level PL);
      

      
                                                              
      

                                                  
  PIELevel::Level getPIELevel() const;

                                              
  void setPIELevel(PIELevel::Level PL);
      

        
                                                                
        

                                                                         
  Optional<CodeModel::Model> getCodeModel() const;

                                                               
  void setCodeModel(CodeModel::Model CL);
        

                                                                  
        

                                                     
  void setProfileSummary(Metadata *M);

                                      
  Metadata *getProfileSummary();
        

                                                            
  bool getRtLibUseGOT() const;

                                                   
  void setRtLibUseGOT();


                                                
  void setOwnedMemoryBuffer(std::unique_ptr<MemoryBuffer> MB);
};

                                                                       
                                                                                
GlobalVariable *collectUsedGlobalVariables(const Module &M,
                                           SmallPtrSetImpl<GlobalValue *> &Set,
                                           bool CompilerUsed);

                                        
inline raw_ostream &operator<<(raw_ostream &O, const Module &M) {
  M.print(O, nullptr);
  return O;
}

                                                                
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(Module, LLVMModuleRef)

                                                                            
          
   
inline Module *unwrap(LLVMModuleProviderRef MP) {
  return reinterpret_cast<Module*>(MP);
}

}                      

#endif                    
