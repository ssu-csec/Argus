//===- llvm/Function.h - Class to represent a single function ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the Function class, which represents a
// single function/procedure in LLVM.
//
// A function basically consists of a list of basic blocks, a list of arguments,
// and a symbol table.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_FUNCTION_H
#define LLVM_IR_FUNCTION_H

#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Argument.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/BasicBlock.h"
#include "llvh/IR/CallingConv.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/GlobalObject.h"
#include "llvh/IR/GlobalValue.h"
#include "llvh/IR/OperandTraits.h"
#include "llvh/IR/SymbolTableListTraits.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/Compiler.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace llvh {

namespace Intrinsic {
enum ID : unsigned;
}

class AssemblyAnnotationWriter;
class Constant;
class DISubprogram;
class LLVMContext;
class Module;
template <typename T> class Optional;
class raw_ostream;
class Type;
class User;

class Function : public GlobalObject, public ilist_node<Function> {
public:
  using BasicBlockListType = SymbolTableList<BasicBlock>;

                            
  using iterator = BasicBlockListType::iterator;
  using const_iterator = BasicBlockListType::const_iterator;

  using arg_iterator = Argument *;
  using const_arg_iterator = const Argument *;

private:
                                              
  BasicBlockListType BasicBlocks;                              
  mutable Argument *Arguments = nullptr;                           
  size_t NumArgs;
  std::unique_ptr<ValueSymbolTable>
      SymTab;                                                                   
  AttributeList AttributeSets;                                     

    
                        
    
                                  
                               
                                 
                                  
                                   
                       
                         
     

                                                       
  enum {
                                                
    IsMaterializableBit = 0,
  };

  friend class SymbolTableListTraits<Function>;

                                                                              
                                                                              
                                                                            
                             
public:
  bool hasLazyArguments() const {
    return getSubclassDataFromValue() & (1<<0);
  }

private:
  void CheckLazyArguments() const {
    if (hasLazyArguments())
      BuildLazyArguments();
  }

  void BuildLazyArguments() const;

  void clearArguments();

                                                                         
                                                                              
                 
     
  Function(FunctionType *Ty, LinkageTypes Linkage, unsigned AddrSpace,
           const Twine &N = "", Module *M = nullptr);

public:
  Function(const Function&) = delete;
  void operator=(const Function&) = delete;
  ~Function();

                                                                        
                                                                          
                              
  const Function &getFunction() const { return *this; }

  static Function *Create(FunctionType *Ty, LinkageTypes Linkage,
                          unsigned AddrSpace, const Twine &N = "",
                          Module *M = nullptr) {
    return new Function(Ty, Linkage, AddrSpace, N, M);
  }

                                                                            
  static Function *Create(FunctionType *Ty, LinkageTypes Linkage,
                          const Twine &N = "", Module *M = nullptr) {
    return new Function(Ty, Linkage, static_cast<unsigned>(-1), N, M);
  }

                                                         
     
                                                                   
                                  
  static Function *Create(FunctionType *Ty, LinkageTypes Linkage,
                          const Twine &N, Module &M);

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                                       
                                                                              
                           
  unsigned getInstructionCount();

                                      
  FunctionType *getFunctionType() const {
    return cast<FunctionType>(getValueType());
  }

                                      
  Type *getReturnType() const { return getFunctionType()->getReturnType(); }

                                                                             
               
  LLVMContext &getContext() const;

                                                                        
                
  bool isVarArg() const { return getFunctionType()->isVarArg(); }

  bool isMaterializable() const {
    return getGlobalObjectSubClassData() & (1 << IsMaterializableBit);
  }
  void setIsMaterializable(bool V) {
    unsigned Mask = 1 << IsMaterializableBit;
    setGlobalObjectSubClassData((~Mask & getGlobalObjectSubClassData()) |
                                (V ? Mask : 0u));
  }

                                                                         
                                                                     
                                                                               
                                                                             
                                                                           
                                   
  Intrinsic::ID getIntrinsicID() const LLVM_READONLY { return IntID; }

                                                                            
                                                                           
                                       
  bool isIntrinsic() const { return HasLLVMReservedName; }

  static Intrinsic::ID lookupIntrinsicID(StringRef Name);

                                                                        
                                                                              
                                                                              
                                                                            
                                                                       
  void recalculateIntrinsicID();

                                                                        
                                                                         
                                                       
  CallingConv::ID getCallingConv() const {
    return static_cast<CallingConv::ID>((getSubclassDataFromValue() >> 4) &
                                        CallingConv::MaxID);
  }
  void setCallingConv(CallingConv::ID CC) {
    auto ID = static_cast<unsigned>(CC);
    assert(!(ID & ~CallingConv::MaxID) && "Unsupported calling convention");
    setValueSubclassData((getSubclassDataFromValue() & 0xc00f) | (ID << 4));
  }

                                                  
  AttributeList getAttributes() const { return AttributeSets; }

                                               
  void setAttributes(AttributeList Attrs) { AttributeSets = Attrs; }

                                               
  void addFnAttr(Attribute::AttrKind Kind) {
    addAttribute(AttributeList::FunctionIndex, Kind);
  }

                                               
  void addFnAttr(StringRef Kind, StringRef Val = StringRef()) {
    addAttribute(AttributeList::FunctionIndex,
                 Attribute::get(getContext(), Kind, Val));
  }

                                               
  void addFnAttr(Attribute Attr) {
    addAttribute(AttributeList::FunctionIndex, Attr);
  }

                                                    
  void removeFnAttr(Attribute::AttrKind Kind) {
    removeAttribute(AttributeList::FunctionIndex, Kind);
  }

                                                   
  void removeFnAttr(StringRef Kind) {
    setAttributes(getAttributes().removeAttribute(
        getContext(), AttributeList::FunctionIndex, Kind));
  }

  enum ProfileCountType { PCT_Invalid, PCT_Real, PCT_Synthetic };

                                        
     
                                                                   
  class ProfileCount {
  private:
    uint64_t Count;
    ProfileCountType PCT;
    static ProfileCount Invalid;

  public:
    ProfileCount() : Count(-1), PCT(PCT_Invalid) {}
    ProfileCount(uint64_t Count, ProfileCountType PCT)
        : Count(Count), PCT(PCT) {}
    bool hasValue() const { return PCT != PCT_Invalid; }
    uint64_t getCount() const { return Count; }
    ProfileCountType getType() const { return PCT; }
    bool isSynthetic() const { return PCT == PCT_Synthetic; }
    explicit operator bool() { return hasValue(); }
    bool operator!() const { return !hasValue(); }
                                                              
    ProfileCount &setCount(uint64_t C) {
      Count = C;
      return *this;
    }
    static ProfileCount getInvalid() { return ProfileCount(-1, PCT_Invalid); }
  };

                                            
     
                                                                            
                                                                 
                                                                               
                                    
  void setEntryCount(ProfileCount Count,
                     const DenseSet<GlobalValue::GUID> *Imports = nullptr);

                                                   
  void setEntryCount(uint64_t Count, ProfileCountType Type = PCT_Real,
                     const DenseSet<GlobalValue::GUID> *Imports = nullptr);

                                            
     
                                                                           
               
  ProfileCount getEntryCount() const;

                                                                 
     
                                                                          
                          
  bool hasProfileData() const { return getEntryCount().hasValue(); }

                                                                            
                                                                              
  DenseSet<GlobalValue::GUID> getImportGUIDs() const;

                                               
  void setSectionPrefix(StringRef Prefix);

                                               
  Optional<StringRef> getSectionPrefix() const;

                                                    
  bool hasFnAttribute(Attribute::AttrKind Kind) const {
    return AttributeSets.hasFnAttribute(Kind);
  }

                                                    
  bool hasFnAttribute(StringRef Kind) const {
    return AttributeSets.hasFnAttribute(Kind);
  }

                                                        
  Attribute getFnAttribute(Attribute::AttrKind Kind) const {
    return getAttribute(AttributeList::FunctionIndex, Kind);
  }

                                                        
  Attribute getFnAttribute(StringRef Kind) const {
    return getAttribute(AttributeList::FunctionIndex, Kind);
  }

                                                  
  unsigned getFnStackAlignment() const {
    if (!hasFnAttribute(Attribute::StackAlignment))
      return 0;
    return AttributeSets.getStackAlignment(AttributeList::FunctionIndex);
  }

                                                                              
                                                                
  bool hasGC() const {
    return getSubclassDataFromValue() & (1<<14);
  }
  const std::string &getGC() const;
  void setGC(std::string Str);
  void clearGC();

                                                   
  void addAttribute(unsigned i, Attribute::AttrKind Kind);

                                                   
  void addAttribute(unsigned i, Attribute Attr);

                                                    
  void addAttributes(unsigned i, const AttrBuilder &Attrs);

                                                                     
  void addParamAttr(unsigned ArgNo, Attribute::AttrKind Kind);

                                                                     
  void addParamAttr(unsigned ArgNo, Attribute Attr);

                                                                      
  void addParamAttrs(unsigned ArgNo, const AttrBuilder &Attrs);

                                                        
  void removeAttribute(unsigned i, Attribute::AttrKind Kind);

                                                        
  void removeAttribute(unsigned i, StringRef Kind);

                                                         
  void removeAttributes(unsigned i, const AttrBuilder &Attrs);

                                                        
  void removeParamAttr(unsigned ArgNo, Attribute::AttrKind Kind);

                                                        
  void removeParamAttr(unsigned ArgNo, StringRef Kind);

                                                        
  void removeParamAttrs(unsigned ArgNo, const AttrBuilder &Attrs);

                                                          
  bool hasAttribute(unsigned i, Attribute::AttrKind Kind) const {
    return getAttributes().hasAttribute(i, Kind);
  }

                                                          
  bool hasParamAttribute(unsigned ArgNo, Attribute::AttrKind Kind) const {
    return getAttributes().hasParamAttribute(ArgNo, Kind);
  }

                                                     
  Attribute getAttribute(unsigned i, Attribute::AttrKind Kind) const {
    return AttributeSets.getAttribute(i, Kind);
  }

                                                     
  Attribute getAttribute(unsigned i, StringRef Kind) const {
    return AttributeSets.getAttribute(i, Kind);
  }

                                                                   
  void addDereferenceableAttr(unsigned i, uint64_t Bytes);

                                                                      
                    
  void addDereferenceableParamAttr(unsigned ArgNo, uint64_t Bytes);

                                                               
                 
  void addDereferenceableOrNullAttr(unsigned i, uint64_t Bytes);

                                                               
                                   
  void addDereferenceableOrNullParamAttr(unsigned ArgNo, uint64_t Bytes);

                                                                
  unsigned getParamAlignment(unsigned ArgNo) const {
    return AttributeSets.getParamAlignment(ArgNo);
  }

                                                               
                            
                                                                            
  uint64_t getDereferenceableBytes(unsigned i) const {
    return AttributeSets.getDereferenceableBytes(i);
  }

                                                                  
                                                                             
  uint64_t getParamDereferenceableBytes(unsigned ArgNo) const {
    return AttributeSets.getParamDereferenceableBytes(ArgNo);
  }

                                                                       
                            
                                                                            
  uint64_t getDereferenceableOrNullBytes(unsigned i) const {
    return AttributeSets.getDereferenceableOrNullBytes(i);
  }

                                                               
                
                                                                 
  uint64_t getParamDereferenceableOrNullBytes(unsigned ArgNo) const {
    return AttributeSets.getParamDereferenceableOrNullBytes(ArgNo);
  }

                                                       
  bool doesNotAccessMemory() const {
    return hasFnAttribute(Attribute::ReadNone);
  }
  void setDoesNotAccessMemory() {
    addFnAttr(Attribute::ReadNone);
  }

                                                                     
  bool onlyReadsMemory() const {
    return doesNotAccessMemory() || hasFnAttribute(Attribute::ReadOnly);
  }
  void setOnlyReadsMemory() {
    addFnAttr(Attribute::ReadOnly);
  }

                                                                      
  bool doesNotReadMemory() const {
    return doesNotAccessMemory() || hasFnAttribute(Attribute::WriteOnly);
  }
  void setDoesNotReadMemory() {
    addFnAttr(Attribute::WriteOnly);
  }

                                                                        
                       
  bool onlyAccessesArgMemory() const {
    return hasFnAttribute(Attribute::ArgMemOnly);
  }
  void setOnlyAccessesArgMemory() { addFnAttr(Attribute::ArgMemOnly); }

                                                              
                                
  bool onlyAccessesInaccessibleMemory() const {
    return hasFnAttribute(Attribute::InaccessibleMemOnly);
  }
  void setOnlyAccessesInaccessibleMemory() {
    addFnAttr(Attribute::InaccessibleMemOnly);
  }

                                                              
                                                                      
  bool onlyAccessesInaccessibleMemOrArgMem() const {
    return hasFnAttribute(Attribute::InaccessibleMemOrArgMemOnly);
  }
  void setOnlyAccessesInaccessibleMemOrArgMem() {
    addFnAttr(Attribute::InaccessibleMemOrArgMemOnly);
  }

                                              
  bool doesNotReturn() const {
    return hasFnAttribute(Attribute::NoReturn);
  }
  void setDoesNotReturn() {
    addFnAttr(Attribute::NoReturn);
  }

                                                                            
  bool doesNoCfCheck() const { return hasFnAttribute(Attribute::NoCfCheck); }

                                              
  bool doesNotThrow() const {
    return hasFnAttribute(Attribute::NoUnwind);
  }
  void setDoesNotThrow() {
    addFnAttr(Attribute::NoUnwind);
  }

                                                 
  bool cannotDuplicate() const {
    return hasFnAttribute(Attribute::NoDuplicate);
  }
  void setCannotDuplicate() {
    addFnAttr(Attribute::NoDuplicate);
  }

                                          
  bool isConvergent() const {
    return hasFnAttribute(Attribute::Convergent);
  }
  void setConvergent() {
    addFnAttr(Attribute::Convergent);
  }
  void setNotConvergent() {
    removeFnAttr(Attribute::Convergent);
  }

                                            
  bool isSpeculatable() const {
    return hasFnAttribute(Attribute::Speculatable);
  }
  void setSpeculatable() {
    addFnAttr(Attribute::Speculatable);
  }

                                                                    
                 
  bool doesNotRecurse() const {
    return hasFnAttribute(Attribute::NoRecurse);
  }
  void setDoesNotRecurse() {
    addFnAttr(Attribute::NoRecurse);
  }

                                                                
                                    
  bool hasUWTable() const {
    return hasFnAttribute(Attribute::UWTable);
  }
  void setHasUWTable() {
    addFnAttr(Attribute::UWTable);
  }

                                                  
  bool needsUnwindTableEntry() const {
    return hasUWTable() || !doesNotThrow() || hasPersonalityFn();
  }

                                                                 
                                 
  bool hasStructRetAttr() const {
    return AttributeSets.hasParamAttribute(0, Attribute::StructRet) ||
           AttributeSets.hasParamAttribute(1, Attribute::StructRet);
  }

                                                                       
                
  bool returnDoesNotAlias() const {
    return AttributeSets.hasAttribute(AttributeList::ReturnIndex,
                                      Attribute::NoAlias);
  }
  void setReturnDoesNotAlias() {
    addAttribute(AttributeList::ReturnIndex, Attribute::NoAlias);
  }

                                                    
  bool optForMinSize() const { return hasFnAttribute(Attribute::MinSize); }

                                                                  
  bool optForSize() const {
    return hasFnAttribute(Attribute::OptimizeForSize) || optForMinSize();
  }

                                                                              
                                                           
  void copyAttributesFrom(const Function *Src);

                                                                             
                              
     
  void deleteBody() {
    dropAllReferences();
    setLinkage(ExternalLinkage);
  }

                                                                               
                             
     
  void removeFromParent();

                                                                             
                     
     
  void eraseFromParent();

                                            
     
                                                                        
                                              
  void stealArgumentListFrom(Function &Src);

                                                                            
                                   
     
  const BasicBlockListType &getBasicBlockList() const { return BasicBlocks; }
        BasicBlockListType &getBasicBlockList()       { return BasicBlocks; }

  static BasicBlockListType Function::*getSublistAccess(BasicBlock*) {
    return &Function::BasicBlocks;
  }

  const BasicBlock       &getEntryBlock() const   { return front(); }
        BasicBlock       &getEntryBlock()         { return front(); }

                                                                                
                                        

                                                                           
     
  inline ValueSymbolTable *getValueSymbolTable() { return SymTab.get(); }
  inline const ValueSymbolTable *getValueSymbolTable() const {
    return SymTab.get();
  }

                                                                                
                                             
    
  iterator                begin()       { return BasicBlocks.begin(); }
  const_iterator          begin() const { return BasicBlocks.begin(); }
  iterator                end  ()       { return BasicBlocks.end();   }
  const_iterator          end  () const { return BasicBlocks.end();   }

  size_t                   size() const { return BasicBlocks.size();  }
  bool                    empty() const { return BasicBlocks.empty(); }
  const BasicBlock       &front() const { return BasicBlocks.front(); }
        BasicBlock       &front()       { return BasicBlocks.front(); }
  const BasicBlock        &back() const { return BasicBlocks.back();  }
        BasicBlock        &back()       { return BasicBlocks.back();  }

                                     
      

  arg_iterator arg_begin() {
    CheckLazyArguments();
    return Arguments;
  }
  const_arg_iterator arg_begin() const {
    CheckLazyArguments();
    return Arguments;
  }

  arg_iterator arg_end() {
    CheckLazyArguments();
    return Arguments + NumArgs;
  }
  const_arg_iterator arg_end() const {
    CheckLazyArguments();
    return Arguments + NumArgs;
  }

  iterator_range<arg_iterator> args() {
    return make_range(arg_begin(), arg_end());
  }
  iterator_range<const_arg_iterator> args() const {
    return make_range(arg_begin(), arg_end());
  }

      

  size_t arg_size() const { return NumArgs; }
  bool arg_empty() const { return arg_size() == 0; }

                                                             
  bool hasPersonalityFn() const {
    return getSubclassDataFromValue() & (1<<3);
  }

                                                                 
  Constant *getPersonalityFn() const;
  void setPersonalityFn(Constant *Fn);

                                                  
  bool hasPrefixData() const {
    return getSubclassDataFromValue() & (1<<1);
  }

                                                        
  Constant *getPrefixData() const;
  void setPrefixData(Constant *PrefixData);

                                                    
  bool hasPrologueData() const {
    return getSubclassDataFromValue() & (1<<2);
  }

                                                          
  Constant *getPrologueData() const;
  void setPrologueData(Constant *PrologueData);

                                                             
                               
  void print(raw_ostream &OS, AssemblyAnnotationWriter *AAW = nullptr,
             bool ShouldPreserveUseListOrder = false,
             bool IsForDebug = false) const;

                                                                               
                                                                           
                                                                                
                                                                               
                   
     
  void viewCFG() const;

                                                                               
                                                                             
                                                                            
                                      
     
  void viewCFGOnly() const;

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == Value::FunctionVal;
  }

                                                                              
                                                                          
                                                                          
                                                                              
                                                                              
                                                                           
             
     
                                                                                
                                                                                
                                           
     
  void dropAllReferences();

                                                                           
                                                                            
                                                                       
     
  bool hasAddressTaken(const User** = nullptr) const;

                                                                        
                                                                           
                                                                             
                                                             
  bool isDefTriviallyDead() const;

                                                                               
                                                                        
  bool callsFunctionThatReturnsTwice() const;

                                  
     
                                                         
  void setSubprogram(DISubprogram *SP);

                                  
     
                                                                             
                         
  DISubprogram *getSubprogram() const;

                                                              
  bool isDebugInfoForProfiling() const;

                                                                              
                   
                                                                   
                                                                       
  bool nullPointerIsDefined() const;

private:
  void allocHungoffUselist();
  template<int Idx> void setHungoffOperand(Constant *C);

                                                                            
                                                 
  void setValueSubclassData(unsigned short D) {
    Value::setValueSubclassData(D);
  }
  void setValueSubclassDataBit(unsigned Bit, bool On);
};

                                                                             
                                             
                                                                              
                                                                 
                                                                     
bool NullPointerIsDefined(const Function *F, unsigned AS = 0);

template <>
struct OperandTraits<Function> : public HungoffOperandTraits<3> {};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(Function, Value)

}                      

#endif                      
