//===-- llvm/GlobalValue.h - Class to represent a global value --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a common base class of all globally definable objects.  As such,
// it is subclassed by GlobalVariable, GlobalAlias and by Function.  This is
// used because you can do certain things with these global objects that you
// can't do to anything else.  For example, use the address of one as a
// constant.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_GLOBALVALUE_H
#define LLVM_IR_GLOBALVALUE_H

#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/IR/Constant.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/MD5.h"
#include <cassert>
#include <cstdint>
#include <string>

namespace llvh {

class Comdat;
class ConstantRange;
class Error;
class GlobalObject;
class Module;

namespace Intrinsic {
  enum ID : unsigned;
}                           

class GlobalValue : public Constant {
public:
                                                                
  enum LinkageTypes {
    ExternalLinkage = 0,                                
    AvailableExternallyLinkage,                                             
    LinkOnceAnyLinkage,                                                     
    LinkOnceODRLinkage,                                                      
    WeakAnyLinkage,                                                             
    WeakODRLinkage,                                                          
    AppendingLinkage,                                                      
    InternalLinkage,                                                           
    PrivateLinkage,                                                    
    ExternalWeakLinkage,                                      
    CommonLinkage                                  
  };

                                                                  
  enum VisibilityTypes {
    DefaultVisibility = 0,                        
    HiddenVisibility,                            
    ProtectedVisibility                             
  };

                                                      
  enum DLLStorageClassTypes {
    DefaultStorageClass   = 0,
    DLLImportStorageClass = 1,                                      
    DLLExportStorageClass = 2                                          
  };

protected:
  GlobalValue(Type *Ty, ValueTy VTy, Use *Ops, unsigned NumOps,
              LinkageTypes Linkage, const Twine &Name, unsigned AddressSpace)
      : Constant(PointerType::get(Ty, AddressSpace), VTy, Ops, NumOps),
        ValueType(Ty), Visibility(DefaultVisibility),
        UnnamedAddrVal(unsigned(UnnamedAddr::None)),
        DllStorageClass(DefaultStorageClass), ThreadLocal(NotThreadLocal),
        HasLLVMReservedName(false), IsDSOLocal(false), IntID((Intrinsic::ID)0U),
        Parent(nullptr) {
    setLinkage(Linkage);
    setName(Name);
  }

  Type *ValueType;

  static const unsigned GlobalValueSubClassDataBits = 17;

                                                                             
          
  unsigned Linkage : 4;                                    
  unsigned Visibility : 2;                                          
  unsigned UnnamedAddrVal : 2;                                           
  unsigned DllStorageClass : 2;                     

  unsigned ThreadLocal : 3;                                                 
                                                 

                                                                               
                                                                 
                                                               
  unsigned HasLLVMReservedName : 1;

                                                                              
                                             
  unsigned IsDSOLocal : 1;

private:
                                                                      
                                            
  unsigned SubClassData : GlobalValueSubClassDataBits;

  friend class Constant;

  void destroyConstantImpl();
  Value *handleOperandChangeImpl(Value *From, Value *To);

                                                                        
                                                                             
           
  bool mayBeDerefined() const {
    switch (getLinkage()) {
    case WeakODRLinkage:
    case LinkOnceODRLinkage:
    case AvailableExternallyLinkage:
      return true;

    case WeakAnyLinkage:
    case LinkOnceAnyLinkage:
    case CommonLinkage:
    case ExternalWeakLinkage:
    case ExternalLinkage:
    case AppendingLinkage:
    case InternalLinkage:
    case PrivateLinkage:
      return isInterposable();
    }

    llvm_unreachable("Fully covered switch above!");
  }

  void maybeSetDsoLocal() {
    if (hasLocalLinkage() ||
        (!hasDefaultVisibility() && !hasExternalWeakLinkage()))
      setDSOLocal(true);
  }

protected:
                                                                    
     
                                                                      
                                                                          
     
                                                                    
  Intrinsic::ID IntID;

  unsigned getGlobalValueSubClassData() const {
    return SubClassData;
  }
  void setGlobalValueSubClassData(unsigned V) {
    assert(V < (1 << GlobalValueSubClassDataBits) && "It will not fit");
    SubClassData = V;
  }

  Module *Parent;                                      

                                   
  void setParent(Module *parent) {
    Parent = parent;
  }

  ~GlobalValue() {
    removeDeadConstantUsers();                                           
  }

public:
  enum ThreadLocalMode {
    NotThreadLocal = 0,
    GeneralDynamicTLSModel,
    LocalDynamicTLSModel,
    InitialExecTLSModel,
    LocalExecTLSModel
  };

  GlobalValue(const GlobalValue &) = delete;

  unsigned getAlignment() const;
  unsigned getAddressSpace() const;

  enum class UnnamedAddr {
    None,
    Local,
    Global,
  };

  bool hasGlobalUnnamedAddr() const {
    return getUnnamedAddr() == UnnamedAddr::Global;
  }

                                                                             
                                                                              
                                                                                
                                                                              
                                                                       
  bool hasAtLeastLocalUnnamedAddr() const {
    return getUnnamedAddr() != UnnamedAddr::None;
  }

  UnnamedAddr getUnnamedAddr() const {
    return UnnamedAddr(UnnamedAddrVal);
  }
  void setUnnamedAddr(UnnamedAddr Val) { UnnamedAddrVal = unsigned(Val); }

  static UnnamedAddr getMinUnnamedAddr(UnnamedAddr A, UnnamedAddr B) {
    if (A == UnnamedAddr::None || B == UnnamedAddr::None)
      return UnnamedAddr::None;
    if (A == UnnamedAddr::Local || B == UnnamedAddr::Local)
      return UnnamedAddr::Local;
    return UnnamedAddr::Global;
  }

  bool hasComdat() const { return getComdat() != nullptr; }
  const Comdat *getComdat() const;
  Comdat *getComdat() {
    return const_cast<Comdat *>(
                           static_cast<const GlobalValue *>(this)->getComdat());
  }

  VisibilityTypes getVisibility() const { return VisibilityTypes(Visibility); }
  bool hasDefaultVisibility() const { return Visibility == DefaultVisibility; }
  bool hasHiddenVisibility() const { return Visibility == HiddenVisibility; }
  bool hasProtectedVisibility() const {
    return Visibility == ProtectedVisibility;
  }
  void setVisibility(VisibilityTypes V) {
    assert((!hasLocalLinkage() || V == DefaultVisibility) &&
           "local linkage requires default visibility");
    Visibility = V;
    maybeSetDsoLocal();
  }

                                                                            
  bool isThreadLocal() const { return getThreadLocalMode() != NotThreadLocal; }
  void setThreadLocal(bool Val) {
    setThreadLocalMode(Val ? GeneralDynamicTLSModel : NotThreadLocal);
  }
  void setThreadLocalMode(ThreadLocalMode Val) {
    assert(Val == NotThreadLocal || getValueID() != Value::FunctionVal);
    ThreadLocal = Val;
  }
  ThreadLocalMode getThreadLocalMode() const {
    return static_cast<ThreadLocalMode>(ThreadLocal);
  }

  DLLStorageClassTypes getDLLStorageClass() const {
    return DLLStorageClassTypes(DllStorageClass);
  }
  bool hasDLLImportStorageClass() const {
    return DllStorageClass == DLLImportStorageClass;
  }
  bool hasDLLExportStorageClass() const {
    return DllStorageClass == DLLExportStorageClass;
  }
  void setDLLStorageClass(DLLStorageClassTypes C) { DllStorageClass = C; }

  bool hasSection() const { return !getSection().empty(); }
  StringRef getSection() const;

                                        
  PointerType *getType() const { return cast<PointerType>(User::getType()); }

  Type *getValueType() const { return ValueType; }

  void setDSOLocal(bool Local) { IsDSOLocal = Local; }

  bool isDSOLocal() const {
    return IsDSOLocal;
  }

  static LinkageTypes getLinkOnceLinkage(bool ODR) {
    return ODR ? LinkOnceODRLinkage : LinkOnceAnyLinkage;
  }
  static LinkageTypes getWeakLinkage(bool ODR) {
    return ODR ? WeakODRLinkage : WeakAnyLinkage;
  }

  static bool isExternalLinkage(LinkageTypes Linkage) {
    return Linkage == ExternalLinkage;
  }
  static bool isAvailableExternallyLinkage(LinkageTypes Linkage) {
    return Linkage == AvailableExternallyLinkage;
  }
  static bool isLinkOnceODRLinkage(LinkageTypes Linkage) {
    return Linkage == LinkOnceODRLinkage;
  }
  static bool isLinkOnceLinkage(LinkageTypes Linkage) {
    return Linkage == LinkOnceAnyLinkage || Linkage == LinkOnceODRLinkage;
  }
  static bool isWeakAnyLinkage(LinkageTypes Linkage) {
    return Linkage == WeakAnyLinkage;
  }
  static bool isWeakODRLinkage(LinkageTypes Linkage) {
    return Linkage == WeakODRLinkage;
  }
  static bool isWeakLinkage(LinkageTypes Linkage) {
    return isWeakAnyLinkage(Linkage) || isWeakODRLinkage(Linkage);
  }
  static bool isAppendingLinkage(LinkageTypes Linkage) {
    return Linkage == AppendingLinkage;
  }
  static bool isInternalLinkage(LinkageTypes Linkage) {
    return Linkage == InternalLinkage;
  }
  static bool isPrivateLinkage(LinkageTypes Linkage) {
    return Linkage == PrivateLinkage;
  }
  static bool isLocalLinkage(LinkageTypes Linkage) {
    return isInternalLinkage(Linkage) || isPrivateLinkage(Linkage);
  }
  static bool isExternalWeakLinkage(LinkageTypes Linkage) {
    return Linkage == ExternalWeakLinkage;
  }
  static bool isCommonLinkage(LinkageTypes Linkage) {
    return Linkage == CommonLinkage;
  }
  static bool isValidDeclarationLinkage(LinkageTypes Linkage) {
    return isExternalWeakLinkage(Linkage) || isExternalLinkage(Linkage);
  }

                                                                        
                                                                              
                                                                  
  static bool isInterposableLinkage(LinkageTypes Linkage) {
    switch (Linkage) {
    case WeakAnyLinkage:
    case LinkOnceAnyLinkage:
    case CommonLinkage:
    case ExternalWeakLinkage:
      return true;

    case AvailableExternallyLinkage:
    case LinkOnceODRLinkage:
    case WeakODRLinkage:
                                                                  

    case ExternalLinkage:
    case AppendingLinkage:
    case InternalLinkage:
    case PrivateLinkage:
      return false;
    }
    llvm_unreachable("Fully covered switch above!");
  }

                                                                              
                              
  static bool isDiscardableIfUnused(LinkageTypes Linkage) {
    return isLinkOnceLinkage(Linkage) || isLocalLinkage(Linkage) ||
           isAvailableExternallyLinkage(Linkage);
  }

                                                                              
                                                                         
                                                                            
                                
  static bool isWeakForLinker(LinkageTypes Linkage)  {
    return Linkage == WeakAnyLinkage || Linkage == WeakODRLinkage ||
           Linkage == LinkOnceAnyLinkage || Linkage == LinkOnceODRLinkage ||
           Linkage == CommonLinkage || Linkage == ExternalWeakLinkage;
  }

                                                                                
                                                    
     
                                                                     
                                                                           
                                                                             
                                              
     
                          
                           
                   
         
     
                         
     
                            
     
                                                                           
                                                                       
                                                                                
                            
     
                                                                            
                                                                             
                                                                          
                                                                
  bool isDefinitionExact() const {
    return !mayBeDerefined();
  }

                                                        
  bool hasExactDefinition() const {
                                                    
                                                                          
                                                                       
                                                                               
                                       
    return !isDeclaration() && isDefinitionExact();
  }

                                                                        
                                                                              
                                                                           
                                       
  bool isInterposable() const { return isInterposableLinkage(getLinkage()); }

  bool hasExternalLinkage() const { return isExternalLinkage(getLinkage()); }
  bool hasAvailableExternallyLinkage() const {
    return isAvailableExternallyLinkage(getLinkage());
  }
  bool hasLinkOnceLinkage() const { return isLinkOnceLinkage(getLinkage()); }
  bool hasLinkOnceODRLinkage() const {
    return isLinkOnceODRLinkage(getLinkage());
  }
  bool hasWeakLinkage() const { return isWeakLinkage(getLinkage()); }
  bool hasWeakAnyLinkage() const { return isWeakAnyLinkage(getLinkage()); }
  bool hasWeakODRLinkage() const { return isWeakODRLinkage(getLinkage()); }
  bool hasAppendingLinkage() const { return isAppendingLinkage(getLinkage()); }
  bool hasInternalLinkage() const { return isInternalLinkage(getLinkage()); }
  bool hasPrivateLinkage() const { return isPrivateLinkage(getLinkage()); }
  bool hasLocalLinkage() const { return isLocalLinkage(getLinkage()); }
  bool hasExternalWeakLinkage() const {
    return isExternalWeakLinkage(getLinkage());
  }
  bool hasCommonLinkage() const { return isCommonLinkage(getLinkage()); }
  bool hasValidDeclarationLinkage() const {
    return isValidDeclarationLinkage(getLinkage());
  }

  void setLinkage(LinkageTypes LT) {
    if (isLocalLinkage(LT))
      Visibility = DefaultVisibility;
    Linkage = LT;
    maybeSetDsoLocal();
  }
  LinkageTypes getLinkage() const { return LinkageTypes(Linkage); }

  bool isDiscardableIfUnused() const {
    return isDiscardableIfUnused(getLinkage());
  }

  bool isWeakForLinker() const { return isWeakForLinker(getLinkage()); }

protected:
                                                                               
                                           
  void copyAttributesFrom(const GlobalValue *Src);

public:
                                                                          
                              
     
                                                                             
                                                                      
                                                                             
                
  static StringRef dropLLVMManglingEscape(StringRef Name) {
    if (!Name.empty() && Name[0] == '\1')
      return Name.substr(1);
    return Name;
  }

                                                                
                                                                    
                                                                  
                                                             
  static std::string getGlobalIdentifier(StringRef Name,
                                         GlobalValue::LinkageTypes Linkage,
                                         StringRef FileName);

                                                                   
                                                                    
  std::string getGlobalIdentifier() const;

                                                                                
                                                                              
                                      
  using GUID = uint64_t;

                                                                         
                                               
  static GUID getGUID(StringRef GlobalName) { return MD5Hash(GlobalName); }

                                                                         
                                               
  GUID getGUID() const { return getGUID(getGlobalIdentifier()); }

                           
                                                                            
          
                                                                          
                                       
        

                                                                               
                                                                          
                                           
  bool isMaterializable() const;

                                               
  Error materialize();

      

                                                                              
                                   
  bool isDeclaration() const;

  bool isDeclarationForLinker() const {
    if (hasAvailableExternallyLinkage())
      return true;

    return isDeclaration();
  }

                                                                            
             
     
                                                                            
                                                                               
                                                                   
  bool isStrongDefinitionForLinker() const {
    return !(isDeclarationForLinker() || isWeakForLinker());
  }

                                                                   
               
  bool canIncreaseAlignment() const;

  const GlobalObject *getBaseObject() const;
  GlobalObject *getBaseObject() {
    return const_cast<GlobalObject *>(
                       static_cast<const GlobalValue *>(this)->getBaseObject());
  }

                                                                
  bool isAbsoluteSymbolRef() const;

                                                                               
                             
  Optional<ConstantRange> getAbsoluteSymbolRange() const;

                                                                                
         
  void removeFromParent();

                                                                           
  void eraseFromParent();

                                                                     
  Module *getParent() { return Parent; }
  const Module *getParent() const { return Parent; }

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == Value::FunctionVal ||
           V->getValueID() == Value::GlobalVariableVal ||
           V->getValueID() == Value::GlobalAliasVal ||
           V->getValueID() == Value::GlobalIFuncVal;
  }

                                                                             
                                                                               
                                                                             
                                                                              
                              
  bool canBeOmittedFromSymbolTable() const;
};

}                      

#endif                         
