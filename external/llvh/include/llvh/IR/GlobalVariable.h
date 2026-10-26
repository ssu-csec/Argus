//===-- llvm/GlobalVariable.h - GlobalVariable class ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the GlobalVariable class, which
// represents a single global variable (or constant) in the VM.
//
// Global variables are constant pointers that refer to hunks of space that are
// allocated by either the VM, or by the linker in a static compiler.  A global
// variable may have an initial value, which is copied into the executables .data
// area.  Global Constants are required to have initializers.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_GLOBALVARIABLE_H
#define LLVM_IR_GLOBALVARIABLE_H

#include "llvh/ADT/PointerUnion.h"
#include "llvh/ADT/Twine.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/GlobalObject.h"
#include "llvh/IR/OperandTraits.h"
#include "llvh/IR/Value.h"
#include <cassert>
#include <cstddef>

namespace llvh {

class Constant;
class Module;

template <typename ValueSubClass> class SymbolTableListTraits;
class DIGlobalVariable;
class DIGlobalVariableExpression;

class GlobalVariable : public GlobalObject, public ilist_node<GlobalVariable> {
  friend class SymbolTableListTraits<GlobalVariable>;

  AttributeSet Attrs;
  bool isConstantGlobal : 1;                                                
  bool isExternallyInitializedConstant : 1;                                   
                                                                             
                                                                     
                                                                       

public:
                                                                          
                                                                               
  GlobalVariable(Type *Ty, bool isConstant, LinkageTypes Linkage,
                 Constant *Initializer = nullptr, const Twine &Name = "",
                 ThreadLocalMode = NotThreadLocal, unsigned AddressSpace = 0,
                 bool isExternallyInitialized = false);
                                                                           
                             
  GlobalVariable(Module &M, Type *Ty, bool isConstant,
                 LinkageTypes Linkage, Constant *Initializer,
                 const Twine &Name = "", GlobalVariable *InsertBefore = nullptr,
                 ThreadLocalMode = NotThreadLocal, unsigned AddressSpace = 0,
                 bool isExternallyInitialized = false);
  GlobalVariable(const GlobalVariable &) = delete;
  GlobalVariable &operator=(const GlobalVariable &) = delete;

  ~GlobalVariable() {
    dropAllReferences();
  }

                                           
  void *operator new(size_t s) {
    return User::operator new(s, 1);
  }

                                                                                      
  void operator delete(void *ptr){
    assert(ptr != nullptr && "must not be nullptr");
    User *Obj = static_cast<User *>(ptr);
                                                                                          
                                                                                        
    Obj->setGlobalVariableNumOperands(1);
    User::operator delete(Obj);
  }

                                    
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

                                                        
     
  inline bool hasInitializer() const { return !isDeclaration(); }

                                                                                
                                                                        
                                                           
     
                                                               
                                                                        
     
              
     
                                                                             
     
                                                                             
             
     
                                                                              
             
  inline bool hasDefinitiveInitializer() const {
    return hasInitializer() &&
                                                                               
                      
      !isInterposable() &&
                                                                             
                                                                            
      !isExternallyInitialized();
  }

                                                                                
                                                                               
  inline bool hasUniqueInitializer() const {
    return
                                                                               
        isStrongDefinitionForLinker() &&
                                                                             
                                                                                
                                                 
        !isExternallyInitialized();
  }

                                                                              
                                                                              
                                            
     
  inline const Constant *getInitializer() const {
    assert(hasInitializer() && "GV doesn't have initializer!");
    return static_cast<Constant*>(Op<0>().get());
  }
  inline Constant *getInitializer() {
    assert(hasInitializer() && "GV doesn't have initializer!");
    return static_cast<Constant*>(Op<0>().get());
  }
                                                                              
                                                                             
                                   
  void setInitializer(Constant *InitVal);

                                                                              
                                                                            
                                  
     
  bool isConstant() const { return isConstantGlobal; }
  void setConstant(bool Val) { isConstantGlobal = Val; }

  bool isExternallyInitialized() const {
    return isExternallyInitializedConstant;
  }
  void setExternallyInitialized(bool Val) {
    isExternallyInitializedConstant = Val;
  }

                                                                              
                                                                       
  void copyAttributesFrom(const GlobalVariable *Src);

                                                                               
                             
     
  void removeFromParent();

                                                                             
                     
     
  void eraseFromParent();

                                                                            
                                                                               
  void dropAllReferences();

                                          
  void addDebugInfo(DIGlobalVariableExpression *GV);

                                                       
  void getDebugInfo(SmallVectorImpl<DIGlobalVariableExpression *> &GVs) const;

                                   
  void addAttribute(Attribute::AttrKind Kind) {
    Attrs = Attrs.addAttribute(getContext(), Kind);
  }

                                   
  void addAttribute(StringRef Kind, StringRef Val = StringRef()) {
    Attrs = Attrs.addAttribute(getContext(), Kind, Val);
  }

                                          
  bool hasAttribute(Attribute::AttrKind Kind) const {
    return Attrs.hasAttribute(Kind);
  }

                                          
  bool hasAttribute(StringRef Kind) const {
    return Attrs.hasAttribute(Kind);
  }

                                          
  bool hasAttributes() const {
    return Attrs.hasAttributes();
  }

                                  
  Attribute getAttribute(Attribute::AttrKind Kind) const {
    return Attrs.getAttribute(Kind);
  }

                                  
  Attribute getAttribute(StringRef Kind) const {
    return Attrs.getAttribute(Kind);
  }

                                              
  AttributeSet getAttributes() const {
    return Attrs;
  }

                                              
                                                           
                                                    
  AttributeList getAttributesAsList(unsigned index) const {
    if (!hasAttributes())
      return AttributeList();
    std::pair<unsigned, AttributeSet> AS[1] = {{index, Attrs}};
    return AttributeList::get(getContext(), AS);
  }

                                        
  void setAttributes(AttributeSet A) {
    Attrs = A;
  }

                                      
  bool hasImplicitSection() const {
    return getAttributes().hasAttribute("bss-section") ||
           getAttributes().hasAttribute("data-section") ||
           getAttributes().hasAttribute("rodata-section");
  }

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == Value::GlobalVariableVal;
  }
};

template <>
struct OperandTraits<GlobalVariable> :
  public OptionalOperandTraits<GlobalVariable> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(GlobalVariable, Value)

}                      

#endif                            
