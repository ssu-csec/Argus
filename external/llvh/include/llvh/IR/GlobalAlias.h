//===-------- llvm/GlobalAlias.h - GlobalAlias class ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the GlobalAlias class, which
// represents a single function or variable alias in the IR.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_GLOBALALIAS_H
#define LLVM_IR_GLOBALALIAS_H

#include "llvh/ADT/ilist_node.h"
#include "llvh/IR/GlobalIndirectSymbol.h"
#include "llvh/IR/Value.h"

namespace llvh {

class Twine;
class Module;
template <typename ValueSubClass> class SymbolTableListTraits;

class GlobalAlias : public GlobalIndirectSymbol,
                    public ilist_node<GlobalAlias> {
  friend class SymbolTableListTraits<GlobalAlias>;

  GlobalAlias(Type *Ty, unsigned AddressSpace, LinkageTypes Linkage,
              const Twine &Name, Constant *Aliasee, Module *Parent);

public:
  GlobalAlias(const GlobalAlias &) = delete;
  GlobalAlias &operator=(const GlobalAlias &) = delete;

                                                                               
                                                   
  static GlobalAlias *create(Type *Ty, unsigned AddressSpace,
                             LinkageTypes Linkage, const Twine &Name,
                             Constant *Aliasee, Module *Parent);

                         
  static GlobalAlias *create(Type *Ty, unsigned AddressSpace,
                             LinkageTypes Linkage, const Twine &Name,
                             Module *Parent);

                                          
  static GlobalAlias *create(Type *Ty, unsigned AddressSpace,
                             LinkageTypes Linkage, const Twine &Name,
                             GlobalValue *Aliasee);

                                                          
  static GlobalAlias *create(LinkageTypes Linkage, const Twine &Name,
                             GlobalValue *Aliasee);

                                                                   
  static GlobalAlias *create(const Twine &Name, GlobalValue *Aliasee);

  void copyAttributesFrom(const GlobalValue *Src) {
    GlobalValue::copyAttributesFrom(Src);
  }

                                                                               
                             
     
  void removeFromParent();

                                                                             
                     
     
  void eraseFromParent();

                                                  
  void setAliasee(Constant *Aliasee);
  const Constant *getAliasee() const {
    return getIndirectSymbol();
  }
  Constant *getAliasee() {
    return getIndirectSymbol();
  }

  static bool isValidLinkage(LinkageTypes L) {
    return isExternalLinkage(L) || isLocalLinkage(L) ||
      isWeakLinkage(L) || isLinkOnceLinkage(L);
  }

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == Value::GlobalAliasVal;
  }
};

}                      

#endif                         
