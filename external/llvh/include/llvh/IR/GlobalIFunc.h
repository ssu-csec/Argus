//===-------- llvm/GlobalIFunc.h - GlobalIFunc class ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \brief
/// This file contains the declaration of the GlobalIFunc class, which
/// represents a single indirect function in the IR. Indirect function uses
/// ELF symbol type extension to mark that the address of a declaration should
/// be resolved at runtime by calling a resolver function.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_GLOBALIFUNC_H
#define LLVM_IR_GLOBALIFUNC_H

#include "llvh/ADT/ilist_node.h"
#include "llvh/IR/GlobalIndirectSymbol.h"
#include "llvh/IR/Value.h"

namespace llvh {

class Twine;
class Module;

                                                                
template <typename ValueSubClass> class SymbolTableListTraits;

class GlobalIFunc final : public GlobalIndirectSymbol,
                          public ilist_node<GlobalIFunc> {
  friend class SymbolTableListTraits<GlobalIFunc>;

  GlobalIFunc(Type *Ty, unsigned AddressSpace, LinkageTypes Linkage,
              const Twine &Name, Constant *Resolver, Module *Parent);

public:
  GlobalIFunc(const GlobalIFunc &) = delete;
  GlobalIFunc &operator=(const GlobalIFunc &) = delete;

                                                                               
                                                   
  static GlobalIFunc *create(Type *Ty, unsigned AddressSpace,
                             LinkageTypes Linkage, const Twine &Name,
                             Constant *Resolver, Module *Parent);

  void copyAttributesFrom(const GlobalIFunc *Src) {
    GlobalValue::copyAttributesFrom(Src);
  }

                                                                         
                
  void removeFromParent();

                                                                           
  void eraseFromParent();

                                                             
  void setResolver(Constant *Resolver) {
    setIndirectSymbol(Resolver);
  }
  const Constant *getResolver() const {
    return getIndirectSymbol();
  }
  Constant *getResolver() {
    return getIndirectSymbol();
  }

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == Value::GlobalIFuncVal;
  }
};

}                      

#endif                         
