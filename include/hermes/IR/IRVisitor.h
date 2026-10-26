/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IR_IRVISITOR_H
#define HERMES_IR_IRVISITOR_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"

#define INCLUDE_ALL_INSTRS

namespace hermes {

                                                                                
                                                                      
template <typename ImplClass, typename ValueRetTy = void>
class IRVisitorBase {
 public:
  ImplClass &asImpl() {
    return static_cast<ImplClass &>(*this);
  }

                        
  ValueRetTy visitValue(const Value &V) {
    return ValueRetTy();
  }

                                                                
                                                      
#define DEF_VALUE(CLASS, PARENT)            \
  ValueRetTy visit##CLASS(const CLASS &I) { \
    return asImpl().visit##PARENT(I);       \
  }
#include "hermes/IR/ValueKinds.def"
};

                                                                   
                                                                    
template <typename ImplClass, typename ValueRetTy = void>
class IRVisitor : public IRVisitorBase<ImplClass, ValueRetTy> {
 public:
  ImplClass &asImpl() {
    return static_cast<ImplClass &>(*this);
  }

                     
  ValueRetTy visit(const Value &V) {
    switch (V.getKind()) {
      default:
        llvm_unreachable("Invalid kind");
#define DEF_VALUE(CLASS, PARENT) \
  case ValueKind::CLASS##Kind:   \
    return asImpl().visit##CLASS(*llvh::cast<CLASS>(&V));
#include "hermes/IR/ValueKinds.def"
    }
    llvm_unreachable("Not reachable, all cases handled");
  }
};

                                                                             
                                                                         
template <typename ImplClass, typename ValueRetTy = void>
class InstructionVisitor : public IRVisitorBase<ImplClass, ValueRetTy> {
 public:
  ImplClass &asImpl() {
    return static_cast<ImplClass &>(*this);
  }

                                                         
                                                           
                          
  void beforeVisitInstruction(const Instruction &V) {}

                        
  ValueRetTy visit(const Instruction &Inst) {
    asImpl().beforeVisitInstruction(Inst);

    switch (Inst.getKind()) {
      default:
        llvm_unreachable("Invalid kind");
#define DEF_VALUE(CLASS, PARENT) \
  case ValueKind::CLASS##Kind:   \
    return asImpl().visit##CLASS(*llvh::cast<CLASS>(&Inst));
#include "hermes/IR/Instrs.def"
    }
    llvm_unreachable("Not reachable, all cases handled");
  }
};

}                        

#undef INCLUDE_ALL_INSTRS
#endif
