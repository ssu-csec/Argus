/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_TERM_H
#define HERMES_OPTIMIZER_SCALAR_TERM_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"
#include "llvh/ADT/DenseSet.h"

using llvh::isa;

namespace hermes {

enum TermKind {
  NormalTermKind,                                
  LambdaTermKind,             
  CallTermKind,              
  EscapeTermKind,                                                              
                                                  
  ObjectTermKind,           
  LoadPropertyTermKind,                                                         
                                 
  StoreOwnPropertyTermKind,                      
  StorePropertyTermKind,                  
  PropertyTermKind,                        
  ArrayTermKind,          
  ModuleTermKind           
};

                                                                          
                                                                              
                                                                            
                                                                             
                                                                             
                                           
                                                                        
class Term {
 public:
  Term(Value *v, unsigned id) : value_id_(id), value_(v) {}

  virtual ~Term() = default;

                                                        
  unsigned value_id_{0};

                                     
  Value *value_{nullptr};

                                          
  TermKind kind_{TermKind::NormalTermKind};
  static bool classof(const Term *) {
    return true;
  }

                                                   
  llvh::DenseSet<Term *> ins_;

                                                     
  llvh::DenseSet<Term *> outs_;
#ifndef NDEBUG
  virtual std::string getPrintStr() = 0;
#endif
};

                                                                
class NormalTerm : public Term {
 public:
  NormalTerm(Value *v, unsigned id) : Term(v, id) {
    kind_ = TermKind::NormalTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    Value *v = (Value *)value_;
    switch (v->getKind()) {
      case ValueKind::VariableKind: {
        Variable *Var = cast<Variable>(v);
        VariableScope *VS = Var->getParent();
        std::string part1("Var(");
        std::string part2(Var->getName().c_str());
        std::string part3("):");
        std::string part4(VS->getFunction()->getInternalName().c_str());
        return part1 + part2 + part3 + part4;
      }
      case ValueKind::FunctionKind: {
        Function *F = cast<Function>(v);
        return F->getInternalName().c_str();
      }
      case ValueKind::ParameterKind: {
        Parameter *P = cast<Parameter>(v);
        std::string part1("Param(");
        std::string part2(P->getName().c_str());
        std::string part3("):");
        std::string part4(P->getParent()->getInternalName().c_str());
        return part1 + part2 + part3 + part4;
      }
      case ValueKind::CreateFunctionInstKind: {
        CreateFunctionInst *I = cast<CreateFunctionInst>(v);
        return I->getName();
      }
      default: {
        return v->getKindStr();
      }
    }
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::NormalTermKind;
  }
};

                                                         
class LambdaTerm : public Term {
 public:
  LambdaTerm(Function *f, unsigned id) : Term(f, id) {
    kind_ = TermKind::LambdaTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    Function *f = (Function *)value_;

    std::string part1("FUN(");
    std::string part2(f->getInternalName().c_str());
    std::string part3(")");

    std::string result = part1 + part2 + part3;
    return result;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::LambdaTermKind;
  }
};

                                                         
class CallTerm : public Term {
 public:
  CallTerm(CallInst *c, unsigned id) : Term(c, id) {
    kind_ = TermKind::CallTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    CallInst *c = (CallInst *)value_;
    std::string part1("CALL(");
    std::string part2(c->getKindStr());
    std::string part3(")");
    std::string result = part1 + part2 + part3;
    return result;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::CallTermKind;
  }
};

                                                          
                                                         
                                                             
                                                
class EscapeTerm : public Term {
 public:
  EscapeTerm(Value *v, unsigned id) : Term(v, id) {
    kind_ = TermKind::EscapeTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    Value *via = (Value *)value_;
    if (!via)
      return "Unknown";
    std::string part1("Unknown(");
    std::string part2(via->getKindStr());
    std::string part3(")");
    std::string result = part1 + part2 + part3;
    return result;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::EscapeTermKind;
  }
};

                                                                  
                                                                     
                                                                        
class ObjectTerm : public Term {
 public:
                                                            
  llvh::DenseSet<Literal *> owns_;

                                                                    
                                                  
  ObjectTerm(Instruction *ai, llvh::DenseSet<Literal *> &owns, unsigned id)
      : Term(ai, id), owns_(owns) {
    kind_ = TermKind::ObjectTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    std::string part1("Object(");
    std::string part2(value_->getKindStr());
    std::string part3(")");
    std::string result = part1 + part2 + part3;
    return result;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::ObjectTermKind;
  }
};

class ArrayTerm : public Term {
 public:
  ArrayTerm(AllocArrayInst *ai, unsigned id) : Term(ai, id) {
    kind_ = TermKind::ArrayTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    std::string part1("Array(");
    std::string part2(value_->getKindStr());
    std::string part3(")");
    std::string result = part1 + part2 + part3;
    return result;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::ArrayTermKind;
  }
};

class LoadPropertyTerm : public Term {
 public:
  Value *prop_;

  LoadPropertyTerm(LoadPropertyInst *li, Value *prop, unsigned id)
      : Term(li, id), prop_(prop) {
    kind_ = TermKind::LoadPropertyTermKind;
  }

#ifndef NDEBUG
  std::string getPrintStr() {
    std::string part1("Load(");
    StringRef printProp;
    if (llvh::isa<LiteralString>(prop_))
      printProp = ((LiteralString *)prop_)->getValue().str();
    else
      printProp = prop_->getKindStr();
    std::string part2(printProp);
    std::string part3(", ");
    std::string part4(value_->getKindStr());
    std::string part5(")");
    return part1 + part2 + part3 + part4 + part5;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::LoadPropertyTermKind;
  }
};

class StoreOwnPropertyTerm : public Term {
 public:
  Value *prop_;
  StoreOwnPropertyTerm(StoreOwnPropertyInst *si, Value *prop, unsigned id)
      : Term(si, id), prop_(prop) {
    kind_ = TermKind::StoreOwnPropertyTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    std::string part1("StoreOwn(");
    StringRef printProp;
    if (llvh::isa<LiteralString>(prop_))
      printProp = ((LiteralString *)prop_)->getValue().str();
    else
      printProp = prop_->getKindStr();
    std::string part2(printProp);
    std::string part3(", ");
    std::string part4(value_->getKindStr());
    std::string part5(")");
    return part1 + part2 + part3 + part4 + part5;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::StoreOwnPropertyTermKind;
  }
};

class StorePropertyTerm : public Term {
 public:
  Value *prop_;
  StorePropertyTerm(StorePropertyInst *si, Value *prop, unsigned id)
      : Term(si, id), prop_(prop) {
    kind_ = TermKind::StorePropertyTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    std::string part1("Store(");
    StringRef tmp;
    if (llvh::isa<LiteralString>(prop_))
      tmp = ((LiteralString *)prop_)->getValue().str();
    else
      tmp = prop_->getKindStr();
    std::string part2(tmp);
    std::string part3(", ");
    std::string part4(value_->getKindStr());
    std::string part5(")");
    return part1 + part2 + part3 + part4 + part5;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::StorePropertyTermKind;
  }
};

class PropertyTerm : public Term {
 public:
  Value *prop_;
  Value *obj_;                    

  PropertyTerm(Value *v, Value *prop, Value *obj, unsigned id)
      : Term(v, id), prop_(prop), obj_(obj) {
    kind_ = TermKind::PropertyTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    std::string part1("Prop(");
    StringRef tmp;
    if (llvh::isa<LiteralString>(prop_))
      tmp = ((LiteralString *)prop_)->getValue().str();
    else
      tmp = prop_->getKindStr();
    std::string part2(tmp);
    std::string part3(", ");
    std::string part4(value_->getKindStr());
    std::string part5(")");
    return part1 + part2 + part3 + part4 + part5;
  }
#endif
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::PropertyTermKind;
  }
};

class ModuleTerm : public Term {
  unsigned int modId_;

 public:
  ModuleTerm(Value *v, unsigned int modId, unsigned id)
      : Term(v, id), modId_(modId) {
    kind_ = TermKind::ModuleTermKind;
  }
#ifndef NDEBUG
  std::string getPrintStr() {
    std::string part1("Module(");
    std::string part2 = std::to_string(modId_);
    std::string part3(")");
    return part1 + part2 + part3;
  }
#else
  std::string getPrintStr() {
    return std::to_string(modId_);
  }
#endif
  static bool classof(const ModuleTerm *) {
    return true;
  }
  static bool classof(const Term *t) {
    return t->kind_ == TermKind::ModuleTermKind;
  }
};
}                    

#endif                                  
