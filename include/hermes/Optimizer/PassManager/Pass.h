/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_PASSMANAGER_PASS_H
#define HERMES_OPTIMIZER_PASSMANAGER_PASS_H

#include "llvh/ADT/StringRef.h"

#include <memory>

namespace hermes {

class Function;
class Module;
class Instruction;
class IRBuilder;

                                                                             
                                                                         
                                                                        
                                                                        
                       
class Pass {
 public:
  enum class PassKind {
    Function,
    Module,
  };

 private:
                                       
  const PassKind kind;
                                   
  llvh::StringRef name;

 public:
                                                           
  explicit Pass(Pass::PassKind K, llvh::StringRef name) : kind(K), name(name) {}

  virtual ~Pass() = default;

                                   
  PassKind getKind() const {
    return kind;
  }

                                           
  llvh::StringRef getName() const {
    return name;
  }
};

class FunctionPass : public Pass {
 public:
  explicit FunctionPass(llvh::StringRef name)
      : Pass(Pass::PassKind::Function, name) {}
  ~FunctionPass() override = default;

                                                 
                                                 
  virtual bool runOnFunction(Function *F) = 0;

  static bool classof(const Pass *S) {
    return S->getKind() == PassKind::Function;
  }
};

class ModulePass : public Pass {
 public:
  explicit ModulePass(llvh::StringRef name)
      : Pass(Pass::PassKind::Module, name) {}
  ~ModulePass() override = default;

                                               
                                           
  virtual bool runOnModule(Module *M) = 0;

  static bool classof(const Pass *S) {
    return S->getKind() == PassKind::Module;
  }
};

                            
#define PASS(ID, NAME, DESCRIPTION) std::unique_ptr<Pass> create##ID();
#include "Passes.def"

}                    

#endif                                       
