/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_UTILS_DUMPER_H
#define HERMES_UTILS_DUMPER_H

#include <map>

#include "hermes/IR/IRVisitor.h"
#include "llvh/ADT/StringRef.h"

namespace llvh {
class raw_ostream;
}                  

namespace hermes {
class Value;
class Argument;
class Instruction;
class BasicBlock;
class Function;
class Module;

class CondBranchInst;
class AllocaInst;
class ReturnInst;
class Parameter;
class BranchInst;

                                                         
void viewGraph(Function *F);

                                                                         
                                 
struct InstructionNamer {
  InstructionNamer() = default;
  std::map<Value *, unsigned> InstrMap;
  unsigned Counter{0};
  void clear();
  unsigned getNumber(Value *);
};

using llvh::raw_ostream;

struct IRPrinter : public IRVisitor<IRPrinter, void> {
                        
  unsigned Indent;

  SourceErrorManager &sm_;
                    
  llvh::raw_ostream &os;
                                                                                
                                                    
  bool needEscape;

  InstructionNamer InstNamer;
  InstructionNamer BBNamer;
  InstructionNamer ScopeNamer;

  explicit IRPrinter(Context &ctx, llvh::raw_ostream &ost, bool escape = false)
      : Indent(0),
        sm_(ctx.getSourceErrorManager()),
        os(ost),
        needEscape(escape) {}

  virtual ~IRPrinter() = default;

  virtual void printFunctionHeader(Function *F);
  virtual void printFunctionVariables(Function *F);
  virtual void printValueLabel(Instruction *I, Value *V, unsigned opIndex);
  virtual void printTypeLabel(Type T);
  virtual void printInstruction(Instruction *I);
  virtual void printInstructionDestination(Instruction *I);
  virtual void printSourceLocation(SMLoc loc);
  virtual void printSourceLocation(SMRange rng);

  void printScopeLabel(ScopeDesc *S);
  void printScope(ScopeDesc *S);
  void printScopeRange(ScopeDesc *Start, ScopeDesc *End);
  void printScopeChain(ScopeDesc *S);

                                                 
     
                             
     
                                                                                
                                                                              
                                                                       
  enum class PrintFunctionParams { No, Yes };
  void printFunctionName(Function *F, PrintFunctionParams printFunctionParams);
  void printVariableName(Variable *V);

  std::string getQuoteSign() {
    return needEscape ? R"(\")" : R"(")";
  }

                                        
  std::string quoteStr(llvh::StringRef name);

                                                            
  std::string escapeStr(llvh::StringRef name);

                                                        
  void visitInstruction(const Instruction &I);
  void visitBasicBlock(const BasicBlock &BB);
  void visitFunction(const Function &F);
  void visitScope(const ScopeDesc &S);
  void visitModule(const Module &M);
};

}                    

#endif
