/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <string>

#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/GraphWriter.h"
#include "llvh/Support/raw_ostream.h"

#include "hermes/AST/Context.h"
#include "hermes/FrontEndDefs/Builtins.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRVisitor.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Wasm/WasmIntrinsics.h"
#include "hermes/Support/Statistic.h"
#include "hermes/Utils/Dumper.h"

using namespace hermes;

using llvh::dyn_cast;
using llvh::isa;

namespace hermes {

std::string IRPrinter::escapeStr(llvh::StringRef name) {
  std::string s = name.str();
  std::string out;
  out += getQuoteSign();
  for (std::string::const_iterator i = s.begin(); i != s.end(); ++i) {
    unsigned char c = *i;
    if (std::isprint(c) && c != '\\' && c != '"') {
      out += c;
    } else {
      out += "\\\\";
      switch (c) {
        case '"':
          out += "\\\"";
          break;
        case '\\':
          out += "\\\\";
          break;
        case '\t':
          out += 't';
          break;
        case '\r':
          out += 'r';
          break;
        case '\n':
          out += 'n';
          break;
        default:
          char const *const hexdig = "0123456789ABCDEF";
          out += 'x';
          out += hexdig[c >> 4];
          out += hexdig[c & 0xF];
      }
    }
  }
  out += getQuoteSign();
  return out;
}

std::string IRPrinter::quoteStr(llvh::StringRef name) {
  if (name.count(" ") || name.empty()) {
    return getQuoteSign() + name.str() + getQuoteSign();
  }
  return name.str();
}

void InstructionNamer::clear() {
  Counter = 0;
  InstrMap.clear();
}
unsigned InstructionNamer::getNumber(Value *T) {
  auto It = InstrMap.find(T);
  if (It != InstrMap.end()) {
    return It->second;
  }
  InstrMap[T] = Counter;
  return Counter++;
}

void IRPrinter::printTypeLabel(Type T) {
                                                       
  if (T.isAnyType())
    return;
  os << " : " << T;
}

void IRPrinter::printValueLabel(Instruction *I, Value *V, unsigned opIndex) {
  auto &ctx = I->getContext();
  if (isa<CallBuiltinInst>(I) && opIndex == CallInst::CalleeIdx) {
    os << "["
       << getBuiltinMethodName(cast<CallBuiltinInst>(I)->getBuiltinIndex())
       << "]";
#ifdef HERMES_RUN_WASM
  } else if (isa<CallIntrinsicInst>(I) && opIndex == 0) {
    os << "["
       << getWasmIntrinsicsName(
              cast<CallIntrinsicInst>(I)->getIntrinsicsIndex())
       << "]";
#endif
  } else if (isa<GetBuiltinClosureInst>(I) && opIndex == 0) {
    os << "["
       << getBuiltinMethodName(
              cast<GetBuiltinClosureInst>(I)->getBuiltinIndex())
       << "]";
  } else if (auto LBI = dyn_cast<LiteralBigInt>(V)) {
    os << LBI->getValue()->str();
  } else if (auto LS = dyn_cast<LiteralString>(V)) {
    os << escapeStr(ctx.toString(LS->getValue()));
  } else if (auto LB = dyn_cast<LiteralBool>(V)) {
    os << (LB->getValue() ? "true" : "false");
  } else if (auto LN = dyn_cast<LiteralNumber>(V)) {
    const auto Num = LN->getValue();
    if (Num == 0 && std::signbit(Num)) {
                                      
      os << "-0";
    } else {
      char buf[NUMBER_TO_STRING_BUF_SIZE];
      numberToString(LN->getValue(), buf, sizeof(buf));
      os << buf;
    }
  } else if (isa<LiteralEmpty>(V)) {
    os << "empty";
  } else if (isa<LiteralNull>(V)) {
    os << "null";
  } else if (isa<LiteralUndefined>(V)) {
    os << "undefined";
  } else if (isa<GlobalObject>(V)) {
    os << "globalObject";
  } else if (isa<EmptySentinel>(V)) {
    os << "empty";
  } else if (isa<Instruction>(V)) {
    os << "%" << InstNamer.getNumber(V);
  } else if (isa<BasicBlock>(V)) {
    os << "%BB" << BBNamer.getNumber(V);
  } else if (auto L = dyn_cast<Label>(V)) {
    auto Name = L->get();
    os << "$" << quoteStr(ctx.toString(Name));
  } else if (auto P = dyn_cast<Parameter>(V)) {
    auto Name = P->getName();
    os << "%" << ctx.toString(Name);
  } else if (auto F = dyn_cast<Function>(V)) {
    os << "%";
    printFunctionName(F, PrintFunctionParams::No);
  } else if (auto S = dyn_cast<ScopeDesc>(V)) {
    os << "%";
    printScopeLabel(S);
  } else if (auto VR = dyn_cast<Variable>(V)) {
    os << "[";
    printVariableName(VR);
    if (I->getParent()->getParent() != VR->getParent()->getFunction()) {
      llvh::StringRef scopeName =
          VR->getParent()->getFunction()->getInternalNameStr();
      os << "@" << quoteStr(scopeName);
    }
    os << "]";
  } else {
    llvm_unreachable("Invalid value");
  }

  printTypeLabel(V->getType());
}

void IRPrinter::printFunctionHeader(Function *F) {
  std::string defKindStr = F->getDefinitionKindStr(false);

  os << defKindStr << " ";
  printFunctionName(F, PrintFunctionParams::Yes);
  printTypeLabel(F->getType());
}

void IRPrinter::printFunctionVariables(Function *F) {
  bool hasGlobals = false;
  if (F->isGlobalScope()) {
    auto &Ctx = F->getContext();
    bool first2 = true;
    for (auto *GP : F->getParent()->getGlobalProperties()) {
      if (!GP->isDeclared())
        continue;
      if (first2) {
        hasGlobals = true;
        os << "globals = [";
      } else {
        os << ", ";
      }
      os << Ctx.toString(GP->getName()->getValue());
      first2 = false;
    }
    if (!first2)
      os << "]";
  }

  bool printNewLine = hasGlobals;
  F->forEachScope([&](ScopeDesc *S) {
    if (printNewLine) {
      os << "\n";
    }
    printNewLine = true;
    printScopeLabel(S);
    os << " = [";
    bool first = true;
    for (auto V : S->getVariables()) {
      if (!first) {
        os << ", ";
      }
      printVariableName(V);
      printTypeLabel(V->getType());
      first = false;
    }
    os << "]";
  });
}

void IRPrinter::printInstructionDestination(Instruction *I) {
  os << "%" << InstNamer.getNumber(I);
}

void IRPrinter::printInstruction(Instruction *I) {
  printInstructionDestination(I);
  os << " = ";
  os << I->getName();

  bool first = true;

  if (auto *binop = dyn_cast<BinaryOperatorInst>(I)) {
    os << " '" << binop->getOperatorStr() << "'";
    first = false;
  } else if (auto *cmpbr = dyn_cast<CompareBranchInst>(I)) {
    os << " '" << cmpbr->getOperatorStr() << "'";
    first = false;
  } else if (auto *unop = dyn_cast<UnaryOperatorInst>(I)) {
    os << " '" << unop->getOperatorStr() << "'";
    first = false;
  }

  for (int i = 0, e = I->getNumOperands(); i < e; i++) {
    Value *O = I->getOperand(i);
    os << (first ? " " : ", ");
    printValueLabel(I, O, i);
    first = false;
  }

  auto codeGenOpts = I->getContext().getCodeGenerationSettings();
  const char *prefix = " // ";

  if (codeGenOpts.dumpTextifiedCallee) {
    auto &ctx = I->getParent()->getParent()->getContext();
    if (auto call = llvh::dyn_cast<CallInst>(I)) {
      if (LiteralString *textifiedCallee = call->getTextifiedCallee()) {
        os << prefix << "textified callee: "
           << escapeStr(ctx.toString(textifiedCallee->getValue()));
        prefix = ", ";
      }
    }
  }
  if (codeGenOpts.dumpSourceLevelScope) {
    if (auto *originalScope = I->getSourceLevelScope()) {
      os << prefix << "scope: ";
      printScopeLabel(originalScope);
      prefix = ", ";
    }
  }

                                                                 
  if (!codeGenOpts.dumpUseList || I->getUsers().empty())
    return;

  llvh::DenseSet<Instruction *> Visited;
  os << prefix << "users:";
  for (auto &U : I->getUsers()) {
    auto *II = cast<Instruction>(U);
    assert(II && "Expecting user to be an Instruction");
    if (Visited.find(II) != Visited.end())
      continue;
    Visited.insert(II);
    os << " %" << InstNamer.getNumber(II);
  }
}

void IRPrinter::printSourceLocation(SMLoc loc) {
  SourceErrorManager::SourceCoords coords;
  if (!sm_.findBufferLineAndLoc(loc, coords))
    return;

  os << sm_.getSourceUrl(coords.bufId) << ":" << coords.line << ":"
     << coords.col;
}

void IRPrinter::printSourceLocation(SMRange rng) {
  SourceErrorManager::SourceCoords start, end;
  if (!sm_.findBufferLineAndLoc(rng.Start, start) ||
      !sm_.findBufferLineAndLoc(rng.End, end))
    return;

  os << "[" << sm_.getSourceUrl(start.bufId) << ":" << start.line << ":"
     << start.col << " ... " << sm_.getSourceUrl(end.bufId) << ":" << end.line
     << ":" << end.col << ")";
}

void IRPrinter::printScopeLabel(ScopeDesc *S) {
  os << "S{";
  printFunctionName(S->getFunction(), PrintFunctionParams::No);
  printScopeRange(S, S->getFunction()->getFunctionScopeDesc());
  os << "}";
}

void IRPrinter::printScope(ScopeDesc *S) {
  os << "#" << ScopeNamer.getNumber(S);
}

void IRPrinter::printScopeRange(ScopeDesc *Start, ScopeDesc *End) {
  if (Start != End) {
    printScopeRange(Start->getParent(), End);
    printScope(Start);
  }
}

void IRPrinter::printScopeChain(ScopeDesc *S) {
  if (S && S->getParent()) {
    printScope(S->getParent());
  }
  printScope(S);
}

void IRPrinter::printFunctionName(
    Function *F,
    PrintFunctionParams printFunctionParams) {
  auto &ctx = F->getContext();
  os << quoteStr(ctx.toString(F->getInternalName()));
  printScopeChain(F->getFunctionScopeDesc()->getParent());
  os << "(";
  if (printFunctionParams != PrintFunctionParams::No) {
    bool first = true;
    for (auto P : F->getParameters()) {
      if (!first) {
        os << ", ";
      }
      os << ctx.toString(P->getName());
      printTypeLabel(P->getType());
      first = false;
    }
  }
  os << ")";
  printScope(F->getFunctionScopeDesc());
}

void IRPrinter::printVariableName(Variable *V) {
  ScopeDesc *VS = V->getParent();
  auto &ctx = VS->getFunction()->getContext();
  os << ctx.toString(V->getName());
  printScope(VS);
}

void IRPrinter::visitModule(const Module &M) {
  ScopeNamer.clear();
  visitScope(*M.getInitialScope());

                                                
  auto begin=std::chrono::steady_clock::now();
  unsigned long long functions=0;
  const char *metricsPath=std::getenv("ARGUS_IR_METRICS");
  auto report=[&](const char *phase) {
    if (!metricsPath || !*metricsPath) return;
    if (FILE *f=std::fopen(metricsPath,"w")) {
      std::fprintf(f,"{\"phase\":\"%s\",\"functions\":%llu,\"elapsed_ns\":%lld}\n",phase,functions,
        (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-begin).count());
      std::fclose(f);
    }
  };
  report("START");
  for (auto &F : M) {
    visit(F); ++functions;
    if ((functions & 127)==0) report("PRINTING");
  }
  report("COMPLETE");
}

void IRPrinter::visitScope(const ScopeDesc &S) {
  ScopeNamer.getNumber(const_cast<ScopeDesc *>(&S));
  for (ScopeDesc *inner : S.getInnerScopes()) {
    visitScope(*inner);
  }
}

void IRPrinter::visitFunction(const Function &F) {
  auto *UF = const_cast<Function *>(&F);
  os.indent(Indent);
  BBNamer.clear();
  InstNamer.clear();
                                          
  for (auto &BB : *UF)
    for (auto &I : BB) {
      InstNamer.getNumber(&I);
    }

  printFunctionHeader(UF);
  os << "\n";
  printFunctionVariables(UF);
  os << "\n";

  auto codeGenOpts = F.getContext().getCodeGenerationSettings();
  if (codeGenOpts.dumpSourceLocation) {
    os << "source location: ";
    printSourceLocation(F.getSourceRange());
    os << "\n";
  }

                                                      
  for (auto &BB : F) {
    visit(BB);
  }

  os.indent(Indent);
  os << "function_end" << "\n";
  os << "\n";
}

void IRPrinter::visitBasicBlock(const BasicBlock &BB) {
  auto *UBB = const_cast<BasicBlock *>(&BB);
  os.indent(Indent);
  os << "%BB" << BBNamer.getNumber(UBB) << ":\n";
  Indent += 2;

                                                      
  for (auto &I : BB) {
    visit(I);
  }

  Indent -= 2;
}

void IRPrinter::visitInstruction(const Instruction &I) {
  auto *UII = const_cast<Instruction *>(&I);
  auto codeGenOpts = I.getContext().getCodeGenerationSettings();
  if (codeGenOpts.dumpSourceLocation) {
    os << "; ";
    printSourceLocation(UII->getLocation());
    os << "\n";
  }
  os.indent(Indent);
  printInstruction(UII);
  os << "\n";
}

}                    

namespace {

                                                                           
                                                                             
struct DottyPrinter : public IRVisitor<DottyPrinter, void> {
  llvh::raw_ostream &os;
  llvh::SmallVector<std::pair<std::string, std::string>, 4> Edges;
  IRPrinter Printer;

  explicit DottyPrinter(
      Context &ctx,
      llvh::raw_ostream &ost,
      llvh::StringRef Title)
      : os(ost), Printer(ctx, ost,                     true) {
    os << " digraph g {\n graph [ rankdir = \"TD\" ];\n";
    os << "labelloc=\"t\"; ";
    os << " node [ fontsize = \"16\" shape = \"record\" ]; edge [ ];\n";
  }

  ~DottyPrinter() {
    os << "\n";

                                          
    for (auto T : Edges) {
      os << "" << T.first << " ->";
      os << "" << T.second << ";\n";
    }
    os << "\n}\n";
  }

                                               
  static std::string toString(BasicBlock *ptr) {
    auto Num = (size_t)ptr;
    return std::to_string(Num);
  }

                                                 
  void visitFunction(const Function &F) {
    os << "label=\"";
    Printer.printFunctionHeader(const_cast<Function *>(&F));
    os << "\";\n";

                                                                    
                                                                          
                                                                           
                                                           
    for (auto &BB : F) {
      for (auto &II : BB) {
        (void)Printer.InstNamer.getNumber(const_cast<Instruction *>(&II));
      }
    }

                                                        
    for (auto &BB : F) {
      visit(BB);
    }
  }

                                                       
                                                                             
                                                                            
                                                
  void visitBasicBlock(const BasicBlock &V) {
    auto *BB = const_cast<BasicBlock *>(&V);
    os << "\"" << toString(BB) << "\"";
    os << "[ label = \"{ ";

    os << " { <self> | <head> \\<\\<%BB" << Printer.BBNamer.getNumber(BB)
       << "\\>\\> | } ";

    int counter = 0;

                                               
    for (auto &I : *BB) {
      counter++;
      os << " | ";

                               
      os << "<L" << counter << ">";
      Printer.printInstruction(&I);
    }

    for (auto I = succ_begin(BB), E = succ_end(BB); I != E; ++I) {
      auto From = toString(BB) + ":L" + std::to_string(counter);
      Edges.push_back({From, toString(*I) + (*I == BB ? ":self" : ":head")});
    }

                       
    os << "}\" shape = \"record\" ]; \n";
  }
};

}                       

void hermes::viewGraph(Function *F) {
#ifndef NDEBUG
  auto &Ctx = F->getContext();
  llvh::StringRef Name = Ctx.toString(F->getInternalName());
  int FD;
                                                                             
  std::string N = Name.str();
  N = N.substr(0, std::min<std::size_t>(N.size(), 140));
  std::string Filename = llvh::createGraphFilename(N, FD);
  {
    llvh::raw_fd_ostream O(FD,                 true);

    if (FD == -1) {
      llvh::errs() << "error opening file '" << Filename << "' for writing!\n";
      return;
    }

    DottyPrinter D(F->getContext(), O, Name);
    D.visitFunction(*F);
  }

  llvh::DisplayGraph(Filename);
  llvh::errs() << " done. \n";
#endif
}
