/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "taintanalysis"
#include "hermes/Optimizer/Taint/TaintAnalysis.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"

using namespace hermes;
using llvh::dbgs;
using llvh::outs;

//===----------------------------------------------------------------------===//
// TaintAnalysis Implementation
//===----------------------------------------------------------------------===//

bool TaintAnalysis::runOnModule(Module *M) {
  outs() << "\n";
  outs() << "========================================\n";
  outs() << "=== Taint Analysis for Hermes IR\n";
  outs() << "========================================\n\n";
  
  // Continue with normal processing

  // Step 1: Analyze closures across the module
  outs() << "[Phase 1] Analyzing closures...\n";
  closureAnalyzer_.analyzeModuleClosures(M);
  outs() << "  Closure analysis complete.\n\n";

  // Step 2: Identify all source instructions
  outs() << "[Phase 2] Identifying taint sources...\n";
  auto sources = identifySources(M);
  outs() << "  Found " << sources.size() << " source(s).\n\n";

  // Step 3: Identify all sink instructions  
  outs() << "[Phase 3] Identifying taint sinks...\n";
  
  // Continue with sink identification
  
  auto sinks = identifySinks(M);
  outs() << "  Found " << sinks.size() << " sink(s).\n\n";

  // Step 4: Analyze function calls for inter-procedural flows
  outs() << "[Phase 4] Analyzing function calls...\n";
  analyzeFunctionCalls(M);
  outs() << "  Function call analysis complete.\n\n";

  // Step 5: Add inter-procedural taint edges
  outs() << "[Phase 5] Creating inter-procedural taint links...\n";
  // TODO: Implement inter-procedural analysis  
  outs() << "  Inter-procedural links created.\n\n";

  // Step 5: Analyze taint flow from sources to sinks
  outs() << "[Phase 5] Analyzing taint propagation...\n";
  analyzeTaintFlow(sources, sinks);
  outs() << "  Taint flow analysis complete.\n\n";

  // Step 6: Report vulnerabilities
  outs() << "[Phase 6] Generating vulnerability report...\n";
  reportVulnerabilities();

  outs() << "\n========================================\n";
  outs() << "=== Taint Analysis Complete\n";
  outs() << "========================================\n\n";

  // This pass does not modify IR
  return false;
}

llvh::SmallVector<Instruction *, 32> TaintAnalysis::identifySources(
    Module *M) {
  llvh::SmallVector<Instruction *, 32> sources;

  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        std::string sourceAPI;
        if (isSourceInstruction(&I, sourceAPI)) {
          sources.push_back(&I);
          LLVM_DEBUG(dbgs() << "  Source: " << sourceAPI << " at "
                            << I.getKindStr() << "\n");
        }
      }
    }
  }

  return sources;
}

llvh::SmallVector<Instruction *, 32> TaintAnalysis::identifySinks(Module *M) {
  llvh::SmallVector<Instruction *, 32> sinks;

  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        std::string sinkAPI;
        SinkType sinkType;
        if (isSinkInstruction(&I, sinkAPI, sinkType)) {
          sinks.push_back(&I);
        }
      }
    }
  }

  return sinks;
}

bool TaintAnalysis::isSourceInstruction(
    Instruction *I,
    std::string &sourceAPI) {
  // Check LoadPropertyInst (e.g., navigator.userAgent)
  if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(I)) {
    if (sourceRegistry_.isSourceProperty(LPI)) {
      // TODO: Improve object tracking to get full API name
      if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        sourceAPI = litProp->getValue().str().str();
        return true;
      }
    }
  }

  // Check CallInst (e.g., Date.now(), fetch())
  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
    if (sourceRegistry_.isSourceCall(CI)) {
      // TODO: Extract method name
      sourceAPI = "<method_call>";
      return true;
    }
  }

  // Check ConstructInst (e.g., new Date())
  if (auto *CI = llvh::dyn_cast<ConstructInst>(I)) {
    if (sourceRegistry_.isSourceConstructor(CI)) {
      // TODO: Extract constructor name
      sourceAPI = "<constructor>";
      return true;
    }
  }

  return false;
}

std::string TaintAnalysis::extractObjectName(Value *object) {
  // Handle TryLoadGlobalPropertyInst (e.g., document, location, window)
  if (auto *GLPI = llvh::dyn_cast<TryLoadGlobalPropertyInst>(object)) {
    if (auto *litProp = llvh::dyn_cast<LiteralString>(GLPI->getProperty())) {
      return litProp->getValue().str().str();
    }
  }
  
  // Handle LoadPropertyInst (e.g., element from document.getElementById)  
  if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(object)) {
    // For now, we can't easily track complex object chains
    // Just return a generic name indicating it's a loaded object
    return "element";
  }
  
  // Handle CallInst results (e.g., result of document.getElementById)
  if (auto *CI = llvh::dyn_cast<CallInst>(object)) {
    // This is a complex case - the object is the result of a function call
    // For cases like document.getElementById('x').innerHTML, this would be the CallInst
    return "element";
  }
  
  // Handle global object
  if (llvh::isa<GlobalObject>(object)) {
    return "global";
  }
  
  // Default case
  return "";
}

bool TaintAnalysis::isSinkInstruction(
    Instruction *I,
    std::string &sinkAPI,
    SinkType &type) {
  
  // Add a counter to see if this function is called at all
  static int callCount = 0;
  callCount++;
  if (callCount <= 3) {  // Only print first few calls to avoid spam
    outs() << "  [DEBUG] isSinkInstruction called " << callCount << " times, instruction: " 
           << I->getKindStr() << "\n";
  }
  
  // Check StorePropertyInst (e.g., element.innerHTML = ...)
  if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(I)) {
    outs() << "  [DEBUG] Found StorePropertyInst!\n";
    if (auto *litProp = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
      std::string propName = litProp->getValue().str().str();
      
      // Try to extract object name for better matching
      std::string objectName = extractObjectName(SPI->getObject());
      outs() << "  [DEBUG] Property assignment: " << objectName << "." << propName << "\n";
      
      // Try with specific object name first  
      if (auto *sinkDef = sinkRegistry_.isPropertySink(objectName, propName)) {
        outs() << "    [DEBUG] Found object-specific sink: " << sinkDef->name << "\n";
        sinkAPI = sinkDef->name;
        type = sinkDef->type;
        return true;
      }
      
      // Fall back to generic property name (works for innerHTML, outerHTML on any element)
      if (auto *sinkDef = sinkRegistry_.isPropertySink("", propName)) {
        outs() << "    [DEBUG] Found generic property sink: " << sinkDef->name << "\n";
        sinkAPI = sinkDef->name;
        type = sinkDef->type;
        return true;
      }
      
      outs() << "    [DEBUG] Property '" << objectName << "." << propName << "' is not a sink\n";
    } else {
      outs() << "  [DEBUG] StorePropertyInst property is not a literal string\n";
    }
  }

  // Check CallInst for method sinks (e.g., document.write, eval)
  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
    Value *callee = CI->getCallee();

    // Check if it's a LoadPropertyInst (method call)
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        std::string methodName = litProp->getValue().str().str();
        
        // Try to extract object name for better matching
        std::string objectName = extractObjectName(LPI->getObject());
        outs() << "  [DEBUG] Method call: " << objectName << "." << methodName << "\n";
        
        // Try with specific object name first
        if (auto *sinkDef = sinkRegistry_.isMethodSink(objectName, methodName)) {
          outs() << "    [DEBUG] Found method sink: " << sinkDef->name << "\n";
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        
        // Fall back to generic method name
        if (auto *sinkDef = sinkRegistry_.isMethodSink("", methodName)) {
          outs() << "    [DEBUG] Found generic method sink: " << sinkDef->name << "\n";
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        
        outs() << "    [DEBUG] Method '" << objectName << "." << methodName << "' is not a sink\n";
      }
    }

    // Check if it's a direct function call (e.g., eval, fetch)
    if (auto *GPI = llvh::dyn_cast<TryLoadGlobalPropertyInst>(callee)) {
      if (auto *litProp = llvh::dyn_cast<LiteralString>(GPI->getProperty())) {
        std::string functionName = litProp->getValue().str().str();
        outs() << "  [DEBUG] Global function call: " << functionName << "\n";
        
        if (auto *sinkDef = sinkRegistry_.isFunctionSink(functionName)) {
          outs() << "    [DEBUG] Found function sink: " << sinkDef->name << "\n";
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        
        outs() << "    [DEBUG] Function '" << functionName << "' is not a sink\n";
      }
    }
  }

  // Check DirectEvalInst (eval() calls)
  if (auto *DEI = llvh::dyn_cast<DirectEvalInst>(I)) {
    outs() << "  [DEBUG] Found DirectEvalInst (eval call)\n";
    if (auto *sinkDef = sinkRegistry_.isFunctionSink("eval")) {
      outs() << "    [DEBUG] Found eval sink: " << sinkDef->name << "\n";
      sinkAPI = sinkDef->name;
      type = sinkDef->type;
      return true;
    }
    outs() << "    [DEBUG] eval not registered as sink\n";
  }

  return false;
}

void TaintAnalysis::analyzeTaintFlow(
    const llvh::SmallVectorImpl<Instruction *> &sources,
    const llvh::SmallVectorImpl<Instruction *> &sinks) {
  // Convert SmallVector to std::vector for DefUseAnalyzer API
  std::vector<Instruction *> sourceVec(sources.begin(), sources.end());
  std::vector<Instruction *> sinkVec(sinks.begin(), sinks.end());

  outs() << "[DEBUG TAINT] Passing " << sinkVec.size() << " sinks to DefUseAnalyzer:\n";
  for (size_t i = 0; i < sinkVec.size(); ++i) {
    outs() << "  [" << i << "] " << sinkVec[i]->getKindStr() << "\n";
  }

  // Convert function calls to DefUseAnalyzer format
  std::vector<DefUseAnalyzer::FunctionCallMapping> callMappings;
  for (const auto &callInfo : functionCalls_) {
    DefUseAnalyzer::FunctionCallMapping mapping;
    mapping.callSite = callInfo.callSite;
    mapping.targetFunction = callInfo.targetFunction;
    mapping.arguments = callInfo.arguments;
    callMappings.push_back(mapping);
  }
  
  // Set function calls in DefUseAnalyzer
  defUseAnalyzer_.setFunctionCalls(callMappings);

  // Perform taint analysis using DefUseAnalyzer
  defUseAnalyzer_.analyzeTaintFlow(sourceVec, sinkVec, &closureAnalyzer_);

  // Get all paths that reached sinks
  const auto &sinkPaths = defUseAnalyzer_.getSinkReachingPaths();
  
  outs() << "[DEBUG TAINT] DefUseAnalyzer found " << sinkPaths.size() << " sink-reaching paths\n";

  // Convert to vulnerability reports
  for (const auto &path : sinkPaths) {
    std::string sourceAPI;
    std::string sinkAPI;
    SinkType sinkType = SinkType::Network; // Default

    // Identify source API
    isSourceInstruction(path.source, sourceAPI);

    // Identify sink API
    isSinkInstruction(path.sink, sinkAPI, sinkType);

    // Create report
    reports_.emplace_back(
        path.source, path.sink, sourceAPI, sinkAPI, sinkType, path.path);
  }
}

void TaintAnalysis::reportVulnerabilities() {
  if (reports_.empty()) {
    outs() << "  ✓ No taint flows detected.\n";
    return;
  }

  outs() << "  ⚠️  Found " << reports_.size()
         << " potential vulnerability(ies):\n\n";

  unsigned index = 1;
  for (const auto &report : reports_) {
    outs() << "  [" << index++ << "] " << getSinkTypeName(report.sinkType)
           << " Vulnerability\n";
    outs() << "      Source: " << report.sourceAPI << "\n";
    outs() << "      Sink:   " << report.sinkAPI << "\n";
    outs() << "      Path length: " << report.path.size()
           << " instruction(s)\n";

    // Print path details (optional, can be verbose)
    if (report.path.size() <= 10) {
      outs() << "      Path: ";
      for (size_t i = 0; i < report.path.size(); ++i) {
        if (i > 0)
          outs() << " → ";
        outs() << report.path[i]->getKindStr();
      }
      outs() << "\n";
    }
    outs() << "\n";
  }
}

const char *TaintAnalysis::getSinkTypeName(SinkType type) {
  switch (type) {
  case SinkType::Network:
    return "Network";
  case SinkType::Storage:
    return "Storage";
  case SinkType::XSS:
    return "XSS";
  case SinkType::CodeInjection:
    return "Code Injection";
  case SinkType::Navigation:
    return "Navigation";
  default:
    return "Unknown";
  }
}

void TaintAnalysis::analyzeFunctionCalls(Module *M) {
  functionCalls_.clear();

  // Find all function calls in the module
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
          // Check if this is a call to a user-defined function (not built-in)
          if (auto *callee = CI->getCallee()) {
            // Look for CreateFunctionInst that created this function
            if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
              // This could be a method call like test() - check if it's user-defined
              Value *base = LPI->getObject();
              if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
                std::string functionName = litProp->getValue().str().str();
                
                // Find the function definition in the module
                Function *targetFunc = nullptr;
                for (auto &candidateF : *M) {
                  if (candidateF.getInternalNameStr() == functionName) {
                    targetFunc = &candidateF;
                    break;
                  }
                }
                
                if (targetFunc && shouldAnalyzeFunction(targetFunc)) {
                  FunctionCallInfo callInfo;
                  callInfo.callSite = CI;
                  callInfo.targetFunction = targetFunc;
                  
                  // Collect arguments - CallInst arguments are after the callee
                  for (unsigned i = 0; i < CI->getNumArguments(); ++i) {
                    callInfo.arguments.push_back(CI->getArgument(i));
                  }
                  
                  functionCalls_.push_back(callInfo);
                  outs() << "  [DEBUG] Found function call: " << functionName 
                         << " with " << callInfo.arguments.size() << " arguments\n";
                }
              }
            }
          }
        }
      }
    }
  }
  
  outs() << "  Found " << functionCalls_.size() << " inter-procedural call(s) to analyze.\n";
}

bool TaintAnalysis::shouldAnalyzeFunction(Function *F) {
  // Skip built-in functions and empty functions
  if (!F || F->empty()) {
    return false;
  }
  
  // Skip functions that are likely built-ins based on naming patterns
  std::string name = F->getInternalNameStr();
  if (name.empty() || name == "global" || name.find("HermesInternal") != std::string::npos) {
    return false;
  }
  
  return true;
}



std::unique_ptr<Pass> hermes::createTaintAnalysis() {
  return std::make_unique<TaintAnalysis>();
}

#undef DEBUG_TYPE
