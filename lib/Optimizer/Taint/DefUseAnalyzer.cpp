/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Optimizer/Taint/DefUseAnalyzer.h"

#include "llvh/Support/Debug.h"

#define DEBUG_TYPE "taint-defuse"

using llvh::dbgs;
using llvh::outs;

namespace hermes {

// Static member initialization
const DefUseAnalyzer::TaintInfo DefUseAnalyzer::emptyTaintInfo_ = {};

//===----------------------------------------------------------------------===//
// Main analysis entry point
//===----------------------------------------------------------------------===//

void DefUseAnalyzer::analyzeTaintFlow(
    const std::vector<Instruction *> &sources,
    const std::vector<Instruction *> &sinks,
    ClosureAnalyzer *closureAnalyzer) {
  clear();
  closureAnalyzer_ = closureAnalyzer;

  // Initialize source and sink sets for quick lookup
  for (auto *source : sources) {
    sources_.insert(source);
  }

  for (auto *sink : sinks) {
    sinks_.insert(sink);
  }

  // Initialize worklist with source instructions
  for (auto *source : sources) {
    std::vector<Instruction *> initialPath = {source};
    markTainted(source, source, initialPath);
    addToWorklist(source, initialPath);
  }

  // Run the main propagation algorithm
  propagateTaint();
  
  // CRITICAL FIX: After DefUse propagation, check for property and frame taint connections
  // This handles cases where StorePropertyInst/StoreFrameInst and LoadPropertyInst/LoadFrameInst don't have direct DefUse relationship
  // Run multiple iterations until no new taint is found
  bool foundNewTaint = true;
  int iterations = 0;
  const int maxIterations = 5;
  
  while (foundNewTaint && iterations < maxIterations) {
    foundNewTaint = false;
    iterations++;
    outs() << "[DEBUG] Global taint connection iteration " << iterations << "\n";
    
    size_t beforeSize = worklist_.size();
    
    checkPropertyTaintConnections();
    checkFrameTaintConnections();
    
    if (worklist_.size() > beforeSize) {
      foundNewTaint = true;
      outs() << "  [DEBUG] Found new taint, continuing propagation...\n";
      propagateTaint();
    }
  }
  
  outs() << "[DEBUG] Global taint connection completed after " << iterations << " iterations\n";
}

void DefUseAnalyzer::clear() {
  taintMap_.clear();
  propertyTaintMap_.clear();
  frameTaintMap_.clear();
  worklist_.clear();
  worklistSet_.clear();
  sinkReachingPaths_.clear();
  sources_.clear();
  sinks_.clear();
  closureAnalyzer_ = nullptr;
}

bool DefUseAnalyzer::isTainted(Value *v) const {
  auto it = taintMap_.find(v);
  return it != taintMap_.end() && it->second.isTainted;
}

const DefUseAnalyzer::TaintInfo &DefUseAnalyzer::getTaintInfo(Value *v) const {
  auto it = taintMap_.find(v);
  if (it != taintMap_.end()) {
    return it->second;
  }
  return emptyTaintInfo_;
}

//===----------------------------------------------------------------------===//
// Worklist algorithm
//===----------------------------------------------------------------------===//

void DefUseAnalyzer::propagateTaint() {
  while (!worklist_.empty()) {
    // Pop the next item from worklist
    auto [currentValue, currentPath] = worklist_.front();
    worklist_.pop_front();
    worklistSet_.erase(currentValue);

    // Check if this value is used in a sink
    if (auto *inst = llvh::dyn_cast<Instruction>(currentValue)) {
      outs() << "[DEBUG PROPAGATE] Checking instruction: " << inst->getKindStr() 
             << ", is sink: " << (isSink(inst) ? "YES" : "NO") << "\n";
      
      if (isSink(inst)) {
        // Record that we reached a sink
        Instruction *source = currentPath.empty() ? nullptr : currentPath.front();
        sinkReachingPaths_.emplace_back(source, currentPath, inst);
        outs() << "[DEBUG PROPAGATE] SINK REACHED! Added to sinkReachingPaths. Total paths: " 
               << sinkReachingPaths_.size() << "\n";
      }
    }

    // Propagate taint to all users via def-use chain
    for (Instruction *user : currentValue->getUsers()) {
      outs() << "[DEBUG USERS] Found user: " << user->getKindStr() << "\n";

      // Dispatch to appropriate handler based on instruction type
      if (auto *movInst = llvh::dyn_cast<MovInst>(user)) {
        handleMovInst(movInst, currentPath);
      } else if (auto *phiInst = llvh::dyn_cast<PhiInst>(user)) {
        handlePhiInst(phiInst, currentPath);
      } else if (auto *binOp = llvh::dyn_cast<BinaryOperatorInst>(user)) {
        handleBinaryOp(binOp, currentPath);
      } else if (auto *callInst = llvh::dyn_cast<CallInst>(user)) {
        handleCallInst(callInst, currentPath);
      } else if (auto *loadProp = llvh::dyn_cast<LoadPropertyInst>(user)) {
        handleLoadProperty(loadProp, currentPath);
      } else if (auto *storeProp = llvh::dyn_cast<StorePropertyInst>(user)) {
        handleStoreProperty(storeProp, currentPath);
      } else if (auto *loadFrame = llvh::dyn_cast<LoadFrameInst>(user)) {
        handleLoadFrame(loadFrame, currentPath);
      } else if (auto *storeFrame = llvh::dyn_cast<StoreFrameInst>(user)) {
        handleStoreFrame(storeFrame, currentPath);
      } else if (auto *retInst = llvh::dyn_cast<ReturnInst>(user)) {
        handleReturn(retInst, currentPath);
      } else if (auto *unaryOp = llvh::dyn_cast<UnaryOperatorInst>(user)) {
        handleUnaryOp(unaryOp, currentPath);
      } else {
        // Generic handler for other instructions that might propagate taint
        handleGenericInst(user, currentPath);
      }
    }
  }
}

void DefUseAnalyzer::addToWorklist(
    Value *v,
    const std::vector<Instruction *> &path) {
  // Only add if not already in worklist
  if (worklistSet_.find(v) == worklistSet_.end()) {
    worklist_.emplace_back(v, path);
    worklistSet_.insert(v);
  }
}

//===----------------------------------------------------------------------===//
// Per-instruction propagation handlers
//===----------------------------------------------------------------------===//

void DefUseAnalyzer::handleMovInst(
    MovInst *inst,
    const std::vector<Instruction *> &path) {
  // MovInst simply copies the value: v1 = mov v0
  // If v0 is tainted, v1 is also tainted
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handlePhiInst(
    PhiInst *inst,
    const std::vector<Instruction *> &path) {
  // PhiInst merges values from different basic blocks
  // If any incoming value is tainted, the phi result is tainted
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handleBinaryOp(
    BinaryOperatorInst *inst,
    const std::vector<Instruction *> &path) {
  // BinaryOperatorInst: v = v0 op v1
  // If either operand is tainted, the result is tainted
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handleCallInst(
    CallInst *inst,
    const std::vector<Instruction *> &path) {
  // CallInst: handle function calls
  // Conservative approach: if any argument is tainted, return value is tainted
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  // Check if the call instruction itself produces a tainted return value
  // This happens when tainted data flows into the call
  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }

  // Inter-procedural analysis: check if this call is in our function mapping
  for (const auto &funcCall : functionCalls_) {
    if (funcCall.callSite == inst) {
      outs() << "[DEBUG INTERPROCEDURAL] Found mapped function call to: " 
             << funcCall.targetFunction->getInternalNameStr() << "\n";
      
      // Get function parameters
      auto &params = funcCall.targetFunction->getParameters();
      
       outs() << "  Arguments: " << funcCall.arguments.size() 
              << ", Parameters: " << params.size() << "\n";
       outs() << "  CallInst has " << inst->getNumArguments() << " arguments:\n";
       for (unsigned i = 0; i < inst->getNumArguments(); ++i) {
         outs() << "    Arg[" << i << "]: " << inst->getArgument(i)->getKindStr() << "\n";
       }
      
       // Map tainted arguments to parameters
       // Use the actual CallInst arguments, not the stored ones from analysis phase
       // Skip argument 0 (this value) and start from argument 1
       for (size_t i = 1; i < inst->getNumArguments() && (i-1) < params.size(); ++i) {
         Value *arg = inst->getArgument(i);
         Parameter *param = params[i-1]; // Parameter index is i-1 since we skip 'this'
         
         outs() << "  [DEBUG] Checking actual CallInst argument " << i << " (type: " << arg->getKindStr() << ") for taint...\n";
         
         // If argument is tainted, propagate to parameter
         if (isTainted(arg)) {
          outs() << "    ✓ Argument " << i << " is tainted! Propagating to parameter.\n";
          
          // Create new path through the function call
          std::vector<Instruction *> paramPath = getTaintInfo(arg).paths[0].path;
          paramPath.push_back(inst); // Add the call instruction
          
          // Mark parameter as tainted
          markTainted(param, getTaintInfo(arg).paths[0].source, paramPath);
          addToWorklist(param, paramPath);
        } else {
          outs() << "    ✗ Argument " << i << " is NOT tainted.\n";
        }
      }
      
      break; // Found the mapping, no need to continue
    }
  }
}

void DefUseAnalyzer::handleLoadProperty(
    LoadPropertyInst *inst,
    const std::vector<Instruction *> &path) {
  // LoadPropertyInst: v1 = load v0["prop"]
  // Check if the property is tainted and propagate to the loaded value
  
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);
  
  bool propagated = false;

  // Get the property name if it's a literal string
  if (auto *propLiteral = llvh::dyn_cast<LiteralString>(inst->getProperty())) {
    std::string propName = propLiteral->getValue().str().str();
    Value *object = inst->getObject();
    
    outs() << "[DEBUG LOAD] Property: " << propName 
           << ", Is property tainted: " << (isPropertyTainted(object, propName) ? "YES" : "NO") << "\n";
    
    // Check if this property is tainted
    if (isPropertyTainted(object, propName)) {
      if (!isTainted(inst) || shouldPropagateTo(inst)) {
        // Get the original source from property taint info
        const auto &propTaintInfo = getPropertyTaintInfo(object, propName);
        if (!propTaintInfo.paths.empty()) {
          outs() << "[DEBUG LOAD] Propagating taint from property: " << propName << "\n";
          markTainted(inst, propTaintInfo.paths[0].source, newPath);
          addToWorklist(inst, newPath);
          propagated = true;
        }
      }
    }
  }
  
  // If property-specific check didn't propagate, use general propagation rules
  // (only if the object or property name itself is tainted)
  if (!propagated) {
    if (!isTainted(inst) || shouldPropagateTo(inst)) {
      outs() << "[DEBUG LOAD] Using general taint propagation\n";
      markTainted(inst, path.front(), newPath);
      addToWorklist(inst, newPath);
    }
  }
}

void DefUseAnalyzer::handleStoreProperty(
    StorePropertyInst *inst,
    const std::vector<Instruction *> &path) {
  // StorePropertyInst: store obj["prop"], value
  // Taint flows from the stored value to the property storage
  
  outs() << "[DEBUG STORE HANDLER] Called for StorePropertyInst\n";
  
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  // Get the property name if it's a literal string
  if (auto *propLiteral = llvh::dyn_cast<LiteralString>(inst->getProperty())) {
    std::string propName = propLiteral->getValue().str().str();
    Value *object = inst->getObject();
    Value *storedValue = inst->getStoredValue();
    
    outs() << "[DEBUG STORE] Property: " << propName 
           << ", StoredValue tainted: " << (isTainted(storedValue) ? "YES" : "NO") << "\n";
    
    // If the stored value is tainted, mark the property as tainted
    if (isTainted(storedValue)) {
      outs() << "[DEBUG STORE] Marking property tainted: " << propName << "\n";
      markPropertyTainted(object, propName, path.front(), newPath);
    }
  }

  // CRITICAL FIX: Mark the store instruction itself as tainted AND add to worklist
  if (!isTainted(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);  // ← This was missing!
    outs() << "[DEBUG STORE] Marked StorePropertyInst as tainted and added to worklist\n";
  }
}

void DefUseAnalyzer::handleLoadFrame(
    LoadFrameInst *inst,
    const std::vector<Instruction *> &path) {
  // LoadFrameInst: load from closure environment
  // Delegate to ClosureAnalyzer if available
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (closureAnalyzer_) {
    // TODO: Query ClosureAnalyzer to see if the frame variable is tainted
    // For now, use conservative approach
    if (!isTainted(inst) || shouldPropagateTo(inst)) {
      markTainted(inst, path.front(), newPath);
      addToWorklist(inst, newPath);
    }
  } else {
    // Without ClosureAnalyzer, we can't track cross-function taint
    // Conservative: assume it might be tainted
    if (!isTainted(inst) || shouldPropagateTo(inst)) {
      markTainted(inst, path.front(), newPath);
      addToWorklist(inst, newPath);
    }
  }
}

void DefUseAnalyzer::handleStoreFrame(
    StoreFrameInst *inst,
    const std::vector<Instruction *> &path) {
  // StoreFrameInst: store to closure environment
  // Delegate to ClosureAnalyzer if available
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);
  
  Value *storedValue = inst->getValue();
  Variable *variable = inst->getVariable();
  Value *environment = inst->getEnvironment();
  
  outs() << "[DEBUG STORE FRAME] StoreFrameInst called, stored value tainted: " 
         << (isTainted(storedValue) ? "YES" : "NO") << "\n";
  outs() << "[DEBUG STORE FRAME] Variable: " << variable->getName().str().str() << "\n";

  // If the stored value is tainted, mark the frame variable as tainted
  if (isTainted(storedValue)) {
    markFrameTainted(environment, variable, path.front(), newPath);
  }

  if (closureAnalyzer_) {
    // TODO: Inform ClosureAnalyzer that we're storing tainted data
    // to a frame variable
  }

  // Mark the instruction as part of the taint path AND add to worklist
  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);  // ← This was missing!
    outs() << "[DEBUG STORE FRAME] Marked StoreFrameInst as tainted and added to worklist\n";
  }
}

void DefUseAnalyzer::handleReturn(
    ReturnInst *inst,
    const std::vector<Instruction *> &path) {
  // ReturnInst: return from function
  // If the return value is tainted, propagate to all call sites
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  // Mark the return instruction as tainted
  if (!isTainted(inst)) {
    markTainted(inst, path.front(), newPath);
  }

  // TODO: Interprocedural analysis
  // Find all call sites and propagate taint to their return values
}

void DefUseAnalyzer::handleUnaryOp(
    Instruction *inst,
    const std::vector<Instruction *> &path) {
  // UnaryOperatorInst: v1 = op v0
  // If v0 is tainted, v1 is tainted
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handleGenericInst(
    Instruction *inst,
    const std::vector<Instruction *> &path) {
  // Generic handler for other instructions
  // Conservative approach: if any operand is tainted, the result is tainted
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  // Most instructions propagate taint from operands to result
  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

//===----------------------------------------------------------------------===//
// Utility methods
//===----------------------------------------------------------------------===//

void DefUseAnalyzer::markTainted(
    Value *v,
    Instruction *source,
    const std::vector<Instruction *> &path) {
  auto &info = taintMap_[v];
  info.isTainted = true;
  info.paths.emplace_back(source, path, nullptr);
}

bool DefUseAnalyzer::shouldPropagateTo(Value *v) const {
  // We should continue propagating if we haven't seen this exact path before
  // For now, always propagate (may lead to redundant work but ensures completeness)
  // TODO: Optimize by tracking unique paths
  return true;
}

bool DefUseAnalyzer::isSink(Instruction *inst) const {
  bool found = sinks_.find(inst) != sinks_.end();
  if (!found && llvh::isa<StorePropertyInst>(inst)) {
    // Debug: check if this StorePropertyInst should be a sink
    outs() << "[DEBUG SINK] StorePropertyInst not found in sinks set. Comparing pointers:\n";
    outs() << "  Current inst: " << inst << "\n";
    for (auto *sink : sinks_) {
      outs() << "  Sink in set: " << sink << " (" << sink->getKindStr() << ")\n";
    }
  }
  return found;
}

bool DefUseAnalyzer::isSource(Instruction *inst) const {
  return sources_.find(inst) != sources_.end();
}

//===----------------------------------------------------------------------===//
// Property taint tracking utilities
//===----------------------------------------------------------------------===//

void DefUseAnalyzer::markPropertyTainted(
    Value *object, 
    const std::string &propertyName,
    Instruction *source,
    const std::vector<Instruction *> &path) {
  // Create a unique key for this (object, property) pair
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(object)) + ":" + propertyName;
  
  auto &taintInfo = propertyTaintMap_[key];
  taintInfo.isTainted = true;
  taintInfo.paths.emplace_back(source, path);
}

bool DefUseAnalyzer::isPropertyTainted(Value *object, const std::string &propertyName) const {
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(object)) + ":" + propertyName;
  auto it = propertyTaintMap_.find(key);
  return it != propertyTaintMap_.end() && it->second.isTainted;
}

const DefUseAnalyzer::TaintInfo &DefUseAnalyzer::getPropertyTaintInfo(
    Value *object, const std::string &propertyName) const {
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(object)) + ":" + propertyName;
  auto it = propertyTaintMap_.find(key);
  return it != propertyTaintMap_.end() ? it->second : emptyTaintInfo_;
}

void DefUseAnalyzer::checkPropertyTaintConnections() {
  outs() << "[DEBUG] Checking property taint connections...\n";
  
  // We need to iterate through all instructions in all functions to find LoadPropertyInst
  // that might load tainted properties
  
  bool foundNewTaint = true;
  int iterations = 0;
  const int maxIterations = 10; // Prevent infinite loops
  
  while (foundNewTaint && iterations < maxIterations) {
    foundNewTaint = false;
    iterations++;
    
    outs() << "[DEBUG] Property taint iteration " << iterations << "\n";
    
    // Iterate through all sources/sinks and their parent functions to find all instructions
    std::unordered_set<Function *> functionsToCheck;
    
    for (auto *source : sources_) {
      if (auto *func = source->getParent()->getParent()) {
        functionsToCheck.insert(func);
      }
    }
    
    for (auto *sink : sinks_) {
      if (auto *func = sink->getParent()->getParent()) {
        functionsToCheck.insert(func);
      }
    }
    
    // Check all LoadPropertyInst in these functions
    for (auto *func : functionsToCheck) {
      for (auto &BB : *func) {
        for (auto &inst : BB) {
          if (auto *loadProp = llvh::dyn_cast<LoadPropertyInst>(&inst)) {
            // Check if this LoadPropertyInst loads a tainted property
            if (auto *propLiteral = llvh::dyn_cast<LiteralString>(loadProp->getProperty())) {
              std::string propName = propLiteral->getValue().str().str();
              Value *object = loadProp->getObject();
              
              outs() << "[DEBUG] Checking LoadPropertyInst for property: " << propName << "\n";
              
              // If property is tainted but the load instruction isn't, propagate taint
              if (isPropertyTainted(object, propName) && !isTainted(loadProp)) {
                outs() << "[DEBUG] Found untainted LoadPropertyInst for tainted property: " << propName << "\n";
                
                const auto &propTaintInfo = getPropertyTaintInfo(object, propName);
                if (!propTaintInfo.paths.empty()) {
                  std::vector<Instruction *> newPath = propTaintInfo.paths[0].path;
                  newPath.push_back(loadProp);
                  
                  markTainted(loadProp, propTaintInfo.paths[0].source, newPath);
                  addToWorklist(loadProp, newPath);
                  foundNewTaint = true;
                  
                  outs() << "[DEBUG] Marked LoadPropertyInst as tainted and added to worklist\n";
                }
              }
            }
          }
        }
      }
    }
    
    // Run another propagation round if we found new taint
    if (foundNewTaint) {
      outs() << "[DEBUG] Running additional propagation round...\n";
      propagateTaint();
    }
  }
  
  outs() << "[DEBUG] Property taint connection check completed after " << iterations << " iterations\n";
}

//===----------------------------------------------------------------------===//
// Frame variable taint tracking utilities
//===----------------------------------------------------------------------===//

void DefUseAnalyzer::markFrameTainted(
    Value *environment,
    Variable *variable,
    Instruction *source,
    const std::vector<Instruction *> &path) {
  // Create a unique key for this (environment, variable) pair
  std::string varName = variable->getName().str().str();
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(environment)) + ":" + varName;
  
  auto &taintInfo = frameTaintMap_[key];
  taintInfo.isTainted = true;
  taintInfo.paths.emplace_back(source, path);
  
  outs() << "[DEBUG FRAME] Marked frame variable tainted: " << varName << "\n";
}

bool DefUseAnalyzer::isFrameTainted(Value *environment, Variable *variable) const {
  std::string varName = variable->getName().str().str();
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(environment)) + ":" + varName;
  auto it = frameTaintMap_.find(key);
  return it != frameTaintMap_.end() && it->second.isTainted;
}

const DefUseAnalyzer::TaintInfo &DefUseAnalyzer::getFrameTaintInfo(
    Value *environment, Variable *variable) const {
  std::string varName = variable->getName().str().str();
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(environment)) + ":" + varName;
  auto it = frameTaintMap_.find(key);
  return it != frameTaintMap_.end() ? it->second : emptyTaintInfo_;
}

void DefUseAnalyzer::checkFrameTaintConnections() {
  outs() << "[DEBUG] Checking frame variable taint connections...\n";
  
  bool foundNewTaint = true;
  int iterations = 0;
  const int maxIterations = 10; // Prevent infinite loops
  
  while (foundNewTaint && iterations < maxIterations) {
    foundNewTaint = false;
    iterations++;
    
    outs() << "[DEBUG] Frame taint iteration " << iterations << "\n";
    
     // Iterate through all functions and their instructions to find LoadFrameInst
     // We need to check ALL functions, not just those containing sources
     if (!sinks_.empty()) {
       Function *function = (*sinks_.begin())->getParent()->getParent();
       Module *module = function->getParent();
       
       for (Function &func : *module) {
         for (BasicBlock &BB : func) {
           for (Instruction &I : BB) {
             if (auto *loadFrame = llvh::dyn_cast<LoadFrameInst>(&I)) {
               Variable *variable = loadFrame->getLoadVariable();
               Value *environment = loadFrame->getEnvironment();
               
               outs() << "[DEBUG] Checking LoadFrameInst for variable: " << variable->getName().str().str() << "\n";
               
               // Check if this variable is tainted in the environment
               if (isFrameTainted(environment, variable) && !isTainted(loadFrame)) {
                 outs() << "    ✓ Found tainted frame variable! Propagating taint.\n";
                 
                 const auto &frameTaintInfo = getFrameTaintInfo(environment, variable);
                 
                 // Mark the LoadFrameInst as tainted and add to worklist
                 markTainted(loadFrame, frameTaintInfo.paths[0].source, frameTaintInfo.paths[0].path);
                 addToWorklist(loadFrame, frameTaintInfo.paths[0].path);
                 
                 outs() << "    [DEBUG FRAME] LoadFrameInst has " << loadFrame->getNumUsers() << " users\n";
                 
                 foundNewTaint = true;
               }
             }
           }
         }
       }
     }
  }
  
  outs() << "[DEBUG] Frame taint connection check completed after " << iterations << " iterations\n";
}

} // namespace hermes
