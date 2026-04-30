
#include "hermes/Optimizer/Taint/DefUseAnalyzer.h"
#include "llvh/Support/Debug.h"

#define DEBUG_TYPE "taint-defuse"

using llvh::dbgs;
using llvh::outs;

namespace hermes {

const DefUseAnalyzer::TaintInfo DefUseAnalyzer::emptyTaintInfo_ = {};

void DefUseAnalyzer::analyzeTaintFlow(
    const std::vector<Instruction *> &sources,
    const std::vector<Instruction *> &sinks,
    ClosureAnalyzer *closureAnalyzer) {
  clear();
  closureAnalyzer_ = closureAnalyzer;

  for (auto *source : sources) {
    sources_.insert(source);
  }

  for (auto *sink : sinks) {
    sinks_.insert(sink);
  }

  for (auto *source : sources) {
    std::vector<Instruction *> initialPath = {source};
    markTainted(source, source, initialPath);
    addToWorklist(source, initialPath);
  }

  propagateTaint();

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

void DefUseAnalyzer::propagateTaint() {
  while (!worklist_.empty()) {
    auto [currentValue, currentPath] = worklist_.front();
    worklist_.pop_front();
    worklistSet_.erase(currentValue);

    if (auto *inst = llvh::dyn_cast<Instruction>(currentValue)) {
      outs() << "[DEBUG PROPAGATE] Checking instruction: " << inst->getKindStr()
             << ", is sink: " << (isSink(inst) ? "YES" : "NO") << "\n";

      if (isSink(inst)) {
        Instruction *source = currentPath.empty() ? nullptr : currentPath.front();
        sinkReachingPaths_.emplace_back(source, currentPath, inst);
        outs() << "[DEBUG PROPAGATE] SINK REACHED! Added to sinkReachingPaths. Total paths: "
               << sinkReachingPaths_.size() << "\n";
      }
    }

    for (Instruction *user : currentValue->getUsers()) {
      outs() << "[DEBUG USERS] Found user: " << user->getKindStr() << "\n";

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
        handleGenericInst(user, currentPath);
      }
    }
  }
}

void DefUseAnalyzer::addToWorklist(
    Value *v,
    const std::vector<Instruction *> &path) {
  if (worklistSet_.find(v) == worklistSet_.end()) {
    worklist_.emplace_back(v, path);
    worklistSet_.insert(v);
  }
}

void DefUseAnalyzer::handleMovInst(
    MovInst *inst,
    const std::vector<Instruction *> &path) {
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
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }

  for (const auto &funcCall : functionCalls_) {
    if (funcCall.callSite == inst) {
      outs() << "[DEBUG INTERPROCEDURAL] Found mapped function call to: "
             << funcCall.targetFunction->getInternalNameStr() << "\n";

      auto &params = funcCall.targetFunction->getParameters();

       outs() << "  Arguments: " << funcCall.arguments.size()
              << ", Parameters: " << params.size() << "\n";
       outs() << "  CallInst has " << inst->getNumArguments() << " arguments:\n";
       for (unsigned i = 0; i < inst->getNumArguments(); ++i) {
         outs() << "    Arg[" << i << "]: " << inst->getArgument(i)->getKindStr() << "\n";
       }

       for (size_t i = 1; i < inst->getNumArguments() && (i-1) < params.size(); ++i) {
         Value *arg = inst->getArgument(i);
         Parameter *param = params[i-1];

         outs() << "  [DEBUG] Checking actual CallInst argument " << i << " (type: " << arg->getKindStr() << ") for taint...\n";

         if (isTainted(arg)) {
          std::string msg = "    [Taint Propagation] Tainted value passed to '" +
                            funcCall.targetFunction->getInternalNameStr().str() +
                            "' at argument #" + std::to_string(i-1) + "\n";
          if (logger_) logger_(msg);
          else outs() << msg;

          std::vector<Instruction *> paramPath = getTaintInfo(arg).paths[0].path;
          paramPath.push_back(inst);

          markTainted(param, getTaintInfo(arg).paths[0].source, paramPath);
          addToWorklist(param, paramPath);
        } else {
        }
      }

      break;
    }
  }
}

void DefUseAnalyzer::handleLoadProperty(
    LoadPropertyInst *inst,
    const std::vector<Instruction *> &path) {

  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  bool propagated = false;

  if (auto *propLiteral = llvh::dyn_cast<LiteralString>(inst->getProperty())) {
    std::string propName = propLiteral->getValue().str().str();
    Value *object = inst->getObject();

    outs() << "[DEBUG LOAD] Property: " << propName
           << ", Is property tainted: " << (isPropertyTainted(object, propName) ? "YES" : "NO") << "\n";

    if (isPropertyTainted(object, propName)) {
      if (!isTainted(inst) || shouldPropagateTo(inst)) {
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

  outs() << "[DEBUG STORE HANDLER] Called for StorePropertyInst\n";

  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (auto *propLiteral = llvh::dyn_cast<LiteralString>(inst->getProperty())) {
    std::string propName = propLiteral->getValue().str().str();
    Value *object = inst->getObject();
    Value *storedValue = inst->getStoredValue();

    outs() << "[DEBUG STORE] Property: " << propName
           << ", StoredValue tainted: " << (isTainted(storedValue) ? "YES" : "NO") << "\n";

    if (isTainted(storedValue)) {
      outs() << "[DEBUG STORE] Marking property tainted: " << propName << "\n";
      markPropertyTainted(object, propName, path.front(), newPath);
    }
  }

  if (!isTainted(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
    outs() << "[DEBUG STORE] Marked StorePropertyInst as tainted and added to worklist\n";
  }
}

void DefUseAnalyzer::handleLoadFrame(
    LoadFrameInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (closureAnalyzer_) {
    if (!isTainted(inst) || shouldPropagateTo(inst)) {
      markTainted(inst, path.front(), newPath);
      addToWorklist(inst, newPath);
    }
  } else {
    if (!isTainted(inst) || shouldPropagateTo(inst)) {
      markTainted(inst, path.front(), newPath);
      addToWorklist(inst, newPath);
    }
  }
}

void DefUseAnalyzer::handleStoreFrame(
    StoreFrameInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  Value *storedValue = inst->getValue();
  Variable *variable = inst->getVariable();
  Value *environment = inst->getEnvironment();

  outs() << "[DEBUG STORE FRAME] StoreFrameInst called, stored value tainted: "
         << (isTainted(storedValue) ? "YES" : "NO") << "\n";
  outs() << "[DEBUG STORE FRAME] Variable: " << variable->getName().str().str() << "\n";

  if (isTainted(storedValue)) {
    markFrameTainted(environment, variable, path.front(), newPath);
  }

  if (closureAnalyzer_) {
  }

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
    outs() << "[DEBUG STORE FRAME] Marked StoreFrameInst as tainted and added to worklist\n";
  }
}

void DefUseAnalyzer::handleReturn(
    ReturnInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst)) {
    markTainted(inst, path.front(), newPath);
  }

}

void DefUseAnalyzer::handleUnaryOp(
    Instruction *inst,
    const std::vector<Instruction *> &path) {
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
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::markTainted(
    Value *v,
    Instruction *source,
    const std::vector<Instruction *> &path) {
  auto &info = taintMap_[v];
  info.isTainted = true;
  info.paths.emplace_back(source, path, nullptr);
}

bool DefUseAnalyzer::shouldPropagateTo(Value *v) const {
  return true;
}

bool DefUseAnalyzer::isSink(Instruction *inst) const {
  bool found = sinks_.find(inst) != sinks_.end();
  if (!found && llvh::isa<StorePropertyInst>(inst)) {
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

void DefUseAnalyzer::markPropertyTainted(
    Value *object,
    const std::string &propertyName,
    Instruction *source,
    const std::vector<Instruction *> &path) {
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

  bool foundNewTaint = true;
  int iterations = 0;
  const int maxIterations = 10;

  while (foundNewTaint && iterations < maxIterations) {
    foundNewTaint = false;
    iterations++;

    outs() << "[DEBUG] Property taint iteration " << iterations << "\n";

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

    for (auto *func : functionsToCheck) {
      for (auto &BB : *func) {
        for (auto &inst : BB) {
          if (auto *loadProp = llvh::dyn_cast<LoadPropertyInst>(&inst)) {
            if (auto *propLiteral = llvh::dyn_cast<LiteralString>(loadProp->getProperty())) {
              std::string propName = propLiteral->getValue().str().str();
              Value *object = loadProp->getObject();

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

    if (foundNewTaint) {
      outs() << "[DEBUG] Running additional propagation round...\n";
      propagateTaint();
    }
  }

  outs() << "[DEBUG] Property taint connection check completed after " << iterations << " iterations\n";
}

void DefUseAnalyzer::markFrameTainted(
    Value *environment,
    Variable *variable,
    Instruction *source,
    const std::vector<Instruction *> &path) {
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
  const int maxIterations = 10;

  while (foundNewTaint && iterations < maxIterations) {
    foundNewTaint = false;
    iterations++;

    outs() << "[DEBUG] Frame taint iteration " << iterations << "\n";

     if (!sinks_.empty()) {
       Function *function = (*sinks_.begin())->getParent()->getParent();
       Module *module = function->getParent();

       for (Function &func : *module) {
         for (BasicBlock &BB : func) {
           for (Instruction &I : BB) {
             if (auto *loadFrame = llvh::dyn_cast<LoadFrameInst>(&I)) {
               Variable *variable = loadFrame->getLoadVariable();
               Value *environment = loadFrame->getEnvironment();

               if (isFrameTainted(environment, variable) && !isTainted(loadFrame)) {
                 outs() << "    ✓ Found tainted frame variable! Propagating taint.\n";

                 const auto &frameTaintInfo = getFrameTaintInfo(environment, variable);

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

}
