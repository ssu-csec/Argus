/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_DEFUSEANALYZER_H
#define HERMES_OPTIMIZER_TAINT_DEFUSEANALYZER_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"

#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hermes {

// Forward declarations
class ClosureAnalyzer;
class Value;
class Instruction;
class MovInst;
class PhiInst;
class BinaryOperatorInst;
class CallInst;
class LoadPropertyInst;
class StorePropertyInst;
class LoadFrameInst;
class StoreFrameInst;
class ReturnInst;

/// DefUseAnalyzer: Core taint propagation engine using Hermes IR's
/// built-in def-use chains (Value::getUsers()).
///
/// This class implements a worklist-based algorithm to track how tainted
/// data flows from sources (e.g., navigator.userAgent) to sinks (e.g., fetch()).
///
/// Key features:
/// - Uses Value::getUsers() for efficient def-use traversal
/// - Records full taint propagation paths for detailed reporting
/// - Integrates with ClosureAnalyzer for cross-function analysis
/// - Handles JavaScript-specific patterns (property access, closures, etc.)
class DefUseAnalyzer {
 public:
  /// Represents a single taint propagation path from source to sink
  struct TaintPath {
    Instruction *source;           ///< The source instruction (e.g., LoadProperty)
    std::vector<Instruction *> path; ///< Sequence of instructions in the path
    Instruction *sink;             ///< The sink instruction, or nullptr if not reached

    TaintPath(
        Instruction *src,
        std::vector<Instruction *> p,
        Instruction *snk = nullptr)
        : source(src), path(std::move(p)), sink(snk) {}
  };

  /// Function call information for inter-procedural analysis
  struct FunctionCallMapping {
    CallInst *callSite;
    Function *targetFunction;
    std::vector<Value *> arguments;
  };

  /// Taint information for a single Value
  struct TaintInfo {
    bool isTainted = false;
    std::vector<TaintPath> paths; ///< All paths that tainted this value
  };

  DefUseAnalyzer() = default;
  ~DefUseAnalyzer() = default;

  /// Main analysis entry point.
  /// Analyzes taint flow from sources to sinks using def-use chains.
  ///
  /// \param sources List of source instructions (e.g., LoadPropertyInst for navigator.userAgent)
  /// \param sinks List of sink instructions (e.g., CallInst for fetch())
  /// \param closureAnalyzer Optional closure analyzer for interprocedural analysis
  void analyzeTaintFlow(
      const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks,
      ClosureAnalyzer *closureAnalyzer = nullptr);

  /// Query if a Value is tainted
  bool isTainted(Value *v) const;

  /// Get detailed taint information for a Value
  const TaintInfo &getTaintInfo(Value *v) const;

  /// Get all paths that reached a sink
  const std::vector<TaintPath> &getSinkReachingPaths() const {
    return sinkReachingPaths_;
  }

  /// Reset the analyzer for a new analysis
  void clear();

  /// Set function call mappings for inter-procedural analysis
  void setFunctionCalls(const std::vector<FunctionCallMapping> &calls) {
    functionCalls_ = calls;
  }

  /// Set logger for reporting
  void setLogger(std::function<void(const std::string&)> logger) {
    logger_ = logger;
  }

  /// Mark a Value as tainted and record the path
  void markTainted(
      Value *v,
      Instruction *source,
      const std::vector<Instruction *> &path);

 private:
  std::function<void(const std::string&)> logger_; 

  //===--------------------------------------------------------------------===//
  // Worklist algorithm
  //===--------------------------------------------------------------------===//

  /// Main taint propagation loop
  void propagateTaint();
  
  /// Check for property taint connections (StorePropertyInst -> LoadPropertyInst)
  /// This handles cases where direct DefUse chains don't exist
  void checkPropertyTaintConnections();
  
  /// Check for frame variable taint connections (StoreFrameInst -> LoadFrameInst)
  /// This handles cases where direct DefUse chains don't exist
  void checkFrameTaintConnections();

  /// Add a value to the worklist for processing
  void addToWorklist(Value *v, const std::vector<Instruction *> &path);

  //===--------------------------------------------------------------------===//
  // Per-instruction propagation handlers
  //===--------------------------------------------------------------------===//

  /// Handle MovInst: v1 = mov v0 ⟹ taint(v0) implies taint(v1)
  void handleMovInst(MovInst *inst, const std::vector<Instruction *> &path);

  /// Handle PhiInst: v = phi [v0, BB0], [v1, BB1] ⟹ any tainted implies v tainted
  void handlePhiInst(PhiInst *inst, const std::vector<Instruction *> &path);

  /// Handle BinaryOperatorInst: v = v0 op v1 ⟹ any operand tainted implies v tainted
  void handleBinaryOp(
      BinaryOperatorInst *inst,
      const std::vector<Instruction *> &path);

  /// Handle CallInst: propagate taint to/from function calls
  /// - If callee is known Function: interprocedural analysis
  /// - If callee is unknown: conservative (taint return value)
  void handleCallInst(CallInst *inst, const std::vector<Instruction *> &path);

  /// Handle LoadPropertyInst: v1 = load v0["prop"]
  /// - Taint flows from object or property to loaded value
  void handleLoadProperty(
      LoadPropertyInst *inst,
      const std::vector<Instruction *> &path);

  /// Handle StorePropertyInst: store v0["prop"], v1
  /// - Taint flows from stored value to property storage
  void handleStoreProperty(
      StorePropertyInst *inst,
      const std::vector<Instruction *> &path);

  /// Handle LoadFrameInst: load from closure environment
  /// - Delegates to ClosureAnalyzer for cross-function tracking
  void handleLoadFrame(
      LoadFrameInst *inst,
      const std::vector<Instruction *> &path);

  /// Handle StoreFrameInst: store to closure environment
  /// - Delegates to ClosureAnalyzer for cross-function tracking
  void handleStoreFrame(
      StoreFrameInst *inst,
      const std::vector<Instruction *> &path);

  /// Handle ReturnInst: propagate taint to call sites
  void handleReturn(ReturnInst *inst, const std::vector<Instruction *> &path);

  /// Generic handler for unary operations
  void handleUnaryOp(Instruction *inst, const std::vector<Instruction *> &path);

  /// Generic handler for instructions that propagate taint from operands
  void handleGenericInst(
      Instruction *inst,
      const std::vector<Instruction *> &path);

  //===--------------------------------------------------------------------===//
  // Utility methods
  //===--------------------------------------------------------------------===//

  /// Check if we should continue propagating to this value
  /// (Returns false if already fully analyzed)
  bool shouldPropagateTo(Value *v) const;

  /// Check if an instruction is a sink
  bool isSink(Instruction *inst) const;

  /// Check if an instruction is a source
  bool isSource(Instruction *inst) const;
  
  /// Property taint tracking utilities
  void markPropertyTainted(
      Value *object, 
      const std::string &propertyName,
      Instruction *source,
      const std::vector<Instruction *> &path);
  
  bool isPropertyTainted(Value *object, const std::string &propertyName) const;
  
  const TaintInfo &getPropertyTaintInfo(Value *object, const std::string &propertyName) const;

  /// Frame variable taint tracking utilities
  void markFrameTainted(
      Value *environment,
      Variable *variable,
      Instruction *source,
      const std::vector<Instruction *> &path);
  
  bool isFrameTainted(Value *environment, Variable *variable) const;
  
  const TaintInfo &getFrameTaintInfo(Value *environment, Variable *variable) const;

  //===--------------------------------------------------------------------===//
  // Data structures
  //===--------------------------------------------------------------------===//

  /// Map from Value to its taint information
  std::unordered_map<Value *, TaintInfo> taintMap_;

  /// Worklist of (Value, path) pairs to process
  std::deque<std::pair<Value *, std::vector<Instruction *>>> worklist_;

  /// Set of Values currently in worklist (for O(1) membership check)
  std::unordered_set<Value *> worklistSet_;

  /// All paths that successfully reached a sink
  std::vector<TaintPath> sinkReachingPaths_;

  /// Set of source instructions
  std::unordered_set<Instruction *> sources_;

  /// Set of sink instructions
  std::unordered_set<Instruction *> sinks_;

  /// Optional closure analyzer for interprocedural analysis
  ClosureAnalyzer *closureAnalyzer_ = nullptr;

  /// Function call mappings for inter-procedural analysis
  std::vector<FunctionCallMapping> functionCalls_;
  
  /// Property taint tracking: maps (object, property) pairs to taint info
  /// Key format: "objectAddress:propertyName" (e.g., "0x1234:innerHTML") 
  std::unordered_map<std::string, TaintInfo> propertyTaintMap_;

  /// Frame variable taint tracking: maps (environment, variable) pairs to taint info
  /// Key format: "environmentAddress:variableName" (e.g., "0x5678:ua")
  std::unordered_map<std::string, TaintInfo> frameTaintMap_;

  /// Empty TaintInfo for queries on non-tainted values
  static const TaintInfo emptyTaintInfo_;
};

} // namespace hermes

#endif // HERMES_OPTIMIZER_TAINT_DEFUSEANALYZER_H
