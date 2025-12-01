/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_CLOSUREANALYZER_H
#define HERMES_OPTIMIZER_TAINT_CLOSUREANALYZER_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"

#include <unordered_map>
#include <unordered_set>

namespace hermes {

// Forward declarations
class Variable;
class ScopeCreationInst;
class LoadFrameInst;
class StoreFrameInst;
class CreateFunctionInst;
class Function;

/// ClosureAnalyzer: Tracks taint flow through closure environments.
///
/// JavaScript closures capture variables from outer scopes, and these
/// variables can flow across function boundaries. This analyzer tracks
/// which Variables in which ScopeCreationInsts are tainted, enabling
/// interprocedural taint analysis.
///
/// Key concepts:
/// - Variable: A JavaScript variable (var/let/const) in a scope
/// - ScopeCreationInst: Creates a closure environment (scope)
/// - StoreFrameInst: Stores a value to a Variable in a scope
/// - LoadFrameInst: Loads a value from a Variable in a scope
/// - CreateFunctionInst: Creates a closure that captures an environment
///
/// Example JavaScript:
/// ```javascript
/// function outer() {
///   let x = taintedData;  // StoreFrameInst to Variable 'x'
///   return function inner() {
///     return x;           // LoadFrameInst from Variable 'x'
///   };
/// }
/// ```
///
/// The analyzer tracks that Variable 'x' is tainted in outer's scope,
/// and propagates this information to inner's LoadFrameInst.
class ClosureAnalyzer {
 public:
  ClosureAnalyzer() = default;
  ~ClosureAnalyzer() = default;

  /// Record that a Variable in a specific scope is tainted
  /// Called when a StoreFrameInst stores a tainted value
  ///
  /// \param variable The Variable being stored to
  /// \param scope The ScopeCreationInst (environment) containing the variable
  void markVariableTainted(Variable *variable, ScopeCreationInst *scope);

  /// Check if a Variable in a specific scope is tainted
  /// Called when a LoadFrameInst loads from a variable
  ///
  /// \param variable The Variable being loaded from
  /// \param scope The ScopeCreationInst (environment) containing the variable
  /// \return true if the variable is tainted in this scope
  bool isVariableTainted(Variable *variable, ScopeCreationInst *scope) const;

  /// Record that a StoreFrameInst stores a tainted value
  /// This is used by DefUseAnalyzer to inform the ClosureAnalyzer
  ///
  /// \param store The StoreFrameInst that stores tainted data
  void recordTaintedStore(StoreFrameInst *store);

  /// Get all LoadFrameInsts that may load tainted data
  /// This is used by DefUseAnalyzer to continue propagation
  ///
  /// \param variable The Variable to check
  /// \param scope The ScopeCreationInst containing the variable
  /// \return Set of LoadFrameInsts that load from this tainted variable
  std::unordered_set<LoadFrameInst *> getTaintedLoads(
      Variable *variable,
      ScopeCreationInst *scope) const;

  /// Analyze all closures in a Function to find Variable flows
  /// This builds the mapping from StoreFrameInst to LoadFrameInst
  ///
  /// \param func The Function to analyze
  void analyzeFunctionClosures(Function *func);

  /// Analyze all closures in a Module
  /// This should be called once before taint analysis
  ///
  /// \param module The Module containing all functions
  void analyzeModuleClosures(Module *module);

  /// Clear all analysis results
  void clear();

  /// Get statistics about closure analysis
  struct Statistics {
    size_t numTaintedVariables;
    size_t numTrackedScopes;
    size_t numStoreFrameInsts;
    size_t numLoadFrameInsts;
  };
  Statistics getStatistics() const;

 private:
  /// Key for identifying a specific Variable in a specific scope
  struct VariableScopeKey {
    Variable *variable;
    ScopeCreationInst *scope;

    bool operator==(const VariableScopeKey &other) const {
      return variable == other.variable && scope == other.scope;
    }
  };

  /// Hash function for VariableScopeKey
  struct VariableScopeKeyHash {
    size_t operator()(const VariableScopeKey &key) const {
      return std::hash<void *>()(key.variable) ^
          (std::hash<void *>()(key.scope) << 1);
    }
  };

  //===--------------------------------------------------------------------===//
  // Helper methods
  //===--------------------------------------------------------------------===//

  /// Build the mapping from Variables to their LoadFrameInsts
  void buildVariableLoadMap(Function *func);

  /// Build the mapping from Variables to their StoreFrameInsts
  void buildVariableStoreMap(Function *func);

  /// Process a CreateFunctionInst to track captured environments
  void processCreateFunction(CreateFunctionInst *createFunc);

  //===--------------------------------------------------------------------===//
  // Data structures
  //===--------------------------------------------------------------------===//

  /// Set of (Variable, Scope) pairs that are tainted
  std::unordered_set<VariableScopeKey, VariableScopeKeyHash>
      taintedVariables_;

  /// Map from (Variable, Scope) to all LoadFrameInsts that load from it
  /// This is built during analyzeModuleClosures() and queried during taint
  /// analysis
  std::unordered_map<
      VariableScopeKey,
      std::unordered_set<LoadFrameInst *>,
      VariableScopeKeyHash>
      variableLoads_;

  /// Map from (Variable, Scope) to all StoreFrameInsts that store to it
  /// This is used for tracking where taint originates
  std::unordered_map<
      VariableScopeKey,
      std::unordered_set<StoreFrameInst *>,
      VariableScopeKeyHash>
      variableStores_;

  /// Map from CreateFunctionInst to the environment it captures
  /// This tracks closure creation
  std::unordered_map<CreateFunctionInst *, ScopeCreationInst *>
      closureEnvironments_;
};

} // namespace hermes

#endif // HERMES_OPTIMIZER_TAINT_CLOSUREANALYZER_H
