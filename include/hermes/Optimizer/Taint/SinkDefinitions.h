/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_SINKDEFINITIONS_H
#define HERMES_OPTIMIZER_TAINT_SINKDEFINITIONS_H

#include <string>
#include <unordered_map>
#include <vector>

namespace hermes {

/// Type of sink operation
enum class SinkType {
  Network,      // fetch, XMLHttpRequest, WebSocket, etc.
  Storage,      // localStorage, sessionStorage, IndexedDB
  XSS,          // innerHTML, document.write, eval
  CodeInjection, // eval, Function constructor, setTimeout/setInterval with string
  Navigation,   // location.href, window.open
  Unknown
};

/// Represents a single sink API definition
struct SinkDefinition {
  std::string name;        // API name (e.g., "fetch", "XMLHttpRequest.open")
  SinkType type;           // Type of sink
  int urlArgIndex;         // Index of URL argument (-1 if not applicable)
  int dataArgIndex;        // Index of data argument (-1 if not applicable)
  bool isMethod;           // true for methods, false for properties
  std::string objectName;  // For methods: object name (e.g., "XMLHttpRequest")
  std::string methodName;  // For methods: method name (e.g., "open")

  SinkDefinition(
      std::string n,
      SinkType t,
      int urlIdx = -1,
      int dataIdx = -1,
      bool method = false,
      std::string objName = "",
      std::string methName = "")
      : name(n),
        type(t),
        urlArgIndex(urlIdx),
        dataArgIndex(dataIdx),
        isMethod(method),
        objectName(std::move(objName)),
        methodName(std::move(methName)) {}
};

/// Registry of all known sink APIs
class SinkRegistry {
 public:
  /// Get the singleton instance
  static SinkRegistry &getInstance();

  /// Check if a property access is a sink
  /// \param objectName Name of the object (e.g., "document")
  /// \param propertyName Name of the property (e.g., "innerHTML")
  /// \return Pointer to SinkDefinition if it's a sink, nullptr otherwise
  const SinkDefinition *isPropertySink(
      const std::string &objectName,
      const std::string &propertyName) const;

  /// Check if a method call is a sink
  /// \param objectName Name of the object (e.g., "XMLHttpRequest")
  /// \param methodName Name of the method (e.g., "send")
  /// \return Pointer to SinkDefinition if it's a sink, nullptr otherwise
  const SinkDefinition *isMethodSink(
      const std::string &objectName,
      const std::string &methodName) const;

  /// Check if a global function is a sink
  /// \param functionName Name of the function (e.g., "eval", "fetch")
  /// \return Pointer to SinkDefinition if it's a sink, nullptr otherwise
  const SinkDefinition *isFunctionSink(
      const std::string &functionName) const;

  /// Get all sinks of a specific type
  std::vector<const SinkDefinition *> getSinksByType(SinkType type) const;

  /// Get total number of registered sinks
  size_t getCount() const { return sinks_.size(); }

 private:
  SinkRegistry();
  ~SinkRegistry() = default;

  // Prevent copying
  SinkRegistry(const SinkRegistry &) = delete;
  SinkRegistry &operator=(const SinkRegistry &) = delete;

  /// Initialize all sink definitions
  void initializeSinks();

  /// Add a sink definition
  void addSink(SinkDefinition sink);

  /// Storage for all sink definitions
  std::vector<SinkDefinition> sinks_;

  /// Index: "objectName.propertyName" -> sink definition
  std::unordered_map<std::string, const SinkDefinition *> propertySinkMap_;

  /// Index: "objectName.methodName" -> sink definition
  std::unordered_map<std::string, const SinkDefinition *> methodSinkMap_;

  /// Index: "functionName" -> sink definition
  std::unordered_map<std::string, const SinkDefinition *> functionSinkMap_;
};

} // namespace hermes

#endif // HERMES_OPTIMIZER_TAINT_SINKDEFINITIONS_H
