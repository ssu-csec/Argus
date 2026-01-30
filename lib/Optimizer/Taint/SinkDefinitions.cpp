/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Optimizer/Taint/SinkDefinitions.h"

#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"

#define DEBUG_TYPE "sink-registry"

using llvh::dbgs;

namespace hermes {

//===----------------------------------------------------------------------===//
// SinkRegistry Implementation
//===----------------------------------------------------------------------===//

SinkRegistry &SinkRegistry::getInstance() {
  static SinkRegistry instance;
  return instance;
}

SinkRegistry::SinkRegistry() {
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Initializing sink definitions...\n");
  
  // Reserve space to prevent vector reallocation and pointer invalidation
  sinks_.reserve(50);  // Reserve space for ~50 sinks
  
  initializeSinks();
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Initialized " << sinks_.size() 
                    << " sink definitions\n");
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Property sink map size: " 
                    << propertySinkMap_.size() << "\n");
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Method sink map size: " 
                    << methodSinkMap_.size() << "\n");
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Function sink map size: " 
                    << functionSinkMap_.size() << "\n");
  
  // Debug: Print all property sinks
  LLVM_DEBUG({
    dbgs() << "[SinkRegistry] Property sinks:\n";
    for (const auto &pair : propertySinkMap_) {
      dbgs() << "  '" << pair.first << "' -> " << pair.second->name << "\n";
    }
  });
}

void SinkRegistry::initializeSinks() {
  // Network Sinks
  addSink(SinkDefinition(
      "fetch", SinkType::Network, 0 /* url */, 1 /* data */, false));
  addSink(SinkDefinition(
      "XMLHttpRequest.open",
      SinkType::Network,
      1 /* url */,
      -1,
      true,
      "XMLHttpRequest",
      "open"));
  addSink(SinkDefinition(
      "XMLHttpRequest.send",
      SinkType::Network,
      -1,
      0 /* data */,
      true,
      "XMLHttpRequest",
      "send"));
  addSink(SinkDefinition(
      "XMLHttpRequest.setRequestHeader",
      SinkType::Network,
      -1,
      1 /* value */,
      true,
      "XMLHttpRequest",
      "setRequestHeader"));
  addSink(SinkDefinition(
      "navigator.sendBeacon",
      SinkType::Network,
      0 /* url */,
      1 /* data */,
      true,
      "navigator",
      "sendBeacon"));

  // Storage Sinks
  addSink(SinkDefinition(
      "localStorage.setItem",
      SinkType::Storage,
      -1,
      1 /* value */,
      true,
      "localStorage",
      "setItem"));
  addSink(SinkDefinition(
      "sessionStorage.setItem",
      SinkType::Storage,
      -1,
      1 /* value */,
      true,
      "sessionStorage",
      "setItem"));
  addSink(SinkDefinition(
      "document.cookie", SinkType::Storage, -1, 0 /* value */, false));

  // XSS Sinks
  addSink(SinkDefinition(
      "document.write",
      SinkType::XSS,
      -1,
      0 /* html */,
      true,
      "document",
      "write"));
  addSink(SinkDefinition(
      "document.writeln",
      SinkType::XSS,
      -1,
      0 /* html */,
      true,
      "document",
      "writeln"));
  addSink(
      SinkDefinition("innerHTML", SinkType::XSS, -1, 0 /* value */, false));
  addSink(
      SinkDefinition("outerHTML", SinkType::XSS, -1, 0 /* value */,false));

  // Code Injection Sinks
  addSink(SinkDefinition(
      "eval", SinkType::CodeInjection, -1, 0 /* code */, false));
  addSink(SinkDefinition(
      "Function", SinkType::CodeInjection, -1, 0 /* code */, false));
  addSink(SinkDefinition(
      "setTimeout",
      SinkType::CodeInjection,
      -1,
      0 /* code */,
      false));
  addSink(SinkDefinition(
      "setInterval",
      SinkType::CodeInjection,
      -1,
      0 /* code */,
      false));

  // Navigation Sinks
  addSink(SinkDefinition(
      "location.href", SinkType::Navigation, -1, 0 /* url */, false));
  addSink(SinkDefinition(
      "location.assign",
      SinkType::Navigation,
      -1,
      0 /* url */,
      true,
      "location",
      "assign"));
  addSink(SinkDefinition(
      "location.replace",
      SinkType::Navigation,
      -1,
      0 /* url */,
      true,
      "location",
      "replace"));
  addSink(SinkDefinition(
      "window.open",
      SinkType::Navigation,
      0 /* url */,
      -1,
      true,
      "window",
      "open"));
   addSink(SinkDefinition(
      "src", 
      SinkType::Network, 
      -1, 
      0 /* value */, 
      false));

  // [추가] WebSocket (실시간 데이터 유출 통로)
   addSink(SinkDefinition(
      "WebSocket.send",
      SinkType::Network,
      -1,
      0 /* data */,
      true,
      "WebSocket",
      "send"));   
}

void SinkRegistry::addSink(SinkDefinition sink) {
  LLVM_DEBUG(dbgs() << "[addSink] Adding sink: '" << sink.name << "' type=" 
                    << (int)sink.type << " method=" << sink.isMethod << "\n");
  sinks_.push_back(std::move(sink));
  const SinkDefinition *def = &sinks_.back();
  LLVM_DEBUG(dbgs() << "[addSink] After move, name: '" << def->name << "'\n");

  if (def->isMethod) {
    // For methods: "objectName.methodName"
    std::string key = def->objectName + "." + def->methodName;
    methodSinkMap_[key] = def;
  } else {
    // For properties and functions
    if (def->objectName.empty()) {
      // Could be global function or generic property
      functionSinkMap_[def->name] = def;
      // Also add to property map for generic properties like "innerHTML"
      LLVM_DEBUG(dbgs() << "[addSink] Adding to property map: '" << def->name << "'\n");
      propertySinkMap_[def->name] = def;
    } else {
      // Property (e.g., "document.cookie") 
      std::string key = def->objectName + "." + def->name;
      propertySinkMap_[key] = def;
    }
  }
}

const SinkDefinition *SinkRegistry::isPropertySink(
    const std::string &objectName,
    const std::string &propertyName) const {
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Checking property sink: '" 
                    << objectName << "." << propertyName << "'\n");
  
  // Try object-specific property first
  std::string key = objectName + "." + propertyName;
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Looking for key: '" << key << "'\n");
  auto it = propertySinkMap_.find(key);
  if (it != propertySinkMap_.end()) {
    LLVM_DEBUG(dbgs() << "[SinkRegistry] Found object-specific sink: " 
                      << it->second->name << "\n");
    return it->second;
  }

  // Try generic property name (e.g., "innerHTML" works on any element)
  LLVM_DEBUG(dbgs() << "[SinkRegistry] Looking for generic property: '" 
                    << propertyName << "'\n");
  auto it2 = propertySinkMap_.find(propertyName);
  if (it2 != propertySinkMap_.end()) {
    LLVM_DEBUG(dbgs() << "[SinkRegistry] Found generic sink: " 
                      << it2->second->name << "\n");
    return it2->second;
  }

  LLVM_DEBUG(dbgs() << "[SinkRegistry] No sink found for '" 
                    << objectName << "." << propertyName << "'\n");
  return nullptr;
}

const SinkDefinition *SinkRegistry::isMethodSink(
    const std::string &objectName,
    const std::string &methodName) const {
  std::string key = objectName + "." + methodName;
  auto it = methodSinkMap_.find(key);
  if (it != methodSinkMap_.end()) {
    return it->second;
  }
  return nullptr;
}

const SinkDefinition *SinkRegistry::isFunctionSink(
    const std::string &functionName) const {
  auto it = functionSinkMap_.find(functionName);
  if (it != functionSinkMap_.end()) {
    return it->second;
  }
  return nullptr;
}

std::vector<const SinkDefinition *> SinkRegistry::getSinksByType(
    SinkType type) const {
  std::vector<const SinkDefinition *> result;
  for (const auto &sink : sinks_) {
    if (sink.type == type) {
      result.push_back(&sink);
    }
  }
  return result;
}

} // namespace hermes

#undef DEBUG_TYPE
