/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Optimizer/Taint/SourceDefinitions.h"
#include "llvh/Support/Casting.h"

using namespace hermes;
using namespace hermes::taint;

//===----------------------------------------------------------------------===//
// SourceRegistry Implementation
//===----------------------------------------------------------------------===//

SourceRegistry &SourceRegistry::getInstance() {
  static SourceRegistry instance;
  return instance;
}

SourceRegistry::SourceRegistry() {
  initializeSources();
  initializeEventTypes();
  initializeEventData();
  buildMaps();
}

void SourceRegistry::initializeSources() {
  // ===== Navigator Sources =====
  // User-Agent and Browser Information
  sources_.emplace_back(
      "navigator.userAgent",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "userAgent",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.appVersion",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "appVersion",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.platform",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "platform",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.language",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "language",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.languages",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "languages",
      ReturnKind::ARRAY);
  sources_.emplace_back(
      "navigator.vendor",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "vendor",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.vendorSub",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "vendorSub",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.product",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "product",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.productSub",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "productSub",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.oscpu",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "oscpu",
      ReturnKind::PRIMITIVE);

  // Hardware and Device Information
  sources_.emplace_back(
      "navigator.hardwareConcurrency",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "hardwareConcurrency",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.deviceMemory",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "deviceMemory",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "navigator.maxTouchPoints",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "maxTouchPoints",
      ReturnKind::PRIMITIVE);

  // Geolocation
  sources_.emplace_back(
      "navigator.geolocation",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "geolocation",
      ReturnKind::OBJECT);

  // Plugins and Media Devices
  sources_.emplace_back(
      "navigator.plugins",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "plugins",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "navigator.mimeTypes",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "mimeTypes",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "navigator.mediaDevices",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "mediaDevices",
      ReturnKind::OBJECT);

  // ===== Screen Sources =====
  sources_.emplace_back(
      "screen.width",
      SourceType::PROPERTY_ACCESS,
      "screen",
      "width",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "screen.height",
      SourceType::PROPERTY_ACCESS,
      "screen",
      "height",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "screen.availWidth",
      SourceType::PROPERTY_ACCESS,
      "screen",
      "availWidth",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "screen.availHeight",
      SourceType::PROPERTY_ACCESS,
      "screen",
      "availHeight",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "screen.colorDepth",
      SourceType::PROPERTY_ACCESS,
      "screen",
      "colorDepth",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "screen.pixelDepth",
      SourceType::PROPERTY_ACCESS,
      "screen",
      "pixelDepth",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "screen.orientation",
      SourceType::PROPERTY_ACCESS,
      "screen",
      "orientation",
      ReturnKind::OBJECT);

  // ===== Document Sources (Read) =====
  sources_.emplace_back(
      "document.cookie",
      SourceType::PROPERTY_ACCESS,
      "document",
      "cookie",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "document.referrer",
      SourceType::PROPERTY_ACCESS,
      "document",
      "referrer",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "document.domain",
      SourceType::PROPERTY_ACCESS,
      "document",
      "domain",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "document.URL",
      SourceType::PROPERTY_ACCESS,
      "document",
      "URL",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "document.documentURI",
      SourceType::PROPERTY_ACCESS,
      "document",
      "documentURI",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "document.title",
      SourceType::PROPERTY_ACCESS,
      "document",
      "title",
      ReturnKind::PRIMITIVE);

  // ===== Location Sources =====
  sources_.emplace_back(
      "location.href",
      SourceType::PROPERTY_ACCESS,
      "location",
      "href",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.protocol",
      SourceType::PROPERTY_ACCESS,
      "location",
      "protocol",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.host",
      SourceType::PROPERTY_ACCESS,
      "location",
      "host",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.hostname",
      SourceType::PROPERTY_ACCESS,
      "location",
      "hostname",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.port",
      SourceType::PROPERTY_ACCESS,
      "location",
      "port",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.pathname",
      SourceType::PROPERTY_ACCESS,
      "location",
      "pathname",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.search",
      SourceType::PROPERTY_ACCESS,
      "location",
      "search",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.hash",
      SourceType::PROPERTY_ACCESS,
      "location",
      "hash",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "location.origin",
      SourceType::PROPERTY_ACCESS,
      "location",
      "origin",
      ReturnKind::PRIMITIVE);

  // ===== Window Sources =====
  sources_.emplace_back(
      "window.name",
      SourceType::PROPERTY_ACCESS,
      "window",
      "name",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "window.origin",
      SourceType::PROPERTY_ACCESS,
      "window",
      "origin",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "window.innerWidth",
      SourceType::PROPERTY_ACCESS,
      "window",
      "innerWidth",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "window.innerHeight",
      SourceType::PROPERTY_ACCESS,
      "window",
      "innerHeight",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "window.outerWidth",
      SourceType::PROPERTY_ACCESS,
      "window",
      "outerWidth",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "window.outerHeight",
      SourceType::PROPERTY_ACCESS,
      "window",
      "outerHeight",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "window.devicePixelRatio",
      SourceType::PROPERTY_ACCESS,
      "window",
      "devicePixelRatio",
      ReturnKind::PRIMITIVE);

  // ===== Storage Sources (Read) =====
  sources_.emplace_back(
      "localStorage.getItem",
      SourceType::METHOD_CALL,
      "localStorage",
      "getItem",
      ReturnKind::PRIMITIVE,
      true);
  sources_.emplace_back(
      "sessionStorage.getItem",
      SourceType::METHOD_CALL,
      "sessionStorage",
      "getItem",
      ReturnKind::PRIMITIVE,
      true);

  // ===== Date/Time Sources =====
  sources_.emplace_back(
      "Date.now",
      SourceType::METHOD_CALL,
      "Date",
      "now",
      ReturnKind::PRIMITIVE,
      true);
  sources_.emplace_back(
      "Date", SourceType::CONSTRUCTION, "Date", "", ReturnKind::OBJECT);

  // ===== Performance Sources =====
  sources_.emplace_back(
      "performance.now",
      SourceType::METHOD_CALL,
      "performance",
      "now",
      ReturnKind::PRIMITIVE,
      true);
  sources_.emplace_back(
      "performance.timing",
      SourceType::PROPERTY_ACCESS,
      "performance",
      "timing",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "performance.navigation",
      SourceType::PROPERTY_ACCESS,
      "performance",
      "navigation",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "performance.memory",
      SourceType::PROPERTY_ACCESS,
      "performance",
      "memory",
      ReturnKind::OBJECT);

  // ===== Network/Fetch Sources =====
  sources_.emplace_back(
      "fetch",
      SourceType::GLOBAL_FUNCTION,
      "",
      "fetch",
      ReturnKind::PROMISE,
      true,
      true);
  sources_.emplace_back(
      "XMLHttpRequest.responseText",
      SourceType::PROPERTY_ACCESS,
      "XMLHttpRequest",
      "responseText",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "XMLHttpRequest.response",
      SourceType::PROPERTY_ACCESS,
      "XMLHttpRequest",
      "response",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "XMLHttpRequest.getResponseHeader",
      SourceType::METHOD_CALL,
      "XMLHttpRequest",
      "getResponseHeader",
      ReturnKind::PRIMITIVE,
      true);

  // ===== Selection Sources =====
  sources_.emplace_back(
      "window.getSelection",
      SourceType::METHOD_CALL,
      "window",
      "getSelection",
      ReturnKind::OBJECT,
      true);
  sources_.emplace_back(
      "document.getSelection",
      SourceType::METHOD_CALL,
      "document",
      "getSelection",
      ReturnKind::OBJECT,
      true);

  // ===== Clipboard Sources =====
  sources_.emplace_back(
      "navigator.clipboard.readText",
      SourceType::METHOD_CALL,
      "clipboard",
      "readText",
      ReturnKind::PROMISE,
      true,
      true);
  sources_.emplace_back(
      "navigator.clipboard.read",
      SourceType::METHOD_CALL,
      "clipboard",
      "read",
      ReturnKind::PROMISE,
      true,
      true);

  // ===== History Sources =====
  sources_.emplace_back(
      "history.length",
      SourceType::PROPERTY_ACCESS,
      "history",
      "length",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "history.state",
      SourceType::PROPERTY_ACCESS,
      "history",
      "state",
      ReturnKind::OBJECT);

  // ===== IndexedDB Sources =====
  sources_.emplace_back(
      "indexedDB.open",
      SourceType::METHOD_CALL,
      "indexedDB",
      "open",
      ReturnKind::OBJECT,
      true);

  // ===== WebSocket Sources =====
  sources_.emplace_back(
      "WebSocket",
      SourceType::CONSTRUCTION,
      "WebSocket",
      "",
      ReturnKind::OBJECT);

  // ===== Canvas Fingerprinting Sources =====
  sources_.emplace_back(
      "CanvasRenderingContext2D.getImageData",
      SourceType::METHOD_CALL,
      "CanvasRenderingContext2D",
      "getImageData",
      ReturnKind::OBJECT,
      true);
  sources_.emplace_back(
      "HTMLCanvasElement.toDataURL",
      SourceType::METHOD_CALL,
      "HTMLCanvasElement",
      "toDataURL",
      ReturnKind::PRIMITIVE,
      true);
  sources_.emplace_back(
      "HTMLCanvasElement.toBlob",
      SourceType::METHOD_CALL,
      "HTMLCanvasElement",
      "toBlob",
      ReturnKind::PROMISE,
      true,
      true);

  // ===== WebGL Fingerprinting Sources =====
  sources_.emplace_back(
      "WebGLRenderingContext.getParameter",
      SourceType::METHOD_CALL,
      "WebGLRenderingContext",
      "getParameter",
      ReturnKind::PRIMITIVE,
      true);
  sources_.emplace_back(
      "WebGLRenderingContext.getSupportedExtensions",
      SourceType::METHOD_CALL,
      "WebGLRenderingContext",
      "getSupportedExtensions",
      ReturnKind::ARRAY,
      true);

  // ===== AudioContext Fingerprinting Sources =====
  sources_.emplace_back(
      "AudioContext",
      SourceType::CONSTRUCTION,
      "AudioContext",
      "",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "AudioContext.createOscillator",
      SourceType::METHOD_CALL,
      "AudioContext",
      "createOscillator",
      ReturnKind::OBJECT,
      true);

  // ===== Battery API Sources =====
  sources_.emplace_back(
      "navigator.getBattery",
      SourceType::METHOD_CALL,
      "navigator",
      "getBattery",
      ReturnKind::PROMISE,
      true,
      true);

  // ===== Connection API Sources =====
  sources_.emplace_back(
      "navigator.connection",
      SourceType::PROPERTY_ACCESS,
      "navigator",
      "connection",
      ReturnKind::OBJECT);

  // ===== MediaDevices Sources =====
  sources_.emplace_back(
      "navigator.mediaDevices.enumerateDevices",
      SourceType::METHOD_CALL,
      "mediaDevices",
      "enumerateDevices",
      ReturnKind::PROMISE,
      true,
      true);
  sources_.emplace_back(
      "navigator.mediaDevices.getUserMedia",
      SourceType::METHOD_CALL,
      "mediaDevices",
      "getUserMedia",
      ReturnKind::PROMISE,
      true,
      true);

  // ===== Gamepad API Sources =====
  sources_.emplace_back(
      "navigator.getGamepads",
      SourceType::METHOD_CALL,
      "navigator",
      "getGamepads",
      ReturnKind::ARRAY,
      true);

  // ===== Notification API Sources =====
  sources_.emplace_back(
      "Notification.permission",
      SourceType::PROPERTY_ACCESS,
      "Notification",
      "permission",
      ReturnKind::PRIMITIVE);

  // ===== Sensor API Sources =====
  sources_.emplace_back(
      "DeviceOrientationEvent",
      SourceType::CONSTRUCTION,
      "DeviceOrientationEvent",
      "",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "DeviceMotionEvent",
      SourceType::CONSTRUCTION,
      "DeviceMotionEvent",
      "",
      ReturnKind::OBJECT);

  // ===== PostMessage Sources =====
  sources_.emplace_back(
      "MessageEvent.data",
      SourceType::PROPERTY_ACCESS,
      "MessageEvent",
      "data",
      ReturnKind::OBJECT);
  sources_.emplace_back(
      "MessageEvent.origin",
      SourceType::PROPERTY_ACCESS,
      "MessageEvent",
      "origin",
      ReturnKind::PRIMITIVE);

  // ===== Form Input Sources =====
  sources_.emplace_back(
      "HTMLInputElement.value",
      SourceType::PROPERTY_ACCESS,
      "HTMLInputElement",
      "value",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "HTMLTextAreaElement.value",
      SourceType::PROPERTY_ACCESS,
      "HTMLTextAreaElement",
      "value",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "HTMLSelectElement.value",
      SourceType::PROPERTY_ACCESS,
      "HTMLSelectElement",
      "value",
      ReturnKind::PRIMITIVE);

  // ===== File API Sources =====
  sources_.emplace_back(
      "FileReader.result",
      SourceType::PROPERTY_ACCESS,
      "FileReader",
      "result",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "File.name",
      SourceType::PROPERTY_ACCESS,
      "File",
      "name",
      ReturnKind::PRIMITIVE);
  sources_.emplace_back(
      "File.size",
      SourceType::PROPERTY_ACCESS,
      "File",
      "size",
      ReturnKind::PRIMITIVE);

  // ===== Crypto Sources =====
  sources_.emplace_back(
      "crypto.getRandomValues",
      SourceType::METHOD_CALL,
      "crypto",
      "getRandomValues",
      ReturnKind::OBJECT,
      true);
  sources_.emplace_back(
      "crypto.randomUUID",
      SourceType::METHOD_CALL,
      "crypto",
      "randomUUID",
      ReturnKind::PRIMITIVE,
      true);
}

void SourceRegistry::initializeEventTypes() {
  // Mouse Events
  eventType_.insert("click");
  eventType_.insert("dblclick");
  eventType_.insert("mousedown");
  eventType_.insert("mouseup");
  eventType_.insert("mousemove");
  eventType_.insert("mouseenter");
  eventType_.insert("mouseleave");
  eventType_.insert("mouseover");
  eventType_.insert("mouseout");
  eventType_.insert("contextmenu");

  // Keyboard Events
  eventType_.insert("keydown");
  eventType_.insert("keyup");
  eventType_.insert("keypress");

  // Form Events
  eventType_.insert("submit");
  eventType_.insert("input");
  eventType_.insert("change");
  eventType_.insert("focus");
  eventType_.insert("blur");

  // Touch Events
  eventType_.insert("touchstart");
  eventType_.insert("touchend");
  eventType_.insert("touchmove");
  eventType_.insert("touchcancel");

  // Drag Events
  eventType_.insert("drag");
  eventType_.insert("dragstart");
  eventType_.insert("dragend");
  eventType_.insert("dragenter");
  eventType_.insert("dragleave");
  eventType_.insert("dragover");
  eventType_.insert("drop");

  // Clipboard Events
  eventType_.insert("copy");
  eventType_.insert("cut");
  eventType_.insert("paste");

  // Network Events
  eventType_.insert("online");
  eventType_.insert("offline");

  // Message Events
  eventType_.insert("message");
  eventType_.insert("messageerror");

  // Storage Events
  eventType_.insert("storage");

  // Device Events
  eventType_.insert("deviceorientation");
  eventType_.insert("devicemotion");
}

void SourceRegistry::initializeEventData() {
  // Mouse Event Properties
  eventDataProps_.insert("clientX");
  eventDataProps_.insert("clientY");
  eventDataProps_.insert("screenX");
  eventDataProps_.insert("screenY");
  eventDataProps_.insert("pageX");
  eventDataProps_.insert("pageY");
  eventDataProps_.insert("offsetX");
  eventDataProps_.insert("offsetY");
  eventDataProps_.insert("button");
  eventDataProps_.insert("buttons");
  eventDataProps_.insert("relatedTarget");

  // Keyboard Event Properties
  eventDataProps_.insert("key");
  eventDataProps_.insert("code");
  eventDataProps_.insert("keyCode");
  eventDataProps_.insert("charCode");
  eventDataProps_.insert("which");
  eventDataProps_.insert("altKey");
  eventDataProps_.insert("ctrlKey");
  eventDataProps_.insert("shiftKey");
  eventDataProps_.insert("metaKey");

  // Touch Event Properties
  eventDataProps_.insert("touches");
  eventDataProps_.insert("targetTouches");
  eventDataProps_.insert("changedTouches");

  // Drag Event Properties
  eventDataProps_.insert("dataTransfer");

  // Clipboard Event Properties
  eventDataProps_.insert("clipboardData");

  // Generic Event Properties
  eventDataProps_.insert("target");
  eventDataProps_.insert("currentTarget");
  eventDataProps_.insert("type");
  eventDataProps_.insert("timeStamp");
  eventDataProps_.insert("data");
  eventDataProps_.insert("origin");
  eventDataProps_.insert("source");
}

void SourceRegistry::buildMaps() {
  for (const auto &source : sources_) {
    // Build property map
    if (!source.propertyName.empty()) {
      propertyMap_[source.propertyName].push_back(&source);
    }

    // Build object map
    if (!source.objectName.empty()) {
      objectMap_[source.objectName].push_back(&source);
    }
  }
}

bool SourceRegistry::isSourceProperty(LoadPropertyInst *LPI) const {
  // TODO: Implement proper object tracking
  // For now, do simple property name matching
  if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
    llvh::StringRef propName = litProp->getValue().str();
    return propertyMap_.count(propName) > 0;
  }
  return false;
}

bool SourceRegistry::isSourceCall(CallInst *CI) const {
  // TODO: Implement proper call target analysis
  // Check if it's a method call on a known source object
  return false;
}

bool SourceRegistry::isSourceConstructor(ConstructInst *CI) const {
  // TODO: Implement constructor tracking
  // Check if the constructor is for a known source type
  return false;
}

const std::vector<const SourceDefinition *> *SourceRegistry::getSourcesByProperty(
    llvh::StringRef propName) const {
  auto it = propertyMap_.find(propName);
  if (it != propertyMap_.end()) {
    return &it->second;
  }
  return nullptr;
}

const std::vector<const SourceDefinition *> *SourceRegistry::getSourcesByObject(
    llvh::StringRef objName) const {
  auto it = objectMap_.find(objName);
  if (it != objectMap_.end()) {
    return &it->second;
  }
  return nullptr;
}

bool SourceRegistry::isEventType(llvh::StringRef eventName) const {
  return eventType_.count(eventName.str()) > 0;
}

bool SourceRegistry::isEventDataProperty(llvh::StringRef propName) const {
  return eventDataProps_.count(propName.str()) > 0;
}

const SourceDefinition *SourceRegistry::getSourceByFullName(
    llvh::StringRef fullName) const {
  for (const auto &source : sources_) {
    if (source.fullName == fullName.str()) {
      return &source;
    }
  }
  return nullptr;
}
