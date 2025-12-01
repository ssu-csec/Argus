/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_SOURCEDEFINITIONS_H
#define HERMES_OPTIMIZER_TAINT_SOURCEDEFINITIONS_H

#include <set>
#include <string>
#include <vector>
#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {
namespace taint {
// Source API의 종류
enum class SourceType {
  // Property 접근: navigator.userAgent
  PROPERTY_ACCESS,

  // 메서드 호출: Date.now()
  METHOD_CALL,

  // Constructor: new Date()
  CONSTRUCTION,

  // 이벤트 데이터: event.clientX
  EVENT_DATA,

  // 전역 함수: getSelection()
  GLOBAL_FUNCTION
};

// Source API가 반환하는 값의 종류
enum class ReturnKind {
  // Primitive 타입 (string, number, boolean)
  PRIMITIVE,

  // Object 타입 (전체가 sensitive)
  OBJECT,

  // Array 타입
  ARRAY,

  // Promise (비동기 처리 필요)
  PROMISE,

  // Function (closure 분석 필요)
  FUNCTION
};

// 하나의 Source API 정의
struct SourceDefinition {
  // API 전체 이름 (예: navigator.userAgent)
  std::string fullName;

  // source 타입
  SourceType type;

  // 객체 이름 (예: "navigator")
  std::string objectName;

  // Property/Method 이름 (예: "userAgent")
  std::string propertyName;

  // 반환값 종류
  ReturnKind returnKind;

  // 메서드인지 여부
  bool isMethod;

  // 비동기 여부
  bool isAsync;

  // 중첩된 property 경로 (예: navigator.userAgentData.brands)
  llvh::SmallVector<std::string, 4> nestedPath;

  SourceDefinition(
      llvh::StringRef fullName,
      SourceType type,
      llvh::StringRef objectName,
      llvh::StringRef propertyName,
      ReturnKind returnKind,
      bool isMethod = false,
      bool isAsync = false)
      : fullName(fullName.str()),
        type(type),
        objectName(objectName.str()),
        propertyName(propertyName.str()),
        returnKind(returnKind),
        isMethod(isMethod),
        isAsync(isAsync) {}
};

// Source API 레지스트리 (Singleton)
class SourceRegistry {
 private:
  // 모든 source 정의
  std::vector<SourceDefinition> sources_;

  // property -> source 빠른 검색
  llvh::DenseMap<llvh::StringRef, std::vector<const SourceDefinition *>>
      propertyMap_;

  // object -> source 빠른 검색
  llvh::DenseMap<llvh::StringRef, std::vector<const SourceDefinition *>>
      objectMap_;

  // 이벤트 타입 목록
  std::set<std::string> eventType_;

  // 이벤트 데이터 property 목록
  std::set<std::string> eventDataProps_;

  SourceRegistry(); // Private constructor

  void initializeSources();
  void initializeEventTypes();
  void initializeEventData();
  void buildMaps();

 public:
  static SourceRegistry &getInstance();

  // LoadPropertyInst가 source API인지 확인
  bool isSourceProperty(LoadPropertyInst *LPI) const;

  /// CallInst가 source API인지 확인
  bool isSourceCall(CallInst *CI) const;

  /// ConstructInst가 source API인지 확인
  bool isSourceConstructor(ConstructInst *CI) const;

  /// Property 이름으로 source 정의 조회
  const std::vector<const SourceDefinition *> *getSourcesByProperty(
      llvh::StringRef propName) const;

  /// Object 이름으로 source 정의 조회
  const std::vector<const SourceDefinition *> *getSourcesByObject(
      llvh::StringRef objName) const;

  /// 이벤트 타입인지 확인 (click, keydown 등)
  bool isEventType(llvh::StringRef eventName) const;

  /// 이벤트 데이터 property인지 확인 (clientX, keyCode 등)
  bool isEventDataProperty(llvh::StringRef propName) const;

  /// API 전체 이름으로 source 정의 조회
  const SourceDefinition *getSourceByFullName(llvh::StringRef fullName) const;

  /// 모든 source 목록 반환
  const std::vector<SourceDefinition> &getAllSources() const {
    return sources_;
  }
};

} // namespace taint
} // namespace hermes

#endif // HERMES_OPTIMIZER_TAINT_SOURCEDEFINITIONS_H