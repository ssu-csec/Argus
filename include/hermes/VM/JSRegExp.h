/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSREGEXP_H
#define HERMES_VM_JSREGEXP_H

#include "hermes/Regex/Regex.h"
#include "hermes/Regex/RegexTypes.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/RegExpMatch.h"
#include "hermes/VM/SmallXString.h"

#include <memory>
#include "llvh/ADT/SmallString.h"

namespace hermes {
namespace vm {

class JSRegExp final : public JSObject {
 public:
  using Super = JSObject;
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSRegExpKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSRegExpKind;
  }

                                                                     
  static PseudoHandle<JSRegExp> create(
      Runtime &runtime,
      Handle<JSObject> prototype);

                                                                                
                            
  static PseudoHandle<JSRegExp> create(Runtime &runtime) {
    return create(runtime, Handle<JSObject>::vmcast(&runtime.regExpPrototype));
  }

                                                                    
                                                                              
                                                               
  static Handle<HiddenClass> createMatchClass(
      Runtime &runtime,
      Handle<HiddenClass> arrayClass);

                                                                         
                                                                               
                                                                         
  static void initialize(
      Handle<JSRegExp> selfHandle,
      Runtime &runtime,
      Handle<StringPrimitive> pattern,
      Handle<StringPrimitive> flags,
      llvh::ArrayRef<uint8_t> bytecode);

                                                                             
                                                                        
                                               
  static ExecutionStatus initialize(
      Handle<JSRegExp> selfHandle,
      Runtime &runtime,
      Handle<JSRegExp> otherHandle,
      Handle<StringPrimitive> flags);

                                                                             
                                                                             
                                                                             
                                                                             
                                                              
  static ExecutionStatus initialize(
      Handle<JSRegExp> selfHandle,
      Runtime &runtime,
      Handle<StringPrimitive> pattern,
      Handle<StringPrimitive> flags);

                                                                
                                                                     
                                                                              
  static PseudoHandle<StringPrimitive> getPattern(
      JSRegExp *self,
      PointerBase &base);

                                                                                
                                                   
  static CallResult<HermesValue> escapePattern(
      Handle<StringPrimitive> pattern,
      Runtime &runtime);

                                                          
  static regex::SyntaxFlags getSyntaxFlags(JSRegExp *self) {
    return self->syntaxFlags_;
  }

                                                   
  static void setSyntaxFlags(JSRegExp *self, regex::SyntaxFlags flags) {
    self->syntaxFlags_ = flags;
  }

  Handle<JSObject> getGroupNameMappings(Runtime &runtime);

  void setGroupNameMappings(Runtime &runtime, JSObject *groupObj);

                                         
                                                                       
                                                                           
                                                                            
                                                                           
                                                                              
                                                                              
                      
                                                                             
                                            
  static CallResult<RegExpMatch> search(
      Handle<JSRegExp> selfHandle,
      Runtime &runtime,
      Handle<StringPrimitive> strHandle,
      uint32_t searchStartOffset);

 public:
  friend void JSRegExpBuildMeta(const GCCell *, Metadata::Builder &);

  JSRegExp(Runtime &runtime, Handle<JSObject> parent, Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz),
        pattern_(
            runtime,
            runtime.getPredefinedString(Predefined::emptyString),
            runtime.getHeap()) {}

 private:
  ~JSRegExp();

                                            
  void initializeBytecode(llvh::ArrayRef<uint8_t> bytecode);

  static ExecutionStatus initializeGroupNameMappingObj(
      Runtime &runtime,
      Handle<JSRegExp> selfHandle,
      std::deque<llvh::SmallVector<char16_t, 5>> &orderedNamedGroups,
      regex::ParsedGroupNamesMapping &parsedMappings);

                                                                            
                                                                           
                                                                                
                                                                             
  GCPointer<StringPrimitive> pattern_;

  uint8_t *bytecode_{};
  uint32_t bytecodeSize_{0};

  regex::SyntaxFlags syntaxFlags_ = {};

  GCPointer<JSObject> groupNameMappings_{nullptr};

                                              
  static void _finalizeImpl(GCCell *cell, GC &gc);
  static size_t _mallocSizeImpl(GCCell *cell);

#ifdef HERMES_MEMORY_INSTRUMENTATION
  static std::string _snapshotNameImpl(GCCell *cell, GC &gc);
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif
};

}                
}                    

#endif                        
