/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                         
                                                                               
                                                                              
                                                        

#ifndef HERMES_STACK_TRACES_TREE_NO_RUNTIME_H
#define HERMES_STACK_TRACES_TREE_NO_RUNTIME_H

#include "hermes/Public/DebuggerTypes.h"
#include "hermes/Support/OptValue.h"
#include "hermes/Support/StringSetVector.h"

#include "llvh/ADT/DenseMap.h"

#include <cstdint>
#include <map>
#include <memory>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

struct StackTracesTree;
class CodeBlock;

struct StackTracesTreeNode {
                                                                              
                                                                               
                                                                           
                                                     
  struct SourceLoc {
    StringSetVector::size_type scriptName;
    ::facebook::hermes::debugger::ScriptID scriptID;
    int32_t lineNo;
    int32_t columnNo;
    SourceLoc(
        StringSetVector::size_type scriptName,
        ::facebook::hermes::debugger::ScriptID scriptID,
        int32_t lineNo,
        int32_t columnNo)
        : scriptName(scriptName),
          scriptID(scriptID),
          lineNo(lineNo),
          columnNo(columnNo) {}

    unsigned hash() const {
      return scriptName ^ scriptID ^ columnNo ^ lineNo;
    };

    bool operator==(const SourceLoc &r) const {
      return scriptName == r.scriptName && scriptID == r.scriptID &&
          lineNo == r.lineNo && columnNo == r.columnNo;
    }
  };

                                                    
  struct SourceLocMapInfo {
    static inline SourceLoc getEmptyKey() {
      return {SIZE_MAX, 0, -1, -1};
    }
    static inline SourceLoc getTombstoneKey() {
      return {SIZE_MAX - 1, 0, -1, -1};
    }
    static unsigned getHashValue(const SourceLoc &v) {
      return v.hash();
    }
    static bool isEqual(const SourceLoc &l, const SourceLoc &r) {
      return l == r;
    }
  };

                                         
  using ChildBytecodeMap = llvh::DenseMap<uint32_t, uint32_t>;

                                                                           
                                                                             
                                                                              
  using ChildCodeblockMap = llvh::DenseMap<const void *, ChildBytecodeMap>;

                                         
  using ChildSourceLocMap =
      llvh::DenseMap<SourceLoc, uint32_t, SourceLocMapInfo>;

  StackTracesTreeNode(
      size_t id,
      StackTracesTreeNode *parent,
      SourceLoc sourceLoc,
      const CodeBlock *codeBlock,
      const void *ip,
      StringSetVector::size_type name)
      : id(id),
        parent(parent),
        sourceLoc(sourceLoc),
        name(name),
        codeBlock_(codeBlock),
        ip_(ip) {};

                                     
  const size_t id;
  StackTracesTreeNode *const parent;
  const SourceLoc sourceLoc;
  const StringSetVector::size_type name;

  llvh::ArrayRef<StackTracesTreeNode *> getChildren() const {
    return children_;
  }

 private:
  friend StackTracesTree;

  StackTracesTreeNode *findChild(
      const CodeBlock *codeBlock,
      uint32_t bytecodeOffset) const;

  OptValue<uint32_t> findChildIndex(const SourceLoc &sourceLoc) const;

  StackTracesTreeNode *findChild(const SourceLoc &sourceLoc) const;

  void addChild(
      StackTracesTreeNode *child,
      const CodeBlock *codeBlock,
      uint32_t bytecodeOffset,
      SourceLoc sourceLoc);

  void addMapping(
      const CodeBlock *codeBlock,
      uint32_t bytecodeOffset,
      uint32_t childIndex);

                                                                               
                                                                                
                                                                              
                                 
  const CodeBlock *codeBlock_;
                                                                           
                             
  const void *ip_;
                                                                         
                                                                              
                                                                            
                                                                          
  int duplicatePushDepth_{0};

                                 
  ChildSourceLocMap sourceLocToChildMap_;

                                                                                
                                      
  ChildCodeblockMap codeBlockToChildMap_;

                                                                              
            
  std::vector<StackTracesTreeNode *> children_{};
};

}                
}                    
#pragma GCC diagnostic pop

#endif                                         
