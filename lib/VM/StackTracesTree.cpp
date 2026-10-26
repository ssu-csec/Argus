/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/StackTracesTree-NoRuntime.h"

#ifdef HERMES_MEMORY_INSTRUMENTATION

#include "hermes/VM/Callable.h"
#include "hermes/VM/StackFrame-inline.h"
#include "hermes/VM/StackTracesTree.h"
#include "hermes/VM/StringPrimitive.h"
#include "hermes/VM/StringView.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

StackTracesTreeNode *StackTracesTreeNode::findChild(
    const CodeBlock *codeBlock,
    uint32_t bytecodeOffset) const {
  auto matchingCodeBlockChildren = codeBlockToChildMap_.find(codeBlock);
  if (matchingCodeBlockChildren != codeBlockToChildMap_.end()) {
    auto matchingOffset =
        matchingCodeBlockChildren->getSecond().find(bytecodeOffset);
    if (matchingOffset != matchingCodeBlockChildren->getSecond().end()) {
      return children_[matchingOffset->getSecond()];
    }
  }
  return nullptr;
}

OptValue<uint32_t> StackTracesTreeNode::findChildIndex(
    const SourceLoc &sourceLoc) const {
  auto matchingChild = sourceLocToChildMap_.find(sourceLoc);
  if (matchingChild != sourceLocToChildMap_.end()) {
    return matchingChild->getSecond();
  }
  return llvh::None;
}

StackTracesTreeNode *StackTracesTreeNode::findChild(
    const SourceLoc &sourceLoc) const {
  auto optIndex = findChildIndex(sourceLoc);
  if (!optIndex.hasValue())
    return nullptr;
  return children_[*optIndex];
}

void StackTracesTreeNode::addChild(
    StackTracesTreeNode *child,
    const CodeBlock *codeBlock,
    uint32_t bytecodeOffset,
    SourceLoc sourceLoc) {
  uint32_t childIndex = children_.size();
  children_.push_back(child);
  bool inserted =
      sourceLocToChildMap_.try_emplace(sourceLoc, childIndex).second;
  (void)inserted;
  assert(inserted && "Tried to add a node for the same sourceLoc twice.");
  addMapping(codeBlock, bytecodeOffset, childIndex);
}

void StackTracesTreeNode::addMapping(
    const CodeBlock *codeBlock,
    uint32_t bytecodeOffset,
    uint32_t childIndex) {
  auto matchingCodeBlockChildren = codeBlockToChildMap_.find(codeBlock);
  if (matchingCodeBlockChildren == codeBlockToChildMap_.end()) {
    ChildBytecodeMap newBytecodeMapping;
    newBytecodeMapping.try_emplace(bytecodeOffset, childIndex);
    codeBlockToChildMap_.try_emplace(
        static_cast<const void *>(codeBlock), std::move(newBytecodeMapping));
  } else {
    auto &bytecodeMapping = matchingCodeBlockChildren->getSecond();
    assert(
        bytecodeMapping.find(bytecodeOffset) == bytecodeMapping.end() &&
        "Tried to add a node for the same codeLoc twice");
    bytecodeMapping.try_emplace(bytecodeOffset, childIndex);
  }
}

StackTracesTree::StackTracesTree()
    : strings_(std::make_shared<StringSetVector>()),
      rootFunctionID_(strings_->insert("(root)")),
      rootScriptNameID_(strings_->insert("")),
      nativeFunctionID_(strings_->insert("(native)")),
      anonymousFunctionID_(strings_->insert("(anonymous)")),
      head_(root_.get()) {}

void StackTracesTree::syncWithRuntimeStack(Runtime &runtime) {
  head_ = root_.get();

  const StackFramePtr framesEnd = *runtime.getStackFrames().end();
  std::vector<std::pair<CodeBlock *, const Inst *>> stack;

                                                                          
                                                                                
                                                                               
                                                     
  for (StackFramePtr cf : runtime.getStackFrames()) {
    CodeBlock *savedCodeBlock = cf.getSavedCodeBlock();
    const Inst *savedIP = cf.getSavedIP();
                                                                        
                                                                            
                                                                               
                       
    StackFramePtr prev = cf.getPreviousFrame();
    if (prev != framesEnd) {
      if (CodeBlock *parentCB = prev.getCalleeCodeBlock(runtime)) {
        assert(
            (!savedCodeBlock || savedCodeBlock == parentCB) &&
            "If savedCodeBlock is non-null, it should match the parent's "
            "callee code block");
        savedCodeBlock = parentCB;
      }
    } else {
                                                                             
                                          
                                                                           
                                                                                
                                                                               
                        
      savedCodeBlock = cf.getCalleeCodeBlock(runtime);
      savedIP = savedCodeBlock->getOffsetPtr(0);
    }
    stack.emplace_back(savedCodeBlock, savedIP);
  }

                                                     
  for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
                                                                               
                                        
    if (it->first && it->second) {
      pushCallStack(runtime, it->first, it->second);
    }
  }
}

StackTracesTreeNode *StackTracesTree::getRootNode() const {
  return root_.get();
}

void StackTracesTree::popCallStack() {
  if (head_->duplicatePushDepth_) {
    head_->duplicatePushDepth_--;
    return;
  }
  head_ = head_->parent;
  assert(head_ && "Pop'ed too far up tree");
}

StackTracesTreeNode::SourceLoc StackTracesTree::computeSourceLoc(
    Runtime &runtime,
    const CodeBlock *codeBlock,
    uint32_t bytecodeOffset) {
  auto location = codeBlock->getSourceLocation(bytecodeOffset);
                                                                      
                                                                          
                    
  RuntimeModule *runtimeModule = codeBlock->getRuntimeModule();
  std::string scriptName;
  auto scriptID = runtimeModule->getScriptID();
  int32_t lineNo, columnNo;
  if (location) {
    scriptName = runtimeModule->getBytecode()->getDebugInfo()->getFilenameByID(
        location->filenameId);
    lineNo = location->line;
    columnNo = location->column;
  } else {
    auto sourceURL = runtimeModule->getSourceURL();
    scriptName = sourceURL.empty() ? "unknown" : sourceURL;
                                                  
    lineNo = runtimeModule->getBytecode()->getSegmentID() + 1;
                                                                             
                                                                         
                                                                             
                                                                    
    columnNo = codeBlock->getVirtualOffset() + bytecodeOffset + 1;
  }
  return {strings_->insert(scriptName), scriptID, lineNo, columnNo};
}

void StackTracesTree::pushCallStack(
    Runtime &runtime,
    const CodeBlock *codeBlock,
    const Inst *ip) {
  assert(codeBlock && ip && "Code block and IP must be known");

                                                                               
                                                                                
                                                                            
                                                                    
                         
  if (head_->codeBlock_ == codeBlock && head_->ip_ == ip) {
    head_->duplicatePushDepth_++;
    return;
  }

  auto bytecodeOffset = codeBlock->getOffsetOf(ip);
                                                                              
                  
  if (auto existingNode = head_->findChild(codeBlock, bytecodeOffset)) {
    head_ = existingNode;
    return;
  }

                                                                         
                                                                      
                                                                 
  auto sourceLoc = computeSourceLoc(runtime, codeBlock, bytecodeOffset);
  if (OptValue<uint32_t> existingNodeIndex = head_->findChildIndex(sourceLoc)) {
    auto existingNode = head_->children_[*existingNodeIndex];
    assert(existingNode->parent && "Stack trace tree node has no parent");
    existingNode->parent->addMapping(
        codeBlock, bytecodeOffset, *existingNodeIndex);
    head_ = existingNode;
    return;
  }

                                  

                                                                               
                                                                        
    
                       
                             
        
                                                                         
    
  auto nameStr = codeBlock->getNameString(runtime.getHeap().getCallbacks());
  auto nameID =
      nameStr.empty() ? anonymousFunctionID_ : strings_->insert(nameStr);

  auto newNode = std::make_unique<StackTracesTreeNode>(
      nextNodeID_++, head_, sourceLoc, codeBlock, ip, nameID);
  auto newNodePtr = newNode.get();
  nodes_.emplace_back(std::move(newNode));
  head_->addChild(newNodePtr, codeBlock, bytecodeOffset, sourceLoc);
  head_ = newNodePtr;
}

StackTracesTreeNode *StackTracesTree::getStackTrace(
    Runtime &runtime,
    const CodeBlock *codeBlock,
    const Inst *ip) {
  if (!codeBlock || !ip) {
    return getRootNode();
  }
  pushCallStack(runtime, codeBlock, ip);
  auto res = head_;
  popCallStack();
  return res;
}

}                
}                    

#endif                                 
