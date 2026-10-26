/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// -*- C++ -*-
//===--------------------------- regex ------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef HERMES_REGEX_NODE_H
#define HERMES_REGEX_NODE_H

#include "hermes/Platform/Unicode/CharacterProperties.h"
#include "hermes/Platform/Unicode/CodePointSet.h"

#include "hermes/Regex/RegexBytecode.h"
#include "hermes/Regex/RegexTypes.h"

#include "llvh/ADT/SmallVector.h"

#include <string>
#include <vector>

namespace hermes {
namespace regex {

class Node;

                                
using NodeList = std::vector<Node *>;
                                                              
using NodeHolder = std::vector<std::unique_ptr<Node>>;

                                                                       
                                                                            
                                                    
                                                                       
                      
class Node {
 public:
                                       
                                                
  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  using CodePoint = uint32_t;
  using CodePointList = llvh::SmallVector<CodePoint, 5>;

                                         
  Node() = default;
  virtual ~Node() = default;

                                                                   
  static void compile(const NodeList &nodes, RegexBytecodeStream &bcs) {
    std::vector<Node *> stack;
    stack.insert(stack.end(), nodes.rbegin(), nodes.rend());
    while (!stack.empty()) {
      if (auto n = stack.back()->emitStep(bcs)) {
        stack.insert(stack.end(), n->rbegin(), n->rend());
      } else {
        stack.pop_back();
      }
    }
  }

                                                                  
  static MatchConstraintSet matchConstraintsForList(const NodeList &nodes) {
    MatchConstraintSet result = 0;
    for (const auto &node : nodes) {
      result |= node->matchConstraints();
    }
    return result;
  }

                                                                                
                                           
  inline static void reverseNodeList(NodeList &nodes);

                                                                           
                     
  inline static void
  optimizeNodeList(NodeList &nodes, SyntaxFlags flags, NodeHolder &nodeHolder);

                                                                    
  virtual bool matchesExactlyOneCharacter() const {
    return false;
  }

                                                                
                                                                   
                              
  virtual bool tryCoalesceCharacters(CodePointList *output) const {
    return false;
  }

 protected:
                                                  
                                                                                
           
  virtual MatchConstraintSet matchConstraints() const {
    return 0;
  }

                                          
  virtual bool isGoal() const {
    return false;
  }

                                                               
  virtual llvh::SmallVector<NodeList *, 1> getChildren() {
    return {};
  }

                                                                            
                                                                               
                                    
  virtual void reverseChildren() {}

 private:
                                                                             
                                                                      
                                                                     
                                                                             
                   
                                                                           
                                                                               
                                                             
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) {
    return nullptr;
  }
};

                                                                       
class GoalNode final : public Node {
 private:
  NodeList *emitStep(RegexBytecodeStream &bcs) override {
    bcs.emit<GoalInsn>();
    return nullptr;
  }

 protected:
  bool isGoal() const override {
    return true;
  }
};

class LoopNode final : public Node {
  using Super = Node;

                                                        
  uint32_t min_;

                                                       
                             
  uint32_t max_;

                                                  
  uint32_t loopId_;

                                                                    
  uint16_t mexpBegin_;

                                                                                
                                             
  uint16_t mexpEnd_;

                                  
  bool greedy_;

                                      
  NodeList loopee_;

                                                   
  MatchConstraintSet loopeeConstraints_;

                                                                            
                         
  std::function<void()> endLoop_;

 public:
                                                    
                                                                               
                                                                            
                                               
                                                                         
                                                                       
                                                                  
  explicit LoopNode(
      uint32_t loopId,
      uint32_t min,
      uint32_t max,
      bool greedy,
      uint16_t mexpBegin,
      uint16_t mexpEnd,
      NodeList loopee)
      : min_(min),
        max_(max),
        loopId_(loopId),
        mexpBegin_(mexpBegin),
        mexpEnd_(mexpEnd),
        greedy_(greedy),
        loopee_(std::move(loopee)),
        loopeeConstraints_(matchConstraintsForList(loopee_)) {}

                                                                                
            
  virtual MatchConstraintSet matchConstraints() const override {
    MatchConstraintSet result = 0;
    if (min_ > 0) {
      result |= loopeeConstraints_;
    }
    return result | Super::matchConstraints();
  }

  virtual llvh::SmallVector<NodeList *, 1> getChildren() override {
    return {&loopee_};
  }

 protected:
  void reverseChildren() override {
    reverseNodeList(loopee_);
  }

 private:
                                                                            
                       
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    if (!endLoop_) {
                                                                            
             
      auto loopEntryPosition = bcs.currentOffset();
      if (isWidth1Loop()) {
        assert(
            mexpBegin_ == mexpEnd_ &&
            "Width 1 loops should not contain capture groups");
        auto loopInsn = bcs.emit<Width1LoopInsn>();
        loopInsn->loopId = loopId_;
        loopInsn->min = min_;
        loopInsn->max = max_;
        loopInsn->greedy = greedy_;
        endLoop_ = [loopInsn, &bcs]() mutable {
          loopInsn->notTakenTarget = bcs.currentOffset();
        };
      } else if (isSimpleLoop()) {
        auto loopInsn = bcs.emit<BeginSimpleLoopInsn>();
        loopInsn->loopeeConstraints = loopeeConstraints_;
        endLoop_ = [loopInsn, loopEntryPosition, &bcs]() mutable {
          bcs.emit<EndSimpleLoopInsn>()->target = loopEntryPosition;
          loopInsn->notTakenTarget = bcs.currentOffset();
        };
      } else {
        auto loopInsn = bcs.emit<BeginLoopInsn>();
        loopInsn->loopId = loopId_;
        loopInsn->min = min_;
        loopInsn->max = max_;
        loopInsn->mexpBegin = mexpBegin_;
        loopInsn->mexpEnd = mexpEnd_;
        loopInsn->greedy = greedy_;
        loopInsn->loopeeConstraints = loopeeConstraints_;
        endLoop_ = [loopInsn, loopEntryPosition, &bcs]() mutable {
          bcs.emit<EndLoopInsn>()->target = loopEntryPosition;
          loopInsn->notTakenTarget = bcs.currentOffset();
        };
      }
      return &loopee_;
    }
                                                                             
                      
    endLoop_();
    endLoop_ = nullptr;
    return nullptr;
  }

                                                                             
                                                                           
  bool isWidth1Loop() const {
    if (loopee_.size() != 1)
      return false;
    return loopee_[0]->matchesExactlyOneCharacter();
  }

                                                                        
                        
  bool isSimpleLoop() const {
    return min_ == 0 && max_ == std::numeric_limits<uint32_t>::max() &&
        mexpBegin_ == mexpEnd_ && greedy_ &&
        (loopeeConstraints_ & MatchConstraintNonEmpty);
  }
};

                                                   
class AlternationNode final : public Node {
  using Super = Node;

                                          
                                                                               
           
  std::vector<NodeList> alternatives_;
                                                       
  std::vector<MatchConstraintSet> elementConstraints_;
                                                                              
                                                                            
                                                                            
                                                   
  std::vector<MatchConstraintSet> restConstraints_;
                                                                               
                                                                         
                                               
  std::vector<RegexBytecodeStream::InstructionWrapper<Jump32Insn>> jumps_;
                                                                             
                                                                           
                                                                              
                                                                              
                             
  std::function<bool()> callNext_;

 public:
                                     
                                                     
  AlternationNode(std::vector<NodeList> alternatives)
      : alternatives_(std::move(alternatives)),
        elementConstraints_(alternatives_.size()),
        restConstraints_(alternatives_.size()) {
    assert(alternatives_.size() > 1 && "Must give at least 2 alternatives");

    jumps_.reserve(alternatives_.size());

                                                                            
                                       
    elementConstraints_.back() = matchConstraintsForList(alternatives_.back());
    restConstraints_.back() = elementConstraints_.back();

    for (auto i = alternatives_.size() - 1; i-- > 0;) {
      elementConstraints_[i] = matchConstraintsForList(alternatives_[i]);
      restConstraints_[i] = restConstraints_[i + 1] & elementConstraints_[i];
    }
  }

                                                                   
                                                                                
                         
  virtual MatchConstraintSet matchConstraints() const override {
    return restConstraints_.front() | Super::matchConstraints();
  }

  virtual llvh::SmallVector<NodeList *, 1> getChildren() override {
    llvh::SmallVector<NodeList *, 1> ret;
    ret.reserve(alternatives_.size());
    for (auto &alternative : alternatives_) {
      ret.push_back(&alternative);
    }
    return ret;
  }

  void reverseChildren() override {
    for (auto &alternative : alternatives_) {
      reverseNodeList(alternative);
    }
  }

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
                                     
                                                                 
                                                              
                                                              
                                                                      

                                                                             
                                 
    if (callNext_ && callNext_()) {
                                                                       
      jumps_.clear();
      callNext_ = nullptr;
      return nullptr;
    }
                                                                           
                                                                   
                                                                            
                                                  
    if (jumps_.size() < alternatives_.size() - 1) {
      auto altInsn = bcs.emit<AlternationInsn>();
      altInsn->primaryConstraints = elementConstraints_[jumps_.size()];
      altInsn->secondaryConstraints = restConstraints_[jumps_.size() + 1];
      callNext_ = [this, altInsn, &bcs]() mutable {
        jumps_.push_back(bcs.emit<Jump32Insn>());
        altInsn->secondaryBranch = bcs.currentOffset();
        return false;
      };
      return &alternatives_[jumps_.size()];
    }
                                                                              
                                                                          
                            
    callNext_ = [this, &bcs]() mutable {
                                           
                                                     
      for (auto &jump : jumps_) {
        jump->target = bcs.currentOffset();
      }
      return true;
    };
    return &alternatives_.back();
  }
};

                                               
class MarkedSubexpressionNode final : public Node {
  using Super = Node;

                                    
  NodeList contents_;

                                        
  MatchConstraintSet contentsConstraints_;

                                           
  uint16_t mexp_;

                                                         
  bool emitEnd_ = false;

 public:
  explicit MarkedSubexpressionNode(NodeList contents, uint16_t mexp)
      : contents_(std::move(contents)),
        contentsConstraints_(matchConstraintsForList(contents_)),
        mexp_(mexp) {}

  void reverseChildren() override {
    reverseNodeList(contents_);
  }

  virtual llvh::SmallVector<NodeList *, 1> getChildren() override {
    return {&contents_};
  }

  virtual MatchConstraintSet matchConstraints() const override {
    return contentsConstraints_ | Super::matchConstraints();
  }

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    if (!emitEnd_) {
      bcs.emit<BeginMarkedSubexpressionInsn>()->mexp = mexp_;
      emitEnd_ = true;
      return &contents_;
    }
    emitEnd_ = false;
    bcs.emit<EndMarkedSubexpressionInsn>()->mexp = mexp_;
    return nullptr;
  }
};

                                                
class BackRefNode final : public Node {
                               
  uint16_t mexp_;

 public:
  explicit BackRefNode(unsigned mexp) : mexp_(mexp) {}

  void setBackRef(unsigned mexp) {
    mexp_ = mexp;
  }

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    bcs.emit<BackRefInsn>()->mexp = mexp_;
    return nullptr;
  }
};

                                                                
class WordBoundaryNode final : public Node {
  using Super = Node;

                                                          
  bool invert_;

 public:
  WordBoundaryNode(bool invert) : invert_(invert) {}

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    bcs.emit<WordBoundaryInsn>()->invert = invert_;
    return nullptr;
  }
};

                                                              
class LeftAnchorNode final : public Node {
  using Super = Node;

  bool multiline_;

 public:
  LeftAnchorNode(SyntaxFlags flags) : multiline_(flags.multiline) {}

  virtual MatchConstraintSet matchConstraints() const override {
    MatchConstraintSet result = 0;
                                                                              
                                 
    if (!multiline_) {
      result |= MatchConstraintAnchoredAtStart;
    }
    return result | Super::matchConstraints();
  }

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    bcs.emit<LeftAnchorInsn>();
    return nullptr;
  }
};

                                                           
class RightAnchorNode : public Node {
  using Super = Node;

 public:
  RightAnchorNode() {}

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    bcs.emit<RightAnchorInsn>();
    return nullptr;
  }
};

                                                                             
                 
class MatchAnyNode final : public Node {
  using Super = Node;
  bool unicode_;
  bool dotAll_;

 public:
                           
                                                                          
                       
                                                                           
  explicit MatchAnyNode(SyntaxFlags flags)
      : unicode_(flags.unicode), dotAll_(flags.dotAll) {}

  virtual MatchConstraintSet matchConstraints() const override {
    return MatchConstraintNonEmpty | Super::matchConstraints();
  }

  virtual bool matchesExactlyOneCharacter() const override {
                                                
    return !unicode_;
  }

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    if (unicode_) {
      if (dotAll_) {
        bcs.emit<U16MatchAnyInsn>();
      } else {
        bcs.emit<U16MatchAnyButNewlineInsn>();
      }
    } else {
      if (dotAll_) {
        bcs.emit<MatchAnyInsn>();
      } else {
        bcs.emit<MatchAnyButNewlineInsn>();
      }
    }
    return nullptr;
  }
};

                                                                             
                
class MatchCharNode final : public Node {
  using Super = Node;
  using Super::CodePointList;

                                                                     
                  
  static constexpr size_t kMinMatchCharNCount = 3;

                                                                             
  static constexpr size_t kMaxMatchCharNCount = UINT8_MAX;

                                              
  CodePointList chars_;

                                                                       
  const bool icase_;

                                      
  const bool unicode_;

 public:
  MatchCharNode(CodePointList chars, SyntaxFlags flags)
      : chars_(std::move(chars)),
        icase_(flags.ignoreCase),
        unicode_(flags.unicode) {}

  virtual MatchConstraintSet matchConstraints() const override {
    MatchConstraintSet result = MatchConstraintNonEmpty;
                                                                              
    if (!std::all_of(chars_.begin(), chars_.end(), isASCII)) {
      result |= MatchConstraintNonASCII;
    }
    return result | Super::matchConstraints();
  }

  void reverseChildren() override {
    std::reverse(chars_.begin(), chars_.end());
  }

  bool tryCoalesceCharacters(CodePointList *output) const override {
    output->append(chars_.begin(), chars_.end());
    return true;
  }

                                                               
                                                      
  bool mayRequireDecodingSurrogatePair(uint32_t cp) const {
    if (!isMemberOfBMP(cp)) {
      return true;
    }
    if (unicode_ && (isHighSurrogate(cp) || isLowSurrogate(cp))) {
                                                                              
                                                                               
                                                                             
                              
      return true;
    }
    return false;
  }

 protected:
  virtual bool matchesExactlyOneCharacter() const override {
                                                                               
                               
    return chars_.size() == 1 &&
        !mayRequireDecodingSurrogatePair(chars_.front());
  }

                                                                  
  void emitASCIIList(llvh::ArrayRef<CodePoint> chars, RegexBytecodeStream &bcs)
      const {
    assert(
        std::all_of(chars.begin(), chars.end(), isASCII) &&
        "All characters should be ASCII");

                                                                      
                           
    auto remaining = chars;
    while (remaining.size() >= kMinMatchCharNCount) {
      size_t groupLen = std::min((size_t)kMaxMatchCharNCount, remaining.size());
      auto group = remaining.take_front(groupLen);
      remaining = remaining.drop_front(groupLen);

      if (icase_) {
        bcs.emit<MatchNCharICase8Insn>()->charCount = groupLen;
      } else {
        bcs.emit<MatchNChar8Insn>()->charCount = groupLen;
      }
      for (char c : group) {
        bcs.emitChar8(c);
      }
    }

                                                     
    for (CodePoint c : remaining) {
      if (icase_) {
        bcs.emit<MatchCharICase8Insn>()->c = c;
      } else {
        bcs.emit<MatchChar8Insn>()->c = c;
      }
    }
  }

                                                                      
  void emitNonASCIIList(
      llvh::ArrayRef<CodePoint> chars,
      RegexBytecodeStream &bcs) const {
    for (uint32_t c : chars) {
      if (mayRequireDecodingSurrogatePair(c)) {
        if (icase_) {
          bcs.emit<U16MatchCharICase32Insn>()->c = c;
        } else {
          bcs.emit<U16MatchChar32Insn>()->c = c;
        }
      } else {
        if (icase_) {
          bcs.emit<MatchCharICase16Insn>()->c = c;
        } else {
          bcs.emit<MatchChar16Insn>()->c = c;
        }
      }
    }
  }

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    llvh::ArrayRef<CodePoint> remaining{chars_};
    while (!remaining.empty()) {
                                                        
      auto asciis = remaining.take_while(isASCII);
      emitASCIIList(asciis, bcs);
      remaining = remaining.drop_front(asciis.size());

                                                            
      auto nonAsciis = remaining.take_until(isASCII);
      emitNonASCIIList(nonAsciis, bcs);
      remaining = remaining.drop_front(nonAsciis.size());
    }
    return nullptr;
  }
};

                                                          
template <class Traits>
class BracketNode : public Node {
  using Super = Node;
  using Super::CodePoint;

  const Traits &traits_;
  CodePointSet codePointSet_;
  std::vector<CharacterClass> classes_;
  bool negate_;
  bool icase_;
  bool unicode_;

                                                                
  bool canMatchASCII() const {
                                                                            
                                  
                                                                    
                                                                             
                                                                
                                                              
                                                                              
    if (icase_ && unicode_)
      return true;

                                                                              
                                                    
    if (negate_) {
      for (const CodePointRange &range : codePointSet_.ranges()) {
        if (range.first == 0 && range.length > 127) {
                                                                        
                                                
          return false;
        }
      }
      return true;
    } else {
                     
                                                                       
                    
      if (!classes_.empty())
        return true;

                                                                                
                                                                                
                      
      for (const CodePointRange &range : codePointSet_.ranges()) {
        if (isASCII(range.first))
          return true;
      }

                                                
      return false;
    }
  }

                                                                                
                                                                               
                                                   
  template <typename Insn>
  void populateInstruction(RegexBytecodeStream &bcs, Insn insn) const {
    insn->negate = negate_;
    for (CharacterClass cc : classes_) {
      if (!cc.inverted_) {
        insn->positiveCharClasses |= cc.type_;
      } else {
        insn->negativeCharClasses |= cc.type_;
      }
    }

                                                 
    CodePointSet cps = icase_
        ? makeCanonicallyEquivalent(codePointSet_, unicode_)
        : codePointSet_;
    for (const CodePointRange &range : cps.ranges()) {
      assert(range.length > 0 && "Ranges should never be empty");
      bcs.emitBracketRange(
          BracketRange32{range.first, range.first + range.length - 1});
    }
    insn->rangeCount = cps.ranges().size();
  }

 public:
  BracketNode(const Traits &traits, bool negate, SyntaxFlags flags)
      : traits_(traits),
        negate_(negate),
        icase_(flags.ignoreCase),
        unicode_(flags.unicode) {}

  void addChar(CodePoint c) {
    codePointSet_.add(c);
  }

  void addRange(CodePoint a, CodePoint b) {
    assert(a <= b && "Invalid range");
    uint32_t length = b - a + 1;
    codePointSet_.add(CodePointRange{a, length});
  }

  void addClass(CharacterClass cls) {
    classes_.push_back(cls);
  }

  void addCodePointRanges(
      llvh::ArrayRef<UnicodeRangePoolRef> rangeArray,
      bool inverted = false) {
    addRangeArrayPoolToBracket(&codePointSet_, rangeArray, inverted);
  }

  virtual MatchConstraintSet matchConstraints() const override {
    MatchConstraintSet result = 0;
    if (!canMatchASCII())
      result |= MatchConstraintNonASCII;

    if (!(codePointSet_.ranges().empty() && classes_.empty()))
      result |= MatchConstraintNonEmpty;

    return result | Super::matchConstraints();
  }

  virtual bool matchesExactlyOneCharacter() const override {
                                                    
    return !unicode_;
  }

 private:
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    if (unicode_) {
      populateInstruction(bcs, bcs.emit<U16BracketInsn>());
    } else {
      populateInstruction(bcs, bcs.emit<BracketInsn>());
    }
    return nullptr;
  }
};

                                                           
class LookaroundNode : public Node {
  using Super = Node;

                                                                     
  NodeList exp_;

                                                     
  MatchConstraintSet expConstraints_;

                                                                         
  const bool invert_;

                                                                     
  const bool forwards_;

                                                                 
  uint16_t mexpBegin_;
  uint16_t mexpEnd_;

                                                          
  std::function<void()> endLookaround_;

 public:
  LookaroundNode(
      NodeList exp,
      uint16_t mexpBegin,
      uint16_t mexpEnd,
      bool invert,
      bool forwards)
      : exp_(std::move(exp)),
        expConstraints_(matchConstraintsForList(exp_)),
        invert_(invert),
        forwards_(forwards),
        mexpBegin_(mexpBegin),
        mexpEnd_(mexpEnd) {
                                                       
                   
                                       
                                                                          
                             
    if (!forwards_) {
      expConstraints_ &= ~MatchConstraintAnchoredAtStart;
    }
  }

  virtual MatchConstraintSet matchConstraints() const override {
                                                          
                                                                 
    MatchConstraintSet result = 0;
    if (!invert_) {
      result |= expConstraints_;
    }
                                                                       
    result &= ~MatchConstraintNonEmpty;
    return result | Super::matchConstraints();
  }

  virtual llvh::SmallVector<NodeList *, 1> getChildren() override {
    return {&exp_};
  }

 private:
                                                             
  virtual NodeList *emitStep(RegexBytecodeStream &bcs) override {
    if (endLookaround_) {
      endLookaround_();
      endLookaround_ = nullptr;
      return nullptr;
    }
    auto lookaround = bcs.emit<LookaroundInsn>();
    lookaround->invert = invert_;
    lookaround->forwards = forwards_;
    lookaround->constraints = expConstraints_;
    lookaround->mexpBegin = mexpBegin_;
    lookaround->mexpEnd = mexpEnd_;
    endLookaround_ = [lookaround, &bcs]() mutable {
      lookaround->continuation = bcs.currentOffset();
    };
    return &exp_;
  }
};

void Node::reverseNodeList(NodeList &nodes) {
                                                    
#ifndef NDEBUG
  for (const auto &node : nodes) {
    assert(
        (!node->isGoal() || (node == nodes.back())) &&
        "Goal node should only be at end");
  }
#endif

                                                       
  if (!nodes.empty()) {
    bool hasGoal = nodes.back()->isGoal();
    std::reverse(nodes.begin(), nodes.end() - (hasGoal ? 1 : 0));
  }

                                     
  for (auto &node : nodes) {
    node->reverseChildren();
  }
}

void Node::optimizeNodeList(
    NodeList &rootNodes,
    SyntaxFlags flags,
    NodeHolder &nodeHolder) {
  std::vector<NodeList *> stack;
  stack.push_back(&rootNodes);

  while (!stack.empty()) {
    auto &nodes = *stack.back();
    stack.pop_back();

                                         
                                                                       
                         
    for (size_t idx = 0, max = nodes.size(); idx < max; idx++) {
      auto childNodes = nodes[idx]->getChildren();
      stack.insert(stack.end(), childNodes.begin(), childNodes.end());
                                                                   
      CodePointList chars;
      size_t rangeStart = idx;
      while (idx < max && nodes[idx]->tryCoalesceCharacters(&chars)) {
        idx++;
      }
      if (idx - rangeStart >= 2) {
                                                
                                             
        nodeHolder.emplace_back(new MatchCharNode(std::move(chars), flags));
        nodes[rangeStart] = nodeHolder.back().get();
                                                                               
                                                      
                                                                     
        std::fill(
            nodes.begin() + (rangeStart + 1), nodes.begin() + idx, nullptr);
      }
    }

                                           
    nodes.erase(std::remove(nodes.begin(), nodes.end(), nullptr), nodes.end());
  }
}

}                   
}                    
#endif                       
