/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_ESTREE_H
#define HERMES_AST_ESTREE_H

#include "hermes/AST/Context.h"
#include "hermes/Support/StringTable.h"

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/ilist.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/SMLoc.h"

namespace hermes {

using llvh::ArrayRef;

namespace sem {
class FunctionInfo;
}                 

namespace ESTree {

using llvh::cast;
using llvh::SMLoc;
using llvh::SMRange;

class Node;
                                                                      
                                                                         
                                                                              
                                                                             
                                                            
using NodeLabel = UniqueString *;
                                                                              
                                                   
                                                                                
                                                                               
             
using NodeString = UniqueString *;
using NodeBoolean = bool;
using NodeNumber = double;
using NodePtr = Node *;
using NodeList = llvh::simple_ilist<Node>;

enum class NodeKind : uint32_t {
#define ESTREE_FIRST(NAME, ...) _##NAME##_First,
#define ESTREE_LAST(NAME) _##NAME##_Last,
#define ESTREE_NODE_0_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_1_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_2_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_3_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_4_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_5_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_6_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_7_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_8_ARGS(NAME, ...) NAME,
#define ESTREE_NODE_9_ARGS(NAME, ...) NAME,
#include "ESTree.def"
};

                                               
class Node : public llvh::ilist_node<Node> {
  Node(const Node &) = delete;
  void operator=(const Node &) = delete;

  NodeKind kind_;

                                                  
                                                          
  unsigned parens_ = 0;

  SMRange sourceRange_{};
  SMLoc debugLoc_{};

 public:
  explicit Node(NodeKind kind) : kind_(kind) {}

  void setSourceRange(SMRange rng) {
    sourceRange_ = rng;
  }
  SMRange getSourceRange() const {
    return sourceRange_;
  }
  void setStartLoc(SMLoc loc) {
    sourceRange_.Start = loc;
  }
  SMLoc getStartLoc() const {
    return sourceRange_.Start;
  }
  void setEndLoc(SMLoc loc) {
    sourceRange_.End = loc;
  }
  SMLoc getEndLoc() const {
    return sourceRange_.End;
  }
  void setDebugLoc(SMLoc loc) {
    debugLoc_ = loc;
  }
  SMLoc getDebugLoc() const {
    return debugLoc_;
  }

  unsigned getParens() const {
    return parens_;
  }
  void incParens() {
    parens_ = parens_ < 2 ? parens_ + 1 : 2;
  }
  void clearParens() {
    parens_ = 0;
  }

                                                   
  void copyLocationFrom(const Node *src) {
    setSourceRange(src->getSourceRange());
    setDebugLoc(src->getDebugLoc());
  }

                                            
  llvh::StringRef getNodeName() {
    switch (getKind()) {
      default:
        llvm_unreachable("invalid node kind");

#define ESTREE_NODE_0_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_1_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_2_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_3_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_4_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_5_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_6_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_7_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_8_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;
#define ESTREE_NODE_9_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return #NAME;

#include "ESTree.def"
    }
  }

  template <class Visitor>
  void visit(Visitor &V) {
    ESTreeVisit(V, this);
  }

                                     
  NodeKind getKind() const {
    return kind_;
  }
  static bool classof(const NodePtr) {
    return true;
  }

                                                                         
                   

  void *
  operator new(size_t size, Context &ctx, size_t alignment = alignof(double)) {
    return ctx.allocateNode(size, alignment);
  }
  void *operator new(size_t, void *mem) {
    return mem;
  }

  void operator delete(void *, const Context &, size_t) {}
  void operator delete(void *, size_t) {}

 private:
                                           

  void *operator new(size_t) {
    llvm_unreachable("AST nodes cannot be allocated with regular new");
  }
  void operator delete(void *) {
    llvm_unreachable("AST nodes cannot be released with regular delete");
  }
};

               
template <class Visitor>
void ESTreeVisit(Visitor &V, const NodeLabel &label) {}
template <class Visitor>
void ESTreeVisit(Visitor &V, const NodeBoolean &label) {}
template <class Visitor>
void ESTreeVisit(Visitor &V, const NodeNumber &label) {}

                             
template <class Visitor>
void ESTreeVisit(Visitor &V, NodeList &Lst) {
  for (auto &Elem : Lst) {
    ESTreeVisit(V, &Elem);
  }
}

                                     
#define ESTREE_FIRST(NAME, ...) class NAME##Node;
#define ESTREE_NODE_0_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_1_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_2_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_3_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_4_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_5_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_6_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_7_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_8_ARGS(NAME, ...) class NAME##Node;
#define ESTREE_NODE_9_ARGS(NAME, ...) class NAME##Node;

#include "ESTree.def"

                                                                           
                
enum class Strictness {
  NotSet,
  NonStrictMode,
  StrictMode,
};

                                                                               
             
inline bool isStrict(Strictness strictness) {
  assert(strictness != Strictness::NotSet && "strictness hasn't been set");
  return strictness == Strictness::StrictMode;
}

                                                                               
                                    
inline Strictness makeStrictness(bool strictMode) {
  return strictMode ? Strictness::StrictMode : Strictness::NonStrictMode;
}

                                                                            
                                                                            
enum class LoweredClassFunctionKind { None, Constructor, DerivedConstructor, Method };

                                           
class FunctionLikeDecoration {
  sem::FunctionInfo *semInfo_{};

 public:
  Strictness strictness{Strictness::NotSet};
  SourceVisibility sourceVisibility{SourceVisibility::Default};

                                                                     
                                                                          
                                                             
                                                      
  bool isMethodDefinition{false};

  LoweredClassFunctionKind loweredClassFunctionKind{
      LoweredClassFunctionKind::None};

                                                                            
                                                                           
                                                                             
                                                                         
                                                                              
  llvh::ArrayRef<Node *> loweredClassPreParameterInitializers;

  void setSemInfo(sem::FunctionInfo *semInfo) {
    assert(semInfo && "setting semInfo to null");
    assert(!semInfo_ && "semInfo is already set");
    semInfo_ = semInfo;
  }

  sem::FunctionInfo *getSemInfo() const {
    assert(semInfo_ && "semInfo is not set!");
    return semInfo_;
  }
};

class ProgramDecoration {
 public:
                                                                            
  NodeList dummyParamList;
};

                                    
class LabelDecorationBase {
  static constexpr unsigned INVALID_LABEL = ~0u;
  unsigned labelIndex_ = INVALID_LABEL;

 public:
  bool isLabelIndexSet() const {
    return labelIndex_ != INVALID_LABEL;
  }

  unsigned getLabelIndex() const {
    assert(isLabelIndexSet() && "labelIndex is not set");
    return labelIndex_;
  }

  void setLabelIndex(unsigned labelIndex) {
    assert(labelIndex != INVALID_LABEL && "setting labelIndex to invalid");
    assert(!isLabelIndexSet() && "labelIndex is already set");
    labelIndex_ = labelIndex;
  }
};

                                                
class GotoDecorationBase : public LabelDecorationBase {};

                                  
                                                                               
                                   
class StatementDecoration {};

                                       
                                                                                
                                       
                                                                           
                   
class LoopStatementDecoration : public LabelDecorationBase {};

class SwitchStatementDecoration : public LabelDecorationBase {};

class BreakStatementDecoration : public GotoDecorationBase {};
class ContinueStatementDecoration : public GotoDecorationBase {};

class LabeledStatementDecoration : public LabelDecorationBase {};

class BlockStatementDecoration {
 public:
                                                                             
  uint32_t bufferId;
                                                                        
  bool isLazyFunctionBody{false};
                                                                               
  bool paramYield{false};
                                                                               
  bool paramAwait{false};
};

class JSXDecoration {};
class FlowDecoration {};
class TSDecoration {};
class PatternDecoration {};
class MatchPatternDecoration {};
class CoverDecoration {};

class CallExpressionLikeDecoration {};
class MemberExpressionLikeDecoration {};

namespace detail {
                                                                               
                                                                              
                                                                       
                                                
template <class T>
struct ParamTrait {
  using Type = T;
};

                                      
template <>
struct ParamTrait<NodeList> {
  using Type = NodeList &&;
};

                                                                        
                                                                             
class EmptyDecoration {};

                                                                                
                               
template <class T>
struct DecoratorTrait {
  using Type = EmptyDecoration;
};

template <>
struct DecoratorTrait<BlockStatementNode> {
  using Type = BlockStatementDecoration;
};
template <>
struct DecoratorTrait<BreakStatementNode> {
  using Type = BreakStatementDecoration;
};
template <>
struct DecoratorTrait<ContinueStatementNode> {
  using Type = ContinueStatementDecoration;
};
template <>
struct DecoratorTrait<SwitchStatementNode> {
  using Type = SwitchStatementDecoration;
};
template <>
struct DecoratorTrait<LabeledStatementNode> {
  using Type = LabeledStatementDecoration;
};
template <>
struct DecoratorTrait<ProgramNode> {
  using Type = ProgramDecoration;
};

}                    

                                         
using BaseNode = Node;

#define ESTREE_FIRST(NAME, BASE)                                  \
  class NAME##Node : public BASE##Node, public NAME##Decoration { \
   public:                                                        \
    explicit NAME##Node(NodeKind kind) : BASE##Node(kind) {}      \
    static bool classof(const Node *V) {                          \
      auto kind = V->getKind();                                   \
      return NodeKind::_##NAME##_First < kind &&                  \
          kind < NodeKind::_##NAME##_Last;                        \
    }                                                             \
  };

#define ESTREE_NODE_0_ARGS(NAME, BASE)                                 \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    explicit NAME##Node() : BASE##Node(NodeKind::NAME) {}              \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      V.leave(this);                                                   \
    }                                                                  \
  };

#define ESTREE_NODE_1_ARGS(NAME, BASE, ARG0TY, ARG0NM, ARG0OPT)          \
  class NAME##Node : public BASE##Node,                                  \
                     public detail::DecoratorTrait<NAME##Node>::Type {   \
   public:                                                               \
    ARG0TY _##ARG0NM;                                                    \
    explicit NAME##Node(detail::ParamTrait<ARG0TY>::Type ARG0NM##_)      \
        : BASE##Node(NodeKind::NAME), _##ARG0NM(std::move(ARG0NM##_)) {} \
    template <class Visitor>                                             \
    void visit(Visitor &V) {                                             \
      if (!V.shouldVisit(this)) {                                        \
        return;                                                          \
      }                                                                  \
      V.enter(this);                                                     \
      ESTreeVisit(V, _##ARG0NM);                                         \
      V.leave(this);                                                     \
    }                                                                    \
    static bool classof(const Node *V) {                                 \
      return V->getKind() == NodeKind::NAME;                             \
    }                                                                    \
  };

#define ESTREE_NODE_2_ARGS(                                            \
    NAME, BASE, ARG0TY, ARG0NM, ARG0OPT, ARG1TY, ARG1NM, ARG1OPT)      \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#define ESTREE_NODE_3_ARGS(                                            \
    NAME,                                                              \
    BASE,                                                              \
    ARG0TY,                                                            \
    ARG0NM,                                                            \
    ARG0OPT,                                                           \
    ARG1TY,                                                            \
    ARG1NM,                                                            \
    ARG1OPT,                                                           \
    ARG2TY,                                                            \
    ARG2NM,                                                            \
    ARG2OPT)                                                           \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    ARG2TY _##ARG2NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_,                    \
        detail::ParamTrait<ARG2TY>::Type ARG2NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)),                             \
          _##ARG2NM(std::move(ARG2NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      ESTreeVisit(V, _##ARG2NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#define ESTREE_NODE_4_ARGS(                                            \
    NAME,                                                              \
    BASE,                                                              \
    ARG0TY,                                                            \
    ARG0NM,                                                            \
    ARG0OPT,                                                           \
    ARG1TY,                                                            \
    ARG1NM,                                                            \
    ARG1OPT,                                                           \
    ARG2TY,                                                            \
    ARG2NM,                                                            \
    ARG2OPT,                                                           \
    ARG3TY,                                                            \
    ARG3NM,                                                            \
    ARG3OPT)                                                           \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    ARG2TY _##ARG2NM;                                                  \
    ARG3TY _##ARG3NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_,                    \
        detail::ParamTrait<ARG2TY>::Type ARG2NM##_,                    \
        detail::ParamTrait<ARG3TY>::Type ARG3NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)),                             \
          _##ARG2NM(std::move(ARG2NM##_)),                             \
          _##ARG3NM(std::move(ARG3NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      ESTreeVisit(V, _##ARG2NM);                                       \
      ESTreeVisit(V, _##ARG3NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
                                                                       \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#define ESTREE_NODE_5_ARGS(                                            \
    NAME,                                                              \
    BASE,                                                              \
    ARG0TY,                                                            \
    ARG0NM,                                                            \
    ARG0OPT,                                                           \
    ARG1TY,                                                            \
    ARG1NM,                                                            \
    ARG1OPT,                                                           \
    ARG2TY,                                                            \
    ARG2NM,                                                            \
    ARG2OPT,                                                           \
    ARG3TY,                                                            \
    ARG3NM,                                                            \
    ARG3OPT,                                                           \
    ARG4TY,                                                            \
    ARG4NM,                                                            \
    ARG4OPT)                                                           \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    ARG2TY _##ARG2NM;                                                  \
    ARG3TY _##ARG3NM;                                                  \
    ARG4TY _##ARG4NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_,                    \
        detail::ParamTrait<ARG2TY>::Type ARG2NM##_,                    \
        detail::ParamTrait<ARG3TY>::Type ARG3NM##_,                    \
        detail::ParamTrait<ARG4TY>::Type ARG4NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)),                             \
          _##ARG2NM(std::move(ARG2NM##_)),                             \
          _##ARG3NM(std::move(ARG3NM##_)),                             \
          _##ARG4NM(std::move(ARG4NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      ESTreeVisit(V, _##ARG2NM);                                       \
      ESTreeVisit(V, _##ARG3NM);                                       \
      ESTreeVisit(V, _##ARG4NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
                                                                       \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#define ESTREE_NODE_6_ARGS(                                            \
    NAME,                                                              \
    BASE,                                                              \
    ARG0TY,                                                            \
    ARG0NM,                                                            \
    ARG0OPT,                                                           \
    ARG1TY,                                                            \
    ARG1NM,                                                            \
    ARG1OPT,                                                           \
    ARG2TY,                                                            \
    ARG2NM,                                                            \
    ARG2OPT,                                                           \
    ARG3TY,                                                            \
    ARG3NM,                                                            \
    ARG3OPT,                                                           \
    ARG4TY,                                                            \
    ARG4NM,                                                            \
    ARG4OPT,                                                           \
    ARG5TY,                                                            \
    ARG5NM,                                                            \
    ARG5OPT)                                                           \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    ARG2TY _##ARG2NM;                                                  \
    ARG3TY _##ARG3NM;                                                  \
    ARG4TY _##ARG4NM;                                                  \
    ARG5TY _##ARG5NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_,                    \
        detail::ParamTrait<ARG2TY>::Type ARG2NM##_,                    \
        detail::ParamTrait<ARG3TY>::Type ARG3NM##_,                    \
        detail::ParamTrait<ARG4TY>::Type ARG4NM##_,                    \
        detail::ParamTrait<ARG5TY>::Type ARG5NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)),                             \
          _##ARG2NM(std::move(ARG2NM##_)),                             \
          _##ARG3NM(std::move(ARG3NM##_)),                             \
          _##ARG4NM(std::move(ARG4NM##_)),                             \
          _##ARG5NM(std::move(ARG5NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      ESTreeVisit(V, _##ARG2NM);                                       \
      ESTreeVisit(V, _##ARG3NM);                                       \
      ESTreeVisit(V, _##ARG4NM);                                       \
      ESTreeVisit(V, _##ARG5NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
                                                                       \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#define ESTREE_NODE_7_ARGS(                                            \
    NAME,                                                              \
    BASE,                                                              \
    ARG0TY,                                                            \
    ARG0NM,                                                            \
    ARG0OPT,                                                           \
    ARG1TY,                                                            \
    ARG1NM,                                                            \
    ARG1OPT,                                                           \
    ARG2TY,                                                            \
    ARG2NM,                                                            \
    ARG2OPT,                                                           \
    ARG3TY,                                                            \
    ARG3NM,                                                            \
    ARG3OPT,                                                           \
    ARG4TY,                                                            \
    ARG4NM,                                                            \
    ARG4OPT,                                                           \
    ARG5TY,                                                            \
    ARG5NM,                                                            \
    ARG5OPT,                                                           \
    ARG6TY,                                                            \
    ARG6NM,                                                            \
    ARG6OPT)                                                           \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    ARG2TY _##ARG2NM;                                                  \
    ARG3TY _##ARG3NM;                                                  \
    ARG4TY _##ARG4NM;                                                  \
    ARG5TY _##ARG5NM;                                                  \
    ARG6TY _##ARG6NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_,                    \
        detail::ParamTrait<ARG2TY>::Type ARG2NM##_,                    \
        detail::ParamTrait<ARG3TY>::Type ARG3NM##_,                    \
        detail::ParamTrait<ARG4TY>::Type ARG4NM##_,                    \
        detail::ParamTrait<ARG5TY>::Type ARG5NM##_,                    \
        detail::ParamTrait<ARG6TY>::Type ARG6NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)),                             \
          _##ARG2NM(std::move(ARG2NM##_)),                             \
          _##ARG3NM(std::move(ARG3NM##_)),                             \
          _##ARG4NM(std::move(ARG4NM##_)),                             \
          _##ARG5NM(std::move(ARG5NM##_)),                             \
          _##ARG6NM(std::move(ARG6NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      ESTreeVisit(V, _##ARG2NM);                                       \
      ESTreeVisit(V, _##ARG3NM);                                       \
      ESTreeVisit(V, _##ARG4NM);                                       \
      ESTreeVisit(V, _##ARG5NM);                                       \
      ESTreeVisit(V, _##ARG6NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
                                                                       \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#define ESTREE_NODE_8_ARGS(                                            \
    NAME,                                                              \
    BASE,                                                              \
    ARG0TY,                                                            \
    ARG0NM,                                                            \
    ARG0OPT,                                                           \
    ARG1TY,                                                            \
    ARG1NM,                                                            \
    ARG1OPT,                                                           \
    ARG2TY,                                                            \
    ARG2NM,                                                            \
    ARG2OPT,                                                           \
    ARG3TY,                                                            \
    ARG3NM,                                                            \
    ARG3OPT,                                                           \
    ARG4TY,                                                            \
    ARG4NM,                                                            \
    ARG4OPT,                                                           \
    ARG5TY,                                                            \
    ARG5NM,                                                            \
    ARG5OPT,                                                           \
    ARG6TY,                                                            \
    ARG6NM,                                                            \
    ARG6OPT,                                                           \
    ARG7TY,                                                            \
    ARG7NM,                                                            \
    ARG7OPT)                                                           \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    ARG2TY _##ARG2NM;                                                  \
    ARG3TY _##ARG3NM;                                                  \
    ARG4TY _##ARG4NM;                                                  \
    ARG5TY _##ARG5NM;                                                  \
    ARG6TY _##ARG6NM;                                                  \
    ARG7TY _##ARG7NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_,                    \
        detail::ParamTrait<ARG2TY>::Type ARG2NM##_,                    \
        detail::ParamTrait<ARG3TY>::Type ARG3NM##_,                    \
        detail::ParamTrait<ARG4TY>::Type ARG4NM##_,                    \
        detail::ParamTrait<ARG5TY>::Type ARG5NM##_,                    \
        detail::ParamTrait<ARG6TY>::Type ARG6NM##_,                    \
        detail::ParamTrait<ARG7TY>::Type ARG7NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)),                             \
          _##ARG2NM(std::move(ARG2NM##_)),                             \
          _##ARG3NM(std::move(ARG3NM##_)),                             \
          _##ARG4NM(std::move(ARG4NM##_)),                             \
          _##ARG5NM(std::move(ARG5NM##_)),                             \
          _##ARG6NM(std::move(ARG6NM##_)),                             \
          _##ARG7NM(std::move(ARG7NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      ESTreeVisit(V, _##ARG2NM);                                       \
      ESTreeVisit(V, _##ARG3NM);                                       \
      ESTreeVisit(V, _##ARG4NM);                                       \
      ESTreeVisit(V, _##ARG5NM);                                       \
      ESTreeVisit(V, _##ARG6NM);                                       \
      ESTreeVisit(V, _##ARG7NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
                                                                       \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#define ESTREE_NODE_9_ARGS(                                            \
    NAME,                                                              \
    BASE,                                                              \
    ARG0TY,                                                            \
    ARG0NM,                                                            \
    ARG0OPT,                                                           \
    ARG1TY,                                                            \
    ARG1NM,                                                            \
    ARG1OPT,                                                           \
    ARG2TY,                                                            \
    ARG2NM,                                                            \
    ARG2OPT,                                                           \
    ARG3TY,                                                            \
    ARG3NM,                                                            \
    ARG3OPT,                                                           \
    ARG4TY,                                                            \
    ARG4NM,                                                            \
    ARG4OPT,                                                           \
    ARG5TY,                                                            \
    ARG5NM,                                                            \
    ARG5OPT,                                                           \
    ARG6TY,                                                            \
    ARG6NM,                                                            \
    ARG6OPT,                                                           \
    ARG7TY,                                                            \
    ARG7NM,                                                            \
    ARG7OPT,                                                           \
    ARG8TY,                                                            \
    ARG8NM,                                                            \
    ARG8OPT)                                                           \
  class NAME##Node : public BASE##Node,                                \
                     public detail::DecoratorTrait<NAME##Node>::Type { \
   public:                                                             \
    ARG0TY _##ARG0NM;                                                  \
    ARG1TY _##ARG1NM;                                                  \
    ARG2TY _##ARG2NM;                                                  \
    ARG3TY _##ARG3NM;                                                  \
    ARG4TY _##ARG4NM;                                                  \
    ARG5TY _##ARG5NM;                                                  \
    ARG6TY _##ARG6NM;                                                  \
    ARG7TY _##ARG7NM;                                                  \
    ARG8TY _##ARG8NM;                                                  \
    explicit NAME##Node(                                               \
        detail::ParamTrait<ARG0TY>::Type ARG0NM##_,                    \
        detail::ParamTrait<ARG1TY>::Type ARG1NM##_,                    \
        detail::ParamTrait<ARG2TY>::Type ARG2NM##_,                    \
        detail::ParamTrait<ARG3TY>::Type ARG3NM##_,                    \
        detail::ParamTrait<ARG4TY>::Type ARG4NM##_,                    \
        detail::ParamTrait<ARG5TY>::Type ARG5NM##_,                    \
        detail::ParamTrait<ARG6TY>::Type ARG6NM##_,                    \
        detail::ParamTrait<ARG7TY>::Type ARG7NM##_,                    \
        detail::ParamTrait<ARG8TY>::Type ARG8NM##_)                    \
        : BASE##Node(NodeKind::NAME),                                  \
          _##ARG0NM(std::move(ARG0NM##_)),                             \
          _##ARG1NM(std::move(ARG1NM##_)),                             \
          _##ARG2NM(std::move(ARG2NM##_)),                             \
          _##ARG3NM(std::move(ARG3NM##_)),                             \
          _##ARG4NM(std::move(ARG4NM##_)),                             \
          _##ARG5NM(std::move(ARG5NM##_)),                             \
          _##ARG6NM(std::move(ARG6NM##_)),                             \
          _##ARG7NM(std::move(ARG7NM##_)),                             \
          _##ARG8NM(std::move(ARG8NM##_)) {}                           \
    template <class Visitor>                                           \
    void visit(Visitor &V) {                                           \
      if (!V.shouldVisit(this)) {                                      \
        return;                                                        \
      }                                                                \
      V.enter(this);                                                   \
      ESTreeVisit(V, _##ARG0NM);                                       \
      ESTreeVisit(V, _##ARG1NM);                                       \
      ESTreeVisit(V, _##ARG2NM);                                       \
      ESTreeVisit(V, _##ARG3NM);                                       \
      ESTreeVisit(V, _##ARG4NM);                                       \
      ESTreeVisit(V, _##ARG5NM);                                       \
      ESTreeVisit(V, _##ARG6NM);                                       \
      ESTreeVisit(V, _##ARG7NM);                                       \
      ESTreeVisit(V, _##ARG8NM);                                       \
      V.leave(this);                                                   \
    }                                                                  \
                                                                       \
    static bool classof(const Node *V) {                               \
      return V->getKind() == NodeKind::NAME;                           \
    }                                                                  \
  };

#include "ESTree.def"

               
template <class Visitor>
void ESTreeVisit(Visitor &V, NodePtr Node) {
  if (!Node) {
    return;
  }

  switch (Node->getKind()) {
    default:
      llvm_unreachable("invalid node kind");

#define ESTREE_NODE_0_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_1_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_2_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_3_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_4_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_5_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_6_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_7_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_8_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);
#define ESTREE_NODE_9_ARGS(NAME, ...) \
  case NodeKind::NAME:                \
    return cast<NAME##Node>(Node)->visit(V);

#include "ESTree.def"
  }
}

                                                                   
NodeList &getParams(FunctionLikeNode *node);

                                                                          
                             
                                                                          
              
BlockStatementNode *getBlockStatement(FunctionLikeNode *node);

                                                     
Node *getObject(MemberExpressionLikeNode *node);

                                                       
Node *getProperty(MemberExpressionLikeNode *node);

                                                           
NodeBoolean getComputed(MemberExpressionLikeNode *node);

                                   
Node *getCallee(CallExpressionLikeNode *node);

                                           
NodeList &getArguments(CallExpressionLikeNode *node);

                                                                             
                 
bool hasSimpleParams(FunctionLikeNode *node);

                                                        
bool hasParamExpressions(FunctionLikeNode *node);

                                                      
bool isGenerator(FunctionLikeNode *node);

                                                   
bool isAsync(FunctionLikeNode *node);

                                                  
struct NodeKindInfo : llvh::DenseMapInfo<NodeKind> {
  static inline NodeKind getEmptyKey() {
    return (NodeKind)(-1);
  }
  static inline NodeKind getTombstoneKey() {
    return (NodeKind)(-2);
  }
  static inline bool isEqual(const NodeKind &a, const NodeKind &b) {
    return a == b;
  }
  static unsigned getHashValue(const NodeKind &Val) {
    return (unsigned)Val;
  }
};

using NodeKindSet = llvh::DenseSet<ESTree::NodeKind, NodeKindInfo>;

                                                                                
                                                                               
constexpr unsigned MAX_NESTED_ASSIGNMENTS = 30000;

                                                                         
                                                                           
                           
constexpr unsigned MAX_NESTED_BINARY = 30000;

                                                                     
                                                     
template <class N>
static N *checkExprOperator(
    ESTree::Node *e,
    llvh::ArrayRef<llvh::StringRef> ops) {
  if (auto *n = llvh::dyn_cast<N>(e)) {
    if (std::find(ops.begin(), ops.end(), n->_operator->str()) != ops.end())
      return n;
  }
  return nullptr;
}

                                                                             
                                                                              
                                                         
                                                       
                                                                           
                                                        
   
                                                                           
                                                                         
                                                       
template <class N>
static llvh::SmallVector<N *, 1> linearizeLeft(
    N *e,
    llvh::ArrayRef<llvh::StringRef> ops) {
  llvh::SmallVector<N *, 1> vec;

  vec.push_back(e);
  while (auto *left = checkExprOperator<N>(e->_left, ops)) {
    e = left;
    vec.push_back(e);
  }

  std::reverse(vec.begin(), vec.end());
  return vec;
}

                                                                              
                                                                              
                                                   
                                                        
                                                                          
                                                         
   
                                                                           
                                                                         
                                                                               
                                                 
template <class N>
static llvh::SmallVector<N *, 1> linearizeRight(
    N *e,
    llvh::ArrayRef<llvh::StringRef> ops) {
  llvh::SmallVector<N *, 1> vec;

  vec.push_back(e);
  while (auto *right = checkExprOperator<N>(e->_right, ops)) {
    e = right;
    vec.push_back(e);
  }

  return vec;
}

}                    
}                    

#endif
