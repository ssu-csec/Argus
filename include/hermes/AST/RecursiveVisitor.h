/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_RECURSIVEVISITOR_H
#define HERMES_AST_RECURSIVEVISITOR_H

#include "hermes/AST/ESTree.h"

#include "llvh/Support/Casting.h"

#include <variant>

namespace hermes {
namespace ESTree {

                                                                                
                                                                             
                                                        
struct UnmodifiedT {};

inline UnmodifiedT Unmodified;

                                                                          
                                                                 
struct RemovedT {};

inline RemovedT Removed;

                                                                             
                                                                               
                        
using VisitResult = std::variant<UnmodifiedT, RemovedT, Node *>;

namespace detail {

                                                                       
template <typename V, typename N, typename U = void>
struct VisitCaller {
  static auto call(V &v, N *node, Node *) {
                                                 
    if constexpr (std::is_same_v<void, decltype(v.visit(node))>) {
                                                               
      v.visit(node);
      return Unmodified;
    } else {
                                                              
      return v.visit(node);
    }
  }
};

                                                                            
                                                                        
                                                                             
template <
    typename V,
    typename N,
    typename = decltype(((V *)nullptr)->visit((N *)nullptr, (Node *)nullptr))>
struct VisitTakesParentImpl {
  using Type = void;
};
template <typename V, typename N>
using EnableIfVisitTakesParent = typename VisitTakesParentImpl<V, N>::Type;

template <typename V, typename N>
struct VisitCaller<V, N, EnableIfVisitTakesParent<V, N>> {
  static auto call(V &v, N *node, Node *parent) {
    if constexpr (std::is_same_v<void, decltype(v.visit(node, parent))>) {
                                                               
      v.visit(node, parent);
      return Unmodified;
    } else {
                                                              
      return v.visit(node, parent);
    }
  }
};

                                                                           
                              

                                                                               
                            
template <typename V, typename N, typename = void>
struct IsReadOnlyVisitImpl {
  static constexpr bool value =
      std::is_same_v<void, decltype(((V *)nullptr)->visit((N *)nullptr))>;
};

                                                                                
        
template <typename V, typename N>
struct IsReadOnlyVisitImpl<V, N, EnableIfVisitTakesParent<V, N>> {
  static constexpr bool value = std::is_same_v<
      void,
      decltype(((V *)nullptr)->visit((N *)nullptr, (Node *)nullptr))>;
};

template <typename V, typename N>
inline constexpr bool isReadOnlyVisit() {
  return IsReadOnlyVisitImpl<V, N>::value;
}

                                                                          
                                                                    
template <typename Visitor>
static constexpr bool isReadOnlyVisitor() {
#define ESTREE_NODE_0_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_1_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_2_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_3_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_4_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_5_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_6_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_7_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_8_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&
#define ESTREE_NODE_9_ARGS(NAME, ...) isReadOnlyVisit<Visitor, NAME##Node>() &&

  return
#include "hermes/AST/ESTree.def"
      true;
}

}                    

using llvh::cast;

                                                                          
                                                                             
             
   
                                    
                          
                                                          
                                  
                                                    
   
                                                                              
                                                                             
   
                                                                            
                                                                               
                               
         
                            
                                          
            
                                                                            
                                                                            
                
   
                                                     
                                
                                       
                                 
            
                                                                         
                                                                               
   
                                                                             
                                                                             
                                                                                
                                                                              
                
   
                                     
                                                                            
                                                                           
                                                          
template <
    class Visitor,
    bool readOnlyVisitor = detail::isReadOnlyVisitor<Visitor>()>
struct RecursiveVisitorDispatch {
                                                                         
                                                                             
                                                  
  static VisitResult visit(Visitor &v, Node *node, Node *parent) {
    if (!node)
      return Unmodified;
    if (LLVM_UNLIKELY(!v.incRecursionDepth(node)))
      return Unmodified;

    VisitResult result;
    switch (node->getKind()) {
      default:
        llvm_unreachable("invalid node kind");

#define VISIT(NAME)                                          \
  case NodeKind::NAME:                                       \
    result = detail::VisitCaller<Visitor, NAME##Node>::call( \
        v, cast<NAME##Node>(node), parent);                  \
    break;

#define ESTREE_NODE_0_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_1_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_2_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_3_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_4_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_5_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_6_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_7_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_8_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_9_ARGS(NAME, ...) VISIT(NAME)

#include "hermes/AST/ESTree.def"

#undef VISIT
    }
    v.decRecursionDepth();
    return result;
  }

  static UnmodifiedT visit(Visitor &, NodeLabel, Node *) {
    return Unmodified;
  }
  static UnmodifiedT visit(Visitor &, NodeBoolean, Node *) {
    return Unmodified;
  }
  static UnmodifiedT visit(Visitor &, NodeNumber &, Node *) {
    return Unmodified;
  }

  static UnmodifiedT visit(Visitor &v, NodeList &list, Node *parent) {
    if constexpr (readOnlyVisitor) {
                                                                             
                      
      for (Node &node : list) {
        visit(v, &node, parent);
      }
    } else {
      for (auto it = list.begin(), end = list.end(); it != end;) {
        auto curr = it++;

                                                                          
                                                                
        list.erase(curr);

        VisitResult res = visit(v, &*curr, parent);
        if (std::holds_alternative<Node *>(res)) {
                                                                 
          list.insert(it, *std::get<Node *>(res));
        } else if (std::holds_alternative<UnmodifiedT>(res)) {
                                                                            
          list.insert(it, *curr);
        } else {
                                                                              
                                  
          assert(
              std::holds_alternative<RemovedT>(res) &&
              "Unexpected VisitResult alternative.");
        }
      }
    }
    return Unmodified;
  }

                                                                             
                                                                          
                                                                   
  static void postVisit(NodeLabel *, UnmodifiedT) {}

  static void postVisit(NodeBoolean *, UnmodifiedT) {}

  static void postVisit(NodeNumber *, UnmodifiedT) {}

  static void postVisit(NodeList *, UnmodifiedT) {}

  static void postVisit(Node **node, VisitResult vr) {
    if (std::holds_alternative<RemovedT>(vr)) {
                                      
      *node = nullptr;
    } else if (std::holds_alternative<Node *>(vr)) {
                                      
      *node = std::get<Node *>(vr);
    } else {
      assert(
          std::holds_alternative<UnmodifiedT>(vr) &&
          "Unexpected VisitResult alternative.");
    }
  }

                                                 
  static void visitChildren(Visitor &v, Node *node) {
    if (!node)
      return;

    switch (node->getKind()) {
      default:
        llvm_unreachable("invalid node kind");

#define VISIT(NAME)    \
  case NodeKind::NAME: \
    return visitChildren(v, cast<NAME##Node>(node));

#define ESTREE_NODE_0_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_1_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_2_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_3_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_4_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_5_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_6_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_7_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_8_ARGS(NAME, ...) VISIT(NAME)
#define ESTREE_NODE_9_ARGS(NAME, ...) VISIT(NAME)

#include "hermes/AST/ESTree.def"

#undef VISIT
    }
  }

#define VISIT(visitor, field, parent)                        \
  if constexpr (readOnlyVisitor) {                           \
                                                             \
    visit(visitor, field, parent);                           \
  } else {                                                   \
    postVisit(&(field), visit(visitor, field, parent));      \
  }

                                                                         
#define ESTREE_NODE_0_ARGS(NAME, BASE) \
  static void visitChildren(Visitor &v, NAME##Node *) {}

#define ESTREE_NODE_1_ARGS(NAME, BASE, ARG0TY, ARG0NM, ARG0OPT) \
  static void visitChildren(Visitor &v, NAME##Node *node) {     \
    VISIT(v, node->_##ARG0NM, node);                            \
  }

#define ESTREE_NODE_2_ARGS(                                       \
    NAME, BASE, ARG0TY, ARG0NM, ARG0OPT, ARG1TY, ARG1NM, ARG1OPT) \
  static void visitChildren(Visitor &v, NAME##Node *node) {       \
    VISIT(v, node->_##ARG0NM, node);                              \
    VISIT(v, node->_##ARG1NM, node);                              \
  }

#define ESTREE_NODE_3_ARGS(                                 \
    NAME,                                                   \
    BASE,                                                   \
    ARG0TY,                                                 \
    ARG0NM,                                                 \
    ARG0OPT,                                                \
    ARG1TY,                                                 \
    ARG1NM,                                                 \
    ARG1OPT,                                                \
    ARG2TY,                                                 \
    ARG2NM,                                                 \
    ARG2OPT)                                                \
  static void visitChildren(Visitor &v, NAME##Node *node) { \
    VISIT(v, node->_##ARG0NM, node);                        \
    VISIT(v, node->_##ARG1NM, node);                        \
    VISIT(v, node->_##ARG2NM, node);                        \
  }

#define ESTREE_NODE_4_ARGS(                                 \
    NAME,                                                   \
    BASE,                                                   \
    ARG0TY,                                                 \
    ARG0NM,                                                 \
    ARG0OPT,                                                \
    ARG1TY,                                                 \
    ARG1NM,                                                 \
    ARG1OPT,                                                \
    ARG2TY,                                                 \
    ARG2NM,                                                 \
    ARG2OPT,                                                \
    ARG3TY,                                                 \
    ARG3NM,                                                 \
    ARG3OPT)                                                \
  static void visitChildren(Visitor &v, NAME##Node *node) { \
    VISIT(v, node->_##ARG0NM, node);                        \
    VISIT(v, node->_##ARG1NM, node);                        \
    VISIT(v, node->_##ARG2NM, node);                        \
    VISIT(v, node->_##ARG3NM, node);                        \
  }

#define ESTREE_NODE_5_ARGS(                                 \
    NAME,                                                   \
    BASE,                                                   \
    ARG0TY,                                                 \
    ARG0NM,                                                 \
    ARG0OPT,                                                \
    ARG1TY,                                                 \
    ARG1NM,                                                 \
    ARG1OPT,                                                \
    ARG2TY,                                                 \
    ARG2NM,                                                 \
    ARG2OPT,                                                \
    ARG3TY,                                                 \
    ARG3NM,                                                 \
    ARG3OPT,                                                \
    ARG4TY,                                                 \
    ARG4NM,                                                 \
    ARG4OPT)                                                \
  static void visitChildren(Visitor &v, NAME##Node *node) { \
    VISIT(v, node->_##ARG0NM, node);                        \
    VISIT(v, node->_##ARG1NM, node);                        \
    VISIT(v, node->_##ARG2NM, node);                        \
    VISIT(v, node->_##ARG3NM, node);                        \
    VISIT(v, node->_##ARG4NM, node);                        \
  }

#define ESTREE_NODE_6_ARGS(                                 \
    NAME,                                                   \
    BASE,                                                   \
    ARG0TY,                                                 \
    ARG0NM,                                                 \
    ARG0OPT,                                                \
    ARG1TY,                                                 \
    ARG1NM,                                                 \
    ARG1OPT,                                                \
    ARG2TY,                                                 \
    ARG2NM,                                                 \
    ARG2OPT,                                                \
    ARG3TY,                                                 \
    ARG3NM,                                                 \
    ARG3OPT,                                                \
    ARG4TY,                                                 \
    ARG4NM,                                                 \
    ARG4OPT,                                                \
    ARG5TY,                                                 \
    ARG5NM,                                                 \
    ARG5OPT)                                                \
  static void visitChildren(Visitor &v, NAME##Node *node) { \
    VISIT(v, node->_##ARG0NM, node);                        \
    VISIT(v, node->_##ARG1NM, node);                        \
    VISIT(v, node->_##ARG2NM, node);                        \
    VISIT(v, node->_##ARG3NM, node);                        \
    VISIT(v, node->_##ARG4NM, node);                        \
    VISIT(v, node->_##ARG5NM, node);                        \
  }

#define ESTREE_NODE_7_ARGS(                                 \
    NAME,                                                   \
    BASE,                                                   \
    ARG0TY,                                                 \
    ARG0NM,                                                 \
    ARG0OPT,                                                \
    ARG1TY,                                                 \
    ARG1NM,                                                 \
    ARG1OPT,                                                \
    ARG2TY,                                                 \
    ARG2NM,                                                 \
    ARG2OPT,                                                \
    ARG3TY,                                                 \
    ARG3NM,                                                 \
    ARG3OPT,                                                \
    ARG4TY,                                                 \
    ARG4NM,                                                 \
    ARG4OPT,                                                \
    ARG5TY,                                                 \
    ARG5NM,                                                 \
    ARG5OPT,                                                \
    ARG6TY,                                                 \
    ARG6NM,                                                 \
    ARG6OPT)                                                \
  static void visitChildren(Visitor &v, NAME##Node *node) { \
    VISIT(v, node->_##ARG0NM, node);                        \
    VISIT(v, node->_##ARG1NM, node);                        \
    VISIT(v, node->_##ARG2NM, node);                        \
    VISIT(v, node->_##ARG3NM, node);                        \
    VISIT(v, node->_##ARG4NM, node);                        \
    VISIT(v, node->_##ARG5NM, node);                        \
    VISIT(v, node->_##ARG6NM, node);                        \
  }

#define ESTREE_NODE_8_ARGS(                                 \
    NAME,                                                   \
    BASE,                                                   \
    ARG0TY,                                                 \
    ARG0NM,                                                 \
    ARG0OPT,                                                \
    ARG1TY,                                                 \
    ARG1NM,                                                 \
    ARG1OPT,                                                \
    ARG2TY,                                                 \
    ARG2NM,                                                 \
    ARG2OPT,                                                \
    ARG3TY,                                                 \
    ARG3NM,                                                 \
    ARG3OPT,                                                \
    ARG4TY,                                                 \
    ARG4NM,                                                 \
    ARG4OPT,                                                \
    ARG5TY,                                                 \
    ARG5NM,                                                 \
    ARG5OPT,                                                \
    ARG6TY,                                                 \
    ARG6NM,                                                 \
    ARG6OPT,                                                \
    ARG7TY,                                                 \
    ARG7NM,                                                 \
    ARG7OPT)                                                \
  static void visitChildren(Visitor &v, NAME##Node *node) { \
    VISIT(v, node->_##ARG0NM, node);                        \
    VISIT(v, node->_##ARG1NM, node);                        \
    VISIT(v, node->_##ARG2NM, node);                        \
    VISIT(v, node->_##ARG3NM, node);                        \
    VISIT(v, node->_##ARG4NM, node);                        \
    VISIT(v, node->_##ARG5NM, node);                        \
    VISIT(v, node->_##ARG6NM, node);                        \
    VISIT(v, node->_##ARG7NM, node);                        \
  }

#define ESTREE_NODE_9_ARGS(                                 \
    NAME,                                                   \
    BASE,                                                   \
    ARG0TY,                                                 \
    ARG0NM,                                                 \
    ARG0OPT,                                                \
    ARG1TY,                                                 \
    ARG1NM,                                                 \
    ARG1OPT,                                                \
    ARG2TY,                                                 \
    ARG2NM,                                                 \
    ARG2OPT,                                                \
    ARG3TY,                                                 \
    ARG3NM,                                                 \
    ARG3OPT,                                                \
    ARG4TY,                                                 \
    ARG4NM,                                                 \
    ARG4OPT,                                                \
    ARG5TY,                                                 \
    ARG5NM,                                                 \
    ARG5OPT,                                                \
    ARG6TY,                                                 \
    ARG6NM,                                                 \
    ARG6OPT,                                                \
    ARG7TY,                                                 \
    ARG7NM,                                                 \
    ARG7OPT,                                                \
    ARG8TY,                                                 \
    ARG8NM,                                                 \
    ARG8OPT)                                                \
  static void visitChildren(Visitor &v, NAME##Node *node) { \
    visit(v, node->_##ARG0NM, node);                        \
    visit(v, node->_##ARG1NM, node);                        \
    visit(v, node->_##ARG2NM, node);                        \
    visit(v, node->_##ARG3NM, node);                        \
    visit(v, node->_##ARG4NM, node);                        \
    visit(v, node->_##ARG5NM, node);                        \
    visit(v, node->_##ARG6NM, node);                        \
    visit(v, node->_##ARG7NM, node);                        \
    visit(v, node->_##ARG8NM, node);                        \
  }

#include "hermes/AST/ESTree.def"

#undef VISIT
};

                                                                       
                                                                           
                                                
template <class Visitor>
void visitESTreeNode(Visitor &v, Node *node, Node *parent = nullptr) {
  RecursiveVisitorDispatch<Visitor>::visit(v, node, parent);
}

                                               
template <class Visitor, class Node>
void visitESTreeChildren(Visitor &v, Node *node) {
  RecursiveVisitorDispatch<Visitor>::visitChildren(v, node);
}

}                    
}                    

#endif                                 
