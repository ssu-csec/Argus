/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/AST/ES6Class.h"
#include "hermes/AST/RecursiveVisitor.h"
#include "hermes/Parser/JSLexer.h"
#include "hermes/Support/InternalIdentifierMaker.h"
#include "hermes/Support/SourceErrorManager.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/raw_ostream.h"
#include <map>
#include <set>

namespace {
using namespace hermes;

                                                                  
                                                                
                                                                     
class NodeVector {
 public:
  using Storage = llvh::SmallVector<ESTree::Node *, 8>;

  NodeVector() = default;
  NodeVector(std::initializer_list<ESTree::Node *> nodes) {
    for (auto &node : nodes) {
      _storage.push_back(node);
    }
  }

  NodeVector(ESTree::NodeList &list) {
    for (auto &node : list) {
      _storage.push_back(&node);
    }
  }

  ~NodeVector() = default;

  size_t size() const {
    return _storage.size();
  }

  Storage::const_iterator begin() const {
    return _storage.begin();
  }

  Storage::const_iterator end() const {
    return _storage.end();
  }

  void append(ESTree::Node *node) {
    _storage.emplace_back(node);
  }

  void prepend(ESTree::Node *node) {
    _storage.insert(_storage.begin(), node);
  }

  ESTree::NodeList toNodeList() const {
    ESTree::NodeList nodeList;
    for (auto &node : _storage) {
      nodeList.push_back(*node);
    }

    return nodeList;
  }

 private:
  Storage _storage;
};

                                                                        
                                                                            
                                                                                 
struct LiteralFieldSuperCalls {
  unsigned calls = 0;
  unsigned depth = 0;
  unsigned nodes = 0;
  bool exhausted = false;

  void visit(ESTree::Node *node) {
    visitESTreeChildren(*this, node);
  }
  void visit(ESTree::CallExpressionNode *call) {
    if (llvh::isa<ESTree::SuperNode>(call->_callee)) ++calls;
    visitESTreeChildren(*this, call);
  }
  bool incRecursionDepth(ESTree::Node *) {
    if (exhausted || depth >= 256 || nodes >= 100000) {
      exhausted = true;
      return false;
    }
    ++depth;
    ++nodes;
    return true;
  }
  void decRecursionDepth() { --depth; }
};

                                                                              
                                                                              
struct ConstructorSuperCalls {
  std::set<ESTree::SuperNode *> calls;
  unsigned depth{0}, nodes{0}; bool exhausted{false};
  void visit(ESTree::Node *n) { visitESTreeChildren(*this,n); }
  void visit(ESTree::CallExpressionNode *n) {
    if (auto *s=llvh::dyn_cast<ESTree::SuperNode>(n->_callee)) calls.insert(s);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::FunctionExpressionNode *) {}
  void visit(ESTree::FunctionDeclarationNode *) {}
  void visit(ESTree::ClassExpressionNode *) {}
  void visit(ESTree::ClassDeclarationNode *) {}
  bool incRecursionDepth(ESTree::Node *) {
    if (exhausted || depth>=256 || ++nodes>100000) {exhausted=true;return false;}
    ++depth;return true;
  }
  void decRecursionDepth() {--depth;}
  bool scan(ESTree::ClassBodyNode *body) {
    for(auto &entry:body->_body) {
      auto *m=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry);
      if (!m || m->_kind->str()!="constructor") continue;
      if(auto *f=llvh::dyn_cast<ESTree::FunctionExpressionNode>(m->_value))
        visitESTreeChildren(*this,f);
    }
    return !exhausted;
  }
};

struct NativePrivateFieldProfile {
  ConstructorSuperCalls constructorSuper;
  Context &context;
  std::map<UniqueString *, ESTree::ClassPrivatePropertyNode *> fields;
  std::map<UniqueString *, unsigned> privateKinds;                                
                                                                            
                                                                       
  std::set<ESTree::AssignmentPatternNode *> identifierParameterDefaults;
                                                                           
                                               
  std::set<ESTree::FunctionExpressionNode *> directMethodFunctions;
  std::set<ESTree::FunctionExpressionNode *> nestedObjectGetters;
  bool parameterDefault{false};
  bool staticBlockContext{false};
  unsigned superBarriers{0};
  std::set<ESTree::SuperNode *> propertySupers;
  unsigned depth{0}, nodes{0}, functions{0};
                                                                           
                                                                               
  unsigned argumentsOwners{0};
  bool fieldInitializer{false};
  bool asyncArrowBody{false};
  UniqueString *className{nullptr};
  bool nameShadowed{false};
  std::set<ESTree::Node *> declarationBindingPatterns;
  std::set<ESTree::AssignmentPatternNode *> declarationBindingDefaults;
  const char *failure{nullptr};
  ESTree::Node *failureNode{nullptr};

  explicit NativePrivateFieldProfile(Context &c) : context(c) {}
  void fail(const char *reason, ESTree::Node *node) {
    if (!failure) { failure=reason; failureNode=node; }
  }
  static ESTree::PrivateNameNode *privateMember(ESTree::Node *node) {
    auto *m=llvh::dyn_cast_or_null<ESTree::MemberExpressionNode>(node);
    return m ? llvh::dyn_cast<ESTree::PrivateNameNode>(m->_property) : nullptr;
  }
  void visit(ESTree::Node *node) { visitESTreeChildren(*this,node); }
  bool incRecursionDepth(ESTree::Node *node) {
    if (failure) return false;
    if (++nodes>100000 || depth>=256) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] PROFILE_BUDGET",node);return false;
    }
    ++depth;return true;
  }
  void decRecursionDepth() { --depth; }
  void visit(ESTree::PrivateNameNode *node) {
    auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(node->_id);
    if (!id || (!fields.count(id->_name) && !privateKinds.count(id->_name)))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] UNRESOLVED_PRIVATE_OWNER",node);
  }
  void visit(ESTree::ClassDeclarationNode *n) { fail("[NATIVE_PRIVATE_UNSUPPORTED] NESTED_CLASS",n); }
  void visit(ESTree::ClassExpressionNode *n) { fail("[NATIVE_PRIVATE_UNSUPPORTED] NESTED_CLASS",n); }
  void visit(ESTree::ClassPropertyNode *n) {
                                                                            
                                                                             
                                                                      
    if (n->_declare || n->_optional || n->_typeAnnotation ||
        n->_tsModifiers || n->_variance) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] MIXED_PUBLIC_FIELD",n); return;
    }
    if (!(llvh::isa<ESTree::StringLiteralNode>(n->_key) ||
          llvh::isa<ESTree::NumericLiteralNode>(n->_key) ||
          (!n->_computed && llvh::isa<ESTree::IdentifierNode>(n->_key)))) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] PUBLIC_FIELD_KEY",n->_key); return;
    }
    if(n->_static && n->_computed) {
      auto *str=llvh::dyn_cast<ESTree::StringLiteralNode>(n->_key);
      if(str&&str->_value->str()=="prototype")
        fail("[NATIVE_PRIVATE_UNSUPPORTED] COMPUTED_STATIC_PROTOTYPE_ORDER",n);
    }
    if(n->_static && !n->_computed) {
      auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(n->_key);
      auto *str=llvh::dyn_cast<ESTree::StringLiteralNode>(n->_key);
      if((id&&id->_name->str()=="prototype") || (str&&str->_value->str()=="prototype"))
        fail("[NATIVE_PRIVATE_INVALID] STATIC_PROTOTYPE_EARLY_ERROR",n);
    }
    const bool old = fieldInitializer; fieldInitializer = true;
    if (n->_value) visitESTreeNode(*this,n->_value);
    fieldInitializer = old;
  }
  void visit(ESTree::StaticBlockNode *n) {
    const bool previous=staticBlockContext;staticBlockContext=true;
    const bool outer=nameShadowed;
    nameShadowed |= hoistedVarShadows(n);
    for(auto &statement:n->_body) nameShadowed |= lexicalDeclarationShadows(&statement);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;staticBlockContext=previous;
  }
  void visit(ESTree::ReturnStatementNode *n) {
    if(staticBlockContext && !functions)
      fail("[NATIVE_PRIVATE_UNSUPPORTED] STATIC_BLOCK_RETURN",n);
    visitESTreeChildren(*this,n);
  }
  static bool superMember(ESTree::Node *node) {
    auto *m=llvh::dyn_cast_or_null<ESTree::MemberExpressionNode>(node);
    return m && llvh::isa<ESTree::SuperNode>(m->_object);
  }
  void visit(ESTree::MemberExpressionNode *n) {
    if(auto *super=llvh::dyn_cast<ESTree::SuperNode>(n->_object)) {
      if(superBarriers || (!n->_computed && !llvh::isa<ESTree::IdentifierNode>(n->_property)) ||
         (n->_computed && !llvh::isa<ESTree::StringLiteralNode>(n->_property) &&
          !llvh::isa<ESTree::NumericLiteralNode>(n->_property)))
        fail("[NATIVE_PRIVATE_UNSUPPORTED] SUPER_PROPERTY_CONTEXT_OR_KEY",n);
      else propertySupers.insert(super);
    }
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::WithStatementNode *n) { fail("[NATIVE_PRIVATE_UNSUPPORTED] DYNAMIC_SCOPE",n); }
  void visit(ESTree::SuperNode *n) { if(!constructorSuper.calls.count(n) && !propertySupers.count(n)) fail("[NATIVE_PRIVATE_UNSUPPORTED] SUPER",n); }
  void visit(ESTree::MetaPropertyNode *n) { fail("[NATIVE_PRIVATE_UNSUPPORTED] META_PROPERTY",n); }
  void visit(ESTree::AwaitExpressionNode *n) {
    if(!asyncArrowBody || parameterDefault) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] ASYNC",n);return;
    }
                                                                                
                                                                             
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::YieldExpressionNode *n) { fail("[NATIVE_PRIVATE_UNSUPPORTED] GENERATOR",n); }
  void collectDeclarationBindings(ESTree::Node *root) {
    llvh::SmallVector<ESTree::Node *,16> pending;
    if(root)pending.push_back(root);
    unsigned seen=0;
    while(!pending.empty()) {
      auto *n=pending.pop_back_val();
      if(++seen>100000) { fail("[NATIVE_PRIVATE_UNSUPPORTED] PROFILE_BUDGET",root);return; }
      if(llvh::isa<ESTree::IdentifierNode>(n) || llvh::isa<ESTree::EmptyNode>(n))continue;
      if(auto *a=llvh::dyn_cast<ESTree::ArrayPatternNode>(n)) {
        declarationBindingPatterns.insert(n);
                                                                             
                                                                               
        for(auto &element:a->_elements) {
          auto *rest=llvh::dyn_cast<ESTree::RestElementNode>(&element);
          if(!llvh::isa<ESTree::IdentifierNode>(&element) &&
             !llvh::isa<ESTree::EmptyNode>(&element) &&
             !(rest && llvh::isa<ESTree::IdentifierNode>(rest->_argument)))
            fail("[NATIVE_PRIVATE_UNSUPPORTED] ARRAY_BINDING_EFFECTFUL", &element);
          pending.push_back(&element);
        }
      } else if(auto *o=llvh::dyn_cast<ESTree::ObjectPatternNode>(n)) {
        declarationBindingPatterns.insert(n);
        for(auto &entry:o->_properties) {
          if(auto *property=llvh::dyn_cast<ESTree::PropertyNode>(&entry))
            pending.push_back(property->_value);
          else pending.push_back(&entry);
        }
      } else if(auto *r=llvh::dyn_cast<ESTree::RestElementNode>(n)) {
        pending.push_back(r->_argument);
      } else if(auto *d=llvh::dyn_cast<ESTree::AssignmentPatternNode>(n)) {
        declarationBindingDefaults.insert(d);pending.push_back(d->_left);
      } else {
                                                                               
        fail("[NATIVE_PRIVATE_UNSUPPORTED] DECLARATION_BINDING_SHAPE",n);
      }
    }
  }
  void visit(ESTree::VariableDeclaratorNode *n) {
    collectDeclarationBindings(n->_id);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::ArrayPatternNode *n) {
    if(!declarationBindingPatterns.count(n))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] DESTRUCTURING",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::ObjectPatternNode *n) {
    if(!declarationBindingPatterns.count(n))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] DESTRUCTURING",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::AssignmentPatternNode *n) {
    if(declarationBindingDefaults.count(n)) {
      visitESTreeChildren(*this,n);return;
    }
    if (!identifierParameterDefaults.count(n) ||
        (!llvh::isa<ESTree::IdentifierNode>(n->_left) && !llvh::isa<ESTree::ObjectPatternNode>(n->_left)) || !n->_right) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] DEFAULT_PARAMETER",n);
      return;
    }
                                                                            
                                                                           
    const bool oldDefault=parameterDefault;
    parameterDefault=true;
    visitESTreeChildren(*this,n);
    parameterDefault=oldDefault;
  }
                                                                              
                                                                             
  bool objectFormal(ESTree::Node *root) {
    auto *d=llvh::dyn_cast<ESTree::AssignmentPatternNode>(root);
    auto *pattern=d?d->_left:root;
    if(!llvh::isa<ESTree::ObjectPatternNode>(pattern))return false;
    llvh::SmallVector<ESTree::Node *,16> pending{root};unsigned seen=0;
    while(!pending.empty()) {
      auto *n=pending.pop_back_val();
      if(++seen>100000){fail("[NATIVE_PRIVATE_UNSUPPORTED] PROFILE_BUDGET",root);return false;}
      if(llvh::isa<ESTree::IdentifierNode>(n))continue;
      if(auto *o=llvh::dyn_cast<ESTree::ObjectPatternNode>(n)) {
        declarationBindingPatterns.insert(o);
        for(auto &entry:o->_properties) {
          if(auto *prop=llvh::dyn_cast<ESTree::PropertyNode>(&entry))pending.push_back(prop->_value);
          else pending.push_back(&entry);
        }
      } else if(auto *r=llvh::dyn_cast<ESTree::RestElementNode>(n)) {
        if(!llvh::isa<ESTree::IdentifierNode>(r->_argument))return false;
      } else if(auto *assignment=llvh::dyn_cast<ESTree::AssignmentPatternNode>(n)) {
        if(!assignment->_right)return false;
        identifierParameterDefaults.insert(assignment);pending.push_back(assignment->_left);
      } else return false;                                                      
    }
    return true;
  }
                                                                                  
                                                                          
  bool simpleArrayFormal(ESTree::Node *node) {
    auto *a=llvh::dyn_cast<ESTree::ArrayPatternNode>(node);
    if(!a)return false;
    for(auto &e:a->_elements)
      if(!llvh::isa<ESTree::IdentifierNode>(&e) && !llvh::isa<ESTree::EmptyNode>(&e))return false;
    declarationBindingPatterns.insert(a);return true;
  }
  void visit(ESTree::PropertyNode *n) {
                                                                             
                                                                               
    auto *fn=llvh::dyn_cast<ESTree::FunctionExpressionNode>(n->_value);
    if(n->_kind->str()=="get" && fn && fn->_params.empty() &&
       !fn->_async && !fn->_generator && !n->_computed)
      nestedObjectGetters.insert(fn);
    visitESTreeChildren(*this,n);
  }
  bool checkNestedFunction(ESTree::FunctionLikeNode *n,
                           ESTree::NodeList &params,
                           bool async, bool generator) {
    if (parameterDefault || (!fieldInitializer && !functions && !staticBlockContext)) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] NESTED_FUNCTION",n);
      return false;
    }
                                                                          
                                                                          
    auto *getter=llvh::dyn_cast<ESTree::FunctionExpressionNode>(n);
    if ((n->isMethodDefinition && (!getter || !nestedObjectGetters.count(getter))) ||
        n->loweredClassFunctionKind!=ESTree::LoweredClassFunctionKind::None) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] NESTED_METHOD",n);
      return false;
    }
    if (generator || (async && !llvh::isa<ESTree::ArrowFunctionExpressionNode>(n))) {
      fail("[NATIVE_PRIVATE_UNSUPPORTED] ASYNC_OR_GENERATOR",n);
      return false;
    }
    for (auto &param:params) {
      if(objectFormal(&param)||simpleArrayFormal(&param))continue;
                                                                            
                                                                              
      if(auto *assignment=llvh::dyn_cast<ESTree::AssignmentPatternNode>(&param)) {
        if(llvh::isa<ESTree::IdentifierNode>(assignment->_left) && assignment->_right) {
          identifierParameterDefaults.insert(assignment);
          continue;
        }
      }
      auto *rest=llvh::dyn_cast<ESTree::RestElementNode>(&param);
      if (!llvh::isa<ESTree::IdentifierNode>(&param) &&
          !(rest && llvh::isa<ESTree::IdentifierNode>(rest->_argument))) {
        fail("[NATIVE_PRIVATE_UNSUPPORTED] NESTED_PARAMETER_SHAPE",&param);
        return false;
      }
    }
    return true;
  }
  void visit(ESTree::ArrowFunctionExpressionNode *n) {
    if (!checkNestedFunction(n,n->_params,n->_async,false)) return;
    const bool oldAsync=asyncArrowBody;asyncArrowBody=n->_async;
    ++functions;
    visitFunctionScope(n,nullptr);
    --functions;asyncArrowBody=oldAsync;
  }
  void visit(ESTree::FunctionDeclarationNode *n) {
    if (!checkNestedFunction(n,n->_params,n->_async,n->_generator)) return;
    const bool oldAsync=asyncArrowBody;asyncArrowBody=false;
    ++functions;++superBarriers;++argumentsOwners;
    visitFunctionScope(n,n->_id);
    --argumentsOwners;--superBarriers;--functions;asyncArrowBody=oldAsync;
  }
  void visit(ESTree::ForInStatementNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= lexicalDeclarationShadows(n->_left);
    if (writesClassName(n->_left)) fail("[NATIVE_PRIVATE_UNSUPPORTED] CLASS_NAME_WRITE",n);
    if (privateMember(n->_left)) fail("[NATIVE_PRIVATE_UNSUPPORTED] ITERATION_WRITE",n);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::ForOfStatementNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= lexicalDeclarationShadows(n->_left);
    if (writesClassName(n->_left)) fail("[NATIVE_PRIVATE_UNSUPPORTED] CLASS_NAME_WRITE",n);
    if (privateMember(n->_left)) fail("[NATIVE_PRIVATE_UNSUPPORTED] ITERATION_WRITE",n);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::ClassPrivatePropertyNode *n) {
                                                                          
                                                                         

    const bool old=fieldInitializer;fieldInitializer=true;
                                                                          
                                                                           
    if (n->_value) visitESTreeNode(*this,n->_value);
    fieldInitializer=old;
  }
  void visit(ESTree::IdentifierNode *n) {
    if (n->_name->str()=="arguments" && !argumentsOwners)
      fail("[NATIVE_PRIVATE_UNSUPPORTED] ARGUMENTS_OWNER_UNPROVEN",n);
  }
  bool patternBindsClassName(ESTree::Node *node) {
    llvh::SmallVector<ESTree::Node *, 8> pending;
    if (node) pending.push_back(node);
    unsigned visited = 0;
    while (!pending.empty()) {
      auto *current = pending.pop_back_val();
      if (++visited > 100000) {
        fail("[NATIVE_PRIVATE_UNSUPPORTED] PROFILE_BUDGET", node);
        return false;
      }
      if (auto *id = llvh::dyn_cast<ESTree::IdentifierNode>(current)) {
        if (id->_name == className) return true;
      } else if (auto *pattern = llvh::dyn_cast<ESTree::AssignmentPatternNode>(current)) {
        pending.push_back(pattern->_left);
      } else if (auto *rest = llvh::dyn_cast<ESTree::RestElementNode>(current)) {
        pending.push_back(rest->_argument);
      } else if (auto *array = llvh::dyn_cast<ESTree::ArrayPatternNode>(current)) {
        for (auto &element : array->_elements) pending.push_back(&element);
      } else if (auto *object = llvh::dyn_cast<ESTree::ObjectPatternNode>(current)) {
        for (auto &entry : object->_properties) {
          if (auto *property = llvh::dyn_cast<ESTree::PropertyNode>(&entry))
            pending.push_back(property->_value);
          else pending.push_back(&entry);
        }
      } else if (auto *decl = llvh::dyn_cast<ESTree::VariableDeclarationNode>(current)) {
        for (auto &entry : decl->_declarations) pending.push_back(&entry);
      } else if (auto *decl = llvh::dyn_cast<ESTree::VariableDeclaratorNode>(current)) {
        pending.push_back(decl->_id);
      }
                                                                         
                                                                             
    }
    return false;
  }
  bool lexicalDeclarationShadows(ESTree::Node *node) {
    if (auto *decl = llvh::dyn_cast_or_null<ESTree::VariableDeclarationNode>(node))
      return decl->_kind->str() != "var" && patternBindsClassName(decl);
    if (auto *fn = llvh::dyn_cast_or_null<ESTree::FunctionDeclarationNode>(node))
      return patternBindsClassName(fn->_id);
    if (auto *cl = llvh::dyn_cast_or_null<ESTree::ClassDeclarationNode>(node))
      return patternBindsClassName(cl->_id);
    return false;
  }
  bool hoistedVarShadows(ESTree::Node *body) {
    struct Find {
      NativePrivateFieldProfile &profile;
      bool found{false}; unsigned depth{0}, nodes{0};
      void visit(ESTree::Node *n) { visitESTreeChildren(*this,n); }
      void visit(ESTree::VariableDeclarationNode *n) {
        if (n->_kind->str()=="var" && profile.patternBindsClassName(n)) found=true;
        visitESTreeChildren(*this,n);
      }
      void visit(ESTree::FunctionExpressionNode *) {}
      void visit(ESTree::ArrowFunctionExpressionNode *) {}
      void visit(ESTree::FunctionDeclarationNode *) {}
      void visit(ESTree::ClassExpressionNode *) {}
      void visit(ESTree::ClassDeclarationNode *) {}
      bool incRecursionDepth(ESTree::Node *n) {
        if (++nodes>100000 || depth>=256) {
          profile.fail("[NATIVE_PRIVATE_UNSUPPORTED] PROFILE_BUDGET",n);
          return false;
        }
        ++depth;return true;
      }
      void decRecursionDepth(){--depth;}
    } find{*this};
    if (body) visitESTreeNode(find,body);
    return find.found;
  }
  template<typename FunctionNode>
  void visitFunctionScope(FunctionNode *fn, ESTree::Node *selfName) {
    const bool outer=nameShadowed;
    nameShadowed |= patternBindsClassName(selfName);
    for (auto &param:fn->_params) nameShadowed |= patternBindsClassName(&param);
                                                                             
    for (auto &param:fn->_params) visitESTreeNode(*this,&param);
    nameShadowed |= hoistedVarShadows(fn->_body);
    if (fn->_body) visitESTreeNode(*this,fn->_body);
    nameShadowed=outer;
  }
  void visit(ESTree::BlockStatementNode *n) {
    const bool outer=nameShadowed;
    for (auto &statement:n->_body) nameShadowed |= lexicalDeclarationShadows(&statement);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::CatchClauseNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= patternBindsClassName(n->_param);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::ForStatementNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= lexicalDeclarationShadows(n->_init);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::SwitchStatementNode *n) {
                                                                       
    visitESTreeNode(*this,n->_discriminant);
    const bool outer=nameShadowed;
    for (auto &entry:n->_cases)
      for (auto &statement:llvh::cast<ESTree::SwitchCaseNode>(&entry)->_consequent)
        nameShadowed |= lexicalDeclarationShadows(&statement);
    for (auto &entry:n->_cases) visitESTreeNode(*this,&entry);
    nameShadowed=outer;
  }
  bool writesClassName(ESTree::Node *node) {
    return !nameShadowed && patternBindsClassName(node);
  }
  void visit(ESTree::AssignmentExpressionNode *n) {
    if(superMember(n->_left) && n->_operator->str()!="=")fail("[NATIVE_PRIVATE_UNSUPPORTED] SUPER_WRITE",n);
    if (writesClassName(n->_left))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] CLASS_NAME_WRITE",n);
    if (privateMember(n->_left) && n->_operator->str()!="=" && n->_operator->str()!="+=")
      fail("[NATIVE_PRIVATE_UNSUPPORTED] COMPOUND_WRITE",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::UpdateExpressionNode *n) {
    if (writesClassName(n->_argument))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] CLASS_NAME_WRITE",n);
                                                                                     
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::UnaryExpressionNode *n) {
    if (n->_operator->str()=="delete" && privateMember(n->_argument))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] DELETE",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::BinaryExpressionNode *n) {
    if (llvh::isa<ESTree::PrivateNameNode>(n->_left))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] PRIVATE_IN",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::CallExpressionNode *n) {
    auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(n->_callee);
    if (id && id->_name->str()=="eval") fail("[NATIVE_PRIVATE_UNSUPPORTED] DYNAMIC_SCOPE",n);
    if (privateMember(n->_callee))
      for (auto &arg:n->_arguments)
        if (llvh::isa<ESTree::SpreadElementNode>(&arg))
          fail("[NATIVE_PRIVATE_UNSUPPORTED] PRIVATE_CALL_SPREAD",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::OptionalMemberExpressionNode *n) {
    if (llvh::isa<ESTree::PrivateNameNode>(n->_property))
      fail("[NATIVE_PRIVATE_UNSUPPORTED] OPTIONAL_PRIVATE",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::OptionalCallExpressionNode *n) {
    if(superMember(n->_callee))fail("[NATIVE_PRIVATE_UNSUPPORTED] SUPER_OPTIONAL_CALL",n);
    if (privateMember(n->_callee))
      for(auto &arg:n->_arguments)
        if(llvh::isa<ESTree::SpreadElementNode>(&arg))
          fail("[NATIVE_PRIVATE_UNSUPPORTED] PRIVATE_CALL_SPREAD",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::TaggedTemplateExpressionNode *n) {
    if(superMember(n->_tag))fail("[NATIVE_PRIVATE_UNSUPPORTED] SUPER_TAGGED_TEMPLATE",n);
    if (privateMember(n->_tag)) fail("[NATIVE_PRIVATE_UNSUPPORTED] PRIVATE_CALL",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::FunctionExpressionNode *n) {
    if (directMethodFunctions.count(n)) {
      if (fieldInitializer || parameterDefault || functions) {
        fail("[NATIVE_PRIVATE_UNSUPPORTED] DIRECT_METHOD_CONTEXT",n);
        return;
      }
      if (n->_generator) {
        fail("[NATIVE_PRIVATE_UNSUPPORTED] ASYNC_OR_GENERATOR",n);
        return;
      }
    } else if (!checkNestedFunction(n,n->_params,n->_async,n->_generator)) {
      return;
    }
    const bool oldAsync=asyncArrowBody;asyncArrowBody=n->_async;
    const bool ordinary=!directMethodFunctions.count(n);
    if(ordinary)++superBarriers;
    ++functions;++argumentsOwners;
                                                                              
                                                                                
    visitFunctionScope(n,n->_id);
    --argumentsOwners;--functions;
    if(ordinary)--superBarriers;asyncArrowBody=oldAsync;
  }

  bool check(ESTree::Node *classNode, ESTree::ClassBodyNode *body,
             ESTree::Node *superClass) {
    ESTree::Node *nameNode=nullptr;
    if (auto *declaration=llvh::dyn_cast<ESTree::ClassDeclarationNode>(classNode)) nameNode=declaration->_id;
    if (auto *expression=llvh::dyn_cast<ESTree::ClassExpressionNode>(classNode)) nameNode=expression->_id;
    if (auto *name=llvh::dyn_cast_or_null<ESTree::IdentifierNode>(nameNode)) className=name->_name;
    if (superClass && !constructorSuper.scan(body)) fail("[NATIVE_DERIVED_UNSUPPORTED] SUPER_SCAN_BUDGET",classNode);
                                                                             
                                                                           
    for (auto &entry:body->_body) {
      if (auto *field=llvh::dyn_cast<ESTree::ClassPrivatePropertyNode>(&entry)) {
                                                                             
                                                                              
                                                                             
        auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(field->_key);
        if (field->_static || field->_declare || field->_optional ||
            field->_typeAnnotation || field->_tsModifiers || field->_variance ||
            !id || id->_name->str()=="constructor") {
          fail("[NATIVE_PRIVATE_UNSUPPORTED] FIELD_DECLARATION",field);continue;
        }
        if (privateKinds.count(id->_name) || !fields.emplace(id->_name,field).second)
          fail("[NATIVE_PRIVATE_UNSUPPORTED] DUPLICATE_PRIVATE_NAME",field);
      } else if (auto *method=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry)) {
                                                                           
                                                                           
                                                                              
        if (auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(method->_key)) {
          auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(name->_id);
          unsigned kind=method->_kind->str()=="method"?1:
              method->_kind->str()=="get"?2:method->_kind->str()=="set"?4:0;
          if (!id || method->_static || method->_computed || !kind || id->_name->str()=="constructor")
            fail("[NATIVE_PRIVATE_UNSUPPORTED] PRIVATE_METHOD_DECLARATION",method);
          else {
            unsigned old=privateKinds[id->_name];
            if(fields.count(id->_name) || (old && (kind==1 || old==1 || (old&kind))))
              fail("[NATIVE_PRIVATE_INVALID] DUPLICATE_PRIVATE_NAME",method);
            privateKinds[id->_name]=old|kind;
          }
        } else if (method->_computed)
          fail("[NATIVE_PRIVATE_UNSUPPORTED] COMPUTED_PUBLIC_METHOD",method);
        else if (method->_kind->str()!="method" && method->_kind->str()!="constructor" &&
                 method->_kind->str()!="get" && method->_kind->str()!="set")
          fail("[NATIVE_PRIVATE_UNSUPPORTED] METHOD_SHAPE",method);
        if(method->_static && !method->_computed) {
          auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(method->_key);
          auto *str=llvh::dyn_cast<ESTree::StringLiteralNode>(method->_key);
          if((id&&id->_name->str()=="prototype") || (str&&str->_value->str()=="prototype"))
            fail("[NATIVE_PRIVATE_INVALID] STATIC_PROTOTYPE_EARLY_ERROR",method);
        }
        auto *fn=llvh::dyn_cast<ESTree::FunctionExpressionNode>(method->_value);
        if (!fn) { fail("[NATIVE_PRIVATE_UNSUPPORTED] METHOD_BODY",method);continue; }
                                                                               
                                                                          
        if ((method->_kind->str()=="get" && !fn->_params.empty()) ||
            (method->_kind->str()=="set" &&
             (fn->_params.size()!=1 ||
              llvh::isa<ESTree::RestElementNode>(&fn->_params.front()))))
          fail("[NATIVE_PRIVATE_INVALID] ACCESSOR_PARAMETERS",method);
        directMethodFunctions.insert(fn);
        bool hasNonSimpleParameter = false;
        for (auto &p:fn->_params) {
          if (llvh::isa<ESTree::IdentifierNode>(&p)) continue;
          if(objectFormal(&p) || (method->_kind->str()!="constructor" && simpleArrayFormal(&p))) {
            hasNonSimpleParameter=true;continue;
          }
          if (auto *rest=llvh::dyn_cast<ESTree::RestElementNode>(&p)) {
                                                                            
                                                                                
            if (llvh::isa<ESTree::IdentifierNode>(rest->_argument)) {
              hasNonSimpleParameter=true;
              continue;
            }
          }
          auto *assignment=llvh::dyn_cast<ESTree::AssignmentPatternNode>(&p);
          if (!assignment ||
              !llvh::isa<ESTree::IdentifierNode>(assignment->_left) ||
              !assignment->_right) {
            fail("[NATIVE_PRIVATE_UNSUPPORTED] PARAMETER_SHAPE",&p);
            continue;
          }
          identifierParameterDefaults.insert(assignment);
          hasNonSimpleParameter = true;
        }
        if (hasNonSimpleParameter) {
                                                                             
                                                                            
                                                                          
          auto *block=llvh::dyn_cast<ESTree::BlockStatementNode>(fn->_body);
          if (!block) {
            fail("[NATIVE_PRIVATE_UNSUPPORTED] METHOD_BODY",fn);
            continue;
          }
          for (auto &statement:block->_body) {
            auto *expression=llvh::dyn_cast<ESTree::ExpressionStatementNode>(&statement);
            if (!expression || !expression->_directive) break;
            if (expression->_directive->str()=="use strict")
              fail("[NATIVE_PRIVATE_UNSUPPORTED] DEFAULT_PARAMETER_STRICT_DIRECTIVE",expression);
          }
        }
      }
    }
    visitESTreeChildren(*this,body);
    if (failure) context.getSourceErrorManager().error(failureNode->getSourceRange(),failure);
    return !failure;
  }
};

                                                                            
                                                                              

                                                                             
                                                                          
static bool isSymbolHasInstanceKey(ESTree::Node *node) {
  auto *m=llvh::dyn_cast<ESTree::MemberExpressionNode>(node);
  if(!m || m->_computed)return false;
  auto *base=llvh::dyn_cast<ESTree::IdentifierNode>(m->_object);
  auto *key=llvh::dyn_cast<ESTree::IdentifierNode>(m->_property);
  return base && key && base->_name->str()=="Symbol" && key->_name->str()=="hasInstance";
}

struct BaseStaticSymbolSuperFinder {
  unsigned depth=0,nodes=0;bool exhausted=false,found=false;
  void visit(ESTree::Node *n) { if(!found)visitESTreeChildren(*this,n); }
  void visit(ESTree::MemberExpressionNode *n) {
    if(llvh::isa<ESTree::SuperNode>(n->_object) && n->_computed && isSymbolHasInstanceKey(n->_property))found=true;
    else if(!found)visitESTreeChildren(*this,n);
  }
                                                             
  void visit(ESTree::FunctionExpressionNode *) {}
  void visit(ESTree::FunctionDeclarationNode *) {}
  void visit(ESTree::ClassExpressionNode *) {}
  void visit(ESTree::ClassDeclarationNode *) {}
  bool incRecursionDepth(ESTree::Node *) {
    if(depth>=256 || nodes>=100000){exhausted=true;return false;}
    ++depth;++nodes;return true;
  }
  void decRecursionDepth(){--depth;}
};

static bool hasBaseStaticSymbolSuper(ESTree::ClassBodyNode *body) {
  for(auto &entry:body->_body) {
    auto *m=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry);
    if(!m || !m->_static)continue;
    auto *fn=llvh::dyn_cast<ESTree::FunctionExpressionNode>(m->_value);
    if(!fn)continue;
    BaseStaticSymbolSuperFinder finder;
    visitESTreeNode(finder,fn->_body);
    if(finder.found && !finder.exhausted)return true;
  }
  return false;
}

struct NativePublicStaticProfile {
  bool baseStaticSymbolSuper=false,staticMethodHome=false;
  ConstructorSuperCalls constructorSuper;
  ESTree::Node *directMethod{nullptr};
  bool methodHome{false};
  std::set<ESTree::Node *> propertySupers;
  Context &context;
  UniqueString *className{nullptr};
  bool initializer{false};
  bool initializerClosure{false};
  bool computedKey{false};
  bool nameShadowed{false};
  bool invalidOriginalSyntax{false};
  unsigned depth{0}, nodes{0};
  const char *failure{nullptr};
  ESTree::Node *failureNode{nullptr};
  explicit NativePublicStaticProfile(Context &c) : context(c) {}
  void fail(const char *why, ESTree::Node *where) {
    if (!failure) { failure=why; failureNode=where; }
  }
  void visit(ESTree::Node *node) { visitESTreeChildren(*this,node); }
  bool incRecursionDepth(ESTree::Node *node) {
    if (failure) return false;
    if (++nodes>100000 || depth>=256) {
      fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] PROFILE_BUDGET",node); return false;
    }
    ++depth; return true;
  }
  void decRecursionDepth() { --depth; }
  static bool literalKey(ESTree::Node *key, bool computed) {
    return llvh::isa<ESTree::StringLiteralNode>(key) ||
        llvh::isa<ESTree::NumericLiteralNode>(key) ||
        (!computed && llvh::isa<ESTree::IdentifierNode>(key));
  }
                                                                                
                                                                                
                                                                     
  bool objectConstructorFormal(ESTree::Node *root) {
    auto *d=llvh::dyn_cast<ESTree::AssignmentPatternNode>(root);
    if(!llvh::isa<ESTree::ObjectPatternNode>(d?d->_left:root))return false;
    llvh::SmallVector<ESTree::Node *,16> pending{root};unsigned seen=0;
    while(!pending.empty()) {
      auto *n=pending.pop_back_val();
      if(++seen>100000){fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] PROFILE_BUDGET",root);return false;}
      if(llvh::isa<ESTree::IdentifierNode>(n))continue;
      if(auto *o=llvh::dyn_cast<ESTree::ObjectPatternNode>(n)) {
        for(auto &entry:o->_properties) {
          if(auto *p=llvh::dyn_cast<ESTree::PropertyNode>(&entry))pending.push_back(p->_value);
          else pending.push_back(&entry);
        }
      } else if(auto *rest=llvh::dyn_cast<ESTree::RestElementNode>(n)) {
        if(!llvh::isa<ESTree::IdentifierNode>(rest->_argument))return false;
      } else if(auto *assignment=llvh::dyn_cast<ESTree::AssignmentPatternNode>(n)) {
        if(!assignment->_right)return false;
        pending.push_back(assignment->_left);
      } else return false;
    }
    return true;
  }
  bool patternBindsClassName(ESTree::Node *node) {
    llvh::SmallVector<ESTree::Node *, 8> pending;
    if (node) pending.push_back(node);
    unsigned visited = 0;
    while (!pending.empty()) {
      auto *current = pending.pop_back_val();
      if (++visited > 100000) {
        fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] PROFILE_BUDGET", node);
        return false;
      }
      if (auto *id = llvh::dyn_cast<ESTree::IdentifierNode>(current)) {
        if (id->_name == className) return true;
      } else if (auto *pattern = llvh::dyn_cast<ESTree::AssignmentPatternNode>(current)) {
        pending.push_back(pattern->_left);
      } else if (auto *rest = llvh::dyn_cast<ESTree::RestElementNode>(current)) {
        pending.push_back(rest->_argument);
      } else if (auto *array = llvh::dyn_cast<ESTree::ArrayPatternNode>(current)) {
        for (auto &element : array->_elements) pending.push_back(&element);
      } else if (auto *object = llvh::dyn_cast<ESTree::ObjectPatternNode>(current)) {
        for (auto &entry : object->_properties) {
          if (auto *property = llvh::dyn_cast<ESTree::PropertyNode>(&entry))
            pending.push_back(property->_value);
          else pending.push_back(&entry);
        }
      } else if (auto *decl = llvh::dyn_cast<ESTree::VariableDeclarationNode>(current)) {
        for (auto &entry : decl->_declarations) pending.push_back(&entry);
      } else if (auto *decl = llvh::dyn_cast<ESTree::VariableDeclaratorNode>(current)) {
        pending.push_back(decl->_id);
      }
                                                                         
                                                                             
    }
    return false;
  }
  bool lexicalDeclarationShadows(ESTree::Node *node) {
    if (auto *decl = llvh::dyn_cast_or_null<ESTree::VariableDeclarationNode>(node))
      return decl->_kind->str() != "var" && patternBindsClassName(decl);
    if (auto *fn = llvh::dyn_cast_or_null<ESTree::FunctionDeclarationNode>(node))
      return patternBindsClassName(fn->_id);
    if (auto *cl = llvh::dyn_cast_or_null<ESTree::ClassDeclarationNode>(node))
      return patternBindsClassName(cl->_id);
    return false;
  }
  bool hoistedVarShadows(ESTree::Node *body) {
    struct Find {
      NativePublicStaticProfile &profile;
      bool found{false}; unsigned depth{0}, nodes{0};
      void visit(ESTree::Node *n) { visitESTreeChildren(*this,n); }
      void visit(ESTree::VariableDeclarationNode *n) {
        if (n->_kind->str()=="var" && profile.patternBindsClassName(n)) found=true;
        visitESTreeChildren(*this,n);
      }
      void visit(ESTree::FunctionExpressionNode *) {}
      void visit(ESTree::ArrowFunctionExpressionNode *) {}
      void visit(ESTree::FunctionDeclarationNode *) {}
      void visit(ESTree::ClassExpressionNode *) {}
      void visit(ESTree::ClassDeclarationNode *) {}
      bool incRecursionDepth(ESTree::Node *n) {
        if (++nodes>100000 || depth>=256) {
          profile.fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] PROFILE_BUDGET",n);
          return false;
        }
        ++depth;return true;
      }
      void decRecursionDepth(){--depth;}
    } find{*this};
    if (body) visitESTreeNode(find,body);
    return find.found;
  }
  template<typename FunctionNode>
  void visitFunctionScope(FunctionNode *fn, ESTree::Node *selfName) {
    const bool outer=nameShadowed;
    nameShadowed |= patternBindsClassName(selfName);
    for (auto &param:fn->_params) nameShadowed |= patternBindsClassName(&param);
                                                                             
    for (auto &param:fn->_params) visitESTreeNode(*this,&param);
    nameShadowed |= hoistedVarShadows(fn->_body);
    if (fn->_body) visitESTreeNode(*this,fn->_body);
    nameShadowed=outer;
  }
  void visit(ESTree::BlockStatementNode *n) {
    const bool outer=nameShadowed;
    for (auto &statement:n->_body) nameShadowed |= lexicalDeclarationShadows(&statement);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::CatchClauseNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= patternBindsClassName(n->_param);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::ForStatementNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= lexicalDeclarationShadows(n->_init);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::SwitchStatementNode *n) {
                                                                       
    visitESTreeNode(*this,n->_discriminant);
    const bool outer=nameShadowed;
    for (auto &entry:n->_cases)
      for (auto &statement:llvh::cast<ESTree::SwitchCaseNode>(&entry)->_consequent)
        nameShadowed |= lexicalDeclarationShadows(&statement);
    for (auto &entry:n->_cases) visitESTreeNode(*this,&entry);
    nameShadowed=outer;
  }
  bool writesClassName(ESTree::Node *node) {
    return !nameShadowed && patternBindsClassName(node);
  }
  void visit(ESTree::AssignmentExpressionNode *n) {
    if(writesClassName(n->_left)) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] CLASS_NAME_WRITE",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::UpdateExpressionNode *n) {
    if(writesClassName(n->_argument)) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] CLASS_NAME_WRITE",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::ForInStatementNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= lexicalDeclarationShadows(n->_left);
    if(writesClassName(n->_left)) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] CLASS_NAME_WRITE",n);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::ForOfStatementNode *n) {
    const bool outer=nameShadowed;
    nameShadowed |= lexicalDeclarationShadows(n->_left);
    if(writesClassName(n->_left)) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] CLASS_NAME_WRITE",n);
    visitESTreeChildren(*this,n);
    nameShadowed=outer;
  }
  void visit(ESTree::CallExpressionNode *n) {
    auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(n->_callee);
    if(id && id->_name->str()=="eval") fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] DIRECT_EVAL",n);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::IdentifierNode *n) {
    if(initializer && n->_name->str()=="arguments")
      fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_ARGUMENTS",n);
  }
  void visit(ESTree::FunctionExpressionNode *n) {
    const bool outer=initializer, nested=initializerClosure;
    initializerClosure |= initializer;
    if(initializerClosure && (n->_async || n->_generator))
      fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_ASYNC_OR_GENERATOR_FUNCTION",n);
                                                                       
                                                                               
    initializer=false;
    const bool oldKey=computedKey;computedKey=false;
    const bool oldHome=methodHome;methodHome=(n==directMethod);
    visitFunctionScope(n,n->_id);methodHome=oldHome;
    computedKey=oldKey;initializer=outer;initializerClosure=nested;
  }
  void visit(ESTree::ArrowFunctionExpressionNode *n) {
    if((initializer||initializerClosure)&&n->_async)
      fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_ASYNC_OR_GENERATOR_FUNCTION",n);
                                                                           
                                                                        
    const bool oldKey=computedKey;computedKey=false;
    visitFunctionScope(n,nullptr);computedKey=oldKey;
  }
  void visit(ESTree::FunctionDeclarationNode *n) {
    const bool outer=initializer, nested=initializerClosure;
    initializerClosure |= initializer;
    if(initializerClosure && (n->_async || n->_generator))
      fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_ASYNC_OR_GENERATOR_FUNCTION",n);
                                                                       
                                                                               
    initializer=false;
    const bool oldKey=computedKey;computedKey=false;
    const bool oldHome=methodHome;methodHome=(n==directMethod);
    visitFunctionScope(n,n->_id);methodHome=oldHome;
    computedKey=oldKey;initializer=outer;initializerClosure=nested;
  }
  void visit(ESTree::ClassExpressionNode *n) {
    if(initializer) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_CLASS",n);
    else visitESTreeChildren(*this,n);
  }
  void visit(ESTree::ClassDeclarationNode *n) {
    if(initializer) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_CLASS",n);
    else visitESTreeChildren(*this,n);
  }
  void visit(ESTree::MemberExpressionNode *n) {
    if(llvh::isa<ESTree::SuperNode>(n->_object) && methodHome && !initializer && !computedKey &&
       ((!n->_computed && llvh::isa<ESTree::IdentifierNode>(n->_property)) ||
        (n->_computed && (llvh::isa<ESTree::StringLiteralNode>(n->_property) ||
          (baseStaticSymbolSuper && staticMethodHome && isSymbolHasInstanceKey(n->_property))))))propertySupers.insert(n->_object);
    visitESTreeChildren(*this,n);
  }
  void visit(ESTree::SuperNode *n) {
    if(constructorSuper.calls.count(n)||propertySupers.count(n))return;
    fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] SUPER_OUTSIDE_PROFILE",n);
  }
  void visit(ESTree::MetaPropertyNode *n) {
    if(initializer) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_META_PROPERTY",n);
  }
  void visit(ESTree::AwaitExpressionNode *n) {
    if(computedKey) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] KEY_SUSPENSION",n);
    else if(initializer) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_ASYNC",n);
    else visitESTreeChildren(*this,n);
  }
  void visit(ESTree::YieldExpressionNode *n) {
    if(computedKey) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] KEY_SUSPENSION",n);
    else if(initializer) fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] INITIALIZER_GENERATOR",n);
    else visitESTreeChildren(*this,n);
  }
  bool check(ESTree::Node *classNode, ESTree::ClassBodyNode *body, ESTree::Node *superClass, bool emitDiagnostic=true) {
    baseStaticSymbolSuper=!superClass && hasBaseStaticSymbolSuper(body);
    auto *decl=llvh::dyn_cast<ESTree::ClassDeclarationNode>(classNode);
    auto *expression=llvh::dyn_cast<ESTree::ClassExpressionNode>(classNode);
    auto *nameNode=decl?decl->_id:expression?expression->_id:nullptr;
    auto *name=nameNode?llvh::dyn_cast<ESTree::IdentifierNode>(nameNode):nullptr;
    if(name)className=name->_name;
    if(superClass && !constructorSuper.scan(body)) fail("[NATIVE_DERIVED_UNSUPPORTED] SUPER_SCAN_BUDGET",classNode);
    if(!context.getCodeGenerationSettings().enableBlockScoping ||
       !context.getCodeGenerationSettings().enableTDZ)
      fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] LEXICAL_TDZ_REQUIRED",classNode);
    bool hasInstanceFields = false;
    for (auto &entry:body->_body)
      if (auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry))
        hasInstanceFields |= !field->_static;
    for(auto &entry:body->_body) {
      if(auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry)) {
        if(field->_declare || field->_optional || field->_typeAnnotation ||
           field->_tsModifiers || field->_variance)
          fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] FIELD_DECLARATION",field);
                                                                         
                                                                             
                                                                            
                                                                           
        if(field->_static && !field->_computed) {
          auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(field->_key);
          auto *str=llvh::dyn_cast<ESTree::StringLiteralNode>(field->_key);
          if((id && id->_name->str()=="prototype") ||
             (str && str->_value->str()=="prototype"))
            fail("[NATIVE_PUBLIC_STATIC_INVALID] STATIC_PROTOTYPE_EARLY_ERROR",field);
        }
        if(field->_computed) {
          computedKey=true;visitESTreeNode(*this,field->_key);computedKey=false;
        }
        initializer=true;
        if(field->_value) visitESTreeNode(*this,field->_value);
        initializer=false;
      } else if(auto *method=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry)) {
                                                                        
                                                                                         
                                                                                      
        auto *fn=llvh::dyn_cast<ESTree::FunctionExpressionNode>(method->_value);
        if(!fn || (fn->_generator && (!method->_static || fn->_async)) ||
           (method->_kind->str()!="method" && method->_kind->str()!="constructor" &&
            method->_kind->str()!="get" && method->_kind->str()!="set"))
          fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] METHOD_SHAPE",method);
        if(method->_computed) {
          computedKey=true;visitESTreeNode(*this,method->_key);computedKey=false;
        }
        if(method->_static && !method->_computed) {
          auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(method->_key);
          auto *str=llvh::dyn_cast<ESTree::StringLiteralNode>(method->_key);
          if((id && id->_name->str()=="prototype") ||
             (str && str->_value->str()=="prototype"))
            fail("[NATIVE_PUBLIC_STATIC_INVALID] STATIC_PROTOTYPE_EARLY_ERROR",method);
        }
        if(llvh::isa<ESTree::PrivateNameNode>(method->_key))
          fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] MIXED_PRIVATE",method);
        if (hasInstanceFields && fn && method->_kind->str()=="constructor") {
          bool hasNonSimple = false;
          for (auto &param:fn->_params) {
            if (llvh::isa<ESTree::IdentifierNode>(&param)) continue;
            hasNonSimple = true;
            if(objectConstructorFormal(&param))continue;
            auto *assignment=llvh::dyn_cast<ESTree::AssignmentPatternNode>(&param);
            if (!assignment || !llvh::isa<ESTree::IdentifierNode>(assignment->_left) ||
                !assignment->_right)
              fail("[NATIVE_PUBLIC_INSTANCE_UNSUPPORTED] PARAMETER_SHAPE",&param);

          }
                                                                        
          if (hasNonSimple) {
            auto *block=llvh::dyn_cast<ESTree::BlockStatementNode>(fn->_body);
            if (!block) fail("[NATIVE_PUBLIC_INSTANCE_UNSUPPORTED] CONSTRUCTOR_BODY",fn);
            else for (auto &statement:block->_body) {
              auto *expression=llvh::dyn_cast<ESTree::ExpressionStatementNode>(&statement);
              if (!expression || !expression->_directive) break;
              if (expression->_directive->str()=="use strict") {
                invalidOriginalSyntax = true;
                fail("[NATIVE_PUBLIC_INSTANCE_UNSUPPORTED] DEFAULT_PARAMETER_STRICT_DIRECTIVE",expression);
              }
            }
          }
        }
        staticMethodHome=method->_static;
        directMethod=method->_value;visitESTreeNode(*this,method->_value);directMethod=nullptr;
        staticMethodHome=false;
      } else fail("[NATIVE_PUBLIC_STATIC_UNSUPPORTED] PRIVATE_STATICBLOCK_OR_OTHER_ELEMENT",&entry);
    }
    if(failure && emitDiagnostic) context.getSourceErrorManager().error(failureNode->getSourceRange(),failure);
    return !failure;
  }
};

struct VisitedClass {
  UniqueString *className = nullptr;
  ESTree::Node *parentClass = nullptr;
  bool superCallFound = false;
  bool nativePublicFields = false;
  bool nativeInstanceFields = false;
  bool nativeDerived = false;
  UniqueString *constructorIdentity = nullptr;
  UniqueString *derivedInitializer = nullptr;
                                                                                
                                                                     
  bool constructorThisInitialized = false;
  UniqueString *superSetInstanceHome = nullptr;
  UniqueString *superSetStaticHome = nullptr;
  std::map<UniqueString *,UniqueString *> privateTokens;
  std::map<UniqueString *,UniqueString *> privateInitializers;
  std::map<UniqueString *,unsigned> privateKinds;
  std::map<UniqueString *,UniqueString *> privateSetterTokens;
  std::map<UniqueString *,UniqueString *> privateFunctions;
  std::map<UniqueString *,UniqueString *> privateSetters;
                                                                               
  std::map<ESTree::ClassPropertyNode *,UniqueString *> publicInstanceInitializers;
  bool cachedPublicKeys{false};
  bool baseStaticSymbolSuper{false};
  std::map<ESTree::Node *,ESTree::Node *> publicKeyStatements;

  VisitedClass(ESTree::NodePtr className, ESTree::NodePtr superClass) {
    if (className != nullptr) {
      this->className = llvh::cast<ESTree::IdentifierNode>(className)->_name;
    }
    this->parentClass = superClass;
  }
};

enum class ClassMemberKind {
  Constructor,
  Method,
  PropertyGetter,
  PropertySetter
};

struct ResolvedClassMember {
  ESTree::Node *key;
  bool isStatic;
  ClassMemberKind kind;
  ESTree::MethodDefinitionNode *definitionNode;

  ResolvedClassMember(
      ESTree::Node *key,
      bool isStatic,
      ClassMemberKind kind,
      ESTree::MethodDefinitionNode *definitionNode)
      : key(key),
        isStatic(isStatic),
        kind(kind),
        definitionNode(definitionNode) {}
};

struct ResolvedClassMembers {
  ESTree::MethodDefinitionNode *constructor = nullptr;

  llvh::SmallVector<ResolvedClassMember, 8> members;
};

static ClassMemberKind getClassMemberKind(
    ESTree::MethodDefinitionNode *methodDefinition) {
  const auto &str = methodDefinition->_kind->str();
  if (str == "constructor") {
    return ClassMemberKind::Constructor;
  } else if (str == "method") {
    return ClassMemberKind::Method;
  } else if (str == "get") {
    return ClassMemberKind::PropertyGetter;
  } else if (str == "set") {
    return ClassMemberKind::PropertySetter;
  }
  hermes_fatal("Invalid ES6 class member");
}

}             

namespace hermes {

                                                                            
                                                                  
                                                                          
                                 
class ES6ClassesTransformations {
 public:
  ES6ClassesTransformations(Context &context)
      : context_(context),
        internalIDs_(context.getStringTable()),
        identVar_(context.getIdentifier("var").getUnderlyingPointer()) {}

  ESTree::VisitResult visit(ESTree::ClassDeclarationNode *classDecl) {
    auto *classBody = llvh::dyn_cast<ESTree::ClassBodyNode>(classDecl->_body);
    if (classBody == nullptr) {
      return doVisitChildren(classDecl);
    }

    const bool derivedClass=classDecl->_superClass!=nullptr;
    const bool privateClass=hasPrivateMembers(classBody);
    const bool publicStatic=usesNativePublicFields(
        classDecl,classBody,classDecl->_superClass);
    auto *expressionResult = createClass(
        classDecl, classDecl->_id, classBody, classDecl->_superClass);

                                                                                  
                                                                           
    auto result = makeSingleVariableDecl(
        expressionResult, copyIdentifier(classDecl->_id), expressionResult,
        (privateClass || publicStatic || derivedClass) ? context_.getIdentifier("let").getUnderlyingPointer() : nullptr);

    return result;
  }

  ESTree::VisitResult visit(ESTree::ClassExpressionNode *classExpr) {
    auto *classBody = llvh::dyn_cast<ESTree::ClassBodyNode>(classExpr->_body);
    if (classBody == nullptr) {
      return doVisitChildren(classExpr);
    }

    return createClass(
        classExpr, classExpr->_id, classBody, classExpr->_superClass);
  }

                                                                        
                                                                         
  ESTree::VisitResult visit(ESTree::OptionalCallExpressionNode *call) {
    if(auto *member=llvh::dyn_cast<ESTree::MemberExpressionNode>(call->_callee)) {
      if(auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(member->_property)) {
        auto *token=nativePrivateToken(name);
        if(!token)return makeUndefinedNode(call);
        auto *id=llvh::cast<ESTree::IdentifierNode>(name->_id);
        auto kind=_currentProcessingClass->privateKinds.find(id->_name);
        auto *base=transformPrivateOperand(member->_object);member->_object=nullptr;
        call->_callee=makeNativePrivateOp(member,
          kind!=_currentProcessingClass->privateKinds.end() && kind->second!=1
            ? "accessor_call_reference" : "call_reference",
          {base,makeIdentifierNode(name,token)});
        NodeVector args;
        for(auto &arg:call->_arguments)args.append(transformPrivateOperand(&arg));
        call->_arguments.clear();call->_arguments=args.toNodeList();
        return call;
      }
    }
    return doVisitChildren(call);
  }

                                                                          
                                                          
                               
  ESTree::VisitResult visit(ESTree::CallExpressionNode *callExpression) {
    if(auto *member=llvh::dyn_cast<ESTree::MemberExpressionNode>(callExpression->_callee)) {
      if(auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(member->_property)) {
        auto *token=nativePrivateToken(name);
        if(!token)return makeUndefinedNode(callExpression);
        auto *id=llvh::cast<ESTree::IdentifierNode>(name->_id);
        auto kind=_currentProcessingClass->privateKinds.find(id->_name);
        NodeVector args;
        args.append(transformPrivateOperand(member->_object));member->_object=nullptr;
        args.append(makeIdentifierNode(name,token));
        for(auto &arg:callExpression->_arguments)args.append(transformPrivateOperand(&arg));
        callExpression->_arguments.clear();
        return makeNativePrivateOp(callExpression,
            kind!=_currentProcessingClass->privateKinds.end() && kind->second!=1?"accessor_call":"call",args);
      }
    }
    auto *topClass = _currentProcessingClass;
    if (topClass == nullptr || (topClass->parentClass == nullptr && topClass->privateTokens.empty() && !topClass->baseStaticSymbolSuper)) {
      return doVisitChildren(callExpression);
    }

    if (callExpression->_callee->getKind() == ESTree::NodeKind::Super) {
                                     
      _currentProcessingClass->superCallFound = true;
      return createSuperCall(
          callExpression,
          topClass->parentClass,
          NodeVector(callExpression->_arguments));
    }

                                             
                                                        
    auto *memberExpressionNode =
        llvh::dyn_cast<ESTree::MemberExpressionNode>(callExpression->_callee);
    if (memberExpressionNode == nullptr ||
        memberExpressionNode->_object->getKind() != ESTree::NodeKind::Super) {
      return doVisitChildren(callExpression);
    }

                                                                        
                                                                            
    const bool computed = memberExpressionNode->_computed;
    if (computed && _ordinarySuperBarrier) {
      context_.getSourceErrorManager().error(callExpression->getSourceRange(),
          "[SUPER_CALL_UNSUPPORTED] ORDINARY_FUNCTION_BOUNDARY");
      return makeUndefinedNode(callExpression);
    }
    if (computed)
      return createNativeSuperReference(
          callExpression, memberExpressionNode->_property, true, true,
          NodeVector(callExpression->_arguments));

    return createSuperMethodCall(
        callExpression,
        topClass->parentClass,
        memberExpressionNode->_property,
        computed,
        NodeVector(callExpression->_arguments));
  }

                                                                  
                       
  ESTree::VisitResult visit(ESTree::MemberExpressionNode *memberExpression) {
    if (auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(memberExpression->_property)) {
      auto *token=nativePrivateToken(name);
      if (!token) return makeUndefinedNode(memberExpression);
      auto *base=transformPrivateOperand(memberExpression->_object);
      memberExpression->_object=nullptr;
      auto *id=llvh::cast<ESTree::IdentifierNode>(name->_id);
      auto kind=_currentProcessingClass->privateKinds.find(id->_name);
      return makeNativePrivateOp(memberExpression,
          kind!=_currentProcessingClass->privateKinds.end() && kind->second!=1?"accessor_get":"get",{
          base,makeIdentifierNode(name,token)});
    }
                                                                     
                         
    if (memberExpression->_object->getKind() != ESTree::NodeKind::Super) {
      return doVisitChildren(memberExpression);
    }

    auto *topClass = _currentProcessingClass;
    if (topClass == nullptr || (topClass->parentClass == nullptr && topClass->privateTokens.empty() && !topClass->baseStaticSymbolSuper)) {
                          
      return doVisitChildren(memberExpression);
    }

    return createGetSuperProperty(
        memberExpression, topClass->parentClass, memberExpression->_property);
  }

  ESTree::VisitResult visit(ESTree::AssignmentExpressionNode *assignment) {
    if (auto *target=llvh::dyn_cast<ESTree::MemberExpressionNode>(assignment->_left)) {
      if (auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(target->_property)) {
        auto *token=nativePrivateToken(name);
        if (!token || (assignment->_operator->str()!="=" && assignment->_operator->str()!="+=")) {
          context_.getSourceErrorManager().error(assignment->getSourceRange(),
              "[NATIVE_PRIVATE_UNSUPPORTED] WRITE_SHAPE");
          return makeUndefinedNode(assignment);
        }
        auto *base=transformPrivateOperand(target->_object);
        auto *rhs=transformPrivateOperand(assignment->_right);
        target->_object=nullptr;assignment->_right=nullptr;
        auto *id=llvh::cast<ESTree::IdentifierNode>(name->_id);
        auto kind=_currentProcessingClass->privateKinds.find(id->_name);
        if(assignment->_operator->str()=="+=") {
          NodeVector args{base,makeIdentifierNode(name,token)};
          const char *addOp="add_field";
          if(kind!=_currentProcessingClass->privateKinds.end()) {
            addOp=kind->second==1?"add_readonly":"add_accessor";
            if(kind->second!=1)args.append(makeIdentifierNode(name,_currentProcessingClass->privateSetterTokens.at(id->_name)));
          }
          args.append(rhs);return makeNativePrivateOp(assignment,addOp,args);
        }
        const char *op="set";
        if(kind!=_currentProcessingClass->privateKinds.end()) {
          op=kind->second==1?"readonly_set":"accessor_set";
          if(kind->second!=1)token=_currentProcessingClass->privateSetterTokens.at(id->_name);
        }
        return makeNativePrivateOp(assignment,op,{
            base,makeIdentifierNode(name,token),rhs});
      }
    }
    auto *member = llvh::dyn_cast<ESTree::MemberExpressionNode>(assignment->_left);
    if (!member || !llvh::isa<ESTree::SuperNode>(member->_object)) {
      if (containsSuperAssignmentTarget(assignment->_left))
        return rejectSuperAssignment(assignment,
            "[SUPER_ASSIGNMENT_UNSUPPORTED] DESTRUCTURING_TARGET");
      return doVisitChildren(assignment);
    }
    if (assignment->_operator->str() != "=")
      return rejectSuperAssignment(assignment,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] COMPOUND_ASSIGNMENT");
    if ((member->_computed &&
         !llvh::isa<ESTree::StringLiteralNode>(member->_property)) ||
        (!member->_computed &&
         !llvh::isa<ESTree::IdentifierNode>(member->_property)))
      return rejectSuperAssignment(assignment,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] COMPUTED_KEY");
    auto *cls = _currentProcessingClass;
    if (!cls || !cls->parentClass)
      return rejectSuperAssignment(assignment,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] NO_DERIVED_CLASS_CONTEXT");
    if (_visitingPropertyInitializer)
      return rejectSuperAssignment(assignment,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] CLASS_FIELD_INITIALIZER");
    if (_currentClassMember && !_visitingClassMethodBody)
      return rejectSuperAssignment(assignment,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] METHOD_KEY_OUTSIDE_PROFILE");
    if (!_currentClassMember && !cls->constructorThisInitialized)
      return rejectSuperAssignment(assignment,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] CONSTRUCTOR_THIS_NOT_PROVED");

                                                                        
                                                                               
    if (!isCertifiedSuperAssignmentRHS(assignment->_right))
      return rejectSuperAssignment(assignment,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] RHS_NOT_CERTIFIED");

    const bool isStatic = _currentClassMember && _currentClassMember->isStatic;
    auto *&home = isStatic ? cls->superSetStaticHome : cls->superSetInstanceHome;
    if (!home)
      home = internalIDs_.next(isStatic ? "super_set_static_home" :
                                         "super_set_instance_home")
                 .getUnderlyingPointer();
    auto *key = member->_computed
        ? createTransformedNode<ESTree::StringLiteralNode>(member->_property,
              llvh::cast<ESTree::StringLiteralNode>(member->_property)->_value)
        : createTransformedNode<ESTree::StringLiteralNode>(member->_property,
              llvh::cast<ESTree::IdentifierNode>(member->_property)->_name);

                                                                               
                                                                             
    auto *holder = createTransformedNode<ESTree::ExpressionStatementNode>(
        assignment->_right, assignment->_right, nullptr);
    assignment->_right = nullptr;
    visitESTreeChildren(*this, holder);
    auto *rhs = holder->_expression;
    holder->_expression = nullptr;
    return makeNativeClassDefinitionOp(assignment,"set_super_literal_property",{
        createTransformedNode<ESTree::ThisExpressionNode>(assignment),makeIdentifierNode(assignment,home),key,rhs});
  }

  ESTree::VisitResult visit(ESTree::UpdateExpressionNode *update) {
    if(auto *target=llvh::dyn_cast<ESTree::MemberExpressionNode>(update->_argument)) {
      if(auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(target->_property)) {
        auto *token=nativePrivateToken(name);
        if(!token)return makeUndefinedNode(update);
        auto *base=transformPrivateOperand(target->_object);target->_object=nullptr;
        auto *id=llvh::cast<ESTree::IdentifierNode>(name->_id);
        auto kind=_currentProcessingClass->privateKinds.find(id->_name);
        const bool accessor=kind!=_currentProcessingClass->privateKinds.end()&&kind->second!=1;
        const bool readonly=kind!=_currentProcessingClass->privateKinds.end()&&kind->second==1;
        std::string operation=accessor?"update_accessor_":readonly?"update_readonly_":"update_field_";
        operation+=update->_operator->str()=="++"?"inc_":"dec_";
        operation+=update->_prefix?"prefix":"postfix";
        NodeVector args{base,makeIdentifierNode(name,token)};
        if(accessor)args.append(makeIdentifierNode(name,_currentProcessingClass->privateSetterTokens.at(id->_name)));
        return makeNativePrivateOp(update,operation,args);
      }
    }
    if (containsSuperAssignmentTarget(update->_argument))
      return rejectSuperAssignment(update,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] UPDATE_TARGET");
    return doVisitChildren(update);
  }

  ESTree::VisitResult visit(ESTree::ForInStatementNode *loop) {
    if (containsSuperAssignmentTarget(loop->_left))
      return rejectSuperAssignment(loop,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] ITERATION_TARGET");
    return doVisitChildren(loop);
  }

  ESTree::VisitResult visit(ESTree::ForOfStatementNode *loop) {
    if (containsSuperAssignmentTarget(loop->_left))
      return rejectSuperAssignment(loop,
          "[SUPER_ASSIGNMENT_UNSUPPORTED] ITERATION_TARGET");
    return doVisitChildren(loop);
  }

  ESTree::VisitResult visit(ESTree::FunctionExpressionNode *function) {
                                                                           
                                                                          
                                                                                
    const bool previousMethodBody = _visitingClassMethodBody;
    _visitingClassMethodBody = _currentClassMember &&
        function == _currentClassMember->definitionNode->_value;
    const bool previousSuperBarrier = _ordinarySuperBarrier;
    _ordinarySuperBarrier = !_visitingClassMethodBody;
    visitESTreeChildren(*this, function);
    _ordinarySuperBarrier = previousSuperBarrier;
    _visitingClassMethodBody = previousMethodBody;
    return ESTree::Unmodified;
  }

  ESTree::VisitResult visit(ESTree::ArrowFunctionExpressionNode *function) {
    const bool previousMethodBody = _visitingClassMethodBody;
    if (_currentProcessingClass && !_currentProcessingClass->privateTokens.empty())
      _visitingClassMethodBody = false;
                                                                            
                                                                              
    visitESTreeChildren(*this, function);
    _visitingClassMethodBody = previousMethodBody;
    return ESTree::Unmodified;
  }

  ESTree::VisitResult visit(ESTree::FunctionDeclarationNode *function) {
    const bool previousMethodBody = _visitingClassMethodBody;
    if (_currentProcessingClass && !_currentProcessingClass->privateTokens.empty())
      _visitingClassMethodBody = false;
                                                                            
                                                                               
    const bool previousSuperBarrier = _ordinarySuperBarrier;
    _ordinarySuperBarrier = true;
    visitESTreeChildren(*this, function);
    _ordinarySuperBarrier = previousSuperBarrier;
    _visitingClassMethodBody = previousMethodBody;
    return ESTree::Unmodified;
  }

  void visit(ESTree::Node *node) {
    visitESTreeChildren(*this, node);
  }

  bool incRecursionDepth(ESTree::Node *n) {
    if (LLVM_UNLIKELY(recursionDepth_ == 0))
      return false;
    --recursionDepth_;
    if (LLVM_UNLIKELY(recursionDepth_ == 0)) {
      context_.getSourceErrorManager().error(
          n->getEndLoc(),
          "Too many nested expressions/statements/declarations");
      return false;
    }
    return true;
  }

  void decRecursionDepth() {
    assert(
        recursionDepth_ < MAX_RECURSION_DEPTH &&
        "recursionDepth_ cannot go negative");
    if (LLVM_LIKELY(recursionDepth_ != 0))
      ++recursionDepth_;
  }

 private:
  Context &context_;
  InternalIdentifierMaker internalIDs_;
  UniqueString *const identVar_;
  VisitedClass *_currentProcessingClass = nullptr;
  const ResolvedClassMember *_currentClassMember = nullptr;
  bool _visitingPropertyInitializer = false;
  bool _visitingClassMethodBody = false;
  bool _visitingStaticBlock = false;
  bool _ordinarySuperBarrier = false;

                                                                             
           
  static constexpr unsigned MAX_RECURSION_DEPTH =
#if defined(HERMES_LIMIT_STACK_DEPTH) || defined(_MSC_VER)
      512
#else
      1024
#endif
      ;

                                                                              
                             
  unsigned recursionDepth_ = MAX_RECURSION_DEPTH;

  ESTree::VisitResult doVisitChildren(ESTree::Node *node) {
    visitESTreeChildren(*this, node);
    return ESTree::Unmodified;
  }

  ESTree::VisitResult rejectSuperAssignment(
      ESTree::Node *node, const char *reason) {
    context_.getSourceErrorManager().error(node->getSourceRange(), reason);
                                                                               
    return ESTree::Unmodified;
  }

  bool isSuperAssignmentScalarLiteral(ESTree::Node *node) {
    return llvh::isa<ESTree::NumericLiteralNode>(node) ||
        llvh::isa<ESTree::StringLiteralNode>(node) ||
        llvh::isa<ESTree::BooleanLiteralNode>(node) ||
        llvh::isa<ESTree::NullLiteralNode>(node);
  }

  bool isCertifiedSuperAssignmentRHS(ESTree::Node *node) {
    if (isSuperAssignmentScalarLiteral(node)) return true;
    auto *unary = llvh::dyn_cast<ESTree::UnaryExpressionNode>(node);
    if (!unary || !unary->_prefix) return false;
    const auto op = unary->_operator->str();
                                                                               
    if (op == "!" || op == "void")
      return isSuperAssignmentScalarLiteral(unary->_argument);
    if (op == "+" || op == "-" || op == "~")
      return llvh::isa<ESTree::NumericLiteralNode>(unary->_argument);
    return false;
  }

  bool containsSuperAssignmentTarget(ESTree::Node *node) {
                                                                               
                                                                              
    llvh::SmallVector<ESTree::Node *, 8> pending;
    if (node) pending.push_back(node);
    while (!pending.empty()) {
      auto *current = pending.pop_back_val();
      if (auto *member = llvh::dyn_cast<ESTree::MemberExpressionNode>(current)) {
        if (llvh::isa<ESTree::SuperNode>(member->_object)) return true;
      } else if (auto *pattern = llvh::dyn_cast<ESTree::AssignmentPatternNode>(current)) {
        pending.push_back(pattern->_left);
      } else if (auto *rest = llvh::dyn_cast<ESTree::RestElementNode>(current)) {
        pending.push_back(rest->_argument);
      } else if (auto *array = llvh::dyn_cast<ESTree::ArrayPatternNode>(current)) {
        for (auto &element : array->_elements) pending.push_back(&element);
      } else if (auto *object = llvh::dyn_cast<ESTree::ObjectPatternNode>(current)) {
        for (auto &entry : object->_properties) {
          if (auto *property = llvh::dyn_cast<ESTree::PropertyNode>(&entry))
            pending.push_back(property->_value);
          else
            pending.push_back(&entry);
        }
      }
    }
    return false;
  }

  void doCopyLocation(ESTree::Node *src, ESTree::Node *dest) {
    if (src != nullptr) {
      dest->setStartLoc(src->getStartLoc());
      dest->setEndLoc(src->getEndLoc());
      dest->setDebugLoc(src->getDebugLoc());
    }
  }

  template <typename T>
  T *copyLocation(ESTree::Node *src, T *dest) {
    doCopyLocation(src, dest);
    return dest;
  }

  template <typename T, typename... Args>
  T *createTransformedNode(ESTree::Node *src, Args &&...args) {
    auto *node = new (context_) T(std::forward<Args>(args)...);
    return copyLocation(src, node);
  }

  ESTree::Node *cloneNodeInternal(ESTree::Node *node) {
    if (node == nullptr) {
      return nullptr;
    }

                                              
    if (auto *identifier = llvh::dyn_cast<ESTree::IdentifierNode>(node)) {
      return createTransformedNode<ESTree::IdentifierNode>(
          node,
          identifier->_name,
          cloneNode(identifier->_typeAnnotation),
          identifier->_optional);
    }
    if (auto *memberExpression =
            llvh::dyn_cast<ESTree::MemberExpressionNode>(node)) {
                                                                             
                                                                                
      ESTree::Node *property;
      if (auto *stringKey = llvh::dyn_cast<ESTree::StringLiteralNode>(
              memberExpression->_property)) {
        property = createTransformedNode<ESTree::StringLiteralNode>(
            stringKey, stringKey->_value);
      } else {
        property = cloneNode(memberExpression->_property);
      }
      return createTransformedNode<ESTree::MemberExpressionNode>(
          node,
          cloneNode(memberExpression->_object),
          property,
          memberExpression->_computed);
    }

                                                                           
    auto &sm = context_.getSourceErrorManager();
    SourceErrorManager::SourceCoords begin{}, end{};
    bool valid = sm.findBufferLineAndLoc(node->getStartLoc(), begin, false);
    bool endValid = sm.findBufferLineAndLoc(node->getEndLoc(), end, false);
    long long first = -1, last = -1;
    if (valid && !sm.isVirtualBufferId(begin.bufId)) {
      const auto *buffer = sm.getSourceBuffer(begin.bufId);
      const auto *a = node->getStartLoc().getPointer();
      const auto *b = node->getEndLoc().getPointer();
      if (a >= buffer->getBufferStart() && a <= buffer->getBufferEnd())
        first = a - buffer->getBufferStart();
      if (endValid && end.bufId == begin.bufId &&
          b >= buffer->getBufferStart() && b <= buffer->getBufferEnd())
        last = b - buffer->getBufferStart();
    }
    llvh::errs() << "[CLASS_CLONE_DIAGNOSTIC] ast=" << node->getNodeName()
                 << " valid=" << valid << " line=" << begin.line
                 << " column=" << begin.col << " end_line=" << end.line
                 << " end_column=" << end.col << " byte=" << first
                 << " end_byte=" << last;
    if (valid) llvh::errs() << " input=" << sm.getSourceUrl(begin.bufId);
    llvh::errs() << "\n";
    llvh::errs().flush();
    llvm_unreachable("Unsupported Node Kind");

    return node;
  }

  template <typename T>
  T *cloneNode(T *node) {
    return llvh::cast_or_null<T>(cloneNodeInternal(node));
  }

                                                                             
                                                                               
  bool isFactoryHeritage(ESTree::Node *node) {
    while (auto *member = llvh::dyn_cast<ESTree::MemberExpressionNode>(node)) {
      node = member->_object;
    }
    return llvh::isa<ESTree::CallExpressionNode>(node);
  }

  static bool hasPrivateMembers(ESTree::ClassBodyNode *body) {
    for (auto &entry:body->_body) {
      if (llvh::isa<ESTree::ClassPrivatePropertyNode>(&entry)) return true;
      if (auto *method=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry))
        if (llvh::isa<ESTree::PrivateNameNode>(method->_key)) return true;
    }
    return false;
  }

  bool hasPublicStaticFields(ESTree::ClassBodyNode *body) {
    for(auto &entry:body->_body)
      if(auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry))
        if(field->_static) return true;
    return false;
  }

  bool usesNativePublicFields(ESTree::Node *node, ESTree::ClassBodyNode *body,
                              ESTree::Node *superClass) {
                                                                              
                                                                         
    if (hasPublicStaticFields(body)) return true;
    if (!superClass && !hasPrivateMembers(body) && hasBaseStaticSymbolSuper(body)) return true;
    if (hasPrivateMembers(body) ||
        !llvh::isa<ESTree::ClassDeclarationNode>(node)) return false;
    for (auto &entry:body->_body)
      if (auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry))
        if (!field->_static) {
                                                                           
                                                                           
                                                                             
                                                                             
          NativePublicStaticProfile probe(context_);
          const bool supported=probe.check(node,body,superClass,false);
          return supported || probe.invalidOriginalSyntax;
        }
    return false;
  }

  ESTree::Node *createClass(
      ESTree::Node *classNode,
      ESTree::Node *id,
      ESTree::ClassBodyNode *classBody,
      ESTree::Node *&superClass) {
    const bool nativeDerived=superClass!=nullptr;
    if (nativeDerived && (!context_.getCodeGenerationSettings().enableBlockScoping ||
                          !context_.getCodeGenerationSettings().enableTDZ)) {
      context_.getSourceErrorManager().error(classNode->getSourceRange(),
          "[NATIVE_DERIVED_UNSUPPORTED] LEXICAL_TDZ_REQUIRED");
      return makeUndefinedNode(classNode);
    }
    const bool hasNativePrivate=hasPrivateMembers(classBody);
    if (hasNativePrivate &&
        (!context_.getCodeGenerationSettings().enableBlockScoping ||
         !context_.getCodeGenerationSettings().enableTDZ)) {
      context_.getSourceErrorManager().error(classNode->getSourceRange(),
          "[NATIVE_PRIVATE_UNSUPPORTED] LEXICAL_TDZ_REQUIRED");
      return makeUndefinedNode(classNode);
    }
                                                                              
                                                                         
    NativePrivateFieldProfile privateProfile(context_);
    if (hasNativePrivate && !privateProfile.check(classNode,classBody,superClass))
      return makeUndefinedNode(classNode);

    const bool hasNativePublicStatic=usesNativePublicFields(classNode,classBody,superClass);
    NativePublicStaticProfile publicProfile(context_);
    if(hasNativePublicStatic && !hasNativePrivate && !publicProfile.check(classNode,classBody,superClass))
      return makeUndefinedNode(classNode);

    const bool anonymousNativeExpression=!id &&
        llvh::isa<ESTree::ClassExpressionNode>(classNode) &&
        (hasNativePrivate || hasNativePublicStatic || nativeDerived);
    auto *nameParameter=anonymousNativeExpression
        ? internalIDs_.next("class_expression_name").getUnderlyingPointer():nullptr;

                                                                          
                                                                           
    bool hasComputedLiteralFields = false;
    for (auto &entry : classBody->_body) {
      auto *field = llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry);
      if (!field || !field->_computed) continue;
      if (hasNativePublicStatic) continue;
      if (field->_static) {
        context_.getSourceErrorManager().error(field->getSourceRange(),
            "[CLASS_FIELD_UNSUPPORTED] STATIC_COMPUTED");
        return makeUndefinedNode(classNode);
      }
      if (!llvh::isa<ESTree::StringLiteralNode>(field->_key) &&
          !llvh::isa<ESTree::NumericLiteralNode>(field->_key)) {
        context_.getSourceErrorManager().error(field->_key->getSourceRange(),
            "[CLASS_FIELD_UNSUPPORTED] COMPUTED_KEY");
        return makeUndefinedNode(classNode);
      }
      hasComputedLiteralFields = true;
    }
                                                                             
                                                                             

    ESTree::Node *resolvedClassId = nullptr;
    if (id == nullptr) {
                                                                              
      resolvedClassId = makeIdentifierNode(
          classNode,
          internalIDs_.next("class_expression").getUnderlyingPointer());
    } else {
      resolvedClassId = id;
    }

    bool cachedPublicKeys=false;
    if(hasNativePublicStatic) for(auto &entry:classBody->_body) {
      if(auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry))
        cachedPublicKeys |= field->_computed && !NativePublicStaticProfile::literalKey(field->_key,true);
      if(auto *method=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry))
        cachedPublicKeys |= method->_computed && !NativePublicStaticProfile::literalKey(method->_key,true);
    }
                                                                                 
                                                                                  
                                                                                  
    auto *definitionTarget=(cachedPublicKeys || nativeDerived)
        ? makeIdentifierNode(classNode,internalIDs_.next("class_key_ctor").getUnderlyingPointer())
        : copyIdentifier(resolvedClassId);
    NodeVector statements;
    if (hasNativePrivate || hasNativePublicStatic || nativeDerived) {
                                                                             
                                                                           
                                                                             
                                                                              
      auto *directive=context_.getStringTable().getString("use strict");
      statements.append(createTransformedNode<ESTree::ExpressionStatementNode>(
          classNode,createTransformedNode<ESTree::StringLiteralNode>(classNode,directive),
          directive));
    }

    ESTree::Node *superClassExpr = nullptr;
    ESTree::Node *currentProcessingSuperClass = nullptr;
    ESTree::Node *superClassArgument = nullptr;
    UniqueString *heritagePrototype=nullptr;
    if (nativeDerived) {
      auto *original=superClass;
      currentProcessingSuperClass=makeIdentifierNode(original,
          internalIDs_.next("class_super").getUnderlyingPointer());
                                                                             
                                                                        
      auto *holder=createTransformedNode<ESTree::ExpressionStatementNode>(
          original,original,nullptr);
      superClass=nullptr;
      visitESTreeChildren(*this,holder);auto *value=holder->_expression;
      holder->_expression=nullptr;
      statements.append(makeSingleVariableDecl(original,
          copyIdentifier(currentProcessingSuperClass),value));
      heritagePrototype=internalIDs_.next("heritage_prototype").getUnderlyingPointer();
      statements.append(makeSingleVariableDecl(original,
          makeIdentifierNode(original,heritagePrototype),
          makeNativeClassDefinitionOp(original,"heritage_prototype",
              {copyIdentifier(currentProcessingSuperClass)})));
      superClassExpr=copyIdentifier(currentProcessingSuperClass);
    } else {
      superClassExpr=new (context_) ESTree::NullLiteralNode();
    }

    auto *oldProcessingClass = _currentProcessingClass;
    auto *oldClassMember = _currentClassMember;
    const bool oldMethodBody = _visitingClassMethodBody;
    const bool oldSuperBarrier = _ordinarySuperBarrier;
    _ordinarySuperBarrier = false;
    VisitedClass currentProcessingClass(
        resolvedClassId, currentProcessingSuperClass);
    currentProcessingClass.cachedPublicKeys=cachedPublicKeys;
    currentProcessingClass.baseStaticSymbolSuper=!nativeDerived && !hasNativePrivate && hasBaseStaticSymbolSuper(classBody);
    currentProcessingClass.nativeDerived=nativeDerived;
    currentProcessingClass.constructorIdentity=
        llvh::cast<ESTree::IdentifierNode>(definitionTarget)->_name;
    if(nativeDerived)
      currentProcessingClass.derivedInitializer=
          internalIDs_.next("derived_fields").getUnderlyingPointer();
    if(cachedPublicKeys) for(auto &entry:classBody->_body) {
      ESTree::NodePtr *slot=nullptr;bool computed=false;
      if(auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry)) {slot=&field->_key;computed=field->_computed;}
      else if(auto *method=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry)) {slot=&method->_key;computed=method->_computed;}
      if(!slot||!computed)continue;
      auto *original=*slot;*slot=nullptr;
                                                                           
                                                                            
      auto *value=transformPrivateOperand(original);
      auto *binding=internalIDs_.next("class_element_key").getUnderlyingPointer();
      *slot=makeIdentifierNode(original,binding);
      currentProcessingClass.publicKeyStatements.emplace(&entry,
          makeSingleVariableDecl(original,makeIdentifierNode(original,binding),
              makeNativePublicOp(original,"to_key",{value})));
    }
    _currentProcessingClass = &currentProcessingClass;
    currentProcessingClass.nativePublicFields=hasNativePublicStatic;
    currentProcessingClass.nativeInstanceFields=hasNativePrivate || hasNativePublicStatic;
    if (hasNativePrivate) {
                                                                          
                                                                     
      for (auto &entry:classBody->_body) {
        auto *field=llvh::dyn_cast<ESTree::ClassPrivatePropertyNode>(&entry);
        if (!field) continue;
        auto *id=llvh::cast<ESTree::IdentifierNode>(field->_key);
        auto *token=internalIDs_.next("private_field_token").getUnderlyingPointer();
        currentProcessingClass.privateTokens.emplace(id->_name,token);
        statements.append(makeSingleVariableDecl(field,makeIdentifierNode(field,token),
            makeNativePrivateOp(field,"create",{})));
      }
    }
    if (hasNativePrivate) {
      currentProcessingClass.privateKinds=privateProfile.privateKinds;
      for (auto &entry:classBody->_body) {
        auto *method=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry);
        if(!method)continue;
        auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(method->_key);
        if(!name)continue;
        auto *id=llvh::cast<ESTree::IdentifierNode>(name->_id);
        if(currentProcessingClass.privateTokens.count(id->_name))continue;
        auto *token=internalIDs_.next("private_member_token").getUnderlyingPointer();
        currentProcessingClass.privateTokens[id->_name]=token;
        statements.append(makeSingleVariableDecl(method,makeIdentifierNode(method,token),
            makeNativePrivateOp(method,"create",{})));
        auto *fn=internalIDs_.next("private_member_function").getUnderlyingPointer();
        currentProcessingClass.privateFunctions[id->_name]=fn;
        statements.append(makeSingleVariableDecl(method,makeIdentifierNode(method,fn),makeUndefinedNode(method)));
        if(privateProfile.privateKinds[id->_name]!=1) {
          auto *setterToken=internalIDs_.next("private_setter_token").getUnderlyingPointer();
          currentProcessingClass.privateSetterTokens[id->_name]=setterToken;
          statements.append(makeSingleVariableDecl(method,makeIdentifierNode(method,setterToken),
              makeNativePrivateOp(method,"create",{})));
          auto *setter=internalIDs_.next("private_setter_function").getUnderlyingPointer();
          currentProcessingClass.privateSetters[id->_name]=setter;
          statements.append(makeSingleVariableDecl(method,makeIdentifierNode(method,setter),makeUndefinedNode(method)));
        }
      }
    }
    if (hasNativePrivate) {
                                                                          
                                                                           
                                                                  
      for (auto &entry:classBody->_body) {
        auto *field=llvh::dyn_cast<ESTree::ClassPrivatePropertyNode>(&entry);
        if (!field || !field->_value) continue;
        auto *id=llvh::cast<ESTree::IdentifierNode>(field->_key);
        auto *binding=internalIDs_.next("private_initializer").getUnderlyingPointer();
        currentProcessingClass.privateInitializers.emplace(id->_name,binding);
        auto *value=field->_value;field->_value=nullptr;
        value=transformPrivateOperand(value);
        auto *privateKey=createTransformedNode<ESTree::StringLiteralNode>(field,
            context_.getStringTable().getString((llvh::Twine("#")+id->_name->str()).str()));
        value=nameNativePublicFieldFunction(field,privateKey,value);
        statements.append(makeSingleVariableDecl(field,makeIdentifierNode(field,binding),
            makeNativePrivateInitializer(field,value)));
      }
    }
    if (currentProcessingClass.nativeInstanceFields) {
                                                                         
                                                                        
      for (auto &entry:classBody->_body) {
        auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry);
        if (!field || field->_static || !field->_value) continue;
        auto *binding=internalIDs_.next("public_instance_initializer").getUnderlyingPointer();
        currentProcessingClass.publicInstanceInitializers.emplace(field,binding);
        auto *value=field->_value; field->_value=nullptr;
        value=transformPrivateOperand(value);
        value=nameNativePublicFieldFunction(field,field->_key,value,cachedPublicKeys&&field->_computed);
        statements.append(makeSingleVariableDecl(field,makeIdentifierNode(field,binding),
            makeNativePrivateInitializer(field,value)));
      }
    }
                                                                               
                                                                             
                                                                          
    _currentClassMember = nullptr;
    _visitingClassMethodBody = false;

    auto classMembers = resolveClassMembers(classBody);
    if(nativeDerived) {
      ESTree::NodeList initializers;
      appendPropertyInitializers(classBody,initializers);
      auto *body=createTransformedNode<ESTree::BlockStatementNode>(classBody,std::move(initializers));
      auto *initialize=createTransformedNode<ESTree::FunctionExpressionNode>(
          classBody,nullptr,ESTree::NodeList{},body,nullptr,nullptr,nullptr,false,false);
      initialize->loweredClassFunctionKind=ESTree::LoweredClassFunctionKind::Method;
      statements.append(makeSingleVariableDecl(classBody,
          makeIdentifierNode(classBody,currentProcessingClass.derivedInitializer),initialize));
    }
    auto *ctorAsFunction = createClassCtor(
        resolvedClassId,
        classBody,
        currentProcessingSuperClass,
        classMembers.constructor);

    auto *defineClassResult = nativeDerived
        ? makeNativeClassDefinitionOp(classNode,"init_derived",
              {copyIdentifier(definitionTarget),copyIdentifier(currentProcessingSuperClass),
               makeIdentifierNode(classNode,heritagePrototype)})
        : (hasNativePrivate || hasNativePublicStatic)
        ? makeNativeClassDefinitionOp(classNode, "init_base",
              {copyIdentifier(definitionTarget)})
        : makeHermesES6InternalCall(classNode, "defineClass",
              {copyIdentifier(ctorAsFunction->_id), superClassExpr});

    if(hasNativePublicStatic || nativeDerived) {
                                                                               
                                                               
      auto *ctorExpression=createTransformedNode<ESTree::FunctionExpressionNode>(
          ctorAsFunction,copyIdentifier(ctorAsFunction->_id),
          std::move(ctorAsFunction->_params),ctorAsFunction->_body,
          nullptr,nullptr,nullptr,false,false);
      ctorExpression->loweredClassFunctionKind=ctorAsFunction->loweredClassFunctionKind;
                                                                             
      ctorExpression->loweredClassPreParameterInitializers=
          ctorAsFunction->loweredClassPreParameterInitializers;
      ctorAsFunction->_body=nullptr;
      statements.append(makeSingleVariableDecl(classNode,
          copyIdentifier(definitionTarget),ctorExpression,
          context_.getIdentifier("const").getUnderlyingPointer()));
    } else statements.append(ctorAsFunction);
    statements.append(toStatement(defineClassResult));
    if(nameParameter)statements.append(toStatement(makeNativePublicOp(classNode,
        "named_function_dynamic",{makeIdentifierNode(classNode,nameParameter),copyIdentifier(definitionTarget)})));

                                                                                
                                                                            
    NodeVector methodStatements;
    appendMethods(definitionTarget, classMembers, methodStatements);
    NodeVector staticStatements;
    if(hasNativePrivate)
      appendNativePrivateStaticBlocks(classBody,definitionTarget,staticStatements);
    if (currentProcessingClass.superSetInstanceHome) {
      auto *prototype = createTransformedNode<ESTree::MemberExpressionNode>(
          classNode, copyIdentifier(definitionTarget),
          makeIdentifierNode(classNode, "prototype"), false);
      statements.append(makeSingleVariableDecl(classNode,
          makeIdentifierNode(classNode,
              currentProcessingClass.superSetInstanceHome), prototype));
    }
    if (currentProcessingClass.superSetStaticHome) {
      statements.append(makeSingleVariableDecl(classNode,
          makeIdentifierNode(classNode,
              currentProcessingClass.superSetStaticHome),
          copyIdentifier(definitionTarget)));
    }
    if(cachedPublicKeys) {
      auto method=methodStatements.begin();
      for(auto &entry:classBody->_body) {
        auto key=currentProcessingClass.publicKeyStatements.find(&entry);
        if(key!=currentProcessingClass.publicKeyStatements.end())statements.append(key->second);
        if(auto *definition=llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry)) {
          if(getClassMemberKind(definition)!=ClassMemberKind::Constructor) {
            assert(method!=methodStatements.end());statements.append(*method++);
          }
        }
      }
      assert(method==methodStatements.end());
      statements.append(makeSingleVariableDecl(classNode,copyIdentifier(resolvedClassId),
          copyIdentifier(definitionTarget),context_.getIdentifier("const").getUnderlyingPointer()));
    } else {
      for (auto *statement : methodStatements) statements.append(statement);
      if(nativeDerived) statements.append(makeSingleVariableDecl(classNode,
          copyIdentifier(resolvedClassId),copyIdentifier(definitionTarget),
          context_.getIdentifier("const").getUnderlyingPointer()));
    }
    if(hasNativePublicStatic && !hasNativePrivate)
      appendNativePublicStaticFields(classBody,definitionTarget,statements);
    for(auto *statement:staticStatements)statements.append(statement);

                                                
    auto *expr = blockToExpression(
        classNode,
        statements,
        ctorAsFunction->_id,
        superClassArgument ? currentProcessingSuperClass : nullptr,
        superClassArgument, cachedPublicKeys || nativeDerived || anonymousNativeExpression);
    if(nameParameter) {
      auto *call=llvh::cast<ESTree::CallExpressionNode>(expr);
      auto *wrapper=llvh::cast<ESTree::ArrowFunctionExpressionNode>(call->_callee);
                                                                                
      wrapper->_params.push_front(*makeIdentifierNode(classNode,nameParameter));
      assert(call->_arguments.empty() && "native heritage is evaluated inside the lexical wrapper");
      call->_callee=nullptr;
      expr=makeNativeClassDefinitionOp(classNode,"anonymous_expression",{wrapper});
    }

    _currentProcessingClass = oldProcessingClass;
    _currentClassMember = oldClassMember;
    _visitingClassMethodBody = oldMethodBody;
    _ordinarySuperBarrier = oldSuperBarrier;

    return expr;
  }

  ESTree::StatementNode *toStatement(ESTree::Node *expression) {
    return createTransformedNode<ESTree::ExpressionStatementNode>(
        expression, expression, nullptr);
  }

  ESTree::IdentifierNode *copyIdentifier(ESTree::Node *identifer) {
    auto *typedIdentifier = llvh::cast<ESTree::IdentifierNode>(identifer);
    return createTransformedNode<ESTree::IdentifierNode>(
        identifer, typedIdentifier->_name, nullptr, false);
  }

  ESTree::Node *makeSingleVariableDecl(
      ESTree::Node *srcNode,
      ESTree::Node *identifier,
      ESTree::Node *value,
      UniqueString *declarationKind=nullptr) {
    auto *variableDeclarator =
        createTransformedNode<ESTree::VariableDeclaratorNode>(
            srcNode, value, identifier);
    ESTree::NodeList variableList;
    variableList.push_back(*variableDeclarator);
    return createTransformedNode<ESTree::VariableDeclarationNode>(
        srcNode, declarationKind ? declarationKind : identVar_, std::move(variableList));
  }

  ESTree::Node *makeNativeClassDefinitionOp(
      ESTree::Node *srcNode,
      llvh::StringRef operation,
      const NodeVector &parameters) {
    return createTransformedNode<ESTree::NativeClassDefinitionOperationNode>(
        srcNode, context_.getIdentifier(operation).getUnderlyingPointer(),
        parameters.toNodeList());
  }

  ESTree::Node *makeHermesES6InternalCall(
      ESTree::Node *srcNode,
      llvh::StringRef methodName,
      const NodeVector &parameters) {
    auto hermesInternalIdentifier =
        makeIdentifierNode(srcNode, "HermesES6Internal");
    auto methodIdentifier = makeIdentifierNode(srcNode, methodName);

    auto *getPropertyNode = createTransformedNode<ESTree::MemberExpressionNode>(
        srcNode, hermesInternalIdentifier, methodIdentifier, false);
    return createTransformedNode<ESTree::CallExpressionNode>(
        srcNode, getPropertyNode, nullptr, parameters.toNodeList());
  }

  ESTree::IdentifierNode *makeIdentifierNode(
      ESTree::Node *srcNode,
      UniqueString *name) {
    return createTransformedNode<ESTree::IdentifierNode>(
        srcNode, name, nullptr, false);
  }

  ESTree::IdentifierNode *makeIdentifierNode(
      ESTree::Node *srcNode,
      llvh::StringRef name) {
    return makeIdentifierNode(
        srcNode, context_.getIdentifier(name).getUnderlyingPointer());
  }

  ESTree::Node *makeUndefinedNode(ESTree::Node *srcNode) {
    return makeIdentifierNode(srcNode, "undefined");
  }

  ESTree::Node *createCallWithForwardedThis(
      ESTree::Node *srcNode,
      ESTree::Node *object,
      NodeVector parameters) {
    auto *this_ = createTransformedNode<ESTree::ThisExpressionNode>(srcNode);

    parameters.prepend(this_);

    auto methodIdentifier = makeIdentifierNode(srcNode, "call");

    auto *getPropertyNode = createTransformedNode<ESTree::MemberExpressionNode>(
        srcNode, object, methodIdentifier, false);
    return createTransformedNode<ESTree::CallExpressionNode>(
        srcNode, getPropertyNode, nullptr, parameters.toNodeList());
  }

  ESTree::Node *createSuperCall(
      ESTree::Node *srcNode,
      ESTree::Node *superClass,
      NodeVector parameters) {
    if (_currentProcessingClass && _currentProcessingClass->nativeDerived) {
      NodeVector args;
      args.append(makeIdentifierNode(srcNode,_currentProcessingClass->constructorIdentity));
      args.append(makeIdentifierNode(srcNode,_currentProcessingClass->derivedInitializer));
      for (auto *p:parameters) args.append(transformPrivateOperand(p));
      return createTransformedNode<ESTree::NativeDerivedSuperOperationNode>(
          srcNode,context_.getIdentifier("super").getUnderlyingPointer(),args.toNodeList());
    }
    return createCallWithForwardedThis(
        srcNode, cloneNode(superClass), std::move(parameters));
  }

  ESTree::Node *createNativeSuperReference(
      ESTree::Node *srcNode,ESTree::Node *property,bool computed,
      bool call,NodeVector parameters) {
    auto *cls=_currentProcessingClass;
    const bool isStatic=_visitingStaticBlock || (_currentClassMember && _currentClassMember->isStatic);
    auto *&home=isStatic?cls->superSetStaticHome:cls->superSetInstanceHome;
    if(!home)home=internalIDs_.next(isStatic?"super_read_static_home":"super_read_instance_home").getUnderlyingPointer();
    ESTree::Node *keyNode=computed ? transformPrivateOperand(property) : property;
    if(!computed)keyNode=createTransformedNode<ESTree::StringLiteralNode>(property,
        llvh::cast<ESTree::IdentifierNode>(property)->_name);
    NodeVector args;
                                                                              
    args.append(createTransformedNode<ESTree::ThisExpressionNode>(srcNode));
    args.append(makeIdentifierNode(srcNode,home));args.append(keyNode);
    for(auto *arg:parameters)args.append(transformPrivateOperand(arg));
    return makeNativeClassDefinitionOp(srcNode,
        computed ? (call ? "call_super_computed_property" : "get_super_computed_property")
                 : (call ? "call_super_property" : "get_super_property"),args);
  }

  void appendNativePrivateStaticBlocks(ESTree::ClassBodyNode *body,
      ESTree::Node *target,NodeVector &statements) {
    for(auto &entry:body->_body) {
      if(auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry)) {
        if(field->_static) {
          const bool old=_visitingStaticBlock;_visitingStaticBlock=true;
          appendNativePublicStaticField(field,target,statements);
          _visitingStaticBlock=old;
        }
        continue;
      }
      auto *block=llvh::dyn_cast<ESTree::StaticBlockNode>(&entry);
      if(!block)continue;
      const bool old=_visitingStaticBlock;_visitingStaticBlock=true;
      visitESTreeChildren(*this,block);_visitingStaticBlock=old;
      auto *fnBody=createTransformedNode<ESTree::BlockStatementNode>(block,std::move(block->_body));
      auto *fn=createTransformedNode<ESTree::FunctionExpressionNode>(
          block,nullptr,ESTree::NodeList{},fnBody,nullptr,nullptr,nullptr,false,false);
      fn->loweredClassFunctionKind=ESTree::LoweredClassFunctionKind::Method;
      statements.append(toStatement(makeNativeClassDefinitionOp(block,"run_static_block",
          {fn,copyIdentifier(target)})));
    }
  }

  ESTree::Node *createGetSuperProperty(
      ESTree::Node *srcNode,
      ESTree::Node *superClass,
      ESTree::Node *propertyName) {
    if(_currentProcessingClass && (!_currentProcessingClass->privateTokens.empty() || _currentProcessingClass->nativePublicFields || _currentProcessingClass->nativeInstanceFields)) {
      auto *member=llvh::cast<ESTree::MemberExpressionNode>(srcNode);
      return createNativeSuperReference(srcNode,propertyName,member->_computed,false,{});
    }
    auto *reflectGet = createTransformedNode<ESTree::MemberExpressionNode>(
        srcNode,
        makeIdentifierNode(srcNode, "Reflect"),
        makeIdentifierNode(srcNode, "get"),
        false);

    ESTree::NodeList parameters;
    if (_currentClassMember && _currentClassMember->isStatic) {
                                                    
      parameters.push_back(*cloneNode(superClass));
    } else {
                                                              
      auto *getParentClassPrototype =
          createTransformedNode<ESTree::MemberExpressionNode>(
              srcNode,
              cloneNode(superClass),
              makeIdentifierNode(srcNode, "prototype"),
              false);
      parameters.push_back(*getParentClassPrototype);
    }

    auto *propertyStringLiteral =
        createTransformedNode<ESTree::StringLiteralNode>(
            propertyName,
            llvh::cast<ESTree::IdentifierNode>(propertyName)->_name);
    auto *this_ = createTransformedNode<ESTree::ThisExpressionNode>(srcNode);

    parameters.push_back(*propertyStringLiteral);
    parameters.push_back(*this_);

    return createTransformedNode<ESTree::CallExpressionNode>(
        srcNode, reflectGet, nullptr, std::move(parameters));
  }

  ESTree::Node *createSetSuperProperty(
      ESTree::Node *srcNode,
      UniqueString *home,
      ESTree::Node *key,
      ESTree::Node *rhs) {
    auto *receiverName = internalIDs_.next("super_set_receiver").getUnderlyingPointer();
    auto *keyName = internalIDs_.next("super_set_key").getUnderlyingPointer();
    auto *baseName = internalIDs_.next("super_set_base").getUnderlyingPointer();
    auto *valueName = internalIDs_.next("super_set_value").getUnderlyingPointer();
    ESTree::NodeList parameters;
    for (auto *name : {receiverName, keyName, baseName, valueName})
      parameters.push_back(*makeIdentifierNode(srcNode, name));

    auto *reflectSet = createTransformedNode<ESTree::MemberExpressionNode>(
        srcNode, makeIdentifierNode(srcNode, "Reflect"),
        makeIdentifierNode(srcNode, "set"), false);
    auto *setResult = createTransformedNode<ESTree::CallExpressionNode>(
        srcNode, reflectSet, nullptr,
        NodeVector{makeIdentifierNode(srcNode, baseName),
                   makeIdentifierNode(srcNode, keyName),
                   makeIdentifierNode(srcNode, valueName),
                   makeIdentifierNode(srcNode, receiverName)}.toNodeList());
    auto *failed = createTransformedNode<ESTree::UnaryExpressionNode>(
        srcNode, context_.getStringTable().getString("!"), setResult, true);
    auto *error = createTransformedNode<ESTree::NewExpressionNode>(
        srcNode, makeIdentifierNode(srcNode, "TypeError"), nullptr,
        NodeVector{createTransformedNode<ESTree::StringLiteralNode>(srcNode,
            context_.getStringTable().getString("super property assignment failed"))}
            .toNodeList());
    auto *throwError = createTransformedNode<ESTree::ThrowStatementNode>(srcNode, error);
    ESTree::NodeList bodyStatements;
    bodyStatements.push_back(*createTransformedNode<ESTree::IfStatementNode>(
        srcNode, failed, throwError, nullptr));
    bodyStatements.push_back(*createTransformedNode<ESTree::ReturnStatementNode>(
        srcNode, makeIdentifierNode(srcNode, valueName)));
    auto *body = createTransformedNode<ESTree::BlockStatementNode>(
        srcNode, std::move(bodyStatements));
    auto *setter = createTransformedNode<ESTree::FunctionExpressionNode>(
        srcNode, nullptr, std::move(parameters), body,
        nullptr, nullptr, nullptr, false, false);

                                                                                
                                                                                
    auto *getPrototypeOf = createTransformedNode<ESTree::MemberExpressionNode>(
        srcNode, makeIdentifierNode(srcNode, "Object"),
        makeIdentifierNode(srcNode, "getPrototypeOf"), false);
    auto *base = createTransformedNode<ESTree::CallExpressionNode>(
        srcNode, getPrototypeOf, nullptr,
        NodeVector{makeIdentifierNode(srcNode, home)}.toNodeList());
                                                                             
                                                                               
    return createTransformedNode<ESTree::CallExpressionNode>(
        srcNode, setter, nullptr,
        NodeVector{createTransformedNode<ESTree::ThisExpressionNode>(srcNode),
                   key, base, rhs}.toNodeList());
  }

  ESTree::Node *createSuperMethodCall(
      ESTree::Node *srcNode,
      ESTree::Node *superClass,
      ESTree::NodePtr property,
      bool computed,
      NodeVector parameters) {
    if(_currentProcessingClass && (!_currentProcessingClass->privateTokens.empty() || _currentProcessingClass->nativePublicFields || _currentProcessingClass->nativeInstanceFields))
      return createNativeSuperReference(srcNode,property,computed,true,std::move(parameters));
    ESTree::Node *getMethodNodeParameter = nullptr;
    if (_currentClassMember && _currentClassMember->isStatic) {
                                                                             
                  
      getMethodNodeParameter = cloneNode(superClass);
    } else {
                                               
                                                          
      auto prototypeIdentifier = makeIdentifierNode(srcNode, "prototype");

      getMethodNodeParameter =
          createTransformedNode<ESTree::MemberExpressionNode>(
              srcNode, cloneNode(superClass), prototypeIdentifier, false);
    }

    auto *getMethodNode = createTransformedNode<ESTree::MemberExpressionNode>(
        srcNode, getMethodNodeParameter, property, computed);

    return createCallWithForwardedThis(
        srcNode, getMethodNode, std::move(parameters));
  }

  ESTree::Node *blockToExpression(
      ESTree::Node *srcNode,
      const NodeVector &statements,
      ESTree::Node *returnVariableName,
      ESTree::Node *superClassParameter,
      ESTree::Node *superClassArgument, bool lexicalWrapper=false) {
    auto stmtList = statements.toNodeList();

    auto *returnStmt = createTransformedNode<ESTree::ReturnStatementNode>(
        srcNode, copyIdentifier(returnVariableName));

    stmtList.push_back(*returnStmt);

    auto *body = createTransformedNode<ESTree::BlockStatementNode>(
        srcNode, std::move(stmtList));

    ESTree::NodeList parameters;
    ESTree::NodeList arguments;
    if (superClassArgument != nullptr) {
                                                                            
                                                                               
                                                                         
      parameters.push_back(*cloneNode(superClassParameter));
      arguments.push_back(*superClassArgument);
    }
    auto *immediateInvokedFunction =
        createTransformedNode<ESTree::FunctionExpressionNode>(
            srcNode,
            nullptr,
            std::move(parameters),
            body,
            nullptr,
            nullptr,
            nullptr,
            false,
            false);

    if(lexicalWrapper) {
      auto *arrow=createTransformedNode<ESTree::ArrowFunctionExpressionNode>(
          srcNode,nullptr,std::move(immediateInvokedFunction->_params),body,
          nullptr,nullptr,nullptr,false,false);
      immediateInvokedFunction->_body=nullptr;
      return createTransformedNode<ESTree::CallExpressionNode>(srcNode,arrow,nullptr,std::move(arguments));
    }
    return createTransformedNode<ESTree::CallExpressionNode>(
        srcNode, immediateInvokedFunction, nullptr, std::move(arguments));
  }

  void unpackStatements(ESTree::Node *stmt, NodeVector &out) {
    auto *expressionStatement =
        llvh::dyn_cast<ESTree::ExpressionStatementNode>(stmt);
    if (expressionStatement == nullptr) {
      out.append(stmt);
      return;
    }

    auto *sequenceExpression = llvh::dyn_cast<ESTree::SequenceExpressionNode>(
        expressionStatement->_expression);
    if (sequenceExpression == nullptr) {
      out.append(stmt);
      return;
    }

    NodeVector expressions(sequenceExpression->_expressions);
    for (auto *node : expressions) {
      auto *emittedExpressionStatement =
          createTransformedNode<ESTree::ExpressionStatementNode>(
              node, node, expressionStatement->_directive);

      out.append(emittedExpressionStatement);
    }
  }

  bool isDirectSuperStatement(ESTree::Node *statement) {
    auto *expression = llvh::dyn_cast<ESTree::ExpressionStatementNode>(statement);
    if (!expression) return false;
    auto *call = llvh::dyn_cast<ESTree::CallExpressionNode>(expression->_expression);
    return call && llvh::isa<ESTree::SuperNode>(call->_callee);
  }

  bool validateLiteralFieldConstructor(
      ESTree::ClassBodyNode *classBody,
      ESTree::MethodDefinitionNode *ctor) {
                                                                             
    if (!ctor) return true;
    auto *function = llvh::dyn_cast<ESTree::FunctionExpressionNode>(ctor->_value);
    auto *body = function
        ? llvh::dyn_cast<ESTree::BlockStatementNode>(function->_body) : nullptr;
    if (!body) {
      context_.getSourceErrorManager().error(classBody->getSourceRange(),
          "[CLASS_FIELD_UNSUPPORTED] CONSTRUCTOR_SHAPE");
      return false;
    }
    LiteralFieldSuperCalls all;
    visitESTreeNode(all, function);
    unsigned direct = 0;
    for (auto &statement : body->_body) {
      if (isDirectSuperStatement(&statement)) {
        ++direct;
        continue;
      }
      auto *expression =
          llvh::dyn_cast<ESTree::ExpressionStatementNode>(&statement);
      auto *sequence = expression
          ? llvh::dyn_cast<ESTree::SequenceExpressionNode>(expression->_expression)
          : nullptr;
      if (!sequence) continue;
                                                                              
      for (auto &item : sequence->_expressions) {
        auto *call = llvh::dyn_cast<ESTree::CallExpressionNode>(&item);
        if (call && llvh::isa<ESTree::SuperNode>(call->_callee)) ++direct;
      }
    }
    if (all.exhausted || all.calls != 1 || direct != 1) {
      context_.getSourceErrorManager().error(ctor->getSourceRange(),
          "[CLASS_FIELD_UNSUPPORTED] CONSTRUCTOR_SUPER_SHAPE");
      return false;
    }
    return true;
  }

  ESTree::FunctionDeclarationNode *createClassCtor(
      ESTree::Node *identifier,
      ESTree::ClassBodyNode *classBody,
      ESTree::Node *superClass,
      ESTree::MethodDefinitionNode *existingCtor) {
    ESTree::NodeList paramList;
    ESTree::NodeList ctorStatements;
    llvh::SmallVector<ESTree::Node *, 8> preParameterInitializers;
    const bool nativePrivateBase = _currentProcessingClass &&
        !_currentProcessingClass->privateTokens.empty();
    const bool nativeInstanceBase = !superClass && _currentProcessingClass &&
        _currentProcessingClass->nativeInstanceFields;

    if (existingCtor != nullptr) {
      auto *ctorExpression =
          llvh::dyn_cast<ESTree::FunctionExpressionNode>(existingCtor->_value);
                                                                        
                                                                           
                                                                              
                                                                          
      if (nativePrivateBase) {
        for (auto &parameter : ctorExpression->_params) {
          auto *defaultValue =
              llvh::dyn_cast<ESTree::AssignmentPatternNode>(&parameter);
          if (defaultValue &&
              llvh::isa<ESTree::IdentifierNode>(defaultValue->_left)) {
            defaultValue->_right = transformPrivateOperand(defaultValue->_right);
          } else {
                                                                                
                                                                               
            visitESTreeChildren(*this,&parameter);
          }
        }
      }
      if (superClass && !nativePrivateBase)
        for (auto &parameter:ctorExpression->_params) visitESTreeChildren(*this,&parameter);
      paramList = std::move(ctorExpression->_params);

      auto *block =
          llvh::dyn_cast<ESTree::BlockStatementNode>(ctorExpression->_body);
      NodeVector tmpStatements;
      for (auto &stmt : block->_body) {
        unpackStatements(&stmt, tmpStatements);
      }
      auto addedPropertyInitializers = superClass != nullptr;

      if (superClass == nullptr) {
                                                                      
        addedPropertyInitializers = true;
        appendPropertyInitializers(classBody, ctorStatements);
        if (nativeInstanceBase) {
          for (auto &generated : ctorStatements)
            preParameterInitializers.push_back(&generated);
        }
      }

      for (auto &stmt : tmpStatements) {
        auto oldSuperCallFound = _currentProcessingClass->superCallFound;
        const bool directSuperStatement = isDirectSuperStatement(stmt);
        visitESTreeChildren(*this, stmt);
        ctorStatements.push_back(*stmt);
                                                                             
                                                                             
        if (superClass && directSuperStatement)
          _currentProcessingClass->constructorThisInitialized = true;
        if (!addedPropertyInitializers && !oldSuperCallFound &&
            _currentProcessingClass->superCallFound) {
                                                
                                                    
          addedPropertyInitializers = true;
          appendPropertyInitializers(classBody, ctorStatements);
        }
      }
    } else {
                          
      if (superClass != nullptr) {
                                   
        auto *superCall=createTransformedNode<ESTree::NativeDerivedSuperOperationNode>(
            classBody,context_.getIdentifier("default_super").getUnderlyingPointer(),
            NodeVector{makeIdentifierNode(classBody,_currentProcessingClass->constructorIdentity),
                makeIdentifierNode(classBody,_currentProcessingClass->derivedInitializer),
                makeIdentifierNode(classBody,"arguments")}.toNodeList());
        ctorStatements.push_back(*toStatement(superCall));
      }

                                                                                  
      if (!superClass) appendPropertyInitializers(classBody, ctorStatements);
      if (nativeInstanceBase) {
        for (auto &generated : ctorStatements)
          preParameterInitializers.push_back(&generated);
      }
    }

    auto *body = createTransformedNode<ESTree::BlockStatementNode>(
        classBody, std::move(ctorStatements));

    auto *constructor=createTransformedNode<ESTree::FunctionDeclarationNode>(
        classBody,
        identifier,
        std::move(paramList),
        body,
        nullptr,
        nullptr,
        nullptr,
        false,
        false);
    if(superClass)
      constructor->loweredClassFunctionKind=ESTree::LoweredClassFunctionKind::DerivedConstructor;
    else if (_currentProcessingClass && (!_currentProcessingClass->privateTokens.empty() ||
                                         _currentProcessingClass->nativePublicFields))
      constructor->loweredClassFunctionKind=ESTree::LoweredClassFunctionKind::Constructor;
    if (!preParameterInitializers.empty()) {
                                                                             
                                                        
      auto **storage = static_cast<ESTree::Node **>(context_.allocateNode(
          sizeof(ESTree::Node *) * preParameterInitializers.size(),
          alignof(ESTree::Node *)));
      for (size_t i = 0; i < preParameterInitializers.size(); ++i)
        storage[i] = preParameterInitializers[i];
      constructor->loweredClassPreParameterInitializers =
          llvh::ArrayRef<ESTree::Node *>(storage, preParameterInitializers.size());
    }
    return constructor;
  }

  UniqueString *nativePrivateToken(ESTree::PrivateNameNode *name) {
    return nativePrivateTokenIdentifier(
        llvh::dyn_cast<ESTree::IdentifierNode>(name->_id),name);
  }

  UniqueString *nativePrivateTokenIdentifier(
      ESTree::IdentifierNode *id,ESTree::Node *source) {
    if (_currentProcessingClass && id) {
      auto it=_currentProcessingClass->privateTokens.find(id->_name);
      if (it!=_currentProcessingClass->privateTokens.end()) return it->second;
    }
    context_.getSourceErrorManager().error(source->getSourceRange(),
        "[NATIVE_PRIVATE_UNSUPPORTED] UNRESOLVED_PRIVATE_OWNER");
    return nullptr;
  }

  ESTree::Node *transformPrivateOperand(ESTree::Node *node) {
    auto *holder=createTransformedNode<ESTree::ExpressionStatementNode>(node,node,nullptr);
    visitESTreeChildren(*this,holder);
    auto *value=holder->_expression;holder->_expression=nullptr;
    return value;
  }

  ESTree::Node *makeNativePrivateOp(ESTree::Node *source,llvh::StringRef op,
                                   const NodeVector &arguments) {
    return createTransformedNode<ESTree::NativePrivateOperationNode>(source,
        context_.getIdentifier(op).getUnderlyingPointer(),arguments.toNodeList());
  }

  ESTree::Node *makeNativePrivateInitializer(ESTree::Node *source,ESTree::Node *value) {
    ESTree::NodeList statements;
    auto *strict=context_.getStringTable().getString("use strict");
    statements.push_back(*createTransformedNode<ESTree::ExpressionStatementNode>(
        source,createTransformedNode<ESTree::StringLiteralNode>(source,strict),strict));
    statements.push_back(*createTransformedNode<ESTree::ReturnStatementNode>(source,value));
    auto *body=createTransformedNode<ESTree::BlockStatementNode>(source,std::move(statements));
    ESTree::NodeList parameters;
    auto *initializer=createTransformedNode<ESTree::FunctionExpressionNode>(source,nullptr,
        std::move(parameters),body,nullptr,nullptr,nullptr,false,false);
    initializer->loweredClassFunctionKind=ESTree::LoweredClassFunctionKind::Method;
    return initializer;
  }

  ESTree::Node *makeNativePublicOp(ESTree::Node *source,llvh::StringRef op,
                                  const NodeVector &arguments) {
    return createTransformedNode<ESTree::NativePublicFieldOperationNode>(source,
        context_.getIdentifier(op).getUnderlyingPointer(),arguments.toNodeList());
  }

  ESTree::Node *nameNativePublicFieldFunction(
      ESTree::Node *source, ESTree::Node *key, ESTree::Node *value, bool cachedKey=false) {
    auto *fn=llvh::dyn_cast<ESTree::FunctionExpressionNode>(value);
    if (!(llvh::isa<ESTree::ArrowFunctionExpressionNode>(value) || (fn&&!fn->_id)))
      return value;
    if(cachedKey)
      return makeNativePublicOp(source,"named_function_dynamic",{cloneNode(key),value});
    ESTree::Node *literal=nullptr;
    if(auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(key))
      literal=createTransformedNode<ESTree::StringLiteralNode>(key,id->_name);
    else if(auto *str=llvh::dyn_cast<ESTree::StringLiteralNode>(key))
      literal=createTransformedNode<ESTree::StringLiteralNode>(key,str->_value);
    else if(auto *num=llvh::dyn_cast<ESTree::NumericLiteralNode>(key))
      literal=createTransformedNode<ESTree::NumericLiteralNode>(key,num->_value);
    if(!literal) {
      context_.getSourceErrorManager().error(source->getSourceRange(),
          "[NATIVE_PUBLIC_FIELD_INVALID_IR] FUNCTION_NAME_KEY");
      return value;
    }
                                                                              
                                                                               
                                                                               
    return makeNativePublicOp(source,"named_function",{literal,value});
  }

  ESTree::Node *makeNativePublicStaticInitializer(ESTree::Node *source,ESTree::Node *value) {
    ESTree::NodeList statements;
    auto *strict=context_.getStringTable().getString("use strict");
    statements.push_back(*createTransformedNode<ESTree::ExpressionStatementNode>(
        source,createTransformedNode<ESTree::StringLiteralNode>(source,strict),strict));
    statements.push_back(*createTransformedNode<ESTree::ReturnStatementNode>(source,value));
    auto *body=createTransformedNode<ESTree::BlockStatementNode>(source,std::move(statements));
    ESTree::NodeList parameters;
    auto *initializer=createTransformedNode<ESTree::FunctionExpressionNode>(source,nullptr,
        std::move(parameters),body,nullptr,nullptr,nullptr,false,false);
    initializer->loweredClassFunctionKind=ESTree::LoweredClassFunctionKind::Method;
    return initializer;
  }

  void appendNativePublicStaticFields(ESTree::ClassBodyNode *body,
                                     ESTree::Node *className,NodeVector &statements) {
    for(auto &entry:body->_body) {
      auto *field=llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry);
      if(field && field->_static)appendNativePublicStaticField(field,className,statements);
    }
  }

  void appendNativePublicStaticField(ESTree::ClassPropertyNode *field,
                                    ESTree::Node *className,NodeVector &statements) {
                                                                              
      auto *key=field->_key;field->_key=nullptr;
      if(!field->_computed) if(auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(key))
        key=createTransformedNode<ESTree::StringLiteralNode>(id,id->_name);
      auto *value=field->_value;field->_value=nullptr;
      if(value) value=transformPrivateOperand(value);                            
      else value=createTransformedNode<ESTree::UnaryExpressionNode>(field,
          context_.getStringTable().getString("void"),
          createTransformedNode<ESTree::NumericLiteralNode>(field,0.0),true);
      value=nameNativePublicFieldFunction(field,key,value,_currentProcessingClass->cachedPublicKeys&&field->_computed);
      auto *initializer=makeNativePublicStaticInitializer(field,value);
      auto *evaluated=makeNativePublicOp(field,"evaluate",{
          initializer,copyIdentifier(className)});
      statements.append(toStatement(makeNativePublicOp(field,"define",{
          copyIdentifier(className),key,evaluated})));
  }


  void appendPropertyInitializers(
      ESTree::ClassBodyNode *classBody,
      ESTree::NodeList &stmtList) {
    const bool previousPropertyInitializer = _visitingPropertyInitializer;
    _visitingPropertyInitializer = true;
    if(_currentProcessingClass) for(auto &member:_currentProcessingClass->privateKinds) {
      auto *name=member.first;
      stmtList.push_back(*toStatement(makeNativePrivateOp(classBody,"init_member",{
          createTransformedNode<ESTree::ThisExpressionNode>(classBody),
          makeIdentifierNode(classBody,_currentProcessingClass->privateTokens.at(name)),
          makeIdentifierNode(classBody,_currentProcessingClass->privateFunctions.at(name))})));
      if(member.second!=1)
        stmtList.push_back(*toStatement(makeNativePrivateOp(classBody,"init_member",{
            createTransformedNode<ESTree::ThisExpressionNode>(classBody),
            makeIdentifierNode(classBody,_currentProcessingClass->privateSetterTokens.at(name)),
            makeIdentifierNode(classBody,_currentProcessingClass->privateSetters.at(name))})));
    }
    for (auto &entry : classBody->_body) {
      if (auto *field=llvh::dyn_cast<ESTree::ClassPrivatePropertyNode>(&entry)) {
        auto *id=llvh::cast<ESTree::IdentifierNode>(field->_key);
        auto *token=nativePrivateTokenIdentifier(id,field);
        if (!token) continue;                                               
        auto initializer=_currentProcessingClass->privateInitializers.find(id->_name);
        ESTree::Node *value;
        if (initializer!=_currentProcessingClass->privateInitializers.end())
          value=makeNativePrivateOp(field,"evaluate",{
              makeIdentifierNode(field,initializer->second),
              createTransformedNode<ESTree::ThisExpressionNode>(field)});
        else
          value=createTransformedNode<ESTree::UnaryExpressionNode>(field,
              context_.getStringTable().getString("void"),
              createTransformedNode<ESTree::NumericLiteralNode>(field,0.0),true);
        stmtList.push_back(*toStatement(makeNativePrivateOp(field,"init",{
            createTransformedNode<ESTree::ThisExpressionNode>(field),
            makeIdentifierNode(id,token),value})));
        continue;
      }
      if (auto *classProperty =
              llvh::dyn_cast<ESTree::ClassPropertyNode>(&entry)) {
        if (_currentProcessingClass && _currentProcessingClass->nativeInstanceFields) {
                                                                            
                                                                        
          if (classProperty->_static) continue;
          auto initializer=_currentProcessingClass->publicInstanceInitializers.find(classProperty);
          ESTree::Node *value;
          if (initializer!=_currentProcessingClass->publicInstanceInitializers.end())
            value=makeNativePublicOp(classProperty,"evaluate",{
                makeIdentifierNode(classProperty,initializer->second),
                createTransformedNode<ESTree::ThisExpressionNode>(classProperty)});
          else value=createTransformedNode<ESTree::UnaryExpressionNode>(classProperty,
              context_.getStringTable().getString("void"),
              createTransformedNode<ESTree::NumericLiteralNode>(classProperty,0.0),true);
          auto *key=classProperty->_key; classProperty->_key=nullptr;
          if (!classProperty->_computed) if (auto *id=llvh::dyn_cast<ESTree::IdentifierNode>(key))
            key=createTransformedNode<ESTree::StringLiteralNode>(id,id->_name);
          stmtList.push_back(*toStatement(makeNativePublicOp(classProperty,"define_instance",{
              createTransformedNode<ESTree::ThisExpressionNode>(classProperty),key,value})));
          continue;
        }
                                                                       
        if (!classProperty->_static && classProperty->_computed &&
            (llvh::isa<ESTree::StringLiteralNode>(classProperty->_key) ||
             llvh::isa<ESTree::NumericLiteralNode>(classProperty->_key))) {
                                                                            
                                                                            
          auto *value = classProperty->_value;
          classProperty->_value = nullptr;
          if (value) {
            auto *holder = createTransformedNode<ESTree::ExpressionStatementNode>(
                value, value, nullptr);
            visitESTreeChildren(*this, holder);
            value = holder->_expression;
            holder->_expression = nullptr;
          } else {
            value = createTransformedNode<ESTree::UnaryExpressionNode>(
                classProperty, context_.getStringTable().getString("void"),
                createTransformedNode<ESTree::NumericLiteralNode>(classProperty, 0.0),
                true);
          }
          auto *key = classProperty->_key;
          classProperty->_key = nullptr;
          auto *definition = makeHermesES6InternalCall(
              classProperty, "defineClassField", {
                  createTransformedNode<ESTree::ThisExpressionNode>(classProperty),
                  key, value});
                                                                               
                                                                             
          stmtList.push_back(*toStatement(definition));
          continue;
        }
                                                                             
                                                                   
        if (!classProperty->_static && !classProperty->_computed &&
            llvh::isa<ESTree::IdentifierNode>(classProperty->_key)) {
          auto *value = classProperty->_value;
          if (value) {
            visitESTreeNode(*this, value);
          } else {
            value = createTransformedNode<ESTree::UnaryExpressionNode>(
                classProperty, context_.getStringTable().getString("void"),
                createTransformedNode<ESTree::NumericLiteralNode>(classProperty, 0.0), true);
          }
          auto *key = llvh::cast<ESTree::IdentifierNode>(classProperty->_key);
          auto *definedValue = makeHermesES6InternalCall(
              classProperty, "defineClassField", {
                  createTransformedNode<ESTree::ThisExpressionNode>(classProperty),
                  createTransformedNode<ESTree::StringLiteralNode>(key, key->_name), value});
                                                                                    
                                                                                  
                                                                                 
          stmtList.push_back(*createThisPropertyInitializer(
              classProperty, classProperty->_key, definedValue));
        } else if (classProperty->_value != nullptr) {
          visitESTreeNode(*this, classProperty->_value);
          stmtList.push_back(*createThisPropertyInitializer(
              classProperty, classProperty->_key, classProperty->_value));
        }
      }
    }
    _visitingPropertyInitializer = previousPropertyInitializer;
  }

  ResolvedClassMembers resolveClassMembers(ESTree::ClassBodyNode *classBody) {
    ResolvedClassMembers resolvedClassMembers;

    for (auto &entry : classBody->_body) {
      if (auto *methodDefinition =
              llvh::dyn_cast<ESTree::MethodDefinitionNode>(&entry)) {
        auto memberKind = getClassMemberKind(methodDefinition);

        if (memberKind == ClassMemberKind::Constructor) {
          resolvedClassMembers.constructor = methodDefinition;
          continue;
        }

        resolvedClassMembers.members.emplace_back(
            methodDefinition->_key,
            methodDefinition->_static,
            memberKind,
            methodDefinition);
      }
    }

    return resolvedClassMembers;
  }

  void visitMethodESTreeChildren(
      const ResolvedClassMember &classMember,
      ESTree::Node *node) {
    auto *previousClassMember = _currentClassMember;
    _currentClassMember = &classMember;
    visitESTreeChildren(*this, node);
    _currentClassMember = previousClassMember;
  }

  void appendMethods(
      ESTree::Node *className,
      const ResolvedClassMembers &classMembers,
      NodeVector &stmtList) {
    for (const auto &classMember : classMembers.members) {
      auto *srcNode = classMember.definitionNode;
      visitMethodESTreeChildren(classMember, srcNode);
      if (_currentProcessingClass && (!_currentProcessingClass->privateTokens.empty() ||
                                      _currentProcessingClass->nativePublicFields)) {
                                                                                
                                                                                 
        auto *method=llvh::cast<ESTree::FunctionExpressionNode>(srcNode->_value);
        method->loweredClassFunctionKind=ESTree::LoweredClassFunctionKind::Method;
      }

      if(auto *name=llvh::dyn_cast<ESTree::PrivateNameNode>(classMember.key)) {
        auto *id=llvh::cast<ESTree::IdentifierNode>(name->_id);
        const bool setter=classMember.kind==ClassMemberKind::PropertySetter;
        auto binding=setter?_currentProcessingClass->privateSetters.at(id->_name)
                           :_currentProcessingClass->privateFunctions.at(id->_name);
        auto prefix=setter?"set #":classMember.kind==ClassMemberKind::PropertyGetter?"get #":"#";
        auto *key=createTransformedNode<ESTree::StringLiteralNode>(name,
            context_.getStringTable().getString((llvh::Twine(prefix)+id->_name->str()).str()));
        auto *fn=makeNativePublicOp(srcNode,"named_function",{key,srcNode->_value});
        srcNode->_value=nullptr;
        auto *assignment=createTransformedNode<ESTree::AssignmentExpressionNode>(srcNode,
            context_.getIdentifier("=").getUnderlyingPointer(),makeIdentifierNode(srcNode,binding),fn);
        stmtList.append(toStatement(assignment));
        continue;
      }
      NodeVector parameters;
      parameters.append(copyIdentifier(className));

      if (!classMember.definitionNode->_computed &&
          llvh::isa<ESTree::IdentifierNode>(classMember.key)) {
                                                                       
                                                                        
                   
        auto *identifierNode =
            llvh::cast<ESTree::IdentifierNode>(classMember.key);
        parameters.append(
            createTransformedNode<ESTree::StringLiteralNode>(
                identifierNode, identifierNode->_name));

        auto *functionExpr =
            llvh::cast<ESTree::FunctionExpressionNode>(srcNode->_value);
                                                                            
                                                                   

        auto newIdentifierNode = cloneNode(identifierNode);
        newIdentifierNode->_name = context_.getStringTable().getString(
            ("#" + newIdentifierNode->_name->str() + "#").str());

        functionExpr->_id = newIdentifierNode;
        parameters.append(functionExpr);
      } else {
                                                                             
                                                                                  
        parameters.append(classMember.key);
        parameters.append(srcNode->_value);
      }

      llvh::StringRef hermesCallName;

      switch (classMember.kind) {
        case ClassMemberKind::Method:
          hermesCallName = classMember.isStatic ? "defineStaticClassMethod"
                                                : "defineClassMethod";
          break;
        case ClassMemberKind::PropertyGetter:
          hermesCallName = classMember.isStatic
              ? "defineStaticClassPropertyGetter"
              : "defineClassPropertyGetter";
          break;
        case ClassMemberKind::PropertySetter:
          hermesCallName = classMember.isStatic
              ? "defineStaticClassPropertySetter"
              : "defineClassPropertySetter";
          break;
        default:
          hermes_fatal("Invalid ES6 class member");
      }

      const bool nativePrivate = _currentProcessingClass &&
          !_currentProcessingClass->privateTokens.empty();
      const bool nativePublic = _currentProcessingClass &&
          _currentProcessingClass->nativePublicFields;
                                                                     
                                                                           
                                                                 
      if (nativePrivate && classMember.definitionNode->_computed) {
        context_.getSourceErrorManager().error(srcNode->getSourceRange(),
            "[NATIVE_CLASS_INVALID_IR] METHOD_PROFILE");
        continue;
      }
      const char *nativeOperation = classMember.kind == ClassMemberKind::PropertyGetter
          ? (classMember.isStatic ? "define_static_getter" : "define_instance_getter")
          : classMember.kind == ClassMemberKind::PropertySetter
          ? (classMember.isStatic ? "define_static_setter" : "define_instance_setter")
          : (classMember.isStatic ? "define_static_method" : "define_instance_method");
      auto *call = (nativePrivate || nativePublic)
          ? makeNativeClassDefinitionOp(srcNode, nativeOperation, parameters)
          : makeHermesES6InternalCall(srcNode, hermesCallName, parameters);

      stmtList.append(toStatement(call));
    }
  }

  ESTree::Node *createThisPropertyInitializer(
      ESTree::Node *srcNode,
      ESTree::Node *identifier,
      ESTree::Node *initialValue) {
    auto *this_ = createTransformedNode<ESTree::ThisExpressionNode>(srcNode);

    auto *getPropertyNode = createTransformedNode<ESTree::MemberExpressionNode>(
        srcNode, this_, identifier, false);
    auto *assignmentExpression =
        createTransformedNode<ESTree::AssignmentExpressionNode>(
            srcNode,
            context_.getStringTable().getString("="),
            getPropertyNode,
            initialValue);

    return toStatement(assignmentExpression);
  }

  UniqueString *getIdentifierForTokenKind(parser::TokenKind tokenKind) const {
    return context_.getStringTable()
        .getIdentifier(hermes::parser::tokenKindStr(tokenKind))
        .getUnderlyingPointer();
  }

  bool isSuperCtorCall(ESTree::Node *node) {
    auto *stmt = llvh::dyn_cast<ESTree::ExpressionStatementNode>(node);
    if (stmt == nullptr) {
      return false;
    }

    auto *call = llvh::dyn_cast<ESTree::CallExpressionNode>(stmt->_expression);
    if (call == nullptr) {
      return false;
    }
    auto *callee = ESTree::getCallee(call);
    return callee->getKind() == ESTree::NodeKind::Super;
  }
};

void transformES6Classes(Context &context, ESTree::Node *node) {
  ES6ClassesTransformations transformations(context);
  visitESTreeNode(transformations, node);
}

}                    
