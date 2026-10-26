/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_DEPENDENCYEXTRACTOR_H
#define HERMES_AST_DEPENDENCYEXTRACTOR_H

#include "hermes/AST/Context.h"
#include "hermes/AST/ESTree.h"

namespace hermes {

                                                                             
                                          
enum class DependencyKind {
                              
  ESM,
                                   
  Type,
                       
  Require,
                      
  Async,
                          
  Resource,
                                    
  PrefetchedResource,
                                         
  GraphQL,
};

inline const char *dependencyKindStr(DependencyKind kind) {
  switch (kind) {
    case DependencyKind::ESM:
      return "ESM";
    case DependencyKind::Type:
      return "Type";
    case DependencyKind::Require:
      return "Require";
    case DependencyKind::Async:
      return "Async";
    case DependencyKind::Resource:
      return "Resource";
    case DependencyKind::PrefetchedResource:
      return "PrefetchedResource";
    case DependencyKind::GraphQL:
      return "GraphQL";
  }
  llvm_unreachable("No other kind of dependency");
}

                                                      
struct Dependency {
                                             
                                                                                
             
  std::string name;

                                 
  DependencyKind kind;
};

                                                         
                                                                              
                       
std::vector<Dependency> extractDependencies(
    Context &astContext,
    ESTree::Node *node);

}                    

#endif
