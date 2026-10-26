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
                 
enum class SourceType {
                                     
  PROPERTY_ACCESS,

                       
  METHOD_CALL,

                            
  CONSTRUCTION,

                           
  EVENT_DATA,

                          
  GLOBAL_FUNCTION
};

                         
enum class ReturnKind {
                                           
  PRIMITIVE,

                              
  OBJECT,

             
  ARRAY,

                        
  PROMISE,

                             
  FUNCTION
};

                    
struct SourceDefinition {
                                       
  std::string fullName;

              
  SourceType type;

                           
  std::string objectName;

                                        
  std::string propertyName;

           
  ReturnKind returnKind;

             
  bool isMethod;

           
  bool isAsync;

                                                        
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

                               
class SourceRegistry {
 private:
                 
  std::vector<SourceDefinition> sources_;

                             
  llvh::DenseMap<llvh::StringRef, std::vector<const SourceDefinition *>>
      propertyMap_;

                           
  llvh::DenseMap<llvh::StringRef, std::vector<const SourceDefinition *>>
      objectMap_;

              
  std::set<std::string> eventType_;

                        
  std::set<std::string> eventDataProps_;

  SourceRegistry();                       

  void initializeSources();
  void initializeEventTypes();
  void initializeEventData();
  void buildMaps();

 public:
  static SourceRegistry &getInstance();

                                      
  bool isSourceProperty(LoadPropertyInst *LPI) const;

                               
  bool isSourceCall(CallInst *CI) const;

                                    
  bool isSourceConstructor(ConstructInst *CI) const;

                                
  const std::vector<const SourceDefinition *> *getSourcesByProperty(
      llvh::StringRef propName) const;

                              
  const std::vector<const SourceDefinition *> *getSourcesByObject(
      llvh::StringRef objName) const;

                                    
  bool isEventType(llvh::StringRef eventName) const;

                                                
  bool isEventDataProperty(llvh::StringRef propName) const;

                              
  const SourceDefinition *getSourceByFullName(llvh::StringRef fullName) const;

                     
  const std::vector<SourceDefinition> &getAllSources() const {
    return sources_;
  }
};

}                   
}                    

#endif                                              