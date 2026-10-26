/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_SINKDEFINITIONS_H
#define HERMES_OPTIMIZER_TAINT_SINKDEFINITIONS_H

#include <string>
#include <unordered_map>
#include <vector>

namespace hermes {

                          
enum class SinkType {
  Network,                                               
  Storage,                                                
  XSS,                                            
  CodeInjection,                                                                  
  Navigation,                                
  Unknown
};

                                           
struct SinkDefinition {
  std::string name;                                                          
  SinkType type;                          
  int urlArgIndex;                                                        
  int dataArgIndex;                                                        
  bool isMethod;                                                    
  std::string objectName;                                                      
  std::string methodName;                                            

  SinkDefinition(
      std::string n,
      SinkType t,
      int urlIdx = -1,
      int dataIdx = -1,
      bool method = false,
      std::string objName = "",
      std::string methName = "")
      : name(n),
        type(t),
        urlArgIndex(urlIdx),
        dataArgIndex(dataIdx),
        isMethod(method),
        objectName(std::move(objName)),
        methodName(std::move(methName)) {}
};

                                   
class SinkRegistry {
 public:
                                
  static SinkRegistry &getInstance();

                                          
                                                             
                                                                  
                                                                         
  const SinkDefinition *isPropertySink(
      const std::string &objectName,
      const std::string &propertyName) const;

                                      
                                                                   
                                                         
                                                                         
  const SinkDefinition *isMethodSink(
      const std::string &objectName,
      const std::string &methodName) const;

                                          
                                                                      
                                                                         
  const SinkDefinition *isFunctionSink(
      const std::string &functionName) const;

                                      
  std::vector<const SinkDefinition *> getSinksByType(SinkType type) const;

                                          
  size_t getCount() const { return sinks_.size(); }

 private:
  SinkRegistry();
  ~SinkRegistry() = default;

                    
  SinkRegistry(const SinkRegistry &) = delete;
  SinkRegistry &operator=(const SinkRegistry &) = delete;

                                     
  void initializeSinks();

                           
  void addSink(SinkDefinition sink);

                                      
  std::vector<SinkDefinition> sinks_;

                                                         
  std::unordered_map<std::string, const SinkDefinition *> propertySinkMap_;

                                                       
  std::unordered_map<std::string, const SinkDefinition *> methodSinkMap_;

                                              
  std::unordered_map<std::string, const SinkDefinition *> functionSinkMap_;
};

}                    

#endif                                            
