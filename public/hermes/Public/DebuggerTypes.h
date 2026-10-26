/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PUBLIC_DEBUGGERTYPES_H
#define HERMES_PUBLIC_DEBUGGERTYPES_H

#include <cstdint>
#include <string>
#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {
class Debugger;
}
}                    

namespace facebook {
namespace hermes {
namespace debugger {

class ProgramState;

                                                                                
                                                                          
                                                     
using String = std::string;

                                                                          
                                                                            
               
using BreakpointID = uint64_t;
                                                                                
constexpr uint64_t kInvalidBreakpoint = 0;

                                                      
                                                         
using ScriptID = uint32_t;

                                                                              
         
constexpr uint32_t kInvalidLocation = ~0u;
struct SourceLocation {
                                  
  uint32_t line = kInvalidLocation;

                                    
  uint32_t column = kInvalidLocation;

                                    
  ScriptID fileId = kInvalidLocation;

                              
  String fileName;
};

                                                                        
struct CallFrameInfo {
                                                   
  String functionName;

                                                            
  SourceLocation location;
};

                                                                                
                                
struct StackTrace {
                                        
  uint32_t callFrameCount() const {
    return frames_.size();
  }

                                                                        
                                        
  CallFrameInfo callFrameForIndex(uint32_t index) const {
    return frames_.at(index);
  }

  StackTrace() {}

 private:
  explicit StackTrace(std::vector<CallFrameInfo> frames)
      : frames_(std::move(frames)) {}
  friend ProgramState;
  friend ::hermes::vm::Debugger;
  std::vector<CallFrameInfo> frames_;
};

                                                             
struct ExceptionDetails {
                                           
  String text;

                                              
  SourceLocation location;

                                                        
  const StackTrace &getStackTrace() const {
    return stackTrace_;
  }

 private:
  friend ::hermes::vm::Debugger;
  StackTrace stackTrace_;
};

                                           
enum class PauseReason {
  ScriptLoaded,                                                             
                                              
  DebuggerStatement,                                   
  Breakpoint,                          
  StepFinish,                                
  Exception,                             
  AsyncTriggerImplicit,                               
                                                        
  AsyncTriggerExplicit,                               
                                                        
  EvalComplete,                                 
};

                                               
enum class StepMode {
  Into,                                   
  Over,                                  
  Out,                                           
};

                                                              
enum class PauseOnThrowMode {
  None,                               
  Uncaught,                                       
  All,                                           
};

                                                                             
                                                                
enum class AsyncPauseKind {
                                                                           
                                                                              
                         
  Implicit,

                                           
                                                                              
  Explicit,
};

                                                       
using ScopeDepth = uint32_t;

                                                                      
struct LexicalInfo {
                                   
  ScopeDepth getScopesCount() const {
    return variableCountsByScope_.size();
  }

                                                       
  uint32_t getVariablesCountInScope(ScopeDepth depth) const {
    return variableCountsByScope_.at(depth);
  }

 private:
  friend ::hermes::vm::Debugger;
  std::vector<uint32_t> variableCountsByScope_;
};

                                   
struct BreakpointInfo {
                           
                                                  
  BreakpointID id;

                                        
  bool enabled;

                                               
  bool resolved;

                                                          
  SourceLocation requestedLocation;

                                                                  
  SourceLocation resolvedLocation;
};

}                      
}                    
}                      

#endif
