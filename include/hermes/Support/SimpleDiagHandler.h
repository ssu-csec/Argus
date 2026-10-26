/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SIMPLEDIAGHANDLER_H
#define HERMES_SUPPORT_SIMPLEDIAGHANDLER_H

#include "hermes/Support/SourceErrorManager.h"

namespace hermes {

                                                                           
                                   
class SimpleDiagHandler {
 public:
                                                                 
  void installInto(SourceErrorManager &sm);

                                                        
  bool haveErrors() const {
    return !firstMessage_.getMessage().empty();
  }

                                               
  const llvh::SMDiagnostic &getFirstMessage() const {
    assert(haveErrors() && "getFirstMessage() called without errors");
    return firstMessage_;
  }

                                                              
  std::string getErrorString() const;

 private:
                                                           
  llvh::SMDiagnostic firstMessage_;

                                  
  static void handler(const llvh::SMDiagnostic &msg, void *ctx);
};

                                                                          
                                                            
class SimpleDiagHandlerRAII : public SimpleDiagHandler {
 public:
  SimpleDiagHandlerRAII(SourceErrorManager &sourceErrorManager);
  ~SimpleDiagHandlerRAII();

 private:
                                                             
  SourceErrorManager &sourceErrorManager_;

                                                          
  void (*const oldHandler_)(const llvh::SMDiagnostic &, void *);
                                                         
  void *const oldContext_;
                               
  unsigned const oldErrorLimit_;
};

}                    

#endif                                      
