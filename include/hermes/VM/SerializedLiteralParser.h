/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SERIALIZEDLITERALPARSER_H
#define HERMES_VM_SERIALIZEDLITERALPARSER_H

#include "hermes/BCGen/HBC/SerializedLiteralParserBase.h"
#include "hermes/Support/Conversions.h"
#include "hermes/VM/HermesValue.h"
#include "llvh/ADT/ArrayRef.h"

namespace hermes {
namespace vm {

class Runtime;
class RuntimeModule;

                                                                 
                                                                        
                                                         
class SerializedLiteralParser : public hbc::SerializedLiteralParserBase {
                                                      
                                                            
                                                                     
                                                          
  RuntimeModule *runtimeModule_;

 public:
                                                                       
                                                          
                                                              
                                                                  
                        
                                                                       
                                                               
  explicit SerializedLiteralParser(
      CharArray buff,
      unsigned int totalLen,
      RuntimeModule *runtimeModule)
      : SerializedLiteralParserBase(buff, totalLen),
        runtimeModule_(runtimeModule) {}

                                                                         
  HermesValue get(Runtime &);
};

}                
}                    

#endif                                       
