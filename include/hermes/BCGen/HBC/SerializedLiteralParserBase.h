/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_SERIALIZEDLITERALPARSERBASE_H
#define HERMES_BCGEN_HBC_SERIALIZEDLITERALPARSERBASE_H

#include "hermes/Support/Conversions.h"
#include "llvh/ADT/ArrayRef.h"

namespace hermes {
namespace hbc {

                                                                             
                                            
class SerializedLiteralParserBase {
 protected:
  using CharArray = llvh::ArrayRef<unsigned char>;

                                                                           
  CharArray buffer_;

                                                
  unsigned int elemsLeft_;

                                    
  unsigned char lastTag_;

                                                                               
                           
  int leftInSeq_{0};

                                               
  int currIdx_{0};

                                                                         
                                                                       
                                                                         
                                           
                                                                    
                                                      
  void parseTagAndSeqLength();

 protected:
                                                                       
                                                          
                                                              
                                                                  
                        
                                                                       
                                                               
  explicit SerializedLiteralParserBase(CharArray buff, unsigned int totalLen)
      : buffer_(buff), elemsLeft_(totalLen) {}

 public:
  bool hasNext() const {
    return elemsLeft_ != 0;
  }
};

}                 
}                    

#endif                                                  
