/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_SERIALIZEDLITERALGENERATOR_H
#define HERMES_BCGEN_HBC_SERIALIZEDLITERALGENERATOR_H

#include "llvh/ADT/ArrayRef.h"

#include <cstdint>

namespace hermes {
class Literal;

namespace hbc {

class BytecodeModuleGenerator;

                                                                 
                                                                             
           
   
                                                                                
                                                                              
                                  
   
                                                                                
                      
              
           
              
   
                                                           
                             
   
                                                                               
                      
                         
             
                         
   
                                                           
                             
   
                                                       
                                                                         
                                                                  
                                                                               
                                                                             
                                                                  
class SerializedLiteralGenerator {
 private:
                                    
  BytecodeModuleGenerator &BMGen_;

 public:
  SerializedLiteralGenerator(BytecodeModuleGenerator &BMGen) : BMGen_(BMGen) {}

  using TagType = unsigned char;

                                                                           
                                                                        
  static constexpr TagType NullTag = 0;
  static constexpr TagType TrueTag = 1 << 4;
  static constexpr TagType FalseTag = 2 << 4;
  static constexpr TagType NumberTag = 3 << 4;
  static constexpr TagType LongStringTag = 4 << 4;
  static constexpr TagType ShortStringTag = 5 << 4;
  static constexpr TagType ByteStringTag = 6 << 4;
  static constexpr TagType IntegerTag = 7 << 4;
  static constexpr TagType TagMask = 0x70;

  static constexpr unsigned SequenceMax = (1 << 12) - 1;

                                                          
                                                                             
          
  void serializeBuffer(
      llvh::ArrayRef<Literal *> literals,
      std::vector<unsigned char> &buff,
      bool isKeyBuffer);
};

}                 
}                    

#endif                                                 
