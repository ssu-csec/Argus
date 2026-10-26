/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_JSONEMITTER_H
#define HERMES_SUPPORT_JSONEMITTER_H

#include <cstdint>
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/raw_ostream.h"

namespace hermes {

                                                                   
                      
                                                                             
                                                                            
                                                                          
                                                                            
                                                                           
                        
   
                                                                             
                                                                             
                                         
   
                  
                                    
                     
                                         
                                 
                               
                      
                                                  
                       
                      
   
class JSONEmitter {
 public:
                                                                         
                                                                                
         
                                                                             
                                                                         
                                                                           
                       
  JSONEmitter(llvh::raw_ostream &OS, bool pretty = false)
      : OS(OS), pretty_(pretty) {}

                                  
  void emitValue(bool val);

                                   
  void emitValue(short val);
  void emitValue(int val);
  void emitValue(long val);
  void emitValue(long long val);

                                            
  void emitValue(unsigned short val);
  void emitValue(unsigned int val);
  void emitValue(unsigned long val);
  void emitValue(unsigned long long val);

                                 
                                                                             
               
  void emitValue(double val);

                                                                         
                        
  void emitValue(llvh::StringRef val);
  void emitValue(const char *val) {
    emitValue(llvh::StringRef(val));
  }
                                                                           
                                                                           
  void emitValue(llvh::ArrayRef<char16_t> val);

                           
  void emitNullValue();

                                                                                
                                                       
  void emitKey(llvh::StringRef key);

                                                                             
                                                           
  template <typename T>
  void emitKeyValue(llvh::StringRef key, const T &val) {
    emitKey(key);
    emitValue(val);
  }

                                                                           
                        
  template <typename T>
  void emitValues(llvh::ArrayRef<T> vals) {
    for (const T &val : vals)
      emitValue(val);
  }

  template <typename T>
  void emitValues(std::initializer_list<T> vals) {
    for (const T &val : vals)
      emitValue(val);
  }

                                  
  void openDict();

                                              
  void closeDict();

                              
  void openArray();

                                         
  void closeArray();

                                    
  void endJSONL();

                                                  
                                       
  JSONEmitter(JSONEmitter &&);

 private:
  JSONEmitter(const JSONEmitter &) = delete;
  void operator=(const JSONEmitter &) = delete;
  void operator=(JSONEmitter &&) = delete;

                                                                        
                                                 
                                         
                                                                  
  void primitiveEmitString(llvh::StringRef str);

                                                              
  bool inDict() const {
    return !states_.empty() && states_.back().type == State::Dict;
  }

                                                          
  bool inArray() const {
    return !states_.empty() && states_.back().type == State::Array;
  }

                                                                               
                                                                         
  void willEmitValue();

                                                            
  void prettyNewLine();

                                                     
  void indentMore();

                                                     
  void indentLess();

                                                                            
                    
  struct State {
                                                    
    enum Type : uint8_t { Dict, Array } type;

                                                              
    bool needsComma;

                                                     
    bool needsKey;

                                                                        
    bool needsValue;

                                            
    bool isEmpty;

                                            
                   State(Type t)
        : type(t),
          needsComma(false),
          needsKey(type == Dict),
          needsValue(false),
          isEmpty(true) {}
  };

                          
  llvh::SmallVector<State, 8> states_;

                              
  llvh::raw_ostream &OS;

                                   
  bool pretty_{false};

                                        
  uint32_t indent_{0};
};

}                    

#endif                                
