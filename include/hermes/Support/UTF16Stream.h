/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_UTF16STREAM_H
#define HERMES_SUPPORT_UTF16STREAM_H

#include <cstdint>

#include "hermes/ADT/OwningArray.h"
#include "llvh/ADT/ArrayRef.h"

namespace hermes {

                                                                                
                                                                                
   
                                                                                
                                                            
class UTF16Stream {
 public:
                                                             
  explicit UTF16Stream(llvh::ArrayRef<char16_t> str)
      : cur_(str.begin()),
        end_(str.end()),
        utf8Begin_(nullptr),
        utf8End_(nullptr),
        beginCapture_(nullptr) {}

                                                                              
                                                                
  explicit UTF16Stream(llvh::ArrayRef<uint8_t> utf8);

                               
  UTF16Stream(UTF16Stream &&rhs) = default;
  UTF16Stream(UTF16Stream &rhs) = delete;
  UTF16Stream &operator=(UTF16Stream &rhs) = delete;

                                                         
                                                             
  bool hasChar() {
    return cur_ != end_ || refill();
  }

                                                            
                                
  char16_t operator*() const {
    assert(cur_ != end_ && "must check hasChar");
    return *cur_;
  }

                                                 
                                
  UTF16Stream &operator++() {
    assert(cur_ != end_ && "must check hasChar");
    ++cur_;
    return *this;
  }

                                                                                
                                                                              
  void beginCapture();

                                                                                
                                                                        
                                                                               
                                                       
  llvh::ArrayRef<char16_t> endCapture();

                                                                               
                                                                                
  void cancelCapture();

 private:
                                                                          
  bool refill();

                                                                            
                                                                               
                                            
  void makeRoomForCapture();

                                                                           
                                              
  const char16_t *cur_;
  const char16_t *end_;

                                                             
  const uint8_t *utf8Begin_;
  const uint8_t *utf8End_;

                                                                          
                                                                       
  const char16_t *beginCapture_;

                                            
  std::vector<char16_t> storage_;
};

}                    

#endif                                
