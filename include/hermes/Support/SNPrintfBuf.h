/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SNPRINTFBUF_H
#define HERMES_SUPPORT_SNPRINTFBUF_H

#include "hermes/Support/Compiler.h"

#include <cassert>
#include <memory>

namespace hermes {

                                                                            
                                                                      
                                                                    
                                                        
class SNPrintfBuf {
 public:
                                                                  
                                                                  
                                
  SNPrintfBuf(int initSize = kInitSize);

                                                                    
                                                      
                                            
  void printf(const char *fmt, ...) HERMES_ATTRIBUTE_FORMAT(printf, 2, 3);

                                                                           
                                         
  const char *c_str() const {
    return buf_.get();
  }

 private:
  static const unsigned kInitSize = 100;

                                                                      
                                                              
                                                                              
  void realloc(int minSize);

  int curSize_;
  std::unique_ptr<char[]> buf_;
  char *bufPtr_;
  int remaining_;
};

}                    

#endif
