/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PARSER_PREPARSER_H
#define HERMES_PARSER_PREPARSER_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/SMLoc.h"

namespace hermes {

namespace parser {
using llvh::SMLoc;

                                               
struct SMLocInfo : llvh::DenseMapInfo<SMLoc> {
  static inline SMLoc getEmptyKey() {
    return SMLoc::getFromPointer(nullptr);
  }
  static inline SMLoc getTombstoneKey() {
    return SMLoc::getFromPointer((const char *)1);
  }
  static inline bool isEqual(const SMLoc &a, const SMLoc &b) {
    return a == b;
  }
  static unsigned getHashValue(const SMLoc &Val) {
    return (unsigned)(uintptr_t)Val.getPointer();
  }
};

                                                                            
                     
struct PreParsedFunctionInfo {
                                       
  SMLoc end;

                                            
  bool strictMode;

                         
                                                                 
                                                         
  llvh::SmallVector<llvh::SmallString<24>, 1> directives{};
};

                                           
struct PreParsedBufferInfo {
                                                    
  llvh::DenseMap<SMLoc, PreParsedFunctionInfo, SMLocInfo> functionInfo{};
};

                                               
struct PreParsedData {
                                                                           
  llvh::SmallVector<std::unique_ptr<PreParsedBufferInfo>, 4> bufferInfo{};

                                                                          
                
  PreParsedBufferInfo *getBufferInfo(uint32_t bufferId) {
    if (bufferInfo.size() < bufferId + 1) {
      bufferInfo.resize(bufferId + 1);
    }
    if (!bufferInfo[bufferId]) {
      bufferInfo[bufferId] = std::make_unique<PreParsedBufferInfo>();
    }
    return bufferInfo[bufferId].get();
  }
};

}                    
}                    
#endif
