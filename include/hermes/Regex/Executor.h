/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_REGEX_EXECUTOR_H
#define HERMES_REGEX_EXECUTOR_H

#include "hermes/Regex/RegexBytecode.h"
#include "hermes/Regex/RegexTypes.h"
#include "hermes/Support/StackOverflowGuard.h"

                                                                                

namespace hermes {
namespace regex {

                                         
enum class MatchRuntimeResult {
                  
  Match,

                     
  NoMatch,

                                          
  StackOverflow,
};

                                                                             
                  
constexpr uint32_t kNotMatched = UINT32_MAX;

                                                  
constexpr uint32_t kBacktrackLimit = 1u << 30;

                                                                                
                                                                               
                                                                                
                                               
struct CapturedRange {
                                                                           
  uint32_t start;

                                                        
  uint32_t end;

                                                        
  bool matched() const {
    return start != kNotMatched;
  }
};

                                                                         
                                                                   
                                                                                
                                                                             
           
                                                                
                                                                
                                                                                
MatchRuntimeResult searchWithBytecode(
    llvh::ArrayRef<uint8_t> bytecode,
    const char16_t *first,
    uint32_t start,
    uint32_t length,
    std::vector<CapturedRange> *captures,
    constants::MatchFlagType matchFlags,
    StackOverflowGuard guard =
#ifdef HERMES_CHECK_NATIVE_STACK
        StackOverflowGuard::nativeStackGuard(
            512 * 1024)                                                  
                                           
#else
        StackOverflowGuard::depthCounterGuard(128)
#endif
);

                               
MatchRuntimeResult searchWithBytecode(
    llvh::ArrayRef<uint8_t> bytecode,
    const char *first,
    uint32_t start,
    uint32_t length,
    std::vector<CapturedRange> *captures,
    constants::MatchFlagType matchFlags,
    StackOverflowGuard guard =
#ifdef HERMES_CHECK_NATIVE_STACK
        StackOverflowGuard::nativeStackGuard(
            512 * 1024)                                                  
                                           
#else
        StackOverflowGuard::depthCounterGuard(128)
#endif
);

}                   
}                    

#endif
