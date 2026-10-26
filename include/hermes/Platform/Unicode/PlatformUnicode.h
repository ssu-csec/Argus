/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMUNICODE_PLATFORMUNICODE_H
#define HERMES_PLATFORMUNICODE_PLATFORMUNICODE_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallVector.h"

                                                  
#define HERMES_PLATFORM_UNICODE_JAVA 1
#define HERMES_PLATFORM_UNICODE_CF 2
#define HERMES_PLATFORM_UNICODE_ICU 3
#define HERMES_PLATFORM_UNICODE_EMSCRIPTEN 4
#define HERMES_PLATFORM_UNICODE_LITE 5

#ifndef HERMES_PLATFORM_UNICODE
#if defined(__ANDROID__) && defined(HERMES_FACEBOOK_BUILD)
#define HERMES_PLATFORM_UNICODE HERMES_PLATFORM_UNICODE_JAVA
#elif defined(__APPLE__)
#define HERMES_PLATFORM_UNICODE HERMES_PLATFORM_UNICODE_CF
#elif defined(__EMSCRIPTEN__)
#define HERMES_PLATFORM_UNICODE HERMES_PLATFORM_UNICODE_EMSCRIPTEN
#else
#define HERMES_PLATFORM_UNICODE HERMES_PLATFORM_UNICODE_ICU
#endif
#endif

namespace hermes {
namespace platform_unicode {

                                                                              
                                                                              
                                             
int localeCompare(
    llvh::ArrayRef<char16_t> left,
    llvh::ArrayRef<char16_t> right);

                                                                              
                                                                               
                                                               
void dateFormat(
    double unixtimeMs,
    bool formatDate,
    bool formatTime,
    llvh::SmallVectorImpl<char16_t> &buf);

                                                               
enum class CaseConversion { ToUpper, ToLower };

                                                                               
                                                                              
                                        
void convertToCase(
    llvh::SmallVectorImpl<char16_t> &cs,
    CaseConversion targetCase,
    bool useCurrentLocale);

                                            
                                                                         
                                        
enum class NormalizationForm { C, D, KC, KD };

                                                                               
                                                                  
                                        
void normalize(llvh::SmallVectorImpl<char16_t> &buf, NormalizationForm form);

}                              
}                    

#endif                                            
