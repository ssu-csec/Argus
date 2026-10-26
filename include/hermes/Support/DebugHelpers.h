/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_DEBUGHELPERS_H
#define HERMES_SUPPORT_DEBUGHELPERS_H 1

#include "llvh/Support/Format.h"

namespace hermes {

                                                                     
                                                             
inline llvh::FormattedNumber format_ptr(const void *ptr) {
                                                                        
                                          
  return llvh::format_hex(
      reinterpret_cast<uintptr_t>(ptr), sizeof(uintptr_t) * 2 + 2);
}

}                    

#endif                                 
