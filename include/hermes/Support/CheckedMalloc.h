/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_CHECKEDMALLOC_H
#define HERMES_SUPPORT_CHECKEDMALLOC_H

#include "hermes/Support/ErrorHandling.h"

#include "llvh/Support/Compiler.h"

#include <cstdlib>

namespace hermes {

                                                         
LLVM_ATTRIBUTE_RETURNS_NONNULL LLVM_ATTRIBUTE_RETURNS_NOALIAS void *
checkedMalloc(size_t size);

                                                                            
                                                                               
                                       
LLVM_ATTRIBUTE_RETURNS_NONNULL LLVM_ATTRIBUTE_RETURNS_NOALIAS inline void *
checkedMalloc2(size_t count, size_t size) {
  size_t totalSize = count * size;
  if (LLVM_UNLIKELY(size > 0 && totalSize / size != count)) {
    hermes_fatal("malloc failure");
  }
  return checkedMalloc(totalSize);
}

                                                             
LLVM_ATTRIBUTE_RETURNS_NONNULL LLVM_ATTRIBUTE_RETURNS_NOALIAS void *
checkedCalloc(size_t count, size_t size);

}                    

#endif                                  
