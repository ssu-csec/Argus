/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_REGEX_REGEXSUPPORT_H
#define HERMES_REGEX_REGEXSUPPORT_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallVector.h"

namespace hermes {
namespace regex {
using GroupName = llvh::SmallVector<char16_t, 5>;
                                    
                                
                                                       
using ParsedGroupNamesMapping =
    llvh::DenseMap<llvh::ArrayRef<char16_t>, uint32_t>;
}                   
}                    

#endif                               
