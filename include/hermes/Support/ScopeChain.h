/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SCOPECHAIN_H
#define HERMES_SUPPORT_SCOPECHAIN_H

#include "llvh/ADT/StringRef.h"

#include <vector>

namespace hermes {
                                                               
struct ScopeChainItem {
                                         
  std::vector<llvh::StringRef> variables;
};
                                                                           
                     
struct ScopeChain {
                                                          
  std::vector<ScopeChainItem> scopes;
};

}                    

#endif                               
