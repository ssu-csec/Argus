/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_INTERNALIDENTIFIERMAKER_H
#define HERMES_SUPPORT_INTERNALIDENTIFIERMAKER_H

#include "hermes/Support/StringTable.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {
                                                                               
                                                       
class InternalIdentifierMaker {
  InternalIdentifierMaker(const InternalIdentifierMaker &) = delete;
  void operator=(const InternalIdentifierMaker &) = delete;

 public:
  explicit InternalIdentifierMaker(StringTable &stringTable)
      : stringTable_(stringTable) {}

                                                                         
                                         
  Identifier next(llvh::StringRef hint);

 private:
  StringTable &stringTable_;
  size_t counter_{};
};

}                    

#endif                                            
