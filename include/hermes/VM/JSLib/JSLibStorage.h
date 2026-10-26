/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSLIB_RUNTIMECOMMONSTORAGE_H
#define HERMES_VM_JSLIB_RUNTIMECOMMONSTORAGE_H

#include "hermes/VM/JSLib/DateCache.h"

#include <random>

namespace hermes {
namespace vm {

                                                                           
                                                                         
struct JSLibStorage {
  JSLibStorage();
  ~JSLibStorage();

                                                                        
  JSLibStorage(const JSLibStorage &) = delete;
  void operator=(const JSLibStorage &) = delete;

                                
  std::mt19937_64 randomEngine_;
  bool randomEngineSeeded_ = false;

                                                                           
  LocalTimeOffsetCache localTimeOffsetCache;
};

}                
}                    

#endif
