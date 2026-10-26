/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSNativeFunctions.h"

#include "hermes/VM/Callable.h"
#include "hermes/VM/JSDataView.h"
#include "hermes/VM/JSDate.h"
#include "hermes/VM/JSError.h"
#include "hermes/VM/JSMapImpl.h"
#include "hermes/VM/JSProxy.h"
#include "hermes/VM/JSRegExp.h"
#include "hermes/VM/JSTypedArray.h"
#include "hermes/VM/JSWeakMapImpl.h"
#include "hermes/VM/JSWeakRef.h"
#include "hermes/VM/PrimitiveBox.h"

#include <limits>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                                            
                   
                                                                  
template <size_t N>
constexpr uint8_t u8sizeof(const char (&str)[N]) {
  static_assert(N <= std::numeric_limits<uint8_t>::max(), "overflowed uint8_t");
  return N;
}

static llvh::DenseMap<const void *, const char *> funcNames() {
  static constexpr uint8_t nameLengths[] = {
#define NATIVE_FUNCTION(func) u8sizeof(#func),
#define NATIVE_CONSTRUCTOR(func) u8sizeof(#func),
#include "hermes/VM/NativeFunctions.def"
#undef NATIVE_FUNCTION
#undef NATIVE_CONSTRUCTOR
  };

  static constexpr char names[] = {
#define NATIVE_FUNCTION(func) #func "\0"
#define NATIVE_CONSTRUCTOR(func) #func "\0"
#include "hermes/VM/NativeFunctions.def"
#undef NATIVE_FUNCTION
#undef NATIVE_CONSTRUCTOR
  };

  static const void *const functionPointers[] = {
#define NATIVE_FUNCTION(func) (void *)func,

                                                                                
           
#define NATIVE_CONSTRUCTOR(func) \
  (void *)(NativeConstructor::CreatorFunction *)func,
#include "hermes/VM/NativeFunctions.def"
#undef NATIVE_FUNCTION
#undef NATIVE_CONSTRUCTOR
  };

  size_t numFuncs = sizeof functionPointers / sizeof *functionPointers;
  llvh::DenseMap<const void *, const char *> map(numFuncs);
  const char *curStr = names;
  for (size_t i = 0; i < numFuncs; ++i) {
    map[functionPointers[i]] = curStr;
    curStr += nameLengths[i];
  }

#ifndef _MSC_VER
                                                                              
                                                            
  assert(map.size() == numFuncs && "A function should only be mapped once");
#endif

  return map;
}

static const char *getFunctionNameImpl(void *func) {
  static auto map = funcNames();
  auto it = map.find(func);
  if (it == map.end()) {
                                                                        
                                             
    return "";
  }
  return it->second;
}

const char *getFunctionName(NativeFunctionPtr func) {
  return getFunctionNameImpl((void *)func);
}

const char *getFunctionName(NativeConstructor::CreatorFunction *func) {
  return getFunctionNameImpl((void *)func);
}

}                
}                    
