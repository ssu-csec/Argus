/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_HASHSTRING_H
#define HERMES_SUPPORT_HASHSTRING_H

#include "hermes/Support/JenkinsHash.h"

#include "llvh/ADT/ArrayRef.h"

namespace hermes {

                                                                         
                                       
                                                                           
   
                                                                         
                                                               
                                                                           
                                                                           
                                                                       
                                                                         
   
                                                                        
template <typename T>
uint32_t hashString(llvh::ArrayRef<T> str) {
  static_assert(
      sizeof(JenkinsHash) == sizeof(uint32_t), "Jenkins Hash must be 32-bit");
  hermes::JenkinsHash hash = hermes::JenkinsHashInit;
  for (const T c : str) {
    hash = hermes::updateJenkinsHash(hash, c);
  }
  return hash;
}

namespace hash_details {
template <std::size_t Count>
constexpr uint32_t constexprHashStringHelper(const char *str) {
  return hermes::updateJenkinsHash(
      constexprHashStringHelper<Count - 1>(str), str[Count - 1]);
}

template <>
constexpr uint32_t constexprHashStringHelper<0>(const char *str) {
  return 0;
}
}                          

                                               
template <std::size_t Count>
constexpr uint32_t constexprHashString(const char (&str)[Count]) {
                                          
  return hash_details::constexprHashStringHelper<Count - 1>(str);
}

}                    

#endif
