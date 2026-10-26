/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                                          
                                                                                

#ifndef HERMES_VM_SMALLXSTRING_H
#define HERMES_VM_SMALLXSTRING_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {
namespace vm {

template <typename T, unsigned N>
class SmallXString : public llvh::SmallVector<T, N> {
  using Super = llvh::SmallVector<T, N>;

 public:
                      
  SmallXString() {}
                              
  SmallXString(llvh::ArrayRef<T> ref) : Super(ref.begin(), ref.end()) {}
                                            
  SmallXString(const T *strz)
      : Super(strz, strz + std::char_traits<T>::length(strz)) {}
                               
  SmallXString(llvh::StringRef strRef)
      : Super(strRef.bytes_begin(), strRef.bytes_end()) {}
                                         
  template <typename It>
  SmallXString(It first, It end) : Super(first, end) {}

                         
  SmallXString &append(llvh::ArrayRef<T> ref) {
    Super::append(ref.begin(), ref.end());
    return *this;
  }

                                      
  SmallXString &append(const T *strz) {
    Super::append(strz, strz + std::char_traits<T>::length(strz));
    return *this;
  }

                         
  SmallXString &append(llvh::StringRef strRef) {
    Super::append(strRef.bytes_begin(), strRef.bytes_end());
    return *this;
  }

                                
  SmallXString &append(T ch) {
    Super::push_back(ch);
    return *this;
  }

                                      
  SmallXString &append(char ch) {
    Super::push_back((unsigned char)ch);
    return *this;
  }

  template <typename in_iter>
  SmallXString &append(in_iter start, in_iter end) {
    Super::append(start, end);
    return *this;
  }

  llvh::ArrayRef<T> arrayRef() const {
    return llvh::ArrayRef<T>(Super::begin(), Super::end());
  }
};

template <unsigned N>
using SmallU16String = SmallXString<char16_t, N>;

}                
}                    

#endif                            
