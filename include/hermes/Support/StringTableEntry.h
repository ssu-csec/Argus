/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_STRINGTABLEENTRY_H
#define HERMES_SUPPORT_STRINGTABLEENTRY_H

#include "llvh/ADT/ArrayRef.h"

#include <cstdint>

namespace hermes {

                                                                     
class StringTableEntry {
  static constexpr uint32_t UTF16_MASK = static_cast<uint32_t>(1) << 31;

                                                      
  uint32_t offset_;

                                                                             
                                  
  uint32_t length_;

 public:
  using StringTableRefTy = llvh::ArrayRef<StringTableEntry>;
  using MutStringTableRefTy = llvh::MutableArrayRef<StringTableEntry>;
  using StringStorageRefTy = llvh::ArrayRef<unsigned char>;

  StringTableEntry(uint32_t offset, uint32_t length, bool isUTF16)
      : offset_(offset), length_(length) {
    if (isUTF16) {
      length_ |= UTF16_MASK;
    }
  }
                                                           
  StringTableEntry() = default;

                                                               
  uint32_t getOffset() const {
    return offset_;
  }

                                                
  uint32_t getLength() const {
    return length_ & (~UTF16_MASK);
  }

                                          
  bool isUTF16() const {
    return length_ & UTF16_MASK;
  }
};

}                    

#endif                                     
