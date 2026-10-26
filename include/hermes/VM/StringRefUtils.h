/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_UTF16REF_H
#define HERMES_VM_UTF16REF_H

#include "llvh/ADT/ArrayRef.h"

namespace llvh {
class raw_ostream;
}

namespace hermes {
namespace vm {

using UTF16Ref = llvh::ArrayRef<char16_t>;
using UTF8Ref = llvh::ArrayRef<uint8_t>;
using ASCIIRef = llvh::ArrayRef<char>;

                     
using utf16_traits = std::char_traits<char16_t>;
using ascii_traits = std::char_traits<char>;

                                                    
UTF16Ref createUTF16Ref(const char16_t *str);

                                                     
ASCIIRef createASCIIRef(const char *str);

llvh::raw_ostream &operator<<(llvh::raw_ostream &OS, ASCIIRef asciiRef);

llvh::raw_ostream &operator<<(llvh::raw_ostream &OS, UTF16Ref u16ref);

                                                    
template <typename T1, typename T2>
bool stringRefEquals(llvh::ArrayRef<T1> str1, llvh::ArrayRef<T2> str2) {
  if (str1.size() != str2.size()) {
    return false;
  }
  return std::equal(str1.begin(), str1.end(), str2.begin());
}

                                                                         
              
template <typename T1, typename T2>
int stringRefCompare(llvh::ArrayRef<T1> str1, llvh::ArrayRef<T2> str2) {
  if (str1.size() >= str2.size()) {
                                                                       
    auto pos = std::mismatch(str2.begin(), str2.end(), str1.begin());
                                                                 
    if (pos.first == str2.end()) {
                                                             
      if (pos.second == str1.end()) {
                                                            
        return 0;
      }
                                        
      return +1;
    }
                                                                    
    return *pos.second > *pos.first ? +1 : -1;
  }
                                                          
  auto pos = std::mismatch(str1.begin(), str1.end(), str2.begin());
  if (pos.first == str1.end()) {
                                                           
                                                    
    return -1;
  }
                                                                  
  return *pos.first > *pos.second ? +1 : -1;
}

}                
}                    

#endif                        
