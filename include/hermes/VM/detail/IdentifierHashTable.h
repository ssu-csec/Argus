/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_IDENTIFIERHASHTABLE_H
#define HERMES_VM_IDENTIFIERHASHTABLE_H

#include "hermes/ADT/CompactArray.h"
#include "hermes/ADT/PtrOrInt.h"
#include "hermes/Support/HashString.h"
#include "hermes/VM/StringRefUtils.h"
#include "hermes/VM/SymbolID.h"

#include "llvh/Support/MathExtras.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {
class IdentifierTable;

class StringPrimitive;

namespace detail {

                                                                           
                                                                       
                                                                
class IdentifierHashTable {
                                         
  static constexpr uint32_t INITIAL_CAPACITY = 1024;

                             
  CompactTable table_;

                                                                           
                                                         
  IdentifierTable *identifierTable_{};

                                                
  uint32_t size_{0};

                                                                          
                                                                         
                                                                         
                                                                     
                                              
  uint32_t nonEmptyEntryCount_{0};

                                                   
  bool shouldGrow() const {
    auto cap = capacity();
    assert(llvh::isPowerOf2_32(cap) && "capacity must be power of 2");
                                             
    return cap - (cap >> 2) < nonEmptyEntryCount_;
  }

                                                         
  void growAndRehash(uint32_t newCapacity);

                                                                      
                                                                  
                                                                       
  template <typename T>
  class HashIteratorWrapper {
    const T *ptr_;

   public:
    explicit HashIteratorWrapper(const T *ptr) : ptr_(ptr) {}

    char16_t operator*() const {
      return *ptr_;
    }

    bool operator==(const HashIteratorWrapper &other) const {
      return ptr_ == other.ptr_;
    }

    bool operator!=(const HashIteratorWrapper &other) const {
      return ptr_ != other.ptr_;
    }

    HashIteratorWrapper &operator++() {
      ++ptr_;
      return *this;
    }
  };

 public:
  explicit IdentifierHashTable(uint32_t capacity = INITIAL_CAPACITY)
      : table_(capacity) {}

                                       
  void setIdentifierTable(IdentifierTable *table) {
    identifierTable_ = table;
  }

                                                                        
  uint32_t size() const {
    return size_;
  }

                                             
  uint32_t capacity() const {
    return table_.size();
  }

                                                                       
                          
  size_t additionalMemorySize() const {
    return table_.additionalMemorySize();
  }

                                                                            
                                                                           
                                
  void reserve(uint32_t count) {
    auto cap = capacity();
    assert(llvh::isPowerOf2_32(cap) && "capacity must be power of 2");
    if ((cap >> 1) < count) {
                                                                  
                                         
      uint32_t newCapacity = llvh::NextPowerOf2(count * 2);
      growAndRehash(newCapacity);
    }
  }

                                                    
                                                          
                                                                          
                                                                         
                                                                           
  template <typename T>
  uint32_t lookupString(llvh::ArrayRef<T> str, bool mustBeNew = false) const {
    return lookupString(str, hermes::hashString(str), mustBeNew);
  }

                                                    
                                              
                                                                          
                                                                         
                                                                           
  template <typename T>
  uint32_t lookupString(
      llvh::ArrayRef<T> str,
      uint32_t hash,
      bool mustBeNew = false) const;

                                                                 
                                 
  uint32_t lookupString(const StringPrimitive *str, bool mustBeNew = false)
      const;

                                                                 
                                                      
  uint32_t lookupString(
      const StringPrimitive *str,
      uint32_t hash,
      bool mustBeNew = false) const;

                                                    
  bool isValid(uint32_t index) const {
    return table_.isValid(index);
  }

                                       
  uint32_t get(uint32_t index) const {
    return table_.get(index);
  }

                                                                 
                                                                       
  void insert(uint32_t idx, SymbolID id);

                                                     
  void remove(uint32_t idx) {
    table_.markAsDeleted(idx);
    size_--;
  }

                                               
                                                  
  template <typename T>
  void remove(llvh::ArrayRef<T> ref) {
    remove(lookupString(ref));
  }

                                                                           
                                                                    
                                                                 
  void remove(const StringPrimitive *str);
};

}                    
}                
}                    
#pragma GCC diagnostic pop

#endif                                   
