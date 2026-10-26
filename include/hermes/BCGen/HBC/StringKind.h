/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_STRINGKIND_H
#define HERMES_SUPPORT_STRINGKIND_H

#include "llvh/ADT/ArrayRef.h"

#include <cassert>
#include <cstdint>
#include <vector>

namespace hermes {

                                                                              
                                                          
class StringKind {
                                                                        
                                    
  static constexpr uint32_t CountBits = 31;
  static constexpr uint32_t MaxCount = (1u << CountBits) - 1;

 public:
                                                                           
                                            
  StringKind() = delete;

  enum Kind : uint32_t {
                                      
    String = 0u << CountBits,

                              
    Identifier = 1u << CountBits,
  };

  struct Accumulator;

                                                                          
                                                                               
                                                 
  struct Entry {
    friend struct StringKind::Accumulator;

                                                                          
                                    
    Entry(Kind k, uint32_t count = 1);

                                        
    inline Kind kind() const;

                                                               
    inline uint32_t count() const;

   private:
                                                                
                              
    Entry &operator++();

    uint32_t datum_;
  };

                                                              
  struct Accumulator {
                                                    
    void push_back(Kind k);

                                 
    inline llvh::ArrayRef<Entry> entries() const &;

                                                                   
    inline std::vector<Entry> entries() &&;

   private:
    std::vector<Entry> entries_;
  };
};

inline StringKind::Kind StringKind::Entry::kind() const {
  return static_cast<Kind>(datum_ & ~MaxCount);
}

inline uint32_t StringKind::Entry::count() const {
  return datum_ & MaxCount;
}

inline llvh::ArrayRef<StringKind::Entry> StringKind::Accumulator::entries()
    const & {
  return entries_;
}

inline std::vector<StringKind::Entry> StringKind::Accumulator::entries() && {
  return std::move(entries_);
}

}                    

#endif                                    
