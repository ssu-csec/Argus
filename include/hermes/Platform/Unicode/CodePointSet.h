/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMUNICODE_CODEPOINTSET_H
#define HERMES_PLATFORMUNICODE_CODEPOINTSET_H

#include <algorithm>
#include <cassert>

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallVector.h"

namespace hermes {

                                                                       
struct CodePointRange {
                                     
  uint32_t first;

                              
  uint32_t length;

                                                     
  uint32_t end() const {
    assert(first + length >= first && "Range overflowed");
    return first + length;
  }

                                                        
  bool overlaps(const CodePointRange &rhs) {
    return this->first < rhs.end() && rhs.first < this->end();
  }

                                                                          
  bool abuts(const CodePointRange &rhs) {
    return this->first == rhs.end() || rhs.first == this->end();
  }
};

                                                                          
                                               

                                                                              
                         
                                                                        
                                                                          
          
                                                                            
                                                                          
                    
class CodePointSet {
 public:
                                             
  void add(CodePointRange r) {
    if (r.length == 0)
      return;

                                                                      
                                           
    auto cmp = [](CodePointRange lhs, CodePointRange rhs) {
      if (lhs.overlaps(rhs) || lhs.abuts(rhs))
        return false;
      return lhs.first < rhs.first;
    };
    auto pair = std::equal_range(ranges_.begin(), ranges_.end(), r, cmp);

    if (pair.first == pair.second) {
                                           
      ranges_.insert(pair.first, r);
    } else {
                                                                              
                                                                           
                
                                                                                
                                                                              
                                                         
      uint32_t start = std::min(r.first, pair.first->first);
      uint32_t end = std::max(r.end(), (pair.second - 1)->end());
      *pair.first = CodePointRange{start, end - start};
      ranges_.erase(pair.first + 1, pair.second);
    }
  }

                                          
  void add(uint32_t cp) {
    add(CodePointRange{cp, 1});
  }

                                       
  bool empty() const {
    return ranges_.empty();
  }

                                                
  uint32_t first() const {
    return ranges_.front().first;
  }

                                           
  uint32_t end() const {
    return ranges_.back().end();
  }

                                 
  llvh::ArrayRef<CodePointRange> ranges() const {
    return ranges_;
  }

                                                                      
  bool contains(uint32_t cp) const {
    auto cmp = [](CodePointRange left, uint32_t cp) {
      return left.first + left.length <= cp;
    };
    auto where = std::lower_bound(ranges_.begin(), ranges_.end(), cp, cmp);
    assert(
        (where == ranges_.end() || where->end() > cp) &&
        "Code point should be inside or before found range");
    return where != ranges_.end() && where->first <= cp;
  }

 private:
  llvh::SmallVector<CodePointRange, 4> ranges_;
};

}                    

#endif                                         
