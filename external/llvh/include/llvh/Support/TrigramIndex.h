//===-- TrigramIndex.h - a heuristic for SpecialCaseList --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//===----------------------------------------------------------------------===//
//
// TrigramIndex implements a heuristic for SpecialCaseList that allows to
// filter out ~99% incoming queries when all regular expressions in the
// SpecialCaseList are simple wildcards with '*' and '.'. If rules are more
// complicated, the check is defeated and it will always pass the queries to a
// full regex.
//
// The basic idea is that in order for a wildcard to match a query, the query
// needs to have all trigrams which occur in the wildcard. We create a trigram
// index (trigram -> list of rules with it) and then count trigrams in the query
// for each rule. If the count for one of the rules reaches the expected value,
// the check passes the query to a regex. If none of the rules got enough
// trigrams, the check tells that the query is definitely not matched by any
// of the rules, and no regex matching is needed.
// A similar idea was used in Google Code Search as described in the blog post:
// https://swtch.com/~rsc/regexp/regexp4.html
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TRIGRAMINDEX_H
#define LLVM_SUPPORT_TRIGRAMINDEX_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringMap.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace llvh {
class StringRef;

class TrigramIndex {
 public:
                                         
  void insert(std::string Regex);

                                                                        
                                                              
  bool isDefinitelyOut(StringRef Query) const;

                                                                  
                                                        
  bool isDefeated() { return Defeated; }
 private:
                                                                           
                                             
  bool Defeated = false;
                                                                           
                                                                           
                                        
  std::vector<unsigned> Counts;
                                                                           
                                                 
                                                                        
                                                                         
                                             
  std::unordered_map<unsigned, SmallVector<size_t, 4>> Index{256};
};

}                   

#endif                                
