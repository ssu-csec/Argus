//===- LineIterator.h - Iterator to read a text buffer's lines --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_LINEITERATOR_H
#define LLVM_SUPPORT_LINEITERATOR_H

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/DataTypes.h"
#include <iterator>

namespace llvh {

class MemoryBuffer;

                                                            
   
                                                                            
                                                                           
                   
   
                                                                            
                                                                             
              
   
                                                                     
class line_iterator {
  const MemoryBuffer *Buffer;
  char CommentMarker;
  bool SkipBlanks;

  unsigned LineNumber;
  StringRef CurrentLine;

public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = StringRef;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

                                          
  line_iterator() : Buffer(nullptr) {}

                                                         
  explicit line_iterator(const MemoryBuffer &Buffer, bool SkipBlanks = true,
                         char CommentMarker = '\0');

                                                                
  bool is_at_eof() const { return !Buffer; }

                                                                 
  bool is_at_end() const { return is_at_eof(); }

                                                                   
  int64_t line_number() const { return LineNumber; }

                                                        
  line_iterator &operator++() {
    advance();
    return *this;
  }
  line_iterator operator++(int) {
    line_iterator tmp(*this);
    advance();
    return tmp;
  }

                                             
  StringRef operator*() const { return CurrentLine; }
  const StringRef *operator->() const { return &CurrentLine; }

  friend bool operator==(const line_iterator &LHS, const line_iterator &RHS) {
    return LHS.Buffer == RHS.Buffer &&
           LHS.CurrentLine.begin() == RHS.CurrentLine.begin();
  }

  friend bool operator!=(const line_iterator &LHS, const line_iterator &RHS) {
    return !(LHS == RHS);
  }

private:
                                            
  void advance();
};
}

#endif
