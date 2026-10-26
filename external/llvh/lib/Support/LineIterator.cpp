//===- LineIterator.cpp - Implementation of line iteration ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/LineIterator.h"
#include "llvh/Support/MemoryBuffer.h"

using namespace llvh;

static bool isAtLineEnd(const char *P) {
  if (*P == '\n')
    return true;
  if (*P == '\r' && *(P + 1) == '\n')
    return true;
  return false;
}

static bool skipIfAtLineEnd(const char *&P) {
  if (*P == '\n') {
    ++P;
    return true;
  }
  if (*P == '\r' && *(P + 1) == '\n') {
    P += 2;
    return true;
  }
  return false;
}

line_iterator::line_iterator(const MemoryBuffer &Buffer, bool SkipBlanks,
                             char CommentMarker)
    : Buffer(Buffer.getBufferSize() ? &Buffer : nullptr),
      CommentMarker(CommentMarker), SkipBlanks(SkipBlanks), LineNumber(1),
      CurrentLine(Buffer.getBufferSize() ? Buffer.getBufferStart() : nullptr,
                  0) {
                                                                              
                              
  if (Buffer.getBufferSize()) {
    assert(Buffer.getBufferEnd()[0] == '\0');
                                                                        
    if (SkipBlanks || !isAtLineEnd(Buffer.getBufferStart()))
      advance();
  }
}

void line_iterator::advance() {
  assert(Buffer && "Cannot advance past the end!");

  const char *Pos = CurrentLine.end();
  assert(Pos == Buffer->getBufferStart() || isAtLineEnd(Pos) || *Pos == '\0');

  if (skipIfAtLineEnd(Pos))
    ++LineNumber;
  if (!SkipBlanks && isAtLineEnd(Pos)) {
                                      
  } else if (CommentMarker == '\0') {
                                                        
    while (skipIfAtLineEnd(Pos))
      ++LineNumber;
  } else {
                                                                         
    for (;;) {
      if (isAtLineEnd(Pos) && !SkipBlanks)
        break;
      if (*Pos == CommentMarker)
        do {
          ++Pos;
        } while (*Pos != '\0' && !isAtLineEnd(Pos));
      if (!skipIfAtLineEnd(Pos))
        break;
      ++LineNumber;
    }
  }

  if (*Pos == '\0') {
                                                                         
    Buffer = nullptr;
    CurrentLine = StringRef();
    return;
  }

                      
  size_t Length = 0;
  while (Pos[Length] != '\0' && !isAtLineEnd(&Pos[Length])) {
    ++Length;
  }

  CurrentLine = StringRef(Pos, Length);
}
