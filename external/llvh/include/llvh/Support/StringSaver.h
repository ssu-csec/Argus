//===- llvm/Support/StringSaver.h -------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_STRINGSAVER_H
#define LLVM_SUPPORT_STRINGSAVER_H

#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/Allocator.h"

namespace llvh {

                                                              
                                              
class StringSaver final {
  BumpPtrAllocator &Alloc;

public:
  StringSaver(BumpPtrAllocator &Alloc) : Alloc(Alloc) {}

                                                                   
  StringRef save(const char *S) { return save(StringRef(S)); }
  StringRef save(StringRef S);
  StringRef save(const Twine &S) { return save(StringRef(S.str())); }
  StringRef save(const std::string &S) { return save(StringRef(S)); }
};

                                                                               
                                                                               
   
                                                                                
                   
   
                                                                             
                         
class UniqueStringSaver final {
  StringSaver Strings;
  llvh::DenseSet<llvh::StringRef> Unique;

public:
  UniqueStringSaver(BumpPtrAllocator &Alloc) : Strings(Alloc) {}

                                                                   
  StringRef save(const char *S) { return save(StringRef(S)); }
  StringRef save(StringRef S);
  StringRef save(const Twine &S) { return save(StringRef(S.str())); }
  StringRef save(const std::string &S) { return save(StringRef(S)); }
};

}
#endif
