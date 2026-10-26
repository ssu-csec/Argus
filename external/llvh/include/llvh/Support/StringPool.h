//===- StringPool.h - Interned string pool ----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares an interned string pool, which helps reduce the cost of
// strings by using the same storage for identical strings.
//
// To intern a string:
//
//   StringPool Pool;
//   PooledStringPtr Str = Pool.intern("wakka wakka");
//
// To use the value of an interned string, use operator bool and operator*:
//
//   if (Str)
//     cerr << "the string is" << *Str << "\n";
//
// Pooled strings are immutable, but you can change a PooledStringPtr to point
// to another instance. So that interned strings can eventually be freed,
// strings in the string pool are reference-counted (automatically).
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_STRINGPOOL_H
#define LLVM_SUPPORT_STRINGPOOL_H

#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include <cassert>

namespace llvh {

  class PooledStringPtr;

                                                                          
                                                                       
                
  class StringPool {
                                                                            
              
    struct PooledString {
      StringPool *Pool = nullptr;                                       
      unsigned Refcount = 0;                                                   

    public:
      PooledString() = default;
    };

    friend class PooledStringPtr;

    using table_t = StringMap<PooledString>;
    using entry_t = StringMapEntry<PooledString>;
    table_t InternTable;

  public:
    StringPool();
    ~StringPool();

                                                                          
                                                                              
                           
    PooledStringPtr intern(StringRef Str);

                                                                     
       
    inline bool empty() const { return InternTable.empty(); }
  };

                                                                             
                                                                                
                                                                               
                                                                         
             
  class PooledStringPtr {
    using entry_t = StringPool::entry_t;

    entry_t *S = nullptr;

  public:
    PooledStringPtr() = default;

    explicit PooledStringPtr(entry_t *E) : S(E) {
      if (S) ++S->getValue().Refcount;
    }

    PooledStringPtr(const PooledStringPtr &That) : S(That.S) {
      if (S) ++S->getValue().Refcount;
    }

    PooledStringPtr &operator=(const PooledStringPtr &That) {
      if (S != That.S) {
        clear();
        S = That.S;
        if (S) ++S->getValue().Refcount;
      }
      return *this;
    }

    void clear() {
      if (!S)
        return;
      if (--S->getValue().Refcount == 0) {
        S->getValue().Pool->InternTable.remove(S);
        S->Destroy();
      }
      S = nullptr;
    }

    ~PooledStringPtr() { clear(); }

    inline const char *begin() const {
      assert(*this && "Attempt to dereference empty PooledStringPtr!");
      return S->getKeyData();
    }

    inline const char *end() const {
      assert(*this && "Attempt to dereference empty PooledStringPtr!");
      return S->getKeyData() + S->getKeyLength();
    }

    inline unsigned size() const {
      assert(*this && "Attempt to dereference empty PooledStringPtr!");
      return S->getKeyLength();
    }

    inline const char *operator*() const { return begin(); }
    inline explicit operator bool() const { return S != nullptr; }

    inline bool operator==(const PooledStringPtr &That) const { return S == That.S; }
    inline bool operator!=(const PooledStringPtr &That) const { return S != That.S; }
  };

}                      

#endif                             
