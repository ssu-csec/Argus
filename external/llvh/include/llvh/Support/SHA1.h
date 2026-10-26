//==- SHA1.h - SHA1 implementation for LLVM                     --*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// This code is taken from public domain
// (http://oauth.googlecode.com/svn/code/c/liboauth/src/sha1.c)
// and modified by wrapping it in a C++ interface for LLVM,
// and removing unnecessary code.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_SHA1_H
#define LLVM_SUPPORT_SHA1_H

#include "llvh/ADT/ArrayRef.h"

#include <array>
#include <cstdint>

namespace llvh {
template <typename T> class ArrayRef;
class StringRef;

                                         
class SHA1 {
public:
  SHA1() { init(); }

                                     
  void init();

                       
  void update(ArrayRef<uint8_t> Data);

                       
  void update(StringRef Str) {
    update(ArrayRef<uint8_t>((uint8_t *)const_cast<char *>(Str.data()),
                             Str.size()));
  }

                                                                               
                                                                            
                                                                        
                     
  StringRef final();

                                                                               
                                                                             
                                                                                
                       
  StringRef result();

                                                         
  static std::array<uint8_t, 20> hash(ArrayRef<uint8_t> Data);

private:
                            
                                                                           
  enum { BLOCK_LENGTH = 64 };
  enum { HASH_LENGTH = 20 };

                   
  struct {
    union {
      uint8_t C[BLOCK_LENGTH];
      uint32_t L[BLOCK_LENGTH / 4];
    } Buffer;
    uint32_t State[HASH_LENGTH / 4];
    uint32_t ByteCount;
    uint8_t BufferOffset;
  } InternalState;

                                                                           
  uint32_t HashResult[HASH_LENGTH / 4];

           
  void writebyte(uint8_t data);
  void hashBlock();
  void addUncounted(uint8_t data);
  void pad();
};

}                      

#endif
