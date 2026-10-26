//===- BinaryStreamReader.h - Reads objects from a binary stream *- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_BINARYSTREAMREADER_H
#define LLVM_SUPPORT_BINARYSTREAMREADER_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/Support/BinaryStreamArray.h"
#include "llvh/Support/BinaryStreamRef.h"
#include "llvh/Support/ConvertUTF.h"
#include "llvh/Support/Endian.h"
#include "llvh/Support/Error.h"
#include "llvh/Support/type_traits.h"

#include <string>
#include <type_traits>

namespace llvh {

                                                                        
                                                                             
                                                                            
                                                                         
                    
class BinaryStreamReader {
public:
  BinaryStreamReader() = default;
  explicit BinaryStreamReader(BinaryStreamRef Ref);
  explicit BinaryStreamReader(BinaryStream &Stream);
  explicit BinaryStreamReader(ArrayRef<uint8_t> Data,
                              llvh::support::endianness Endian);
  explicit BinaryStreamReader(StringRef Data, llvh::support::endianness Endian);

  BinaryStreamReader(const BinaryStreamReader &Other)
      : Stream(Other.Stream), Offset(Other.Offset) {}

  BinaryStreamReader &operator=(const BinaryStreamReader &Other) {
    Stream = Other.Stream;
    Offset = Other.Offset;
    return *this;
  }

  virtual ~BinaryStreamReader() {}

                                                                               
                                                                             
                                                                     
     
                                                                                
                                        
  Error readLongestContiguousChunk(ArrayRef<uint8_t> &Buffer);

                                                                             
                                                                           
                                                                          
                                                         
     
                                                                                
                                        
  Error readBytes(ArrayRef<uint8_t> &Buffer, uint32_t Size);

                                                                             
                                                                              
                                                                               
                
     
                                                                                
                                        
  template <typename T> Error readInteger(T &Dest) {
    static_assert(std::is_integral<T>::value,
                  "Cannot call readInteger with non-integral value!");

    ArrayRef<uint8_t> Bytes;
    if (auto EC = readBytes(Bytes, sizeof(T)))
      return EC;

    Dest = llvh::support::endian::read<T, llvh::support::unaligned>(
        Bytes.data(), Stream.getEndian());
    return Error::success();
  }

                             
  template <typename T> Error readEnum(T &Dest) {
    static_assert(std::is_enum<T>::value,
                  "Cannot call readEnum with non-enum value!");
    typename std::underlying_type<T>::type N;
    if (auto EC = readInteger(N))
      return EC;
    Dest = static_cast<T>(N);
    return Error::success();
  }

                                                                                
                                                                           
                                                
     
                                                                                
                                        
  Error readCString(StringRef &Dest);

                                                                         
              
     
                                                                                
                                        
  Error readWideString(ArrayRef<UTF16> &Dest);

                                                                               
                                                                           
                                                
     
                                                                                
                                        
  Error readFixedString(StringRef &Dest, uint32_t Length);

                                                                              
                                                                             
                                                                              
     
                                                                                
                                        
  Error readStreamRef(BinaryStreamRef &Ref);

                                                                           
                                                                        
                                                                              
                    
     
                                                                                
                                        
  Error readStreamRef(BinaryStreamRef &Ref, uint32_t Length);

                                                                              
                                                                        
                                                                              
                    
     
                                                                                
                                        
  Error readSubstream(BinarySubstreamRef &Stream, uint32_t Size);

                                                                               
                                                                           
                                                                         
                                                                                
                                                                     
             
     
                                                                                
                                        
  template <typename T> Error readObject(const T *&Dest) {
    ArrayRef<uint8_t> Buffer;
    if (auto EC = readBytes(Buffer, sizeof(T)))
      return EC;
    Dest = reinterpret_cast<const T *>(Buffer.data());
    return Error::success();
  }

                                                                            
                                                                               
                                                                            
                                                                               
                                                                               
                                                  
     
                                                                                
                                        
  template <typename T>
  Error readArray(ArrayRef<T> &Array, uint32_t NumElements) {
    ArrayRef<uint8_t> Bytes;
    if (NumElements == 0) {
      Array = ArrayRef<T>();
      return Error::success();
    }

    if (NumElements > UINT32_MAX / sizeof(T))
      return make_error<BinaryStreamError>(
          stream_error_code::invalid_array_size);

    if (auto EC = readBytes(Bytes, NumElements * sizeof(T)))
      return EC;

    assert(alignmentAdjustment(Bytes.data(), alignof(T)) == 0 &&
           "Reading at invalid alignment!");

    Array = ArrayRef<T>(reinterpret_cast<const T *>(Bytes.data()), NumElements);
    return Error::success();
  }

                                                                           
                                                                          
                                                                         
                                                                             
              
     
                                                                                
                                        
  template <typename T, typename U>
  Error readArray(VarStreamArray<T, U> &Array, uint32_t Size) {
    BinaryStreamRef S;
    if (auto EC = readStreamRef(S, Size))
      return EC;
    Array.setUnderlyingStream(S);
    return Error::success();
  }

                                                                               
                                                                          
                                                                         
                                                                               
              
     
                                                                                
                                        
  template <typename T>
  Error readArray(FixedStreamArray<T> &Array, uint32_t NumItems) {
    if (NumItems == 0) {
      Array = FixedStreamArray<T>();
      return Error::success();
    }

    if (NumItems > UINT32_MAX / sizeof(T))
      return make_error<BinaryStreamError>(
          stream_error_code::invalid_array_size);

    BinaryStreamRef View;
    if (auto EC = readStreamRef(View, NumItems * sizeof(T)))
      return EC;

    Array = FixedStreamArray<T>(View);
    return Error::success();
  }

  bool empty() const { return bytesRemaining() == 0; }
  void setOffset(uint32_t Off) { Offset = Off; }
  uint32_t getOffset() const { return Offset; }
  uint32_t getLength() const { return Stream.getLength(); }
  uint32_t bytesRemaining() const { return getLength() - getOffset(); }

                                                     
     
                                                                             
                                                          
  Error skip(uint32_t Amount);

                                                                          
                                                                         
     
                                           
  uint8_t peek() const;

  Error padToAlignment(uint32_t Align);

  std::pair<BinaryStreamReader, BinaryStreamReader>
  split(uint32_t Offset) const;

private:
  BinaryStreamRef Stream;
  uint32_t Offset = 0;
};
}                  

#endif                                     
