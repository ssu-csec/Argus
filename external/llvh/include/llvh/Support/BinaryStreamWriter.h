//===- BinaryStreamWriter.h - Writes objects to a BinaryStream ---*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_BINARYSTREAMWRITER_H
#define LLVM_SUPPORT_BINARYSTREAMWRITER_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/BinaryStreamArray.h"
#include "llvh/Support/BinaryStreamError.h"
#include "llvh/Support/BinaryStreamRef.h"
#include "llvh/Support/Endian.h"
#include "llvh/Support/Error.h"
#include <cstdint>
#include <type_traits>
#include <utility>

namespace llvh {

                                                                       
                                                                              
                                                                               
                                                                               
                                        
class BinaryStreamWriter {
public:
  BinaryStreamWriter() = default;
  explicit BinaryStreamWriter(WritableBinaryStreamRef Ref);
  explicit BinaryStreamWriter(WritableBinaryStream &Stream);
  explicit BinaryStreamWriter(MutableArrayRef<uint8_t> Data,
                              llvh::support::endianness Endian);

  BinaryStreamWriter(const BinaryStreamWriter &Other)
      : Stream(Other.Stream), Offset(Other.Offset) {}

  BinaryStreamWriter &operator=(const BinaryStreamWriter &Other) {
    Stream = Other.Stream;
    Offset = Other.Offset;
    return *this;
  }

  virtual ~BinaryStreamWriter() {}

                                                                      
                                                                         
                                     
     
                                                                         
                                                  
  Error writeBytes(ArrayRef<uint8_t> Buffer);

                                                                
                                                                   
                                                             
     
                                                                         
                                                  
  template <typename T> Error writeInteger(T Value) {
    static_assert(std::is_integral<T>::value,
                  "Cannot call writeInteger with non-integral value!");
    uint8_t Buffer[sizeof(T)];
    llvh::support::endian::write<T, llvh::support::unaligned>(
        Buffer, Value, Stream.getEndian());
    return writeBytes(Buffer);
  }

                             
  template <typename T> Error writeEnum(T Num) {
    static_assert(std::is_enum<T>::value,
                  "Cannot call writeEnum with non-Enum type");

    using U = typename std::underlying_type<T>::type;
    return writeInteger<U>(static_cast<U>(Num));
  }

                                                                         
                                                                           
                                                                               
               
     
                                                                         
                                                  
  Error writeCString(StringRef Str);

                                                                     
                                                                           
                                           
     
                                                                         
                                                  
  Error writeFixedString(StringRef Str);

                                                                           
                                                                              
                                            
     
                                                                         
                                                  
  Error writeStreamRef(BinaryStreamRef Ref);

                                                                                
                                                                              
                                            
     
                                                                         
                                                  
  Error writeStreamRef(BinaryStreamRef Ref, uint32_t Size);

                                                                               
                                                                               
                                                                         
     
                                                                         
                                                  
  template <typename T> Error writeObject(const T &Obj) {
    static_assert(!std::is_pointer<T>::value,
                  "writeObject should not be used with pointers, to write "
                  "the pointed-to value dereference the pointer before calling "
                  "writeObject");
    return writeBytes(
        ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(&Obj), sizeof(T)));
  }

                                                                             
                                                                             
                                                                            
                   
     
                                                                         
                                                  
  template <typename T> Error writeArray(ArrayRef<T> Array) {
    if (Array.empty())
      return Error::success();
    if (Array.size() > UINT32_MAX / sizeof(T))
      return make_error<BinaryStreamError>(
          stream_error_code::invalid_array_size);

    return writeBytes(
        ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(Array.data()),
                          Array.size() * sizeof(T)));
  }

                                                                       
     
                                                                         
                                                  
  template <typename T, typename U>
  Error writeArray(VarStreamArray<T, U> Array) {
    return writeStreamRef(Array.getUnderlyingStream());
  }

                                                                           
     
                                                                         
                                                  
  template <typename T> Error writeArray(FixedStreamArray<T> Array) {
    return writeStreamRef(Array.getUnderlyingStream());
  }

                                                           
  std::pair<BinaryStreamWriter, BinaryStreamWriter> split(uint32_t Off) const;

  void setOffset(uint32_t Off) { Offset = Off; }
  uint32_t getOffset() const { return Offset; }
  uint32_t getLength() const { return Stream.getLength(); }
  uint32_t bytesRemaining() const { return getLength() - getOffset(); }
  Error padToAlignment(uint32_t Align);

protected:
  WritableBinaryStreamRef Stream;
  uint32_t Offset = 0;
};

}                      

#endif                                     
