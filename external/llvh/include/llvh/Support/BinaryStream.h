//===- BinaryStream.h - Base interface for a stream of data -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_BINARYSTREAM_H
#define LLVM_SUPPORT_BINARYSTREAM_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/BitmaskEnum.h"
#include "llvh/Support/BinaryStreamError.h"
#include "llvh/Support/Endian.h"
#include "llvh/Support/Error.h"
#include <cstdint>

namespace llvh {

enum BinaryStreamFlags {
  BSF_None = 0,
  BSF_Write = 1,                             
  BSF_Append = 2,                                          
  LLVM_MARK_AS_BITMASK_ENUM(                     BSF_Append)
};

                                                                      
                                                                         
                                                                             
                                                                              
                                                                               
                                                                            
              
class BinaryStream {
public:
  virtual ~BinaryStream() = default;

  virtual llvh::support::endianness getEndian() const = 0;

                                                                       
                                                                              
             
  virtual Error readBytes(uint32_t Offset, uint32_t Size,
                          ArrayRef<uint8_t> &Buffer) = 0;

                                                                       
                       
  virtual Error readLongestContiguousChunk(uint32_t Offset,
                                           ArrayRef<uint8_t> &Buffer) = 0;

                                                        
  virtual uint32_t getLength() = 0;

                                           
  virtual BinaryStreamFlags getFlags() const { return BSF_None; }

protected:
  Error checkOffsetForRead(uint32_t Offset, uint32_t DataSize) {
    if (Offset > getLength())
      return make_error<BinaryStreamError>(stream_error_code::invalid_offset);
    if (getLength() < DataSize + Offset)
      return make_error<BinaryStreamError>(stream_error_code::stream_too_short);
    return Error::success();
  }
};

                                                                      
                                                                             
                                                                             
                                                                              
                              
class WritableBinaryStream : public BinaryStream {
public:
  ~WritableBinaryStream() override = default;

                                                                     
                                                                             
                                                        
  virtual Error writeBytes(uint32_t Offset, ArrayRef<uint8_t> Data) = 0;

                                                                 
  virtual Error commit() = 0;

                                           
  BinaryStreamFlags getFlags() const override { return BSF_Write; }

protected:
  Error checkOffsetForWrite(uint32_t Offset, uint32_t DataSize) {
    if (!(getFlags() & BSF_Append))
      return checkOffsetForRead(Offset, DataSize);

    if (Offset > getLength())
      return make_error<BinaryStreamError>(stream_error_code::invalid_offset);
    return Error::success();
  }
};

}                      

#endif                               
