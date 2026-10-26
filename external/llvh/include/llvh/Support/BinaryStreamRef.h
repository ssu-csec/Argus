//===- BinaryStreamRef.h - A copyable reference to a stream -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_BINARYSTREAMREF_H
#define LLVM_SUPPORT_BINARYSTREAMREF_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/Optional.h"
#include "llvh/Support/BinaryStream.h"
#include "llvh/Support/BinaryStreamError.h"
#include "llvh/Support/Error.h"
#include <algorithm>
#include <cstdint>
#include <memory>

namespace llvh {

                                                      
template <class RefType, class StreamType> class BinaryStreamRefBase {
protected:
  BinaryStreamRefBase() = default;
  explicit BinaryStreamRefBase(StreamType &BorrowedImpl)
      : BorrowedImpl(&BorrowedImpl), ViewOffset(0) {
    if (!(BorrowedImpl.getFlags() & BSF_Append))
      Length = BorrowedImpl.getLength();
  }

  BinaryStreamRefBase(std::shared_ptr<StreamType> SharedImpl, uint32_t Offset,
                      Optional<uint32_t> Length)
      : SharedImpl(SharedImpl), BorrowedImpl(SharedImpl.get()),
        ViewOffset(Offset), Length(Length) {}
  BinaryStreamRefBase(StreamType &BorrowedImpl, uint32_t Offset,
                      Optional<uint32_t> Length)
      : BorrowedImpl(&BorrowedImpl), ViewOffset(Offset), Length(Length) {}
  BinaryStreamRefBase(const BinaryStreamRefBase &Other) = default;
  BinaryStreamRefBase &operator=(const BinaryStreamRefBase &Other) = default;

  BinaryStreamRefBase &operator=(BinaryStreamRefBase &&Other) = default;
  BinaryStreamRefBase(BinaryStreamRefBase &&Other) = default;

public:
  llvh::support::endianness getEndian() const {
    return BorrowedImpl->getEndian();
  }

  uint32_t getLength() const {
    if (Length.hasValue())
      return *Length;

    return BorrowedImpl ? (BorrowedImpl->getLength() - ViewOffset) : 0;
  }

                                                                            
                                                                             
          
  RefType drop_front(uint32_t N) const {
    if (!BorrowedImpl)
      return RefType();

    N = std::min(N, getLength());
    RefType Result(static_cast<const RefType &>(*this));
    if (N == 0)
      return Result;

    Result.ViewOffset += N;
    if (Result.Length.hasValue())
      *Result.Length -= N;
    return Result;
  }

                                                                           
                                                                              
                                                       
  RefType drop_back(uint32_t N) const {
    if (!BorrowedImpl)
      return RefType();

    RefType Result(static_cast<const RefType &>(*this));
    N = std::min(N, getLength());

    if (N == 0)
      return Result;

                                                                             
                                                                             
    if (!Result.Length.hasValue())
      Result.Length = getLength();

    *Result.Length -= N;
    return Result;
  }

                                                                               
  RefType keep_front(uint32_t N) const {
    assert(N <= getLength());
    return drop_back(getLength() - N);
  }

                                                                              
  RefType keep_back(uint32_t N) const {
    assert(N <= getLength());
    return drop_front(getLength() - N);
  }

                                                                        
              
  RefType drop_symmetric(uint32_t N) const {
    return drop_front(N).drop_back(N);
  }

                                                                             
                                            
  RefType slice(uint32_t Offset, uint32_t Len) const {
    return drop_front(Offset).keep_front(Len);
  }

  bool valid() const { return BorrowedImpl != nullptr; }

  bool operator==(const RefType &Other) const {
    if (BorrowedImpl != Other.BorrowedImpl)
      return false;
    if (ViewOffset != Other.ViewOffset)
      return false;
    if (Length != Other.Length)
      return false;
    return true;
  }

protected:
  Error checkOffsetForRead(uint32_t Offset, uint32_t DataSize) const {
    if (Offset > getLength())
      return make_error<BinaryStreamError>(stream_error_code::invalid_offset);
    if (getLength() < DataSize + Offset)
      return make_error<BinaryStreamError>(stream_error_code::stream_too_short);
    return Error::success();
  }

  std::shared_ptr<StreamType> SharedImpl;
  StreamType *BorrowedImpl = nullptr;
  uint32_t ViewOffset = 0;
  Optional<uint32_t> Length;
};

                                                                        
                                                                                
                                                                                
                                                                          
                                                                               
                                                                          
                                                                       
class BinaryStreamRef
    : public BinaryStreamRefBase<BinaryStreamRef, BinaryStream> {
  friend BinaryStreamRefBase<BinaryStreamRef, BinaryStream>;
  friend class WritableBinaryStreamRef;
  BinaryStreamRef(std::shared_ptr<BinaryStream> Impl, uint32_t ViewOffset,
                  Optional<uint32_t> Length)
      : BinaryStreamRefBase(Impl, ViewOffset, Length) {}

public:
  BinaryStreamRef() = default;
  BinaryStreamRef(BinaryStream &Stream);
  BinaryStreamRef(BinaryStream &Stream, uint32_t Offset,
                  Optional<uint32_t> Length);
  explicit BinaryStreamRef(ArrayRef<uint8_t> Data,
                           llvh::support::endianness Endian);
  explicit BinaryStreamRef(StringRef Data, llvh::support::endianness Endian);

  BinaryStreamRef(const BinaryStreamRef &Other) = default;
  BinaryStreamRef &operator=(const BinaryStreamRef &Other) = default;
  BinaryStreamRef(BinaryStreamRef &&Other) = default;
  BinaryStreamRef &operator=(BinaryStreamRef &&Other) = default;

                                         
  BinaryStreamRef(BinaryStreamRef &S, uint32_t Offset,
                  uint32_t Length) = delete;

                                                                             
                                 
     
                                                                             
                                                                             
                                                        
  Error readBytes(uint32_t Offset, uint32_t Size,
                  ArrayRef<uint8_t> &Buffer) const;

                                                                          
                                                                           
     
                                                                          
                                              
  Error readLongestContiguousChunk(uint32_t Offset,
                                   ArrayRef<uint8_t> &Buffer) const;
};

struct BinarySubstreamRef {
  uint32_t Offset;                                          
  BinaryStreamRef StreamData;               

  BinarySubstreamRef slice(uint32_t Off, uint32_t Size) const {
    BinaryStreamRef SubSub = StreamData.slice(Off, Size);
    return {Off + Offset, SubSub};
  }
  BinarySubstreamRef drop_front(uint32_t N) const {
    return slice(N, size() - N);
  }
  BinarySubstreamRef keep_front(uint32_t N) const { return slice(0, N); }

  std::pair<BinarySubstreamRef, BinarySubstreamRef>
  split(uint32_t Offset) const {
    return std::make_pair(keep_front(Offset), drop_front(Offset));
  }

  uint32_t size() const { return StreamData.getLength(); }
  bool empty() const { return size() == 0; }
};

class WritableBinaryStreamRef
    : public BinaryStreamRefBase<WritableBinaryStreamRef,
                                 WritableBinaryStream> {
  friend BinaryStreamRefBase<WritableBinaryStreamRef, WritableBinaryStream>;
  WritableBinaryStreamRef(std::shared_ptr<WritableBinaryStream> Impl,
                          uint32_t ViewOffset, Optional<uint32_t> Length)
      : BinaryStreamRefBase(Impl, ViewOffset, Length) {}

  Error checkOffsetForWrite(uint32_t Offset, uint32_t DataSize) const {
    if (!(BorrowedImpl->getFlags() & BSF_Append))
      return checkOffsetForRead(Offset, DataSize);

    if (Offset > getLength())
      return make_error<BinaryStreamError>(stream_error_code::invalid_offset);
    return Error::success();
  }

public:
  WritableBinaryStreamRef() = default;
  WritableBinaryStreamRef(WritableBinaryStream &Stream);
  WritableBinaryStreamRef(WritableBinaryStream &Stream, uint32_t Offset,
                          Optional<uint32_t> Length);
  explicit WritableBinaryStreamRef(MutableArrayRef<uint8_t> Data,
                                   llvh::support::endianness Endian);
  WritableBinaryStreamRef(const WritableBinaryStreamRef &Other) = default;
  WritableBinaryStreamRef &
  operator=(const WritableBinaryStreamRef &Other) = default;

  WritableBinaryStreamRef(WritableBinaryStreamRef &&Other) = default;
  WritableBinaryStreamRef &operator=(WritableBinaryStreamRef &&Other) = default;

                                                 
  WritableBinaryStreamRef(WritableBinaryStreamRef &S, uint32_t Offset,
                          uint32_t Length) = delete;

                                                                            
                                               
     
                                                                               
                                                                             
                                                    
  Error writeBytes(uint32_t Offset, ArrayRef<uint8_t> Data) const;

                                                                         
  operator BinaryStreamRef() const;

                                                                 
  Error commit();
};

}                      

#endif                                  
