//===--- MemoryBuffer.h - Memory Buffer Interface ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the MemoryBuffer interface.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_MEMORYBUFFER_H
#define LLVM_SUPPORT_MEMORYBUFFER_H

#include "llvh-c/Types.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/ErrorOr.h"
#include "llvh/Support/FileSystem.h"
#include <cstddef>
#include <cstdint>
#include <memory>

namespace llvh {

class MemoryBufferRef;

                                                                             
                                                                              
                                                                            
                                                                             
                                              
   
                                                                               
                                                                        
                                                                         
                                                          
class MemoryBuffer {
  const char *BufferStart;                        
  const char *BufferEnd;                        

protected:
  MemoryBuffer() = default;

  void init(const char *BufStart, const char *BufEnd,
            bool RequiresNullTerminator);

  static constexpr sys::fs::mapped_file_region::mapmode Mapmode =
      sys::fs::mapped_file_region::readonly;

public:
  MemoryBuffer(const MemoryBuffer &) = delete;
  MemoryBuffer &operator=(const MemoryBuffer &) = delete;
  virtual ~MemoryBuffer();

  const char *getBufferStart() const { return BufferStart; }
  const char *getBufferEnd() const   { return BufferEnd; }
  size_t getBufferSize() const { return BufferEnd-BufferStart; }

  StringRef getBuffer() const {
    return StringRef(BufferStart, getBufferSize());
  }

                                                                              
           
  virtual StringRef getBufferIdentifier() const { return "Unknown buffer"; }

                                                                             
                                                                             
                                                                          
                     
     
                                                                             
                                                                              
                                                                              
  static ErrorOr<std::unique_ptr<MemoryBuffer>>
  getFile(const Twine &Filename, int64_t FileSize = -1,
          bool RequiresNullTerminator = true, bool IsVolatile = false);

                                                                    
                                                                     
                                                                             
  static ErrorOr<std::unique_ptr<MemoryBuffer>>
  getFileAsStream(const Twine &Filename);

                                                                        
                                                                          
                                                                               
  static ErrorOr<std::unique_ptr<MemoryBuffer>>
  getOpenFileSlice(int FD, const Twine &Filename, uint64_t MapSize,
                   int64_t Offset, bool IsVolatile = false);

                                                                       
                   
     
                                                                             
                                                                              
                                                                              
  static ErrorOr<std::unique_ptr<MemoryBuffer>>
  getOpenFile(int FD, const Twine &Filename, uint64_t FileSize,
              bool RequiresNullTerminator = true, bool IsVolatile = false);

                                                                            
                                                                
  static std::unique_ptr<MemoryBuffer>
  getMemBuffer(StringRef InputData, StringRef BufferName = "",
               bool RequiresNullTerminator = true);

  static std::unique_ptr<MemoryBuffer>
  getMemBuffer(MemoryBufferRef Ref, bool RequiresNullTerminator = true);

                                                                             
                                                                                
  static std::unique_ptr<MemoryBuffer>
  getMemBufferCopy(StringRef InputData, const Twine &BufferName = "");

                                                          
  static ErrorOr<std::unique_ptr<MemoryBuffer>> getSTDIN();

                                                                              
             
  static ErrorOr<std::unique_ptr<MemoryBuffer>>
  getFileOrSTDIN(const Twine &Filename, int64_t FileSize = -1,
                 bool RequiresNullTerminator = true);

                                                             
  static ErrorOr<std::unique_ptr<MemoryBuffer>>
  getFileSlice(const Twine &Filename, uint64_t MapSize, uint64_t Offset,
               bool IsVolatile = false);

                                                                                
                                       
                                                                                

                                                                  
  enum BufferKind {
    MemoryBuffer_Malloc,
    MemoryBuffer_MMap
  };

                                                                    
                   
  virtual BufferKind getBufferKind() const = 0;

  MemoryBufferRef getMemBufferRef() const;
};

                                                                          
                                                                              
                                                                             
                               
class WritableMemoryBuffer : public MemoryBuffer {
protected:
  WritableMemoryBuffer() = default;

  static constexpr sys::fs::mapped_file_region::mapmode Mapmode =
      sys::fs::mapped_file_region::priv;

public:
  using MemoryBuffer::getBuffer;
  using MemoryBuffer::getBufferEnd;
  using MemoryBuffer::getBufferStart;

                                                                      
                                                               
  char *getBufferStart() {
    return const_cast<char *>(MemoryBuffer::getBufferStart());
  }
  char *getBufferEnd() {
    return const_cast<char *>(MemoryBuffer::getBufferEnd());
  }
  MutableArrayRef<char> getBuffer() {
    return {getBufferStart(), getBufferEnd()};
  }

  static ErrorOr<std::unique_ptr<WritableMemoryBuffer>>
  getFile(const Twine &Filename, int64_t FileSize = -1,
          bool IsVolatile = false);

                                                                     
  static ErrorOr<std::unique_ptr<WritableMemoryBuffer>>
  getFileSlice(const Twine &Filename, uint64_t MapSize, uint64_t Offset,
               bool IsVolatile = false);

                                                                                
                                                                         
                                                             
  static std::unique_ptr<WritableMemoryBuffer>
  getNewUninitMemBuffer(size_t Size, const Twine &BufferName = "");

                                                                              
                                                                              
                                                     
  static std::unique_ptr<WritableMemoryBuffer>
  getNewMemBuffer(size_t Size, const Twine &BufferName = "");

private:
                                                              
                                     
                                                     
  using MemoryBuffer::getFileAsStream;
  using MemoryBuffer::getFileOrSTDIN;
  using MemoryBuffer::getMemBuffer;
  using MemoryBuffer::getMemBufferCopy;
  using MemoryBuffer::getOpenFile;
  using MemoryBuffer::getOpenFileSlice;
  using MemoryBuffer::getSTDIN;
};

                                                                            
                                                                                
                                                                               
                                                                    
class WriteThroughMemoryBuffer : public MemoryBuffer {
protected:
  WriteThroughMemoryBuffer() = default;

  static constexpr sys::fs::mapped_file_region::mapmode Mapmode =
      sys::fs::mapped_file_region::readwrite;

public:
  using MemoryBuffer::getBuffer;
  using MemoryBuffer::getBufferEnd;
  using MemoryBuffer::getBufferStart;

                                                                      
                                                               
  char *getBufferStart() {
    return const_cast<char *>(MemoryBuffer::getBufferStart());
  }
  char *getBufferEnd() {
    return const_cast<char *>(MemoryBuffer::getBufferEnd());
  }
  MutableArrayRef<char> getBuffer() {
    return {getBufferStart(), getBufferEnd()};
  }

  static ErrorOr<std::unique_ptr<WriteThroughMemoryBuffer>>
  getFile(const Twine &Filename, int64_t FileSize = -1);

                                                                      
  static ErrorOr<std::unique_ptr<WriteThroughMemoryBuffer>>
  getFileSlice(const Twine &Filename, uint64_t MapSize, uint64_t Offset);

private:
                                                              
                                     
                                                     
  using MemoryBuffer::getFileAsStream;
  using MemoryBuffer::getFileOrSTDIN;
  using MemoryBuffer::getMemBuffer;
  using MemoryBuffer::getMemBufferCopy;
  using MemoryBuffer::getOpenFile;
  using MemoryBuffer::getOpenFileSlice;
  using MemoryBuffer::getSTDIN;
};

class MemoryBufferRef {
  StringRef Buffer;
  StringRef Identifier;

public:
  MemoryBufferRef() = default;
  MemoryBufferRef(MemoryBuffer& Buffer)
      : Buffer(Buffer.getBuffer()), Identifier(Buffer.getBufferIdentifier()) {}
  MemoryBufferRef(StringRef Buffer, StringRef Identifier)
      : Buffer(Buffer), Identifier(Identifier) {}

  StringRef getBuffer() const { return Buffer; }

  StringRef getBufferIdentifier() const { return Identifier; }

  const char *getBufferStart() const { return Buffer.begin(); }
  const char *getBufferEnd() const { return Buffer.end(); }
  size_t getBufferSize() const { return Buffer.size(); }
};

                                                                
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(MemoryBuffer, LLVMMemoryBufferRef)

}                      

#endif                               
