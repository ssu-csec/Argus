//===--- raw_ostream.h - Raw output stream ----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the raw_ostream class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_RAW_OSTREAM_H
#define LLVM_SUPPORT_RAW_OSTREAM_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <system_error>

namespace llvh {

class formatv_object_base;
class format_object_base;
class FormattedString;
class FormattedNumber;
class FormattedBytes;

namespace sys {
namespace fs {
enum FileAccess : unsigned;
enum OpenFlags : unsigned;
enum CreationDisposition : unsigned;
}                    
}                     

                                                                              
                                                                                
                                                                
                      
class raw_ostream {
private:
                                                            
                                                                  
                                                                     
                                                             
     
                                           
                                               
                                                                       
                                                                   
                                                  
     
                                                                         
                                                                             
                              
     
                                                                                
                                                                             
                  
  char *OutBufStart, *OutBufEnd, *OutBufCur;

  enum BufferKind {
    Unbuffered = 0,
    InternalBuffer,
    ExternalBuffer
  } BufferMode;

public:
                                                           
  enum Colors {
    BLACK = 0,
    RED,
    GREEN,
    YELLOW,
    BLUE,
    MAGENTA,
    CYAN,
    WHITE,
    SAVEDCOLOR
  };

  explicit raw_ostream(bool unbuffered = false)
      : BufferMode(unbuffered ? Unbuffered : InternalBuffer) {
                                
    OutBufStart = OutBufEnd = OutBufCur = nullptr;
  }

  raw_ostream(const raw_ostream &) = delete;
  void operator=(const raw_ostream &) = delete;

  virtual ~raw_ostream();

                                                     
  uint64_t tell() const { return current_pos() + GetNumBytesInBuffer(); }

                                                                                
                            
                                                                                

                                                                            
           
  void SetBuffered();

                                                                     
  void SetBufferSize(size_t Size) {
    flush();
    SetBufferAndMode(new char[Size], Size, InternalBuffer);
  }

  size_t GetBufferSize() const {
                                                                          
                                                                         
    if (BufferMode != Unbuffered && OutBufStart == nullptr)
      return preferred_buffer_size();

                                                              
    return OutBufEnd - OutBufStart;
  }

                                                                             
                                                                            
                                                 
  void SetUnbuffered() {
    flush();
    SetBufferAndMode(nullptr, 0, Unbuffered);
  }

  size_t GetNumBytesInBuffer() const {
    return OutBufCur - OutBufStart;
  }

                                                                                
                          
                                                                                

  void flush() {
    if (OutBufCur != OutBufStart)
      flush_nonempty();
  }

  raw_ostream &operator<<(char C) {
    if (OutBufCur >= OutBufEnd)
      return write(C);
    *OutBufCur++ = C;
    return *this;
  }

  raw_ostream &operator<<(unsigned char C) {
    if (OutBufCur >= OutBufEnd)
      return write(C);
    *OutBufCur++ = C;
    return *this;
  }

  raw_ostream &operator<<(signed char C) {
    if (OutBufCur >= OutBufEnd)
      return write(C);
    *OutBufCur++ = C;
    return *this;
  }

  raw_ostream &operator<<(StringRef Str) {
                                                                      
    size_t Size = Str.size();

                                          
    if (Size > (size_t)(OutBufEnd - OutBufCur))
      return write(Str.data(), Size);

    if (Size) {
      memcpy(OutBufCur, Str.data(), Size);
      OutBufCur += Size;
    }
    return *this;
  }

  raw_ostream &operator<<(const char *Str) {
                                                                               
                                           

    return this->operator<<(StringRef(Str));
  }

  raw_ostream &operator<<(const std::string &Str) {
                                                                                
    return write(Str.data(), Str.length());
  }

  raw_ostream &operator<<(const SmallVectorImpl<char> &Str) {
    return write(Str.data(), Str.size());
  }

  raw_ostream &operator<<(unsigned long N);
  raw_ostream &operator<<(long N);
  raw_ostream &operator<<(unsigned long long N);
  raw_ostream &operator<<(long long N);
  raw_ostream &operator<<(const void *P);

  raw_ostream &operator<<(unsigned int N) {
    return this->operator<<(static_cast<unsigned long>(N));
  }

  raw_ostream &operator<<(int N) {
    return this->operator<<(static_cast<long>(N));
  }

  raw_ostream &operator<<(double N);

                                                                
  raw_ostream &write_hex(unsigned long long N);

                                                   
  using uuid_t = uint8_t[16];
  raw_ostream &write_uuid(const uuid_t UUID);

                                                                             
                                                    
  raw_ostream &write_escaped(StringRef Str, bool UseHexEscapes = false);

  raw_ostream &write(unsigned char C);
  raw_ostream &write(const char *Ptr, size_t Size);

                                                                     
  raw_ostream &operator<<(const format_object_base &Fmt);

                                                                          
  raw_ostream &operator<<(const FormattedString &);

                                                                        
  raw_ostream &operator<<(const FormattedNumber &);

                                                                              
  raw_ostream &operator<<(const formatv_object_base &);

                                                                           
  raw_ostream &operator<<(const FormattedBytes &);

                                         
  raw_ostream &indent(unsigned NumSpaces);

                                            
  raw_ostream &write_zeros(unsigned NumZeros);

                                                                              
              
                                                                           
                                                               
                                                   
                                                                         
                                                             
  virtual raw_ostream &changeColor(enum Colors Color,
                                   bool Bold = false,
                                   bool BG = false) {
    (void)Color;
    (void)Bold;
    (void)BG;
    return *this;
  }

                                                                         
                                                      
  virtual raw_ostream &resetColor() { return *this; }

                                                    
  virtual raw_ostream &reverseColor() { return *this; }

                                                                        
                                                                          
                                                          
  virtual bool is_displayed() const { return false; }

                                                                               
  virtual bool has_colors() const { return is_displayed(); }

                                                                                
                       
                                                                                

private:
                                                                            
                                          
                                      
     
                                                                             
                                                                  
     
                                                                               
                                                  
     
                                                    
     
                             
  virtual void write_impl(const char *Ptr, size_t Size) = 0;

                                                                           
                              
  virtual uint64_t current_pos() const = 0;

protected:
                                                                             
                                                                            
                                                                            
  void SetBuffer(char *BufferStart, size_t Size) {
    SetBufferAndMode(BufferStart, Size, ExternalBuffer);
  }

                                                                          
  virtual size_t preferred_buffer_size() const;

                                                                              
                 
  const char *getBufferStart() const { return OutBufStart; }

                                                                                
                      
                                                                                
private:
                                        
  void SetBufferAndMode(char *BufferStart, size_t Size, BufferKind Mode);

                                                                                
                                                             
  void flush_nonempty();

                                                                            
                                 
  void copy_to_buffer(const char *Ptr, size_t Size);

  virtual void anchor();
};

                                                                          
                                                                              
                                                                      
class raw_pwrite_stream : public raw_ostream {
  virtual void pwrite_impl(const char *Ptr, size_t Size, uint64_t Offset) = 0;
  void anchor() override;

public:
  explicit raw_pwrite_stream(bool Unbuffered = false)
      : raw_ostream(Unbuffered) {}
  void pwrite(const char *Ptr, size_t Size, uint64_t Offset) {
#ifndef NDEBUG
    uint64_t Pos = tell();
                                                                           
                    
    if (Pos)
      assert(Size + Offset <= Pos && "We don't support extending the stream");
#endif
    pwrite_impl(Ptr, Size, Offset);
  }
};

                                                                                
                      
                                                                                

                                                   
   
class raw_fd_ostream : public raw_pwrite_stream {
  int FD;
  bool ShouldClose;

  bool SupportsSeeking;

#ifdef _WIN32
                                                                          
                                                             
  bool IsWindowsConsole = false;
#endif

  std::error_code EC;

  uint64_t pos;

                                  
  void write_impl(const char *Ptr, size_t Size) override;

  void pwrite_impl(const char *Ptr, size_t Size, uint64_t Offset) override;

                                                                           
                              
  uint64_t current_pos() const override { return pos; }

                                         
  size_t preferred_buffer_size() const override;

                                                                        
  void error_detected(std::error_code EC) { this->EC = EC; }

  void anchor() override;

public:
                                                                          
                                                                          
                
                                                                            
     
                                                                     
                                                                             
                 
  raw_fd_ostream(StringRef Filename, std::error_code &EC);
  raw_fd_ostream(StringRef Filename, std::error_code &EC,
                 sys::fs::CreationDisposition Disp);
  raw_fd_ostream(StringRef Filename, std::error_code &EC,
                 sys::fs::FileAccess Access);
  raw_fd_ostream(StringRef Filename, std::error_code &EC,
                 sys::fs::OpenFlags Flags);
  raw_fd_ostream(StringRef Filename, std::error_code &EC,
                 sys::fs::CreationDisposition Disp, sys::fs::FileAccess Access,
                 sys::fs::OpenFlags Flags);

                                                                             
                                                                               
                                    
  raw_fd_ostream(int fd, bool shouldClose, bool unbuffered=false);

  ~raw_fd_ostream() override;

                                                                                
            
  void close();

  bool supportsSeeking() { return SupportsSeeking; }

                                                                                
                                                             
  uint64_t seek(uint64_t off);

  raw_ostream &changeColor(enum Colors colors, bool bold=false,
                           bool bg=false) override;
  raw_ostream &resetColor() override;

  raw_ostream &reverseColor() override;

  bool is_displayed() const override;

  bool has_colors() const override;

  std::error_code error() const { return EC; }

                                                                               
                                        
                                                                         
                                                                       
  bool has_error() const { return bool(EC); }

                                                                                
                                                                              
                                                                               
                          
     
                                           
                                     
                                                  
     
  void clear_error() { EC = std::error_code(); }
};

                                                                               
                             
raw_ostream &outs();

                                                                              
                             
raw_ostream &errs();

                                                                           
raw_ostream &nulls();

                                                                                
                         
                                                                                

                                                                          
                                                       
class raw_string_ostream : public raw_ostream {
  std::string &OS;

                                  
  void write_impl(const char *Ptr, size_t Size) override;

                                                                           
                              
  uint64_t current_pos() const override { return OS.size(); }

public:
  explicit raw_string_ostream(std::string &O) : OS(O) {}
  ~raw_string_ostream() override;

                                                                                
                
  std::string& str() {
    flush();
    return OS;
  }
};

                                                                          
                                                                      
                                                                        
                                                                             
                                                              
class raw_svector_ostream : public raw_pwrite_stream {
  SmallVectorImpl<char> &OS;

                                  
  void write_impl(const char *Ptr, size_t Size) override;

  void pwrite_impl(const char *Ptr, size_t Size, uint64_t Offset) override;

                                                    
  uint64_t current_pos() const override;

public:
                                          
     
                                                                              
                                                         
  explicit raw_svector_ostream(SmallVectorImpl<char> &O) : OS(O) {
    SetUnbuffered();
  }

  ~raw_svector_ostream() override = default;

  void flush() = delete;

                                                 
  StringRef str() { return StringRef(OS.data(), OS.size()); }
};

                                           
class raw_null_ostream : public raw_pwrite_stream {
                                  
  void write_impl(const char *Ptr, size_t size) override;
  void pwrite_impl(const char *Ptr, size_t Size, uint64_t Offset) override;

                                                                           
                              
  uint64_t current_pos() const override;

public:
  explicit raw_null_ostream() = default;
  ~raw_null_ostream() override;
};

class buffer_ostream : public raw_svector_ostream {
  raw_ostream &OS;
  SmallVector<char, 0> Buffer;

public:
  buffer_ostream(raw_ostream &OS) : raw_svector_ostream(Buffer), OS(OS) {}
  ~buffer_ostream() override { OS << str(); }
};

}                      

#endif                              
