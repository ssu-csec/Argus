//===--- raw_ostream.cpp - Implement the raw_ostream classes --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This implements support for bulk buffered stream output.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/raw_ostream.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/Config/config.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/FormatVariadic.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/NativeFormatting.h"
#include "llvh/Support/Process.h"
#include "llvh/Support/Program.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <iterator>
#include <sys/stat.h>
#include <system_error>

                                  
#if defined(HAVE_FCNTL_H)
# include <fcntl.h>
#endif

#if defined(HAVE_UNISTD_H)
# include <unistd.h>
#endif

#if defined(__CYGWIN__)
#include <io.h>
#endif

#if defined(_MSC_VER)
#include <io.h>
#ifndef STDIN_FILENO
# define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO 2
#endif
#endif

#ifdef _WIN32
#include "llvh/Support/ConvertUTF.h"
#include "Windows/WindowsSupport.h"
#endif

using namespace llvh;

raw_ostream::~raw_ostream() {
                                                                  
                          
  assert(OutBufCur == OutBufStart &&
         "raw_ostream destructor called with non-empty buffer!");

  if (BufferMode == InternalBuffer)
    delete [] OutBufStart;
}

size_t raw_ostream::preferred_buffer_size() const {
                                                   
  return BUFSIZ;
}

void raw_ostream::SetBuffered() {
                                                              
  if (size_t Size = preferred_buffer_size())
    SetBufferSize(Size);
  else
                                                                 
    SetUnbuffered();
}

void raw_ostream::SetBufferAndMode(char *BufferStart, size_t Size,
                                   BufferKind Mode) {
  assert(((Mode == Unbuffered && !BufferStart && Size == 0) ||
          (Mode != Unbuffered && BufferStart && Size != 0)) &&
         "stream must be unbuffered or have at least one byte");
                                                                              
                                                          
  assert(GetNumBytesInBuffer() == 0 && "Current buffer is non-empty!");

  if (BufferMode == InternalBuffer)
    delete [] OutBufStart;
  OutBufStart = BufferStart;
  OutBufEnd = OutBufStart+Size;
  OutBufCur = OutBufStart;
  BufferMode = Mode;

  assert(OutBufStart <= OutBufEnd && "Invalid size!");
}

raw_ostream &raw_ostream::operator<<(unsigned long N) {
  write_integer(*this, static_cast<uint64_t>(N), 0, IntegerStyle::Integer);
  return *this;
}

raw_ostream &raw_ostream::operator<<(long N) {
  write_integer(*this, static_cast<int64_t>(N), 0, IntegerStyle::Integer);
  return *this;
}

raw_ostream &raw_ostream::operator<<(unsigned long long N) {
  write_integer(*this, static_cast<uint64_t>(N), 0, IntegerStyle::Integer);
  return *this;
}

raw_ostream &raw_ostream::operator<<(long long N) {
  write_integer(*this, static_cast<int64_t>(N), 0, IntegerStyle::Integer);
  return *this;
}

raw_ostream &raw_ostream::write_hex(unsigned long long N) {
  llvh::write_hex(*this, N, HexPrintStyle::Lower);
  return *this;
}

raw_ostream &raw_ostream::write_uuid(const uuid_t UUID) {
  for (int Idx = 0; Idx < 16; ++Idx) {
    *this << format("%02" PRIX32, UUID[Idx]);
    if (Idx == 3 || Idx == 5 || Idx == 7 || Idx == 9)
      *this << "-";
  }
  return *this;
}


raw_ostream &raw_ostream::write_escaped(StringRef Str,
                                        bool UseHexEscapes) {
  for (unsigned char c : Str) {
    switch (c) {
    case '\\':
      *this << '\\' << '\\';
      break;
    case '\t':
      *this << '\\' << 't';
      break;
    case '\n':
      *this << '\\' << 'n';
      break;
    case '"':
      *this << '\\' << '"';
      break;
    default:
      if (isPrint(c)) {
        *this << c;
        break;
      }

                                              
      if (UseHexEscapes) {
        *this << '\\' << 'x';
        *this << hexdigit((c >> 4 & 0xF));
        *this << hexdigit((c >> 0) & 0xF);
      } else {
                                                      
        *this << '\\';
        *this << char('0' + ((c >> 6) & 7));
        *this << char('0' + ((c >> 3) & 7));
        *this << char('0' + ((c >> 0) & 7));
      }
    }
  }

  return *this;
}

raw_ostream &raw_ostream::operator<<(const void *P) {
  llvh::write_hex(*this, (uintptr_t)P, HexPrintStyle::PrefixLower);
  return *this;
}

raw_ostream &raw_ostream::operator<<(double N) {
  llvh::write_double(*this, N, FloatStyle::Exponent);
  return *this;
}

void raw_ostream::flush_nonempty() {
  assert(OutBufCur > OutBufStart && "Invalid call to flush_nonempty.");
  size_t Length = OutBufCur - OutBufStart;
  OutBufCur = OutBufStart;
  write_impl(OutBufStart, Length);
}

raw_ostream &raw_ostream::write(unsigned char C) {
                                                  
  if (LLVM_UNLIKELY(OutBufCur >= OutBufEnd)) {
    if (LLVM_UNLIKELY(!OutBufStart)) {
      if (BufferMode == Unbuffered) {
        write_impl(reinterpret_cast<char*>(&C), 1);
        return *this;
      }
                                        
      SetBuffered();
      return write(C);
    }

    flush_nonempty();
  }

  *OutBufCur++ = C;
  return *this;
}

raw_ostream &raw_ostream::write(const char *Ptr, size_t Size) {
                                                  
  if (LLVM_UNLIKELY(size_t(OutBufEnd - OutBufCur) < Size)) {
    if (LLVM_UNLIKELY(!OutBufStart)) {
      if (BufferMode == Unbuffered) {
        write_impl(Ptr, Size);
        return *this;
      }
                                        
      SetBuffered();
      return write(Ptr, Size);
    }

    size_t NumBytes = OutBufEnd - OutBufCur;

                                                                           
                                                                          
                                                                 
    if (LLVM_UNLIKELY(OutBufCur == OutBufStart)) {
      assert(NumBytes != 0 && "undefined behavior");
      size_t BytesToWrite = Size - (Size % NumBytes);
      write_impl(Ptr, BytesToWrite);
      size_t BytesRemaining = Size - BytesToWrite;
      if (BytesRemaining > size_t(OutBufEnd - OutBufCur)) {
                                                      
        return write(Ptr + BytesToWrite, BytesRemaining);
      }
      copy_to_buffer(Ptr + BytesToWrite, BytesRemaining);
      return *this;
    }

                                                                               
                                                                 
    copy_to_buffer(Ptr, NumBytes);
    flush_nonempty();
    return write(Ptr + NumBytes, Size - NumBytes);
  }

  copy_to_buffer(Ptr, Size);

  return *this;
}

void raw_ostream::copy_to_buffer(const char *Ptr, size_t Size) {
  assert(Size <= size_t(OutBufEnd - OutBufCur) && "Buffer overrun!");

                                                                         
             
  switch (Size) {
  case 4: OutBufCur[3] = Ptr[3]; LLVM_FALLTHROUGH;
  case 3: OutBufCur[2] = Ptr[2]; LLVM_FALLTHROUGH;
  case 2: OutBufCur[1] = Ptr[1]; LLVM_FALLTHROUGH;
  case 1: OutBufCur[0] = Ptr[0]; LLVM_FALLTHROUGH;
  case 0: break;
  default:
    memcpy(OutBufCur, Ptr, Size);
    break;
  }

  OutBufCur += Size;
}

                    
raw_ostream &raw_ostream::operator<<(const format_object_base &Fmt) {
                                                                    
                                      
  size_t NextBufferSize = 127;
  size_t BufferBytesLeft = OutBufEnd - OutBufCur;
  if (BufferBytesLeft > 3) {
    size_t BytesUsed = Fmt.print(OutBufCur, BufferBytesLeft);

                                                   
    if (BytesUsed <= BufferBytesLeft) {
      OutBufCur += BytesUsed;
      return *this;
    }

                                                                             
                  
    NextBufferSize = BytesUsed;
  }

                                                                             
                                                                            
                                  
  SmallVector<char, 128> V;

  while (true) {
    V.resize(NextBufferSize);

                                           
    size_t BytesUsed = Fmt.print(V.data(), NextBufferSize);

                                                
    if (BytesUsed <= NextBufferSize)
      return write(V.data(), BytesUsed);

                                            
    assert(BytesUsed > NextBufferSize && "Didn't grow buffer!?");
    NextBufferSize = BytesUsed;
  }
}

raw_ostream &raw_ostream::operator<<(const formatv_object_base &Obj) {
  SmallString<128> S;
  Obj.format(*this);
  return *this;
}

raw_ostream &raw_ostream::operator<<(const FormattedString &FS) {
  if (FS.Str.size() >= FS.Width || FS.Justify == FormattedString::JustifyNone) {
    this->operator<<(FS.Str);
    return *this;
  }
  const size_t Difference = FS.Width - FS.Str.size();
  switch (FS.Justify) {
  case FormattedString::JustifyLeft:
    this->operator<<(FS.Str);
    this->indent(Difference);
    break;
  case FormattedString::JustifyRight:
    this->indent(Difference);
    this->operator<<(FS.Str);
    break;
  case FormattedString::JustifyCenter: {
    int PadAmount = Difference / 2;
    this->indent(PadAmount);
    this->operator<<(FS.Str);
    this->indent(Difference - PadAmount);
    break;
  }
  default:
    llvm_unreachable("Bad Justification");
  }
  return *this;
}

raw_ostream &raw_ostream::operator<<(const FormattedNumber &FN) {
  if (FN.Hex) {
    HexPrintStyle Style;
    if (FN.Upper && FN.HexPrefix)
      Style = HexPrintStyle::PrefixUpper;
    else if (FN.Upper && !FN.HexPrefix)
      Style = HexPrintStyle::Upper;
    else if (!FN.Upper && FN.HexPrefix)
      Style = HexPrintStyle::PrefixLower;
    else
      Style = HexPrintStyle::Lower;
    llvh::write_hex(*this, FN.HexValue, Style, FN.Width);
  } else {
    llvh::SmallString<16> Buffer;
    llvh::raw_svector_ostream Stream(Buffer);
    llvh::write_integer(Stream, FN.DecValue, 0, IntegerStyle::Integer);
    if (Buffer.size() < FN.Width)
      indent(FN.Width - Buffer.size());
    (*this) << Buffer;
  }
  return *this;
}

raw_ostream &raw_ostream::operator<<(const FormattedBytes &FB) {
  if (FB.Bytes.empty())
    return *this;

  size_t LineIndex = 0;
  auto Bytes = FB.Bytes;
  const size_t Size = Bytes.size();
  HexPrintStyle HPS = FB.Upper ? HexPrintStyle::Upper : HexPrintStyle::Lower;
  uint64_t OffsetWidth = 0;
  if (FB.FirstByteOffset.hasValue()) {
                                                                         
                                                                          
                          
    size_t Lines = Size / FB.NumPerLine;
    uint64_t MaxOffset = *FB.FirstByteOffset + Lines * FB.NumPerLine;
    unsigned Power = 0;
    if (MaxOffset > 0)
      Power = llvh::Log2_64_Ceil(MaxOffset);
    OffsetWidth = std::max<uint64_t>(4, llvh::alignTo(Power, 4) / 4);
  }

                                                                            
  unsigned NumByteGroups =
      alignTo(FB.NumPerLine, FB.ByteGroupSize) / FB.ByteGroupSize;
  unsigned BlockCharWidth = FB.NumPerLine * 2 + NumByteGroups - 1;

  while (!Bytes.empty()) {
    indent(FB.IndentLevel);

    if (FB.FirstByteOffset.hasValue()) {
      uint64_t Offset = FB.FirstByteOffset.getValue();
      llvh::write_hex(*this, Offset + LineIndex, HPS, OffsetWidth);
      *this << ": ";
    }

    auto Line = Bytes.take_front(FB.NumPerLine);

    size_t CharsPrinted = 0;
                                                  
    for (size_t I = 0; I < Line.size(); ++I, CharsPrinted += 2) {
      if (I && (I % FB.ByteGroupSize) == 0) {
        ++CharsPrinted;
        *this << " ";
      }
      llvh::write_hex(*this, Line[I], HPS, 2);
    }

    if (FB.ASCII) {
                                                                           
                                                            
      assert(BlockCharWidth >= CharsPrinted);
      indent(BlockCharWidth - CharsPrinted + 2);
      *this << "|";

                                                               
      for (uint8_t Byte : Line) {
        if (isPrint(Byte))
          *this << static_cast<char>(Byte);
        else
          *this << '.';
      }
      *this << '|';
    }

    Bytes = Bytes.drop_front(Line.size());
    LineIndex += Line.size();
    if (LineIndex < Size)
      *this << '\n';
  }
  return *this;
}

template <char C>
static raw_ostream &write_padding(raw_ostream &OS, unsigned NumChars) {
  static const char Chars[] = {C, C, C, C, C, C, C, C, C, C, C, C, C, C, C, C,
                               C, C, C, C, C, C, C, C, C, C, C, C, C, C, C, C,
                               C, C, C, C, C, C, C, C, C, C, C, C, C, C, C, C,
                               C, C, C, C, C, C, C, C, C, C, C, C, C, C, C, C,
                               C, C, C, C, C, C, C, C, C, C, C, C, C, C, C, C};

                                                                 
  if (NumChars < array_lengthof(Chars))
    return OS.write(Chars, NumChars);

  while (NumChars) {
    unsigned NumToWrite = std::min(NumChars,
                                   (unsigned)array_lengthof(Chars)-1);
    OS.write(Chars, NumToWrite);
    NumChars -= NumToWrite;
  }
  return OS;
}

                                       
raw_ostream &raw_ostream::indent(unsigned NumSpaces) {
  return write_padding<' '>(*this, NumSpaces);
}

                                          
raw_ostream &raw_ostream::write_zeros(unsigned NumZeros) {
  return write_padding<'\0'>(*this, NumZeros);
}

void raw_ostream::anchor() {}

                                                                                
                    
                                                                                

                              
void format_object_base::home() {
}

                                                                                
                  
                                                                                

static int getFD(StringRef Filename, std::error_code &EC,
                 sys::fs::CreationDisposition Disp, sys::fs::FileAccess Access,
                 sys::fs::OpenFlags Flags) {
  assert((Access & sys::fs::FA_Write) &&
         "Cannot make a raw_ostream from a read-only descriptor!");

                                                                         
                                                                               
  if (Filename == "-") {
    EC = std::error_code();
                                                                   
                
    if (!(Flags & sys::fs::OF_Text))
      sys::ChangeStdoutToBinary();
    return STDOUT_FILENO;
  }

  int FD;
  if (Access & sys::fs::FA_Read)
    EC = sys::fs::openFileForReadWrite(Filename, FD, Disp, Flags);
  else
    EC = sys::fs::openFileForWrite(Filename, FD, Disp, Flags);
  if (EC)
    return -1;

  return FD;
}

raw_fd_ostream::raw_fd_ostream(StringRef Filename, std::error_code &EC)
    : raw_fd_ostream(Filename, EC, sys::fs::CD_CreateAlways, sys::fs::FA_Write,
                     sys::fs::OF_None) {}

raw_fd_ostream::raw_fd_ostream(StringRef Filename, std::error_code &EC,
                               sys::fs::CreationDisposition Disp)
    : raw_fd_ostream(Filename, EC, Disp, sys::fs::FA_Write, sys::fs::OF_None) {}

raw_fd_ostream::raw_fd_ostream(StringRef Filename, std::error_code &EC,
                               sys::fs::FileAccess Access)
    : raw_fd_ostream(Filename, EC, sys::fs::CD_CreateAlways, Access,
                     sys::fs::OF_None) {}

raw_fd_ostream::raw_fd_ostream(StringRef Filename, std::error_code &EC,
                               sys::fs::OpenFlags Flags)
    : raw_fd_ostream(Filename, EC, sys::fs::CD_CreateAlways, sys::fs::FA_Write,
                     Flags) {}

raw_fd_ostream::raw_fd_ostream(StringRef Filename, std::error_code &EC,
                               sys::fs::CreationDisposition Disp,
                               sys::fs::FileAccess Access,
                               sys::fs::OpenFlags Flags)
    : raw_fd_ostream(getFD(Filename, EC, Disp, Access, Flags), true) {}

                                                                                
                                                 
raw_fd_ostream::raw_fd_ostream(int fd, bool shouldClose, bool unbuffered)
    : raw_pwrite_stream(unbuffered), FD(fd), ShouldClose(shouldClose) {
  if (FD < 0 ) {
    ShouldClose = false;
    return;
  }

                                                                             
                                                                            
                                                                                
                                                                             
                                                                                
                                                                               
  if (FD <= STDERR_FILENO)
    ShouldClose = false;

#ifdef _WIN32
                                                                         
  IsWindowsConsole =
      ::GetFileType((HANDLE)::_get_osfhandle(fd)) == FILE_TYPE_CHAR;
#endif

                               
  off_t loc = ::lseek(FD, 0, SEEK_CUR);
#ifdef _WIN32
                                                           
  sys::fs::file_status Status;
  std::error_code EC = status(FD, Status);
  SupportsSeeking = !EC && Status.type() == sys::fs::file_type::regular_file;
#else
  SupportsSeeking = loc != (off_t)-1;
#endif
  if (!SupportsSeeking)
    pos = 0;
  else
    pos = static_cast<uint64_t>(loc);
}

raw_fd_ostream::~raw_fd_ostream() {
  if (FD >= 0) {
    flush();
    if (ShouldClose) {
      if (auto EC = sys::Process::SafelyCloseFileDescriptor(FD))
        error_detected(EC);
    }
  }

#ifdef __MINGW32__
                                                   
                                                                      
                                                                     
                
  if (FD == 2) return;
#endif

                                                                      
                                                                   
                                                                   
                                                           
  if (has_error())
    report_fatal_error("IO failure on output stream: " + error().message(),
                                        false);
}

#if defined(_WIN32)
                                                                      
                                                                         
                                                                               
                                            
                                                                           
                                    
                                                                           
                       
  
                                                                          
                                                                             
                                                                          
                                                                              
                                            
static bool write_console_impl(int FD, StringRef Data) {
  SmallVector<wchar_t, 256> WideText;

                                                   
  if (auto EC = sys::windows::UTF8ToUTF16(Data, WideText))
    return false;

                                                                             
                                                  
  size_t MaxWriteSize = WideText.size();
  if (!RunningWindows8OrGreater())
    MaxWriteSize = 32767;

  size_t WCharsWritten = 0;
  do {
    size_t WCharsToWrite =
        std::min(MaxWriteSize, WideText.size() - WCharsWritten);
    DWORD ActuallyWritten;
    bool Success =
        ::WriteConsoleW((HANDLE)::_get_osfhandle(FD), &WideText[WCharsWritten],
                        WCharsToWrite, &ActuallyWritten,
                                     nullptr);

                                                                            
                                                                              
                                           
    if (!Success)
      return false;

    WCharsWritten += ActuallyWritten;
  } while (WCharsWritten != WideText.size());
  return true;
}
#endif

void raw_fd_ostream::write_impl(const char *Ptr, size_t Size) {
  assert(FD >= 0 && "File already closed.");
  pos += Size;

#if defined(_WIN32)
                                                                              
                                                                        
  if (IsWindowsConsole)
    if (write_console_impl(FD, StringRef(Ptr, Size)))
      return;
#endif

                                                            
                                                               
                                              
  size_t MaxWriteSize = INT32_MAX;

#if defined(__linux__)
                                                                           
                                      
  MaxWriteSize = 1024 * 1024 * 1024;
#endif

  do {
    size_t ChunkSize = std::min(Size, MaxWriteSize);
    ssize_t ret = ::write(FD, Ptr, ChunkSize);

    if (ret < 0) {
                                                                     
        
                                                                       
                                                                         
                                                                     
                                                                     
                                                                       
                                                                
      if (errno == EINTR || errno == EAGAIN
#ifdef EWOULDBLOCK
          || errno == EWOULDBLOCK
#endif
          )
        continue;

                                                                  
      error_detected(std::error_code(errno, std::generic_category()));
      break;
    }

                                                                     
                                                                  
                                                             
    Ptr += ret;
    Size -= ret;
  } while (Size > 0);
}

void raw_fd_ostream::close() {
  assert(ShouldClose);
  ShouldClose = false;
  flush();
  if (auto EC = sys::Process::SafelyCloseFileDescriptor(FD))
    error_detected(EC);
  FD = -1;
}

uint64_t raw_fd_ostream::seek(uint64_t off) {
  assert(SupportsSeeking && "Stream does not support seeking!");
  flush();
#ifdef _WIN32
  pos = ::_lseeki64(FD, off, SEEK_SET);
#elif defined(HAVE_LSEEK64)
  pos = ::lseek64(FD, off, SEEK_SET);
#else
  pos = ::lseek(FD, off, SEEK_SET);
#endif
  if (pos == (uint64_t)-1)
    error_detected(std::error_code(errno, std::generic_category()));
  return pos;
}

void raw_fd_ostream::pwrite_impl(const char *Ptr, size_t Size,
                                 uint64_t Offset) {
  uint64_t Pos = tell();
  seek(Offset);
  write(Ptr, Size);
  seek(Pos);
}

size_t raw_fd_ostream::preferred_buffer_size() const {
#if defined(_WIN32)
                                                                             
                                                                               
                                                                               
                                                                            
                
  if (IsWindowsConsole)
    return 0;
  return raw_ostream::preferred_buffer_size();
#elif !defined(__minix) && !(defined(__APPLE__) && defined(HERMES_IS_MOBILE_BUILD)) && !defined(__EMSCRIPTEN__)
                             
  assert(FD >= 0 && "File not yet open!");
  struct stat statbuf;
  if (fstat(FD, &statbuf) != 0)
    return 0;

                                                               
                                                                
                    
  if (S_ISCHR(statbuf.st_mode) && isatty(FD))
    return 0;
                                     
  return statbuf.st_blksize;
#else
  return raw_ostream::preferred_buffer_size();
#endif
}

raw_ostream &raw_fd_ostream::changeColor(enum Colors colors, bool bold,
                                         bool bg) {
  if (sys::Process::ColorNeedsFlush())
    flush();
  const char *colorcode =
    (colors == SAVEDCOLOR) ? sys::Process::OutputBold(bg)
    : sys::Process::OutputColor(colors, bold, bg);
  if (colorcode) {
    size_t len = strlen(colorcode);
    write(colorcode, len);
                                                     
    pos -= len;
  }
  return *this;
}

raw_ostream &raw_fd_ostream::resetColor() {
  if (sys::Process::ColorNeedsFlush())
    flush();
  const char *colorcode = sys::Process::ResetColor();
  if (colorcode) {
    size_t len = strlen(colorcode);
    write(colorcode, len);
                                                     
    pos -= len;
  }
  return *this;
}

raw_ostream &raw_fd_ostream::reverseColor() {
  if (sys::Process::ColorNeedsFlush())
    flush();
  const char *colorcode = sys::Process::OutputReverse();
  if (colorcode) {
    size_t len = strlen(colorcode);
    write(colorcode, len);
                                                     
    pos -= len;
  }
  return *this;
}

bool raw_fd_ostream::is_displayed() const {
  return sys::Process::FileDescriptorIsDisplayed(FD);
}

bool raw_fd_ostream::has_colors() const {
  return sys::Process::FileDescriptorHasColors(FD);
}

void raw_fd_ostream::anchor() {}

                                                                                
                           
                                                                                

                                                                           
                                          
raw_ostream &llvh::outs() {
                                                  
  std::error_code EC;
  static raw_fd_ostream S("-", EC, sys::fs::F_None);
  assert(!EC);
  return S;
}

                                                                          
                                          
raw_ostream &llvh::errs() {
                                                    
  static raw_fd_ostream S(STDERR_FILENO, false, true);
  return S;
}

                                                                              
raw_ostream &llvh::nulls() {
  static raw_null_ostream S;
  return S;
}

                                                                                
                      
                                                                                

raw_string_ostream::~raw_string_ostream() {
  flush();
}

void raw_string_ostream::write_impl(const char *Ptr, size_t Size) {
  OS.append(Ptr, Size);
}

                                                                                
                       
                                                                                

uint64_t raw_svector_ostream::current_pos() const { return OS.size(); }

void raw_svector_ostream::write_impl(const char *Ptr, size_t Size) {
  OS.append(Ptr, Ptr + Size);
}

void raw_svector_ostream::pwrite_impl(const char *Ptr, size_t Size,
                                      uint64_t Offset) {
  memcpy(OS.data() + Offset, Ptr, Size);
}

                                                                                
                    
                                                                                

raw_null_ostream::~raw_null_ostream() {
#ifndef NDEBUG
                                                                        
                                                                           
                                                                  
  flush();
#endif
}

void raw_null_ostream::write_impl(const char *Ptr, size_t Size) {
}

uint64_t raw_null_ostream::current_pos() const {
  return 0;
}

void raw_null_ostream::pwrite_impl(const char *Ptr, size_t Size,
                                   uint64_t Offset) {}

void raw_pwrite_stream::anchor() {}
