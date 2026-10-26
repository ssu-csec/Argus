//===- Format.h - Efficient printf-style formatting for streams -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the format() function, which can be used with other
// LLVM subsystems to provide printf-style formatting.  This gives all the power
// and risk of printf.  This can be used like this (with raw_ostreams as an
// example):
//
//    OS << "mynumber: " << format("%4.5f", 1234.412) << '\n';
//
// Or if you prefer:
//
//  OS << format("mynumber: %4.5f\n", 1234.412);
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FORMAT_H
#define LLVM_SUPPORT_FORMAT_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/DataTypes.h"
#include <cassert>
#include <cstdio>
#include <tuple>

namespace llvh {

                                                                         
                                                     
class format_object_base {
protected:
  const char *Fmt;
  ~format_object_base() = default;                                  
  format_object_base(const format_object_base &) = default;
  virtual void home();                               

                                                                    
  virtual int snprint(char *Buffer, unsigned BufferSize) const = 0;

public:
  format_object_base(const char *fmt) : Fmt(fmt) {}

                                                                            
                                                                           
                                                                           
  unsigned print(char *Buffer, unsigned BufferSize) const {
    assert(BufferSize && "Invalid buffer size!");

                                                               
    int N = snprint(Buffer, BufferSize);

                                                                            
    if (N < 0)
      return BufferSize * 2;

                                                                            
                  
    if (unsigned(N) >= BufferSize)
      return N + 1;

                                                                          
    return N;
  }
};

                                                                       
                                                                           
                                                                             
                                            

                                                                       
template <typename... Args> struct validate_format_parameters;
template <typename Arg, typename... Args>
struct validate_format_parameters<Arg, Args...> {
  static_assert(std::is_scalar<Arg>::value,
                "format can't be used with non fundamental / non pointer type");
  validate_format_parameters() { validate_format_parameters<Args...>(); }
};
template <> struct validate_format_parameters<> {};

template <typename... Ts>
class format_object final : public format_object_base {
  std::tuple<Ts...> Vals;

  template <std::size_t... Is>
  int snprint_tuple(char *Buffer, unsigned BufferSize,
                    index_sequence<Is...>) const {
#ifdef _MSC_VER
    return _snprintf(Buffer, BufferSize, Fmt, std::get<Is>(Vals)...);
#else
    return snprintf(Buffer, BufferSize, Fmt, std::get<Is>(Vals)...);
#endif
  }

public:
  format_object(const char *fmt, const Ts &... vals)
      : format_object_base(fmt), Vals(vals...) {
    validate_format_parameters<Ts...>();
  }

  int snprint(char *Buffer, unsigned BufferSize) const override {
    return snprint_tuple(Buffer, BufferSize, index_sequence_for<Ts...>());
  }
};

                                                                          
                                                                        
                                                       
   
                                
         
                                             
            

template <typename... Ts>
inline format_object<Ts...> format(const char *Fmt, const Ts &... Vals) {
  return format_object<Ts...>(Fmt, Vals...);
}

                                                                               
class FormattedString {
public:
  enum Justification { JustifyNone, JustifyLeft, JustifyRight, JustifyCenter };
  FormattedString(StringRef S, unsigned W, Justification J)
      : Str(S), Width(W), Justify(J) {}

private:
  StringRef Str;
  unsigned Width;
  Justification Justify;
  friend class raw_ostream;
};

                                                                
                                                                        
                               
inline FormattedString left_justify(StringRef Str, unsigned Width) {
  return FormattedString(Str, Width, FormattedString::JustifyLeft);
}

                                                               
                                                                        
                               
inline FormattedString right_justify(StringRef Str, unsigned Width) {
  return FormattedString(Str, Width, FormattedString::JustifyRight);
}

                                                                          
                                                                        
                               
inline FormattedString center_justify(StringRef Str, unsigned Width) {
  return FormattedString(Str, Width, FormattedString::JustifyCenter);
}

                                                                      
class FormattedNumber {
  uint64_t HexValue;
  int64_t DecValue;
  unsigned Width;
  bool Hex;
  bool Upper;
  bool HexPrefix;
  friend class raw_ostream;

public:
  FormattedNumber(uint64_t HV, int64_t DV, unsigned W, bool H, bool U,
                  bool Prefix)
      : HexValue(HV), DecValue(DV), Width(W), Hex(H), Upper(U),
        HexPrefix(Prefix) {}
};

                                                                             
                                                          
                                                   
                                                   
                                                     
                                                   
inline FormattedNumber format_hex(uint64_t N, unsigned Width,
                                  bool Upper = false) {
  assert(Width <= 18 && "hex width must be <= 18");
  return FormattedNumber(N, 0, Width, true, Upper, true);
}

                                                                             
                                                                           
                                            
                                                           
                                                           
                                                             
                                                           
inline FormattedNumber format_hex_no_prefix(uint64_t N, unsigned Width,
                                            bool Upper = false) {
  assert(Width <= 16 && "hex width must be <= 16");
  return FormattedNumber(N, 0, Width, true, Upper, false);
}

                                                                              
                                                                          
                                               
                                               
                                             
                                               
inline FormattedNumber format_decimal(int64_t N, unsigned Width) {
  return FormattedNumber(0, N, Width, false, false, false);
}

class FormattedBytes {
  ArrayRef<uint8_t> Bytes;

                                                                           
  Optional<uint64_t> FirstByteOffset;
  uint32_t IndentLevel;                                              
  uint32_t NumPerLine;                                       
  uint8_t ByteGroupSize;                                                 
  bool Upper;                                                       
  bool ASCII;                                                                   
  friend class raw_ostream;

public:
  FormattedBytes(ArrayRef<uint8_t> B, uint32_t IL, Optional<uint64_t> O,
                 uint32_t NPL, uint8_t BGS, bool U, bool A)
      : Bytes(B), FirstByteOffset(O), IndentLevel(IL), NumPerLine(NPL),
        ByteGroupSize(BGS), Upper(U), ASCII(A) {

    if (ByteGroupSize > NumPerLine)
      ByteGroupSize = NumPerLine;
  }
};

inline FormattedBytes
format_bytes(ArrayRef<uint8_t> Bytes, Optional<uint64_t> FirstByteOffset = None,
             uint32_t NumPerLine = 16, uint8_t ByteGroupSize = 4,
             uint32_t IndentLevel = 0, bool Upper = false) {
  return FormattedBytes(Bytes, IndentLevel, FirstByteOffset, NumPerLine,
                        ByteGroupSize, Upper, false);
}

inline FormattedBytes
format_bytes_with_ascii(ArrayRef<uint8_t> Bytes,
                        Optional<uint64_t> FirstByteOffset = None,
                        uint32_t NumPerLine = 16, uint8_t ByteGroupSize = 4,
                        uint32_t IndentLevel = 0, bool Upper = false) {
  return FormattedBytes(Bytes, IndentLevel, FirstByteOffset, NumPerLine,
                        ByteGroupSize, Upper, true);
}

}                      

#endif
