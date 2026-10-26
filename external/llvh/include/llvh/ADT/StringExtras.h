//===- llvm/ADT/StringExtras.h - Useful string functions --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains some functions that are useful when dealing with strings.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_STRINGEXTRAS_H
#define LLVM_ADT_STRINGEXTRAS_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <string>
#include <utility>

namespace llvh {

template<typename T> class SmallVectorImpl;
class raw_ostream;

                                                       
                                                     
inline char hexdigit(unsigned X, bool LowerCase = false) {
  const char HexChar = LowerCase ? 'a' : 'A';
  return X < 10 ? '0' + X : HexChar + X - 10;
}

                                                                             
                                                                                
                
inline std::vector<StringRef> toStringRefArray(const char *const *Strings) {
  std::vector<StringRef> Result;
  while (*Strings)
    Result.push_back(*Strings++);
  return Result;
}

                                          
inline StringRef toStringRef(bool B) { return StringRef(B ? "true" : "false"); }

                                                               
inline StringRef toStringRef(ArrayRef<uint8_t> Input) {
  return StringRef(reinterpret_cast<const char *>(Input.begin()), Input.size());
}

                                                               
inline ArrayRef<uint8_t> arrayRefFromStringRef(StringRef Input) {
  return {Input.bytes_begin(), Input.bytes_end()};
}

                                                                            
          
   
                                                      
inline unsigned hexDigitValue(char C) {
  if (C >= '0' && C <= '9') return C-'0';
  if (C >= 'a' && C <= 'f') return C-'a'+10U;
  if (C >= 'A' && C <= 'F') return C-'A'+10U;
  return -1U;
}

                                                             
inline bool isDigit(char C) { return C >= '0' && C <= '9'; }

                                                                
inline bool isHexDigit(char C) { return hexDigitValue(C) != -1U; }

                                                                           
inline bool isAlpha(char C) {
  return ('a' <= C && C <= 'z') || ('A' <= C && C <= 'Z');
}

                                                                              
                                                 
inline bool isAlnum(char C) { return isAlpha(C) || isDigit(C); }

                                                                    
inline bool isASCII(char C) { return static_cast<unsigned char>(C) <= 127; }

                                                 
inline bool isASCII(llvh::StringRef S) {
  for (char C : S)
    if (LLVM_UNLIKELY(!isASCII(C)))
      return false;
  return true;
}

                                               
   
                                                                              
                                      
inline bool isPrint(char C) {
  unsigned char UC = static_cast<unsigned char>(C);
  return (0x20 <= UC) && (UC <= 0x7E);
}

                                                                       
inline char toLower(char x) {
  if (x >= 'A' && x <= 'Z')
    return x - 'A' + 'a';
  return x;
}

                                                                       
inline char toUpper(char x) {
  if (x >= 'a' && x <= 'z')
    return x - 'a' + 'A';
  return x;
}

inline std::string utohexstr(uint64_t X, bool LowerCase = false) {
  char Buffer[17];
  char *BufPtr = std::end(Buffer);

  if (X == 0) *--BufPtr = '0';

  while (X) {
    unsigned char Mod = static_cast<unsigned char>(X) & 15;
    *--BufPtr = hexdigit(Mod, LowerCase);
    X >>= 4;
  }

  return std::string(BufPtr, std::end(Buffer));
}

                                                              
                                                       
inline std::string toHex(StringRef Input, bool LowerCase = false) {
  static const char *const LUT = "0123456789ABCDEF";
  const uint8_t Offset = LowerCase ? 32 : 0;
  size_t Length = Input.size();

  std::string Output;
  Output.reserve(2 * Length);
  for (size_t i = 0; i < Length; ++i) {
    const unsigned char c = Input[i];
    Output.push_back(LUT[c >> 4] | Offset);
    Output.push_back(LUT[c & 15] | Offset);
  }
  return Output;
}

inline std::string toHex(ArrayRef<uint8_t> Input, bool LowerCase = false) {
  return toHex(toStringRef(Input), LowerCase);
}

inline uint8_t hexFromNibbles(char MSB, char LSB) {
  unsigned U1 = hexDigitValue(MSB);
  unsigned U2 = hexDigitValue(LSB);
  assert(U1 != -1U && U2 != -1U);

  return static_cast<uint8_t>((U1 << 4) | U2);
}

                                                                     
                                                   
inline std::string fromHex(StringRef Input) {
  if (Input.empty())
    return std::string();

  std::string Output;
  Output.reserve((Input.size() + 1) / 2);
  if (Input.size() % 2 == 1) {
    Output.push_back(hexFromNibbles('0', Input.front()));
    Input = Input.drop_front();
  }

  assert(Input.size() % 2 == 0);
  while (!Input.empty()) {
    uint8_t Hex = hexFromNibbles(Input[0], Input[1]);
    Output.push_back(Hex);
    Input = Input.drop_front(2);
  }
  return Output;
}

                                                                     
                                                                
                                                                           
template <typename N> bool to_integer(StringRef S, N &Num, unsigned Base = 0) {
  return !S.getAsInteger(Base, Num);
}

namespace detail {
template <typename N>
inline bool to_float(const Twine &T, N &Num, N (*StrTo)(const char *, char **)) {
  SmallString<32> Storage;
  StringRef S = T.toNullTerminatedStringRef(Storage);
  char *End;
  N Temp = StrTo(S.data(), &End);
  if (*End != '\0')
    return false;
  Num = Temp;
  return true;
}
}

inline bool to_float(const Twine &T, float &Num) {
  return detail::to_float(T, Num, strtof);
}

inline bool to_float(const Twine &T, double &Num) {
  return detail::to_float(T, Num, strtod);
}

#ifndef __ANDROID__
inline bool to_float(const Twine &T, long double &Num) {
  return detail::to_float(T, Num, strtold);
}
#endif

inline std::string utostr(uint64_t X, bool isNeg = false) {
  char Buffer[21];
  char *BufPtr = std::end(Buffer);

  if (X == 0) *--BufPtr = '0';                           

  while (X) {
    *--BufPtr = '0' + char(X % 10);
    X /= 10;
  }

  if (isNeg) *--BufPtr = '-';                          
  return std::string(BufPtr, std::end(Buffer));
}

inline std::string itostr(int64_t X) {
  if (X < 0)
    return utostr(static_cast<uint64_t>(-X), true);
  else
    return utostr(static_cast<uint64_t>(X));
}

                                                                       
                                                                     
                                                         
StringRef::size_type StrInStrNoCase(StringRef s1, StringRef s2);

                                                                         
                                                                           
                                                                            
                                                                          
                                                                      
                          
std::pair<StringRef, StringRef> getToken(StringRef Source,
                                         StringRef Delimiters = " \t\n\v\f\r");

                                                                          
                                                                  
void SplitString(StringRef Source,
                 SmallVectorImpl<StringRef> &OutFragments,
                 StringRef Delimiters = " \t\n\v\f\r");

                                                                           
inline StringRef getOrdinalSuffix(unsigned Val) {
                                                             
                                                   
  switch (Val % 100) {
  case 11:
  case 12:
  case 13:
    return "th";
  default:
    switch (Val % 10) {
      case 1: return "st";
      case 2: return "nd";
      case 3: return "rd";
      default: return "th";
    }
  }
}

                                                                          
                                         
void printEscapedString(StringRef Name, raw_ostream &Out);

                                                                       
               
void printHTMLEscaped(StringRef String, raw_ostream &Out);

                                                                          
void printLowerCase(StringRef String, raw_ostream &Out);

namespace detail {

template <typename IteratorT>
inline std::string join_impl(IteratorT Begin, IteratorT End,
                             StringRef Separator, std::input_iterator_tag) {
  std::string S;
  if (Begin == End)
    return S;

  S += (*Begin);
  while (++Begin != End) {
    S += Separator;
    S += (*Begin);
  }
  return S;
}

template <typename IteratorT>
inline std::string join_impl(IteratorT Begin, IteratorT End,
                             StringRef Separator, std::forward_iterator_tag) {
  std::string S;
  if (Begin == End)
    return S;

  size_t Len = (std::distance(Begin, End) - 1) * Separator.size();
  for (IteratorT I = Begin; I != End; ++I)
    Len += (*Begin).size();
  S.reserve(Len);
  S += (*Begin);
  while (++Begin != End) {
    S += Separator;
    S += (*Begin);
  }
  return S;
}

template <typename Sep>
inline void join_items_impl(std::string &Result, Sep Separator) {}

template <typename Sep, typename Arg>
inline void join_items_impl(std::string &Result, Sep Separator,
                            const Arg &Item) {
  Result += Item;
}

template <typename Sep, typename Arg1, typename... Args>
inline void join_items_impl(std::string &Result, Sep Separator, const Arg1 &A1,
                            Args &&... Items) {
  Result += A1;
  Result += Separator;
  join_items_impl(Result, Separator, std::forward<Args>(Items)...);
}

inline size_t join_one_item_size(char C) { return 1; }
inline size_t join_one_item_size(const char *S) { return S ? ::strlen(S) : 0; }

template <typename T> inline size_t join_one_item_size(const T &Str) {
  return Str.size();
}

inline size_t join_items_size() { return 0; }

template <typename A1> inline size_t join_items_size(const A1 &A) {
  return join_one_item_size(A);
}
template <typename A1, typename... Args>
inline size_t join_items_size(const A1 &A, Args &&... Items) {
  return join_one_item_size(A) + join_items_size(std::forward<Args>(Items)...);
}

}                        

                                                                         
                 
template <typename IteratorT>
inline std::string join(IteratorT Begin, IteratorT End, StringRef Separator) {
  using tag = typename std::iterator_traits<IteratorT>::iterator_category;
  return detail::join_impl(Begin, End, Separator, tag());
}

                                                                         
                         
template <typename Range>
inline std::string join(Range &&R, StringRef Separator) {
  return join(R.begin(), R.end(), Separator);
}

                                                                         
                                                                          
                                                                            
                                         
template <typename Sep, typename... Args>
inline std::string join_items(Sep Separator, Args &&... Items) {
  std::string Result;
  if (sizeof...(Items) == 0)
    return Result;

  size_t NS = detail::join_one_item_size(Separator);
  size_t NI = detail::join_items_size(std::forward<Args>(Items)...);
  Result.reserve(NI + (sizeof...(Items) - 1) * NS + 1);
  detail::join_items_impl(Result, Separator, std::forward<Args>(Items)...);
  return Result;
}

}                      

#endif                           
