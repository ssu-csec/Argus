//===- FormatProviders.h - Formatters for common LLVM types -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements format providers for many common LLVM types, for example
// allowing precision and width specifiers for scalar and string types.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FORMATPROVIDERS_H
#define LLVM_SUPPORT_FORMATPROVIDERS_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringSwitch.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/FormatVariadicDetails.h"
#include "llvh/Support/NativeFormatting.h"

#include <type_traits>
#include <vector>

namespace llvh {
namespace detail {
template <typename T>
struct use_integral_formatter
    : public std::integral_constant<
          bool, is_one_of<T, uint8_t, int16_t, uint16_t, int32_t, uint32_t,
                          int64_t, uint64_t, int, unsigned, long, unsigned long,
                          long long, unsigned long long>::value> {};

template <typename T>
struct use_char_formatter
    : public std::integral_constant<bool, std::is_same<T, char>::value> {};

template <typename T>
struct is_cstring
    : public std::integral_constant<bool,
                                    is_one_of<T, char *, const char *>::value> {
};

template <typename T>
struct use_string_formatter
    : public std::integral_constant<bool,
                                    std::is_convertible<T, llvh::StringRef>::value> {};

template <typename T>
struct use_pointer_formatter
    : public std::integral_constant<bool, std::is_pointer<T>::value &&
                                              !is_cstring<T>::value> {};

template <typename T>
struct use_double_formatter
    : public std::integral_constant<bool, std::is_floating_point<T>::value> {};

class HelperFunctions {
protected:
  static Optional<size_t> parseNumericPrecision(StringRef Str) {
    size_t Prec;
    Optional<size_t> Result;
    if (Str.empty())
      Result = None;
    else if (Str.getAsInteger(10, Prec)) {
      assert(false && "Invalid precision specifier");
      Result = None;
    } else {
      assert(Prec < 100 && "Precision out of range");
      Result = std::min<size_t>(99u, Prec);
    }
    return Result;
  }

  static bool consumeHexStyle(StringRef &Str, HexPrintStyle &Style) {
    if (!Str.startswith_lower("x"))
      return false;

    if (Str.consume_front("x-"))
      Style = HexPrintStyle::Lower;
    else if (Str.consume_front("X-"))
      Style = HexPrintStyle::Upper;
    else if (Str.consume_front("x+") || Str.consume_front("x"))
      Style = HexPrintStyle::PrefixLower;
    else if (Str.consume_front("X+") || Str.consume_front("X"))
      Style = HexPrintStyle::PrefixUpper;
    return true;
  }

  static size_t consumeNumHexDigits(StringRef &Str, HexPrintStyle Style,
                                    size_t Default) {
    Str.consumeInteger(10, Default);
    if (isPrefixedHexStyle(Style))
      Default += 2;
    return Default;
  }
};
}

                                                                       
   
                                                           
   
                                          
                                            
                                                      
   
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
   

template <typename T>
struct format_provider<
    T, typename std::enable_if<detail::use_integral_formatter<T>::value>::type>
    : public detail::HelperFunctions {
private:
public:
  static void format(const T &V, llvh::raw_ostream &Stream, StringRef Style) {
    HexPrintStyle HS;
    size_t Digits = 0;
    if (consumeHexStyle(Style, HS)) {
      Digits = consumeNumHexDigits(Style, HS, 0);
      write_hex(Stream, V, HS, Digits);
      return;
    }

    IntegerStyle IS = IntegerStyle::Integer;
    if (Style.consume_front("N") || Style.consume_front("n"))
      IS = IntegerStyle::Number;
    else if (Style.consume_front("D") || Style.consume_front("d"))
      IS = IntegerStyle::Integer;

    Style.consumeInteger(10, Digits);
    assert(Style.empty() && "Invalid integral format style!");
    write_integer(Stream, V, Digits, IS);
  }
};

                                                                    
   
                                                         
   
                                             
                                            
                                                                 
   
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
   
                                                                                
                                                           
template <typename T>
struct format_provider<
    T, typename std::enable_if<detail::use_pointer_formatter<T>::value>::type>
    : public detail::HelperFunctions {
private:
public:
  static void format(const T &V, llvh::raw_ostream &Stream, StringRef Style) {
    HexPrintStyle HS = HexPrintStyle::PrefixUpper;
    consumeHexStyle(Style, HS);
    size_t Digits = consumeNumHexDigits(Style, HS, sizeof(void *) * 2);
    write_hex(Stream, reinterpret_cast<std::uintptr_t>(V), HS, Digits);
  }
};

                                                                       
                                                    
   
                                                        
   
                                
   
                                                                          
                                                                             
                                      

template <typename T>
struct format_provider<
    T, typename std::enable_if<detail::use_string_formatter<T>::value>::type> {
  static void format(const T &V, llvh::raw_ostream &Stream, StringRef Style) {
    size_t N = StringRef::npos;
    if (!Style.empty() && Style.getAsInteger(10, N)) {
      assert(false && "Style is not a valid integer");
    }
    llvh::StringRef S = V;
    Stream << S.substr(0, N);
  }
};

                                                         
   
                                                        

template <> struct format_provider<Twine> {
  static void format(const Twine &V, llvh::raw_ostream &Stream,
                     StringRef Style) {
    format_provider<std::string>::format(V.str(), Stream, Style);
  }
};

                                                        
   
                                                           
   
                                                 
   
                                                                      
                                                                      
   
template <typename T>
struct format_provider<
    T, typename std::enable_if<detail::use_char_formatter<T>::value>::type> {
  static void format(const char &V, llvh::raw_ostream &Stream,
                     StringRef Style) {
    if (Style.empty())
      Stream << V;
    else {
      int X = static_cast<int>(V);
      format_provider<int>::format(X, Stream, Style);
    }
  }
};

                                                        
   
                                                         
   
                                                            
   
                                        
                                        
                                        
                                        
                                        
                                        
                                        
                                        
                                        
                                        
template <> struct format_provider<bool> {
  static void format(const bool &B, llvh::raw_ostream &Stream,
                     StringRef Style) {
    Stream << StringSwitch<const char *>(Style)
                  .Case("Y", B ? "YES" : "NO")
                  .Case("y", B ? "yes" : "no")
                  .CaseLower("D", B ? "1" : "0")
                  .Case("T", B ? "TRUE" : "FALSE")
                  .Cases("t", "", B ? "true" : "false")
                  .Default(B ? "1" : "0");
  }
};

                                                                  
   
                                                               
   
                                           
                                          
                                                    
   
                                                           
                                                           
                                                           
                                                           
                                                           
                                                           
                                                           
                                                           
                                                           
                                                           
                                                           
   
                                                                           
         

template <typename T>
struct format_provider<
    T, typename std::enable_if<detail::use_double_formatter<T>::value>::type>
    : public detail::HelperFunctions {
  static void format(const T &V, llvh::raw_ostream &Stream, StringRef Style) {
    FloatStyle S;
    if (Style.consume_front("P") || Style.consume_front("p"))
      S = FloatStyle::Percent;
    else if (Style.consume_front("F") || Style.consume_front("f"))
      S = FloatStyle::Fixed;
    else if (Style.consume_front("E"))
      S = FloatStyle::ExponentUpper;
    else if (Style.consume_front("e"))
      S = FloatStyle::Exponent;
    else
      S = FloatStyle::Fixed;

    Optional<size_t> Precision = parseNumericPrecision(Style);
    if (!Precision.hasValue())
      Precision = getDefaultPrecision(S);

    write_double(Stream, static_cast<double>(V), S, Precision);
  }
};

namespace detail {
template <typename IterT>
using IterValue = typename std::iterator_traits<IterT>::value_type;

template <typename IterT>
struct range_item_has_provider
    : public std::integral_constant<
          bool, !uses_missing_provider<IterValue<IterT>>::value> {};
}

                                                    
   
                                                                        
   
                                                       
   
                                                       
                                              
                                              
                                                                      
                                                                 
   
                                                                              
                                                                                
                                                                          
                                                                              
                                                                              
                             
   
                                                                         
                                                               
   

template <typename IterT> class format_provider<llvh::iterator_range<IterT>> {
  using value = typename std::iterator_traits<IterT>::value_type;
  using reference = typename std::iterator_traits<IterT>::reference;

  static StringRef consumeOneOption(StringRef &Style, char Indicator,
                                    StringRef Default) {
    if (Style.empty())
      return Default;
    if (Style.front() != Indicator)
      return Default;
    Style = Style.drop_front();
    if (Style.empty()) {
      assert(false && "Invalid range style");
      return Default;
    }

    for (const char *D : {"[]", "<>", "()"}) {
      if (Style.front() != D[0])
        continue;
      size_t End = Style.find_first_of(D[1]);
      if (End == StringRef::npos) {
        assert(false && "Missing range option end delimeter!");
        return Default;
      }
      StringRef Result = Style.slice(1, End);
      Style = Style.drop_front(End + 1);
      return Result;
    }
    assert(false && "Invalid range style!");
    return Default;
  }

  static std::pair<StringRef, StringRef> parseOptions(StringRef Style) {
    StringRef Sep = consumeOneOption(Style, '$', ", ");
    StringRef Args = consumeOneOption(Style, '@', "");
    assert(Style.empty() && "Unexpected text in range option string!");
    return std::make_pair(Sep, Args);
  }

public:
  static_assert(detail::range_item_has_provider<IterT>::value,
                "Range value_type does not have a format provider!");
  static void format(const llvh::iterator_range<IterT> &V,
                     llvh::raw_ostream &Stream, StringRef Style) {
    StringRef Sep;
    StringRef ArgStyle;
    std::tie(Sep, ArgStyle) = parseOptions(Style);
    auto Begin = V.begin();
    auto End = V.end();
    if (Begin != End) {
      auto Adapter =
          detail::build_format_adapter(std::forward<reference>(*Begin));
      Adapter.format(Stream, ArgStyle);
      ++Begin;
    }
    while (Begin != End) {
      Stream << Sep;
      auto Adapter =
          detail::build_format_adapter(std::forward<reference>(*Begin));
      Adapter.format(Stream, ArgStyle);
      ++Begin;
    }
  }
};
}

#endif
