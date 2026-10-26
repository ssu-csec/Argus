//===- FormatVariadic.h - Efficient type-safe string formatting --*- C++-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the formatv() function which can be used with other LLVM
// subsystems to provide printf-like formatting, but with improved safety and
// flexibility.  The result of `formatv` is an object which can be streamed to
// a raw_ostream or converted to a std::string or llvh::SmallString.
//
//   // Convert to std::string.
//   std::string S = formatv("{0} {1}", 1234.412, "test").str();
//
//   // Convert to llvh::SmallString
//   SmallString<8> S = formatv("{0} {1}", 1234.412, "test").sstr<8>();
//
//   // Stream to an existing raw_ostream.
//   OS << formatv("{0} {1}", 1234.412, "test");
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FORMATVARIADIC_H
#define LLVM_SUPPORT_FORMATVARIADIC_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/FormatCommon.h"
#include "llvh/Support/FormatProviders.h"
#include "llvh/Support/FormatVariadicDetails.h"
#include "llvh/Support/raw_ostream.h"
#include <cstddef>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace llvh {

enum class ReplacementType { Empty, Format, Literal };

struct ReplacementItem {
  ReplacementItem() = default;
  explicit ReplacementItem(StringRef Literal)
      : Type(ReplacementType::Literal), Spec(Literal) {}
  ReplacementItem(StringRef Spec, size_t Index, size_t Align, AlignStyle Where,
                  char Pad, StringRef Options)
      : Type(ReplacementType::Format), Spec(Spec), Index(Index), Align(Align),
        Where(Where), Pad(Pad), Options(Options) {}

  ReplacementType Type = ReplacementType::Empty;
  StringRef Spec;
  size_t Index = 0;
  size_t Align = 0;
  AlignStyle Where = AlignStyle::Right;
  char Pad;
  StringRef Options;
};

class formatv_object_base {
protected:
                                                                              
                                                                             
                                                                              
                                                                        
                                                                                
                                                                     
                        
  struct create_adapters {
    template <typename... Ts>
    std::vector<detail::format_adapter *> operator()(Ts &... Items) {
      return std::vector<detail::format_adapter *>{&Items...};
    }
  };

  StringRef Fmt;
  std::vector<detail::format_adapter *> Adapters;
  std::vector<ReplacementItem> Replacements;

  static bool consumeFieldLayout(StringRef &Spec, AlignStyle &Where,
                                 size_t &Align, char &Pad);

  static std::pair<ReplacementItem, StringRef>
  splitLiteralAndReplacement(StringRef Fmt);

public:
  formatv_object_base(StringRef Fmt, std::size_t ParamCount)
      : Fmt(Fmt), Replacements(parseFormatString(Fmt)) {
    Adapters.reserve(ParamCount);
  }

  formatv_object_base(formatv_object_base const &rhs) = delete;

  formatv_object_base(formatv_object_base &&rhs)
      : Fmt(std::move(rhs.Fmt)),
        Adapters(),                                              
        Replacements(std::move(rhs.Replacements)) {
    Adapters.reserve(rhs.Adapters.size());
  };

  void format(raw_ostream &S) const {
    for (auto &R : Replacements) {
      if (R.Type == ReplacementType::Empty)
        continue;
      if (R.Type == ReplacementType::Literal) {
        S << R.Spec;
        continue;
      }
      if (R.Index >= Adapters.size()) {
        S << R.Spec;
        continue;
      }

      auto W = Adapters[R.Index];

      FmtAlign Align(*W, R.Where, R.Align, R.Pad);
      Align.format(S, R.Options);
    }
  }
  static std::vector<ReplacementItem> parseFormatString(StringRef Fmt);

  static Optional<ReplacementItem> parseReplacementItem(StringRef Spec);

  std::string str() const {
    std::string Result;
    raw_string_ostream Stream(Result);
    Stream << *this;
    Stream.flush();
    return Result;
  }

  template <unsigned N> SmallString<N> sstr() const {
    SmallString<N> Result;
    raw_svector_ostream Stream(Result);
    Stream << *this;
    return Result;
  }

  template <unsigned N> operator SmallString<N>() const { return sstr<N>(); }

  operator std::string() const { return str(); }
};

template <typename Tuple> class formatv_object : public formatv_object_base {
                                                                              
                                                                               
                                                                    
  Tuple Parameters;

public:
  formatv_object(StringRef Fmt, Tuple &&Params)
      : formatv_object_base(Fmt, std::tuple_size<Tuple>::value),
        Parameters(std::move(Params)) {
    Adapters = apply_tuple(create_adapters(), Parameters);
  }

  formatv_object(formatv_object const &rhs) = delete;

  formatv_object(formatv_object &&rhs)
      : formatv_object_base(std::move(rhs)),
        Parameters(std::move(rhs.Parameters)) {
    Adapters = apply_tuple(create_adapters(), Parameters);
  }
};

                                                                
  
                            
  
                                                                       
                                                    
  
                                                          
                                       
                                   
                                                       
                                                  
                                
                                   
  
                                                                           
                                                                  
                                                                                
                   
                                                                          
                                                                         
                                                                      
                                                                            
                                     
                                                                               
                                       
                                                                        
                                                                    
                                                                              
                                   
                                                                             
                                                                               
                                                                            
                                                                            
                                                                                
                                                               
  
                           
  
                                                                              
                                                                              
                                                                             
                               
  
                           
                                                                               
                                                                            
                                                                            
                                                                                
                         
  
                                      
  
                                                                              
                                                                             
                          
  
                         
  
                                                                             
                          
  
                                                                            
                                                                            
                                                                     
                                                                           
                                                          
                                                                         
                                                           
                                                                             
                                                                              
  
                                                                             
                      
  
                                       
  
                                                                            
                                                                              
                                                                                
                                             
  
template <typename... Ts>
inline auto formatv(const char *Fmt, Ts &&... Vals) -> formatv_object<decltype(
    std::make_tuple(detail::build_format_adapter(std::forward<Ts>(Vals))...))> {
  using ParamTuple = decltype(
      std::make_tuple(detail::build_format_adapter(std::forward<Ts>(Vals))...));
  return formatv_object<ParamTuple>(
      Fmt,
      std::make_tuple(detail::build_format_adapter(std::forward<Ts>(Vals))...));
}

}                      

#endif                                 
