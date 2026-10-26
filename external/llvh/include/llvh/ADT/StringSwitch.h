//===--- StringSwitch.h - Switch-on-literal-string Construct --------------===/
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//===----------------------------------------------------------------------===/
//
//  This file implements the StringSwitch template, which mimics a switch()
//  statement whose cases are string literals.
//
//===----------------------------------------------------------------------===/
#ifndef LLVM_ADT_STRINGSWITCH_H
#define LLVM_ADT_STRINGSWITCH_H

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/Compiler.h"
#include <cassert>
#include <cstring>

namespace llvh {

                                                              
   
                                                                        
                                                                       
                                                                            
                                                                    
                                                                     
   
         
                                              
                       
                             
                             
                           
                         
                             
                                        
                             
            
template<typename T, typename R = T>
class StringSwitch {
                                 
  const StringRef Str;

                                                                     
                       
  Optional<T> Result;

public:
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  explicit StringSwitch(StringRef S)
  : Str(S), Result() { }

                                  
  StringSwitch(const StringSwitch &) = delete;

                                                               
  void operator=(const StringSwitch &) = delete;
  void operator=(StringSwitch &&other) = delete;

  StringSwitch(StringSwitch &&other)
    : Str(other.Str), Result(std::move(other.Result)) { }

  ~StringSwitch() = default;

                                 
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Case(StringLiteral S, T Value) {
    if (!Result && Str == S) {
      Result = std::move(Value);
    }
    return *this;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch& EndsWith(StringLiteral S, T Value) {
    if (!Result && Str.endswith(S)) {
      Result = std::move(Value);
    }
    return *this;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch& StartsWith(StringLiteral S, T Value) {
    if (!Result && Str.startswith(S)) {
      Result = std::move(Value);
    }
    return *this;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, T Value) {
    return Case(S0, Value).Case(S1, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      T Value) {
    return Case(S0, Value).Cases(S1, S2, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      StringLiteral S3, T Value) {
    return Case(S0, Value).Cases(S1, S2, S3, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      StringLiteral S3, StringLiteral S4, T Value) {
    return Case(S0, Value).Cases(S1, S2, S3, S4, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      StringLiteral S3, StringLiteral S4, StringLiteral S5,
                      T Value) {
    return Case(S0, Value).Cases(S1, S2, S3, S4, S5, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      StringLiteral S3, StringLiteral S4, StringLiteral S5,
                      StringLiteral S6, T Value) {
    return Case(S0, Value).Cases(S1, S2, S3, S4, S5, S6, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      StringLiteral S3, StringLiteral S4, StringLiteral S5,
                      StringLiteral S6, StringLiteral S7, T Value) {
    return Case(S0, Value).Cases(S1, S2, S3, S4, S5, S6, S7, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      StringLiteral S3, StringLiteral S4, StringLiteral S5,
                      StringLiteral S6, StringLiteral S7, StringLiteral S8,
                      T Value) {
    return Case(S0, Value).Cases(S1, S2, S3, S4, S5, S6, S7, S8, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &Cases(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                      StringLiteral S3, StringLiteral S4, StringLiteral S5,
                      StringLiteral S6, StringLiteral S7, StringLiteral S8,
                      StringLiteral S9, T Value) {
    return Case(S0, Value).Cases(S1, S2, S3, S4, S5, S6, S7, S8, S9, Value);
  }

                                    
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &CaseLower(StringLiteral S, T Value) {
    if (!Result && Str.equals_lower(S))
      Result = std::move(Value);

    return *this;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &EndsWithLower(StringLiteral S, T Value) {
    if (!Result && Str.endswith_lower(S))
      Result = Value;

    return *this;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &StartsWithLower(StringLiteral S, T Value) {
    if (!Result && Str.startswith_lower(S))
      Result = std::move(Value);

    return *this;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &CasesLower(StringLiteral S0, StringLiteral S1, T Value) {
    return CaseLower(S0, Value).CaseLower(S1, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &CasesLower(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                           T Value) {
    return CaseLower(S0, Value).CasesLower(S1, S2, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &CasesLower(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                           StringLiteral S3, T Value) {
    return CaseLower(S0, Value).CasesLower(S1, S2, S3, Value);
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StringSwitch &CasesLower(StringLiteral S0, StringLiteral S1, StringLiteral S2,
                           StringLiteral S3, StringLiteral S4, T Value) {
    return CaseLower(S0, Value).CasesLower(S1, S2, S3, S4, Value);
  }

  LLVM_NODISCARD
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  R Default(T Value) {
    if (Result)
      return std::move(*Result);
    return Value;
  }

  LLVM_NODISCARD
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  operator R() {
    assert(Result && "Fell off the end of a string-switch");
    return std::move(*Result);
  }
};

}                      

#endif                           
