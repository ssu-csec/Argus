//===- llvm/Support/YAMLTraits.h --------------------------------*- C++ -*-===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_YAMLTRAITS_H
#define LLVM_SUPPORT_YAMLTRAITS_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/AlignOf.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/Endian.h"
#include "llvh/Support/Regex.h"
#include "llvh/Support/SourceMgr.h"
#include "llvh/Support/YAMLParser.h"
#include "llvh/Support/raw_ostream.h"
#include <cassert>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace llvh {
namespace yaml {

struct EmptyContext {};

                                                                           
                                         
   
                                        
                                                    
                                           
                                           
                                          
           
          
template<class T>
struct MappingTraits {
                  
                                            
                            
                                                  
    
                                                                           
                           
                                   
};

                                                                       
                                                            
   
                                                          
                                                                  
                                           
                                           
                                          
                            
           
          
template <class T, class Context> struct MappingContextTraits {
                  
                                                          
                            
                                                                
    
                                                                           
                           
                                   
};

                                                                       
                                                                     
                                                        
   
                                                
                                                            
                                                
                                                 
                                                  
             
            
template<typename T>
struct ScalarEnumerationTraits {
                  
                                               
};

                                                                        
                                                                   
                          
   
                                             
                                                       
                                                    
                                                     
                                                      
            
           
template<typename T>
struct ScalarBitSetTraits {
                  
                                          
};

                                                                           
                                                                             
                                                                  
enum class QuotingType { None, Single, Double };

                                                                            
                                        
   
                 
                                    
                                                                               
                                          
                                          
          
                                                                         
                                          
                                                             
                              
          
                                                                                
         
template<typename T>
struct ScalarTraits {
                  
    
                                             
                                                                           
    
                                                                
                                                                    
                                                                   
    
                                                         
                                            
};

                                                                            
                                                     
   
                  
                                         
                                                                               
          
                                          
                      
          
                                                                         
                                          
                                                             
                              
          
         
template <typename T>
struct BlockScalarTraits {
                  
    
                                             
                                                                           
    
                                                                
                                                                    
                                                                    
};

                                                                           
                                          
   
                 
                                           
                                                       
                             
          
                                                                       
                                     
                                 
                             
          
         
template<typename T, typename EnableIf = void>
struct SequenceTraits {
                  
                                        
                                                                 
    
                                                                 
                                    
                                   
};

                                                                          
                                                      
template<typename T, typename EnableIf = void>
struct SequenceElementTraits {
                  
                            
};

                                                                           
                                     
template<typename T>
struct DocumentListTraits {
                  
                                        
                                                                 
};

                                                                           
                                                                                
                                  
template <typename T>
struct CustomMappingTraits {
                                                          
                                         
};

                                                     
template <typename T>
struct MissingTrait;

                                                           
template <class T>
struct has_ScalarEnumerationTraits
{
  using Signature_enumeration = void (*)(class IO&, T&);

  template <typename U>
  static char test(SameType<Signature_enumeration, &U::enumeration>*);

  template <typename U>
  static double test(...);

public:
  static bool const value =
    (sizeof(test<ScalarEnumerationTraits<T>>(nullptr)) == 1);
};

                                                      
template <class T>
struct has_ScalarBitSetTraits
{
  using Signature_bitset = void (*)(class IO&, T&);

  template <typename U>
  static char test(SameType<Signature_bitset, &U::bitset>*);

  template <typename U>
  static double test(...);

public:
  static bool const value = (sizeof(test<ScalarBitSetTraits<T>>(nullptr)) == 1);
};

                                                
template <class T>
struct has_ScalarTraits
{
  using Signature_input = StringRef (*)(StringRef, void*, T&);
  using Signature_output = void (*)(const T&, void*, raw_ostream&);
  using Signature_mustQuote = QuotingType (*)(StringRef);

  template <typename U>
  static char test(SameType<Signature_input, &U::input> *,
                   SameType<Signature_output, &U::output> *,
                   SameType<Signature_mustQuote, &U::mustQuote> *);

  template <typename U>
  static double test(...);

public:
  static bool const value =
      (sizeof(test<ScalarTraits<T>>(nullptr, nullptr, nullptr)) == 1);
};

                                                     
template <class T>
struct has_BlockScalarTraits
{
  using Signature_input = StringRef (*)(StringRef, void *, T &);
  using Signature_output = void (*)(const T &, void *, raw_ostream &);

  template <typename U>
  static char test(SameType<Signature_input, &U::input> *,
                   SameType<Signature_output, &U::output> *);

  template <typename U>
  static double test(...);

public:
  static bool const value =
      (sizeof(test<BlockScalarTraits<T>>(nullptr, nullptr)) == 1);
};

                                                        
template <class T, class Context> struct has_MappingTraits {
  using Signature_mapping = void (*)(class IO &, T &, Context &);

  template <typename U>
  static char test(SameType<Signature_mapping, &U::mapping>*);

  template <typename U>
  static double test(...);

public:
  static bool const value =
      (sizeof(test<MappingContextTraits<T, Context>>(nullptr)) == 1);
};

                                                 
template <class T> struct has_MappingTraits<T, EmptyContext> {
  using Signature_mapping = void (*)(class IO &, T &);

  template <typename U>
  static char test(SameType<Signature_mapping, &U::mapping> *);

  template <typename U> static double test(...);

public:
  static bool const value = (sizeof(test<MappingTraits<T>>(nullptr)) == 1);
};

                                                                    
template <class T, class Context> struct has_MappingValidateTraits {
  using Signature_validate = StringRef (*)(class IO &, T &, Context &);

  template <typename U>
  static char test(SameType<Signature_validate, &U::validate>*);

  template <typename U>
  static double test(...);

public:
  static bool const value =
      (sizeof(test<MappingContextTraits<T, Context>>(nullptr)) == 1);
};

                                                             
template <class T> struct has_MappingValidateTraits<T, EmptyContext> {
  using Signature_validate = StringRef (*)(class IO &, T &);

  template <typename U>
  static char test(SameType<Signature_validate, &U::validate> *);

  template <typename U> static double test(...);

public:
  static bool const value = (sizeof(test<MappingTraits<T>>(nullptr)) == 1);
};

                                                  
template <class T>
struct has_SequenceMethodTraits
{
  using Signature_size = size_t (*)(class IO&, T&);

  template <typename U>
  static char test(SameType<Signature_size, &U::size>*);

  template <typename U>
  static double test(...);

public:
  static bool const value =  (sizeof(test<SequenceTraits<T>>(nullptr)) == 1);
};

                                                       
template <class T>
struct has_CustomMappingTraits
{
  using Signature_input = void (*)(IO &io, StringRef key, T &v);

  template <typename U>
  static char test(SameType<Signature_input, &U::inputOne>*);

  template <typename U>
  static double test(...);

public:
  static bool const value =
      (sizeof(test<CustomMappingTraits<T>>(nullptr)) == 1);
};

                                                                      
                                                               
                                                            
template <typename T, bool Enabled = std::is_class<T>::value>
class has_FlowTraits
{
public:
   static const bool value = false;
};

                                                                
                                                                   
                                    
template <class T>
struct has_FlowTraits<T, true>
{
  struct Fallback { bool flow; };
  struct Derived : T, Fallback { };

  template<typename C>
  static char (&f(SameType<bool Fallback::*, &C::flow>*))[1];

  template<typename C>
  static char (&f(...))[2];

public:
  static bool const value = sizeof(f<Derived>(nullptr)) == 2;
};

                                                 
template<typename T>
struct has_SequenceTraits : public std::integral_constant<bool,
                                      has_SequenceMethodTraits<T>::value > { };

                                                     
template <class T>
struct has_DocumentListTraits
{
  using Signature_size = size_t (*)(class IO &, T &);

  template <typename U>
  static char test(SameType<Signature_size, &U::size>*);

  template <typename U>
  static double test(...);

public:
  static bool const value = (sizeof(test<DocumentListTraits<T>>(nullptr))==1);
};

inline bool isNumeric(StringRef S) {
  const static auto skipDigits = [](StringRef Input) {
    return Input.drop_front(
        std::min(Input.find_first_not_of("0123456789"), Input.size()));
  };

                                                                           
          
  if (S.empty() || S.equals("+") || S.equals("-"))
    return false;

  if (S.equals(".nan") || S.equals(".NaN") || S.equals(".NAN"))
    return true;

                                                            
  StringRef Tail = (S.front() == '-' || S.front() == '+') ? S.drop_front() : S;

                                                                               
               
  if (Tail.equals(".inf") || Tail.equals(".Inf") || Tail.equals(".INF"))
    return true;

                                  
                                                                              
                                               
  if (S.startswith("0o"))
    return S.size() > 2 &&
           S.drop_front(2).find_first_not_of("01234567") == StringRef::npos;

  if (S.startswith("0x"))
    return S.size() > 2 && S.drop_front(2).find_first_not_of(
                               "0123456789abcdefABCDEF") == StringRef::npos;

                                                                               
  S = Tail;

                                                                              
                                                                                
                      
  if (S.startswith(".") &&
      (S.equals(".") ||
       (S.size() > 1 && std::strchr("0123456789", S[1]) == nullptr)))
    return false;

  if (S.startswith("E") || S.startswith("e"))
    return false;

  enum ParseState {
    Default,
    FoundDot,
    FoundExponent,
  };
  ParseState State = Default;

  S = skipDigits(S);

                            
  if (S.empty())
    return true;

  if (S.front() == '.') {
    State = FoundDot;
    S = S.drop_front();
  } else if (S.front() == 'e' || S.front() == 'E') {
    State = FoundExponent;
    S = S.drop_front();
  } else {
    return false;
  }

  if (State == FoundDot) {
    S = skipDigits(S);
    if (S.empty())
      return true;

    if (S.front() == 'e' || S.front() == 'E') {
      State = FoundExponent;
      S = S.drop_front();
    } else {
      return false;
    }
  }

  assert(State == FoundExponent && "Should have found exponent at this point.");
  if (S.empty())
    return false;

  if (S.front() == '+' || S.front() == '-') {
    S = S.drop_front();
    if (S.empty())
      return false;
  }

  return skipDigits(S).empty();
}

inline bool isNull(StringRef S) {
  return S.equals("null") || S.equals("Null") || S.equals("NULL") ||
         S.equals("~");
}

inline bool isBool(StringRef S) {
  return S.equals("true") || S.equals("True") || S.equals("TRUE") ||
         S.equals("false") || S.equals("False") || S.equals("FALSE");
}

                     
                                                                                
                                                                               
                                                                                
                                           
inline QuotingType needsQuotes(StringRef S) {
  if (S.empty())
    return QuotingType::Single;
  if (isspace(S.front()) || isspace(S.back()))
    return QuotingType::Single;
  if (isNull(S))
    return QuotingType::Single;
  if (isBool(S))
    return QuotingType::Single;
  if (isNumeric(S))
    return QuotingType::Single;

                      
                                                                           
                                          
  static constexpr char Indicators[] = R"(-?:\,[]{}#&*!|>'"%@`)";
  if (S.find_first_of(Indicators) == 0)
    return QuotingType::Single;

  QuotingType MaxQuotingNeeded = QuotingType::None;
  for (unsigned char C : S) {
                        
    if (isAlnum(C))
      continue;

    switch (C) {
                              
    case '_':
    case '-':
    case '/':
    case '^':
    case '.':
    case ',':
    case ' ':
                                                
    case 0x9:
      continue;
                                                                            
              
    case 0xA:
    case 0xD:
      MaxQuotingNeeded = QuotingType::Single;
      continue;
                                                                
    case 0x7F:
      return QuotingType::Double;
    default: {
                                                                             
               
      if (C <= 0x1F)
        return QuotingType::Double;

                                   
      if ((C & 0x80) != 0)
        return QuotingType::Double;

                                                                   
      MaxQuotingNeeded = QuotingType::Single;
    }
    }
  }

  return MaxQuotingNeeded;
}

template <typename T, typename Context>
struct missingTraits
    : public std::integral_constant<bool,
                                    !has_ScalarEnumerationTraits<T>::value &&
                                        !has_ScalarBitSetTraits<T>::value &&
                                        !has_ScalarTraits<T>::value &&
                                        !has_BlockScalarTraits<T>::value &&
                                        !has_MappingTraits<T, Context>::value &&
                                        !has_SequenceTraits<T>::value &&
                                        !has_CustomMappingTraits<T>::value &&
                                        !has_DocumentListTraits<T>::value> {};

template <typename T, typename Context>
struct validatedMappingTraits
    : public std::integral_constant<
          bool, has_MappingTraits<T, Context>::value &&
                    has_MappingValidateTraits<T, Context>::value> {};

template <typename T, typename Context>
struct unvalidatedMappingTraits
    : public std::integral_constant<
          bool, has_MappingTraits<T, Context>::value &&
                    !has_MappingValidateTraits<T, Context>::value> {};

                                   
class IO {
public:
  IO(void *Ctxt = nullptr);
  virtual ~IO();

  virtual bool outputting() = 0;

  virtual unsigned beginSequence() = 0;
  virtual bool preflightElement(unsigned, void *&) = 0;
  virtual void postflightElement(void*) = 0;
  virtual void endSequence() = 0;
  virtual bool canElideEmptySequence() = 0;

  virtual unsigned beginFlowSequence() = 0;
  virtual bool preflightFlowElement(unsigned, void *&) = 0;
  virtual void postflightFlowElement(void*) = 0;
  virtual void endFlowSequence() = 0;

  virtual bool mapTag(StringRef Tag, bool Default=false) = 0;
  virtual void beginMapping() = 0;
  virtual void endMapping() = 0;
  virtual bool preflightKey(const char*, bool, bool, bool &, void *&) = 0;
  virtual void postflightKey(void*) = 0;
  virtual std::vector<StringRef> keys() = 0;

  virtual void beginFlowMapping() = 0;
  virtual void endFlowMapping() = 0;

  virtual void beginEnumScalar() = 0;
  virtual bool matchEnumScalar(const char*, bool) = 0;
  virtual bool matchEnumFallback() = 0;
  virtual void endEnumScalar() = 0;

  virtual bool beginBitSetScalar(bool &) = 0;
  virtual bool bitSetMatch(const char*, bool) = 0;
  virtual void endBitSetScalar() = 0;

  virtual void scalarString(StringRef &, QuotingType) = 0;
  virtual void blockScalarString(StringRef &) = 0;

  virtual void setError(const Twine &) = 0;

  template <typename T>
  void enumCase(T &Val, const char* Str, const T ConstVal) {
    if ( matchEnumScalar(Str, outputting() && Val == ConstVal) ) {
      Val = ConstVal;
    }
  }

                                                                         
  template <typename T>
  void enumCase(T &Val, const char* Str, const uint32_t ConstVal) {
    if ( matchEnumScalar(Str, outputting() && Val == static_cast<T>(ConstVal)) ) {
      Val = ConstVal;
    }
  }

  template <typename FBT, typename T>
  void enumFallback(T &Val) {
    if (matchEnumFallback()) {
      EmptyContext Context;
                                                                              
      FBT Res = static_cast<typename FBT::BaseType>(Val);
      yamlize(*this, Res, true, Context);
      Val = static_cast<T>(static_cast<typename FBT::BaseType>(Res));
    }
  }

  template <typename T>
  void bitSetCase(T &Val, const char* Str, const T ConstVal) {
    if ( bitSetMatch(Str, outputting() && (Val & ConstVal) == ConstVal) ) {
      Val = static_cast<T>(Val | ConstVal);
    }
  }

                                                                         
  template <typename T>
  void bitSetCase(T &Val, const char* Str, const uint32_t ConstVal) {
    if ( bitSetMatch(Str, outputting() && (Val & ConstVal) == ConstVal) ) {
      Val = static_cast<T>(Val | ConstVal);
    }
  }

  template <typename T>
  void maskedBitSetCase(T &Val, const char *Str, T ConstVal, T Mask) {
    if (bitSetMatch(Str, outputting() && (Val & Mask) == ConstVal))
      Val = Val | ConstVal;
  }

  template <typename T>
  void maskedBitSetCase(T &Val, const char *Str, uint32_t ConstVal,
                        uint32_t Mask) {
    if (bitSetMatch(Str, outputting() && (Val & Mask) == ConstVal))
      Val = Val | ConstVal;
  }

  void *getContext();
  void setContext(void *);

  template <typename T> void mapRequired(const char *Key, T &Val) {
    EmptyContext Ctx;
    this->processKey(Key, Val, true, Ctx);
  }

  template <typename T, typename Context>
  void mapRequired(const char *Key, T &Val, Context &Ctx) {
    this->processKey(Key, Val, true, Ctx);
  }

  template <typename T> void mapOptional(const char *Key, T &Val) {
    EmptyContext Ctx;
    mapOptionalWithContext(Key, Val, Ctx);
  }

  template <typename T>
  void mapOptional(const char *Key, T &Val, const T &Default) {
    EmptyContext Ctx;
    mapOptionalWithContext(Key, Val, Default, Ctx);
  }

  template <typename T, typename Context>
  typename std::enable_if<has_SequenceTraits<T>::value, void>::type
  mapOptionalWithContext(const char *Key, T &Val, Context &Ctx) {
                                                          
    if (this->canElideEmptySequence() && !(Val.begin() != Val.end()))
      return;
    this->processKey(Key, Val, false, Ctx);
  }

  template <typename T, typename Context>
  void mapOptionalWithContext(const char *Key, Optional<T> &Val, Context &Ctx) {
    this->processKeyWithDefault(Key, Val, Optional<T>(),              false,
                                Ctx);
  }

  template <typename T, typename Context>
  typename std::enable_if<!has_SequenceTraits<T>::value, void>::type
  mapOptionalWithContext(const char *Key, T &Val, Context &Ctx) {
    this->processKey(Key, Val, false, Ctx);
  }

  template <typename T, typename Context>
  void mapOptionalWithContext(const char *Key, T &Val, const T &Default,
                              Context &Ctx) {
    this->processKeyWithDefault(Key, Val, Default, false, Ctx);
  }

private:
  template <typename T, typename Context>
  void processKeyWithDefault(const char *Key, Optional<T> &Val,
                             const Optional<T> &DefaultValue, bool Required,
                             Context &Ctx) {
    assert(DefaultValue.hasValue() == false &&
           "Optional<T> shouldn't have a value!");
    void *SaveInfo;
    bool UseDefault = true;
    const bool sameAsDefault = outputting() && !Val.hasValue();
    if (!outputting() && !Val.hasValue())
      Val = T();
    if (Val.hasValue() &&
        this->preflightKey(Key, Required, sameAsDefault, UseDefault,
                           SaveInfo)) {
      yamlize(*this, Val.getValue(), Required, Ctx);
      this->postflightKey(SaveInfo);
    } else {
      if (UseDefault)
        Val = DefaultValue;
    }
  }

  template <typename T, typename Context>
  void processKeyWithDefault(const char *Key, T &Val, const T &DefaultValue,
                             bool Required, Context &Ctx) {
    void *SaveInfo;
    bool UseDefault;
    const bool sameAsDefault = outputting() && Val == DefaultValue;
    if ( this->preflightKey(Key, Required, sameAsDefault, UseDefault,
                                                                  SaveInfo) ) {
      yamlize(*this, Val, Required, Ctx);
      this->postflightKey(SaveInfo);
    }
    else {
      if ( UseDefault )
        Val = DefaultValue;
    }
  }

  template <typename T, typename Context>
  void processKey(const char *Key, T &Val, bool Required, Context &Ctx) {
    void *SaveInfo;
    bool UseDefault;
    if ( this->preflightKey(Key, Required, false, UseDefault, SaveInfo) ) {
      yamlize(*this, Val, Required, Ctx);
      this->postflightKey(SaveInfo);
    }
  }

private:
  void *Ctxt;
};

namespace detail {

template <typename T, typename Context>
void doMapping(IO &io, T &Val, Context &Ctx) {
  MappingContextTraits<T, Context>::mapping(io, Val, Ctx);
}

template <typename T> void doMapping(IO &io, T &Val, EmptyContext &Ctx) {
  MappingTraits<T>::mapping(io, Val);
}

}                        

template <typename T>
typename std::enable_if<has_ScalarEnumerationTraits<T>::value, void>::type
yamlize(IO &io, T &Val, bool, EmptyContext &Ctx) {
  io.beginEnumScalar();
  ScalarEnumerationTraits<T>::enumeration(io, Val);
  io.endEnumScalar();
}

template <typename T>
typename std::enable_if<has_ScalarBitSetTraits<T>::value, void>::type
yamlize(IO &io, T &Val, bool, EmptyContext &Ctx) {
  bool DoClear;
  if ( io.beginBitSetScalar(DoClear) ) {
    if ( DoClear )
      Val = static_cast<T>(0);
    ScalarBitSetTraits<T>::bitset(io, Val);
    io.endBitSetScalar();
  }
}

template <typename T>
typename std::enable_if<has_ScalarTraits<T>::value, void>::type
yamlize(IO &io, T &Val, bool, EmptyContext &Ctx) {
  if ( io.outputting() ) {
    std::string Storage;
    raw_string_ostream Buffer(Storage);
    ScalarTraits<T>::output(Val, io.getContext(), Buffer);
    StringRef Str = Buffer.str();
    io.scalarString(Str, ScalarTraits<T>::mustQuote(Str));
  }
  else {
    StringRef Str;
    io.scalarString(Str, ScalarTraits<T>::mustQuote(Str));
    StringRef Result = ScalarTraits<T>::input(Str, io.getContext(), Val);
    if ( !Result.empty() ) {
      io.setError(Twine(Result));
    }
  }
}

template <typename T>
typename std::enable_if<has_BlockScalarTraits<T>::value, void>::type
yamlize(IO &YamlIO, T &Val, bool, EmptyContext &Ctx) {
  if (YamlIO.outputting()) {
    std::string Storage;
    raw_string_ostream Buffer(Storage);
    BlockScalarTraits<T>::output(Val, YamlIO.getContext(), Buffer);
    StringRef Str = Buffer.str();
    YamlIO.blockScalarString(Str);
  } else {
    StringRef Str;
    YamlIO.blockScalarString(Str);
    StringRef Result =
        BlockScalarTraits<T>::input(Str, YamlIO.getContext(), Val);
    if (!Result.empty())
      YamlIO.setError(Twine(Result));
  }
}

template <typename T, typename Context>
typename std::enable_if<validatedMappingTraits<T, Context>::value, void>::type
yamlize(IO &io, T &Val, bool, Context &Ctx) {
  if (has_FlowTraits<MappingTraits<T>>::value)
    io.beginFlowMapping();
  else
    io.beginMapping();
  if (io.outputting()) {
    StringRef Err = MappingTraits<T>::validate(io, Val);
    if (!Err.empty()) {
      errs() << Err << "\n";
      assert(Err.empty() && "invalid struct trying to be written as yaml");
    }
  }
  detail::doMapping(io, Val, Ctx);
  if (!io.outputting()) {
    StringRef Err = MappingTraits<T>::validate(io, Val);
    if (!Err.empty())
      io.setError(Err);
  }
  if (has_FlowTraits<MappingTraits<T>>::value)
    io.endFlowMapping();
  else
    io.endMapping();
}

template <typename T, typename Context>
typename std::enable_if<unvalidatedMappingTraits<T, Context>::value, void>::type
yamlize(IO &io, T &Val, bool, Context &Ctx) {
  if (has_FlowTraits<MappingTraits<T>>::value) {
    io.beginFlowMapping();
    detail::doMapping(io, Val, Ctx);
    io.endFlowMapping();
  } else {
    io.beginMapping();
    detail::doMapping(io, Val, Ctx);
    io.endMapping();
  }
}

template <typename T>
typename std::enable_if<has_CustomMappingTraits<T>::value, void>::type
yamlize(IO &io, T &Val, bool, EmptyContext &Ctx) {
  if ( io.outputting() ) {
    io.beginMapping();
    CustomMappingTraits<T>::output(io, Val);
    io.endMapping();
  } else {
    io.beginMapping();
    for (StringRef key : io.keys())
      CustomMappingTraits<T>::inputOne(io, key, Val);
    io.endMapping();
  }
}

template <typename T>
typename std::enable_if<missingTraits<T, EmptyContext>::value, void>::type
yamlize(IO &io, T &Val, bool, EmptyContext &Ctx) {
  char missing_yaml_trait_for_type[sizeof(MissingTrait<T>)];
}

template <typename T, typename Context>
typename std::enable_if<has_SequenceTraits<T>::value, void>::type
yamlize(IO &io, T &Seq, bool, Context &Ctx) {
  if ( has_FlowTraits< SequenceTraits<T>>::value ) {
    unsigned incnt = io.beginFlowSequence();
    unsigned count = io.outputting() ? SequenceTraits<T>::size(io, Seq) : incnt;
    for(unsigned i=0; i < count; ++i) {
      void *SaveInfo;
      if ( io.preflightFlowElement(i, SaveInfo) ) {
        yamlize(io, SequenceTraits<T>::element(io, Seq, i), true, Ctx);
        io.postflightFlowElement(SaveInfo);
      }
    }
    io.endFlowSequence();
  }
  else {
    unsigned incnt = io.beginSequence();
    unsigned count = io.outputting() ? SequenceTraits<T>::size(io, Seq) : incnt;
    for(unsigned i=0; i < count; ++i) {
      void *SaveInfo;
      if ( io.preflightElement(i, SaveInfo) ) {
        yamlize(io, SequenceTraits<T>::element(io, Seq, i), true, Ctx);
        io.postflightElement(SaveInfo);
      }
    }
    io.endSequence();
  }
}

template<>
struct ScalarTraits<bool> {
  static void output(const bool &, void* , raw_ostream &);
  static StringRef input(StringRef, void *, bool &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<StringRef> {
  static void output(const StringRef &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, StringRef &);
  static QuotingType mustQuote(StringRef S) { return needsQuotes(S); }
};

template<>
struct ScalarTraits<std::string> {
  static void output(const std::string &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, std::string &);
  static QuotingType mustQuote(StringRef S) { return needsQuotes(S); }
};

template<>
struct ScalarTraits<uint8_t> {
  static void output(const uint8_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, uint8_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<uint16_t> {
  static void output(const uint16_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, uint16_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<uint32_t> {
  static void output(const uint32_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, uint32_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<uint64_t> {
  static void output(const uint64_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, uint64_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<int8_t> {
  static void output(const int8_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, int8_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<int16_t> {
  static void output(const int16_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, int16_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<int32_t> {
  static void output(const int32_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, int32_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<int64_t> {
  static void output(const int64_t &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, int64_t &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<float> {
  static void output(const float &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, float &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<double> {
  static void output(const double &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, double &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

                                                                             
                                                                           
                                      
template <typename value_type, support::endianness endian, size_t alignment>
struct ScalarTraits<support::detail::packed_endian_specific_integral<
    value_type, endian, alignment>> {
  using endian_type =
      support::detail::packed_endian_specific_integral<value_type, endian,
                                                       alignment>;

  static void output(const endian_type &E, void *Ctx, raw_ostream &Stream) {
    ScalarTraits<value_type>::output(static_cast<value_type>(E), Ctx, Stream);
  }

  static StringRef input(StringRef Str, void *Ctx, endian_type &E) {
    value_type V;
    auto R = ScalarTraits<value_type>::input(Str, Ctx, V);
    E = static_cast<endian_type>(V);
    return R;
  }

  static QuotingType mustQuote(StringRef Str) {
    return ScalarTraits<value_type>::mustQuote(Str);
  }
};

                                                           
                                                           
template <typename TNorm, typename TFinal>
struct MappingNormalization {
  MappingNormalization(IO &i_o, TFinal &Obj)
      : io(i_o), BufPtr(nullptr), Result(Obj) {
    if ( io.outputting() ) {
      BufPtr = new (&Buffer) TNorm(io, Obj);
    }
    else {
      BufPtr = new (&Buffer) TNorm(io);
    }
  }

  ~MappingNormalization() {
    if ( ! io.outputting() ) {
      Result = BufPtr->denormalize(io);
    }
    BufPtr->~TNorm();
  }

  TNorm* operator->() { return BufPtr; }

private:
  using Storage = AlignedCharArrayUnion<TNorm>;

  Storage       Buffer;
  IO           &io;
  TNorm        *BufPtr;
  TFinal       &Result;
};

                                                           
                                                           
template <typename TNorm, typename TFinal>
struct MappingNormalizationHeap {
  MappingNormalizationHeap(IO &i_o, TFinal &Obj, BumpPtrAllocator *allocator)
    : io(i_o), Result(Obj) {
    if ( io.outputting() ) {
      BufPtr = new (&Buffer) TNorm(io, Obj);
    }
    else if (allocator) {
      BufPtr = allocator->Allocate<TNorm>();
      new (BufPtr) TNorm(io);
    } else {
      BufPtr = new TNorm(io);
    }
  }

  ~MappingNormalizationHeap() {
    if ( io.outputting() ) {
      BufPtr->~TNorm();
    }
    else {
      Result = BufPtr->denormalize(io);
    }
  }

  TNorm* operator->() { return BufPtr; }

private:
  using Storage = AlignedCharArrayUnion<TNorm>;

  Storage       Buffer;
  IO           &io;
  TNorm        *BufPtr = nullptr;
  TFinal       &Result;
};

   
                                                                           
                
   
                                                                        
                                                                       
                                                                      
                                                                          
                                                                      
                                                               
                                
   
class Input : public IO {
public:
                                                                
                                                           
                                 
  Input(StringRef InputContent,
        void *Ctxt = nullptr,
        SourceMgr::DiagHandlerTy DiagHandler = nullptr,
        void *DiagHandlerCtxt = nullptr);
  Input(MemoryBufferRef Input,
        void *Ctxt = nullptr,
        SourceMgr::DiagHandlerTy DiagHandler = nullptr,
        void *DiagHandlerCtxt = nullptr);
  ~Input() override;

                                                                   
  std::error_code error();

private:
  bool outputting() override;
  bool mapTag(StringRef, bool) override;
  void beginMapping() override;
  void endMapping() override;
  bool preflightKey(const char *, bool, bool, bool &, void *&) override;
  void postflightKey(void *) override;
  std::vector<StringRef> keys() override;
  void beginFlowMapping() override;
  void endFlowMapping() override;
  unsigned beginSequence() override;
  void endSequence() override;
  bool preflightElement(unsigned index, void *&) override;
  void postflightElement(void *) override;
  unsigned beginFlowSequence() override;
  bool preflightFlowElement(unsigned , void *&) override;
  void postflightFlowElement(void *) override;
  void endFlowSequence() override;
  void beginEnumScalar() override;
  bool matchEnumScalar(const char*, bool) override;
  bool matchEnumFallback() override;
  void endEnumScalar() override;
  bool beginBitSetScalar(bool &) override;
  bool bitSetMatch(const char *, bool ) override;
  void endBitSetScalar() override;
  void scalarString(StringRef &, QuotingType) override;
  void blockScalarString(StringRef &) override;
  void setError(const Twine &message) override;
  bool canElideEmptySequence() override;

  class HNode {
    virtual void anchor();

  public:
    HNode(Node *n) : _node(n) { }
    virtual ~HNode() = default;

    static bool classof(const HNode *) { return true; }

    Node *_node;
  };

  class EmptyHNode : public HNode {
    void anchor() override;

  public:
    EmptyHNode(Node *n) : HNode(n) { }

    static bool classof(const HNode *n) { return NullNode::classof(n->_node); }

    static bool classof(const EmptyHNode *) { return true; }
  };

  class ScalarHNode : public HNode {
    void anchor() override;

  public:
    ScalarHNode(Node *n, StringRef s) : HNode(n), _value(s) { }

    StringRef value() const { return _value; }

    static bool classof(const HNode *n) {
      return ScalarNode::classof(n->_node) ||
             BlockScalarNode::classof(n->_node);
    }

    static bool classof(const ScalarHNode *) { return true; }

  protected:
    StringRef _value;
  };

  class MapHNode : public HNode {
    void anchor() override;

  public:
    MapHNode(Node *n) : HNode(n) { }

    static bool classof(const HNode *n) {
      return MappingNode::classof(n->_node);
    }

    static bool classof(const MapHNode *) { return true; }

    using NameToNode = StringMap<std::unique_ptr<HNode>>;

    NameToNode Mapping;
    SmallVector<std::string, 6> ValidKeys;
  };

  class SequenceHNode : public HNode {
    void anchor() override;

  public:
    SequenceHNode(Node *n) : HNode(n) { }

    static bool classof(const HNode *n) {
      return SequenceNode::classof(n->_node);
    }

    static bool classof(const SequenceHNode *) { return true; }

    std::vector<std::unique_ptr<HNode>> Entries;
  };

  std::unique_ptr<Input::HNode> createHNodes(Node *node);
  void setError(HNode *hnode, const Twine &message);
  void setError(Node *node, const Twine &message);

public:
                                                             
                                                     
  bool setCurrentDocument();
  bool nextDocument();

                                                                      
  const Node *getCurrentNode() const;

private:
  SourceMgr                           SrcMgr;                       
  std::unique_ptr<llvh::yaml::Stream> Strm;
  std::unique_ptr<HNode>              TopNode;
  std::error_code                     EC;
  BumpPtrAllocator                    StringAllocator;
  document_iterator                   DocIterator;
  std::vector<bool>                   BitValuesUsed;
  HNode *CurrentNode = nullptr;
  bool                                ScalarMatchFound;
};

   
                                                                               
                
   
class Output : public IO {
public:
  Output(raw_ostream &, void *Ctxt = nullptr, int WrapColumn = 70);
  ~Output() override;

                                                                  
                                                                       
                                                                            
                                                                           
             
  void setWriteDefaultValues(bool Write) { WriteDefaultValues = Write; }

  bool outputting() override;
  bool mapTag(StringRef, bool) override;
  void beginMapping() override;
  void endMapping() override;
  bool preflightKey(const char *key, bool, bool, bool &, void *&) override;
  void postflightKey(void *) override;
  std::vector<StringRef> keys() override;
  void beginFlowMapping() override;
  void endFlowMapping() override;
  unsigned beginSequence() override;
  void endSequence() override;
  bool preflightElement(unsigned, void *&) override;
  void postflightElement(void *) override;
  unsigned beginFlowSequence() override;
  bool preflightFlowElement(unsigned, void *&) override;
  void postflightFlowElement(void *) override;
  void endFlowSequence() override;
  void beginEnumScalar() override;
  bool matchEnumScalar(const char*, bool) override;
  bool matchEnumFallback() override;
  void endEnumScalar() override;
  bool beginBitSetScalar(bool &) override;
  bool bitSetMatch(const char *, bool ) override;
  void endBitSetScalar() override;
  void scalarString(StringRef &, QuotingType) override;
  void blockScalarString(StringRef &) override;
  void setError(const Twine &message) override;
  bool canElideEmptySequence() override;

                                                             
                                                       
  void beginDocuments();
  bool preflightDocument(unsigned);
  void postflightDocument();
  void endDocuments();

private:
  void output(StringRef s);
  void outputUpToEndOfLine(StringRef s);
  void newLineCheck();
  void outputNewLine();
  void paddedKey(StringRef key);
  void flowKey(StringRef Key);

  enum InState {
    inSeq,
    inFlowSeq,
    inMapFirstKey,
    inMapOtherKey,
    inFlowMapFirstKey,
    inFlowMapOtherKey
  };

  raw_ostream &Out;
  int WrapColumn;
  SmallVector<InState, 8> StateStack;
  int Column = 0;
  int ColumnAtFlowStart = 0;
  int ColumnAtMapFlowStart = 0;
  bool NeedBitValueComma = false;
  bool NeedFlowSequenceComma = false;
  bool EnumerationMatchFound = false;
  bool NeedsNewLine = false;
  bool WriteDefaultValues = false;
};

                                                                        
                                                                           
                                                                             
                                                                              
                                                                           
                                                                             
                                                                 
                                 
#define LLVM_YAML_STRONG_TYPEDEF(_base, _type)                                 \
    struct _type {                                                             \
        _type() = default;                                                     \
        _type(const _base v) : value(v) {}                                     \
        _type(const _type &v) = default;                                       \
        _type &operator=(const _type &rhs) = default;                          \
        _type &operator=(const _base &rhs) { value = rhs; return *this; }      \
        operator const _base & () const { return value; }                      \
        bool operator==(const _type &rhs) const { return value == rhs.value; } \
        bool operator==(const _base &rhs) const { return value == rhs; }       \
        bool operator<(const _type &rhs) const { return value < rhs.value; }   \
        _base value;                                                           \
        using BaseType = _base;                                                \
    };

   
                                                              
                                             
   
LLVM_YAML_STRONG_TYPEDEF(uint8_t, Hex8)
LLVM_YAML_STRONG_TYPEDEF(uint16_t, Hex16)
LLVM_YAML_STRONG_TYPEDEF(uint32_t, Hex32)
LLVM_YAML_STRONG_TYPEDEF(uint64_t, Hex64)

template<>
struct ScalarTraits<Hex8> {
  static void output(const Hex8 &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, Hex8 &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<Hex16> {
  static void output(const Hex16 &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, Hex16 &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<Hex32> {
  static void output(const Hex32 &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, Hex32 &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

template<>
struct ScalarTraits<Hex64> {
  static void output(const Hex64 &, void *, raw_ostream &);
  static StringRef input(StringRef, void *, Hex64 &);
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

                                                                            
template <typename T>
inline
typename std::enable_if<has_DocumentListTraits<T>::value, Input &>::type
operator>>(Input &yin, T &docList) {
  int i = 0;
  EmptyContext Ctx;
  while ( yin.setCurrentDocument() ) {
    yamlize(yin, DocumentListTraits<T>::element(yin, docList, i), true, Ctx);
    if ( yin.error() )
      return yin;
    yin.nextDocument();
    ++i;
  }
  return yin;
}

                                                                                
template <typename T>
inline typename std::enable_if<has_MappingTraits<T, EmptyContext>::value,
                               Input &>::type
operator>>(Input &yin, T &docMap) {
  EmptyContext Ctx;
  yin.setCurrentDocument();
  yamlize(yin, docMap, true, Ctx);
  return yin;
}

                                                                         
              
template <typename T>
inline
typename std::enable_if<has_SequenceTraits<T>::value, Input &>::type
operator>>(Input &yin, T &docSeq) {
  EmptyContext Ctx;
  if (yin.setCurrentDocument())
    yamlize(yin, docSeq, true, Ctx);
  return yin;
}

                                                                           
template <typename T>
inline
typename std::enable_if<has_BlockScalarTraits<T>::value, Input &>::type
operator>>(Input &In, T &Val) {
  EmptyContext Ctx;
  if (In.setCurrentDocument())
    yamlize(In, Val, true, Ctx);
  return In;
}

                                                                         
template <typename T>
inline
typename std::enable_if<has_CustomMappingTraits<T>::value, Input &>::type
operator>>(Input &In, T &Val) {
  EmptyContext Ctx;
  if (In.setCurrentDocument())
    yamlize(In, Val, true, Ctx);
  return In;
}

                                                                          
template <typename T>
inline typename std::enable_if<missingTraits<T, EmptyContext>::value,
                               Input &>::type
operator>>(Input &yin, T &docSeq) {
  char missing_yaml_trait_for_type[sizeof(MissingTrait<T>)];
  return yin;
}

                                                                            
template <typename T>
inline
typename std::enable_if<has_DocumentListTraits<T>::value, Output &>::type
operator<<(Output &yout, T &docList) {
  EmptyContext Ctx;
  yout.beginDocuments();
  const size_t count = DocumentListTraits<T>::size(yout, docList);
  for(size_t i=0; i < count; ++i) {
    if ( yout.preflightDocument(i) ) {
      yamlize(yout, DocumentListTraits<T>::element(yout, docList, i), true,
              Ctx);
      yout.postflightDocument();
    }
  }
  yout.endDocuments();
  return yout;
}

                                                                    
template <typename T>
inline typename std::enable_if<has_MappingTraits<T, EmptyContext>::value,
                               Output &>::type
operator<<(Output &yout, T &map) {
  EmptyContext Ctx;
  yout.beginDocuments();
  if ( yout.preflightDocument(0) ) {
    yamlize(yout, map, true, Ctx);
    yout.postflightDocument();
  }
  yout.endDocuments();
  return yout;
}

                                                                         
template <typename T>
inline
typename std::enable_if<has_SequenceTraits<T>::value, Output &>::type
operator<<(Output &yout, T &seq) {
  EmptyContext Ctx;
  yout.beginDocuments();
  if ( yout.preflightDocument(0) ) {
    yamlize(yout, seq, true, Ctx);
    yout.postflightDocument();
  }
  yout.endDocuments();
  return yout;
}

                                                                             
template <typename T>
inline
typename std::enable_if<has_BlockScalarTraits<T>::value, Output &>::type
operator<<(Output &Out, T &Val) {
  EmptyContext Ctx;
  Out.beginDocuments();
  if (Out.preflightDocument(0)) {
    yamlize(Out, Val, true, Ctx);
    Out.postflightDocument();
  }
  Out.endDocuments();
  return Out;
}

                                                                           
template <typename T>
inline
typename std::enable_if<has_CustomMappingTraits<T>::value, Output &>::type
operator<<(Output &Out, T &Val) {
  EmptyContext Ctx;
  Out.beginDocuments();
  if (Out.preflightDocument(0)) {
    yamlize(Out, Val, true, Ctx);
    Out.postflightDocument();
  }
  Out.endDocuments();
  return Out;
}

                                                                          
template <typename T>
inline typename std::enable_if<missingTraits<T, EmptyContext>::value,
                               Output &>::type
operator<<(Output &yout, T &seq) {
  char missing_yaml_trait_for_type[sizeof(MissingTrait<T>)];
  return yout;
}

template <bool B> struct IsFlowSequenceBase {};
template <> struct IsFlowSequenceBase<true> { static const bool flow = true; };

template <typename T, bool Flow>
struct SequenceTraitsImpl : IsFlowSequenceBase<Flow> {
private:
  using type = typename T::value_type;

public:
  static size_t size(IO &io, T &seq) { return seq.size(); }

  static type &element(IO &io, T &seq, size_t index) {
    if (index >= seq.size())
      seq.resize(index + 1);
    return seq[index];
  }
};

                                                                             
            
template <bool> struct CheckIsBool { static const bool value = true; };

                                                                            
                                            
template <typename T>
struct SequenceTraits<std::vector<T>,
                      typename std::enable_if<CheckIsBool<
                          SequenceElementTraits<T>::flow>::value>::type>
    : SequenceTraitsImpl<std::vector<T>, SequenceElementTraits<T>::flow> {};
template <typename T, unsigned N>
struct SequenceTraits<SmallVector<T, N>,
                      typename std::enable_if<CheckIsBool<
                          SequenceElementTraits<T>::flow>::value>::type>
    : SequenceTraitsImpl<SmallVector<T, N>, SequenceElementTraits<T>::flow> {};

                                                      
template <typename T>
struct SequenceElementTraits<
    T, typename std::enable_if<std::is_fundamental<T>::value>::type> {
  static const bool flow = true;
};

                                             
template<> struct SequenceElementTraits<std::string> {
  static const bool flow = false;
};
template<> struct SequenceElementTraits<StringRef> {
  static const bool flow = false;
};
template<> struct SequenceElementTraits<std::pair<std::string, std::string>> {
  static const bool flow = false;
};

                                                                       
template <typename T> struct StdMapStringCustomMappingTraitsImpl {
  using map_type = std::map<std::string, T>;

  static void inputOne(IO &io, StringRef key, map_type &v) {
    io.mapRequired(key.str().c_str(), v[key]);
  }

  static void output(IO &io, map_type &v) {
    for (auto &p : v)
      io.mapRequired(p.first.c_str(), p.second);
  }
};

}                      
}                      

#define LLVM_YAML_IS_SEQUENCE_VECTOR_IMPL(TYPE, FLOW)                          \
  namespace llvh {                                                             \
  namespace yaml {                                                             \
  static_assert(                                                               \
      !std::is_fundamental<TYPE>::value &&                                     \
      !std::is_same<TYPE, std::string>::value &&                               \
      !std::is_same<TYPE, llvh::StringRef>::value,                             \
      "only use LLVM_YAML_IS_SEQUENCE_VECTOR for types you control");          \
  template <> struct SequenceElementTraits<TYPE> {                             \
    static const bool flow = FLOW;                                             \
  };                                                                           \
  }                                                                            \
  }

                                                                 
                                         
#define LLVM_YAML_IS_SEQUENCE_VECTOR(type)                                     \
  LLVM_YAML_IS_SEQUENCE_VECTOR_IMPL(type, false)

                                                                 
                                              
#define LLVM_YAML_IS_FLOW_SEQUENCE_VECTOR(type)                                \
  LLVM_YAML_IS_SEQUENCE_VECTOR_IMPL(type, true)

#define LLVM_YAML_DECLARE_MAPPING_TRAITS(Type)                                 \
  namespace llvh {                                                             \
  namespace yaml {                                                             \
  template <> struct MappingTraits<Type> {                                     \
    static void mapping(IO &IO, Type &Obj);                                    \
  };                                                                           \
  }                                                                            \
  }

#define LLVM_YAML_DECLARE_ENUM_TRAITS(Type)                                    \
  namespace llvh {                                                             \
  namespace yaml {                                                             \
  template <> struct ScalarEnumerationTraits<Type> {                           \
    static void enumeration(IO &io, Type &Value);                              \
  };                                                                           \
  }                                                                            \
  }

#define LLVM_YAML_DECLARE_BITSET_TRAITS(Type)                                  \
  namespace llvh {                                                             \
  namespace yaml {                                                             \
  template <> struct ScalarBitSetTraits<Type> {                                \
    static void bitset(IO &IO, Type &Options);                                 \
  };                                                                           \
  }                                                                            \
  }

#define LLVM_YAML_DECLARE_SCALAR_TRAITS(Type, MustQuote)                       \
  namespace llvh {                                                             \
  namespace yaml {                                                             \
  template <> struct ScalarTraits<Type> {                                      \
    static void output(const Type &Value, void *ctx, raw_ostream &Out);        \
    static StringRef input(StringRef Scalar, void *ctxt, Type &Value);         \
    static QuotingType mustQuote(StringRef) { return MustQuote; }              \
  };                                                                           \
  }                                                                            \
  }

                                                                 
                                              
#define LLVM_YAML_IS_DOCUMENT_LIST_VECTOR(_type)                               \
  namespace llvh {                                                             \
  namespace yaml {                                                             \
  template <unsigned N>                                                        \
  struct DocumentListTraits<SmallVector<_type, N>>                             \
      : public SequenceTraitsImpl<SmallVector<_type, N>, false> {};            \
  template <>                                                                  \
  struct DocumentListTraits<std::vector<_type>>                                \
      : public SequenceTraitsImpl<std::vector<_type>, false> {};               \
  }                                                                            \
  }

                                                                                
               
#define LLVM_YAML_IS_STRING_MAP(_type)                                         \
  namespace llvh {                                                             \
  namespace yaml {                                                             \
  template <>                                                                  \
  struct CustomMappingTraits<std::map<std::string, _type>>                     \
      : public StdMapStringCustomMappingTraitsImpl<_type> {};                  \
  }                                                                            \
  }

#endif                             
