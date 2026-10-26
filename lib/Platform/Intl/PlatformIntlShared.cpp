/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                         
            
#include "hermes/Platform/Intl/PlatformIntlShared.h"
#include "hermes/Platform/Intl/PlatformIntl.h"
#include "impl_icu/LocaleBCP47Object.h"

using namespace ::hermes;

namespace hermes {
namespace platform_intl {

                                                        
vm::CallResult<std::vector<std::u16string>> getCanonicalLocales(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales) {
                                                    
  auto localeBcp47ObjectsRes =
      impl_icu::LocaleBCP47Object::canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(localeBcp47ObjectsRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
                                       
  std::vector<std::u16string> canonicalLocales;
  for (const auto &localeBcp47Object : *localeBcp47ObjectsRes) {
    canonicalLocales.push_back(localeBcp47Object.getCanonicalizedLocaleId());
  }
  return canonicalLocales;
}

                    
                                                                 
vm::CallResult<Options> toDateTimeOptions(
    vm::Runtime &runtime,
    Options options,
    std::u16string_view required,
    std::u16string_view defaults) {
                                                                                
                       
                                                     
                                 
  bool needDefaults = true;
                                            
  if (required == u"date" || required == u"any") {
                                                                               
         
                                                                        
                                
    static constexpr std::u16string_view props[] = {
        u"weekday", u"year", u"month", u"day"};
    for (const auto &prop : props) {
                                              
      if (options.find(std::u16string(prop)) != options.end()) {
                                                                    
        needDefaults = false;
      }
    }
  }
                                            
  if (required == u"time" || required == u"any") {
                                                                         
                                               
    static constexpr std::u16string_view props[] = {
        u"dayPeriod", u"hour", u"minute", u"second", u"fractionalSecondDigits"};
    for (const auto &prop : props) {
                                              
      if (options.find(std::u16string(prop)) != options.end()) {
                                                                    
        needDefaults = false;
      }
    }
  }
                                                     
  auto dateStyle = options.find(u"dateStyle");
                                                     
  auto timeStyle = options.find(u"timeStyle");
                                                                        
                           
  if (dateStyle != options.end() || timeStyle != options.end()) {
    needDefaults = false;
  }
                                                                  
  if (required == u"date" && timeStyle != options.end()) {
                                      
    return runtime.raiseTypeError(
        "Unexpectedly found timeStyle option for \"date\" property");
  }
                                                                   
  if (required == u"time" && dateStyle != options.end()) {
                                      
    return runtime.raiseTypeError(
        "Unexpectedly found dateStyle option for \"time\" property");
  }
                                                                             
  if (needDefaults && (defaults == u"date" || defaults == u"all")) {
                                                                       
    static constexpr std::u16string_view props[] = {u"year", u"month", u"day"};
    for (const auto &prop : props) {
                                                                          
      options.emplace(prop, Option(std::u16string(u"numeric")));
    }
  }
                                                                             
  if (needDefaults && (defaults == u"time" || defaults == u"all")) {
                                                                           
    static constexpr std::u16string_view props[] = {
        u"hour", u"minute", u"second"};
    for (const auto &prop : props) {
                                                                          
      options.emplace(prop, Option(std::u16string(u"numeric")));
    }
  }
                       
  return options;
}

                                                                                 
std::u16string toASCIIUppercase(std::u16string_view tz) {
  std::u16string result;
  std::uint8_t offset = 'a' - 'A';
  for (char16_t c16 : tz) {
    if (c16 >= 'a' && c16 <= 'z') {
      result.push_back((char)c16 - offset);
    } else {
      result.push_back(c16);
    }
  }
  return result;
}

}                           
}                    
