/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "LocaleResolver.h"

#include "Constants.h"
#include "IntlUtils.h"
#include "LocaleBCP47Object.h"
#include "LocaleConverter.h"
#include "OptionHelpers.h"
#include "hermes/Platform/Unicode/icu.h"

#include <unordered_set>

namespace hermes {
namespace platform_intl {
namespace impl_icu {
namespace {

   
                                          
                                                         
   
const std::unordered_set<std::string> &getAvailableLocales() {
                                                              
  static const auto *availableLocales = [] {
    auto *availLocales = new std::unordered_set<std::string>();
    const int32_t countAvailable = uloc_countAvailable();
    for (int32_t i = 0; i < countAvailable; ++i) {
      const char *locale = uloc_getAvailable(i);
      std::string bcp47Locale = convertICUtoBCP47Locale(locale);
      availLocales->insert(toLowerASCII(bcp47Locale));
    }
    return availLocales;
  }();
  return *availableLocales;
}

   
                                                        
                                                                   
                                           
   
LocaleBCP47Object getDefaultLocale() {
  return LocaleBCP47Object::forLanguageTag(
             toUTF16ASCII(convertICUtoBCP47Locale(uloc_getDefault())))
      .value_or(LocaleBCP47Object());
}

   
                                                                 
             
                                          
                                       
                                                                 
                                                                  
   
LocaleBCP47Object toLocaleBCP47ObjectWithExtensions(
    std::string_view locale,
    const std::map<std::u16string, std::u16string> &extensions) {
  LocaleBCP47Object result =
      LocaleBCP47Object::forLanguageTag(toUTF16ASCII(locale))
          .value_or(LocaleBCP47Object());
  result.updateExtensionMap(extensions);
  return result;
}

   
                                                                        
                                                   
                                                                    
                           
                                                                       
                                                                 
   
std::string bestAvailableLocale(std::u16string_view locale) {
  const std::unordered_set<std::string> &availableLocales =
      getAvailableLocales();
                                
                                                                  
  std::string candidate = toUTF8ASCII(locale);
               
  while (true) {
                                                                              
                      
    if (availableLocales.find(candidate) != availableLocales.end()) {
      return candidate;
    }

                                                                        
                                                                               
                      
    size_t pos = candidate.rfind('-');
    if (pos == std::string::npos) {
      return std::string();
    }

                                                                                
                              
    if (pos >= 2 && candidate[pos - 2] == '-') {
      pos -= 2;
    }

                                                                        
                                                  
    candidate.resize(pos);
  }
}

   
                                                                   
                     
                                             
                                                       
                                                                           
         
   
LocaleBCP47Object lookupMatcher(
    const std::vector<LocaleBCP47Object> &requestedLocales) {
                                   
                                                                     
  for (const auto &localeBcp47Object : requestedLocales) {
                                                                      
                                                                 
                                   
                                                                       
    std::string availableLocale =
        bestAvailableLocale(localeBcp47Object.getLocaleNoExt());

                                                                      
                           
    if (!availableLocale.empty()) {
                                                           
                                                                    
                           
                                                                     
                                                               
                            
                                                            
                                  
      return toLocaleBCP47ObjectWithExtensions(
          availableLocale, localeBcp47Object.getExtensionMap());
    }
  }
                                         
                                           
                      
  return getDefaultLocale();
}

   
                                                                          
                                                               
                    
                                                                         
         
   
std::string bestFitBestAvailableLocale(
    const LocaleBCP47Object &localeBCP47Object) {
  UErrorCode status = U_ZERO_ERROR;
  char result[ULOC_FULLNAME_CAPACITY + 1];                          
  UAcceptResult outResult = ULOC_ACCEPT_VALID;

  std::string localeICU =
      convertBCP47toICULocale(localeBCP47Object.getLocaleNoExt());
  const char *acceptList[1]{localeICU.c_str()};

  UEnumeration *availableLocales =
      uloc_openAvailableByType(ULOC_AVAILABLE_DEFAULT, &status);

  int32_t localeLen = uloc_acceptLanguage(
      result,
      ULOC_FULLNAME_CAPACITY,
      &outResult,
      acceptList,
      1,
      availableLocales,
      &status);

  uenum_close(availableLocales);

                                                         
  assert(
      localeLen <= ULOC_FULLNAME_CAPACITY &&
      "locale string length is longer than expected");
  if (U_SUCCESS(status) && outResult != ULOC_ACCEPT_FAILED &&
      localeLen <= ULOC_FULLNAME_CAPACITY) {
    return convertICUtoBCP47Locale(result);
  }

  return std::string();
}

   
                                                                     
                     
                                              
                                                        
                                                                           
         
   
LocaleBCP47Object bestFitMatcher(
    const std::vector<LocaleBCP47Object> &requestedLocales) {
  for (const auto &localeBcp47Object : requestedLocales) {
                                   
                                                                       
    std::string availableLocale = bestFitBestAvailableLocale(localeBcp47Object);

    if (!availableLocale.empty()) {
      return toLocaleBCP47ObjectWithExtensions(
          availableLocale, localeBcp47Object.getExtensionMap());
    }
  }
  return getDefaultLocale();
}

   
                                                              
                                           
                                                          
                                                                      
                                                        
                                                              
   
std::map<std::u16string, std::u16string> getSupportedExtensions(
    const LocaleBCP47Object &localeBCP47Object,
    llvh::ArrayRef<std::u16string_view> relevantExtensionKeys,
    const std::function<bool(
        std::u16string_view,                    
        std::u16string_view,                     
        const LocaleBCP47Object &)> &isExtensionTypeSupported) {
  std::map<std::u16string, std::u16string> exts;

  const std::map<std::u16string, std::u16string> &extensionsMap =
      localeBCP47Object.getExtensionMap();

  for (auto const &extension : extensionsMap) {
    std::u16string_view extType{extension.second};
    if (extType.empty()) {
      extType = constants::opt_value::trueStr;
    }
    if ((llvh::find(relevantExtensionKeys, extension.first) !=
         relevantExtensionKeys.end()) &&
        isExtensionTypeSupported(extension.first, extType, localeBCP47Object)) {
      exts.emplace(extension.first, extType);
    }
  }
  return exts;
}

}             

                                             
ResolvedResult resolveLocale(
    const std::vector<LocaleBCP47Object> &requestedLocales,
    const Options &opt,
    llvh::ArrayRef<std::u16string_view> relevantExtensionKeys,
    const std::function<bool(
        std::u16string_view,                    
        std::u16string_view,                     
        const LocaleBCP47Object &)> &isExtensionTypeSupported) {
  Option matcher = opt.at(constants::opt_name::localeMatcher);
  LocaleBCP47Object matchedLocaleObj;
  if (matcher.getString() == constants::opt_value::locale_matcher::lookup) {
    matchedLocaleObj = lookupMatcher(requestedLocales);
  } else {
    matchedLocaleObj = bestFitMatcher(requestedLocales);
  }

  std::map<std::u16string, std::u16string> extensions = getSupportedExtensions(
      matchedLocaleObj, relevantExtensionKeys, isExtensionTypeSupported);

  Options resolvedOptions;
  for (const auto &extView : relevantExtensionKeys) {
    std::u16string ext{extView};
    auto extIter = extensions.find(ext);
    if (extIter != extensions.end()) {
      resolvedOptions.emplace(ext, extIter->second);
    }
    auto optIter = opt.find(ext);
    if (optIter != opt.end()) {
      Option option = optIter->second;
      std::u16string_view optExtType;
      if (option.isNumber()) {
                                                                         
                                              
        assert(
            false &&
            "unexpected number-type option for a relevant extension key");
      } else if (option.isBool()) {
        optExtType = option.getBool() ? constants::opt_value::trueStr
                                      : constants::opt_value::falseStr;
      } else {
        optExtType = option.getString();
      }
                                                      
                                                                     
                                                                         
                                    
                                          
                                                     
      if (isExtensionTypeSupported(ext, optExtType, matchedLocaleObj)) {
                                                                               
                                               
        resolvedOptions.insert_or_assign(ext, option);
        if (extIter != extensions.end() && extIter->second != optExtType) {
                                                                      
                                                                      
                              
          extensions.erase(extIter);
        }
      }
    }
  }

  matchedLocaleObj.updateExtensionMap(extensions);
  ResolvedResult result;
  result.resolvedOpts = resolvedOptions;
  result.localeBcp47Object = matchedLocaleObj;
  return result;
}

vm::CallResult<std::vector<std::u16string>> supportedLocales(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  auto localeBcp47ObjectsRes =
      LocaleBCP47Object::canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(localeBcp47ObjectsRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  auto matcherRes = getStringOption(
      runtime,
      options,
      constants::opt_name::localeMatcher,
      constants::opt_value::locale_matcher::validLocaleMatchers,
      constants::opt_value::locale_matcher::best_fit);
  if (LLVM_UNLIKELY(matcherRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  std::vector<std::u16string> subset;
  for (auto const &localeBcp47Object : *localeBcp47ObjectsRes) {
    std::string locale;
    if (**matcherRes == constants::opt_value::locale_matcher::lookup) {
      locale = bestAvailableLocale(localeBcp47Object.getLocaleNoExt());
    } else {
      locale = bestFitBestAvailableLocale(localeBcp47Object);
    }
    if (!locale.empty()) {
      subset.emplace_back(localeBcp47Object.getCanonicalizedLocaleId());
    }
  }
  return subset;
}

}                      
}                           
}                    
