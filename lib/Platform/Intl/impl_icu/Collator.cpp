/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "Collator.h"

#include "Constants.h"
#include "IntlUtils.h"
#include "LocaleBCP47Object.h"
#include "LocaleConverter.h"
#include "LocaleResolver.h"
#include "OptionHelpers.h"
#include "hermes/Platform/Intl/BCP47Parser.h"

#include <algorithm>
#include <optional>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

constexpr char16_t collationTypeDefault[] = u"default";
constexpr char16_t collationTypeSearch[] = u"search";
constexpr char16_t collationTypeStandard[] = u"standard";

vm::ExecutionStatus Collator::initialize(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  if (LLVM_UNLIKELY(
          initializeCollator(runtime, locales, options) ==
          vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  };

  std::string localeICU = convertBCP47toICULocale(resolvedInternalLocale_);

  UErrorCode err{U_ZERO_ERROR};
  coll_ = ucol_open(localeICU.c_str(), &err);

  if (U_FAILURE(err)) {
                                                                          
    err = U_ZERO_ERROR;
    coll_ = ucol_open("", &err);
  }
  assert(U_SUCCESS(err) && "failed to open collator");

                                                 
                                                                
                                     
                                           
  ucol_setAttribute(coll_, UCOL_NORMALIZATION_MODE, UCOL_ON, &err);

  setAttributes();

  return vm::ExecutionStatus::RETURNED;
}

Collator::~Collator() {
  close();
}

void Collator::close() {
  if (coll_ != nullptr) {
    ucol_close(coll_);
  }
}

   
                                                                                
                                                                                
        
                                                                                                         
                                                               
                                   
   
void Collator::setAttributes() {
                                       
                                                                          
                                                              
                                                                              
                                                                  
  UErrorCode errNumeric{U_ZERO_ERROR};
  if (resolvedNumericValue_ == true) {
    ucol_setAttribute(coll_, UCOL_NUMERIC_COLLATION, UCOL_ON, &errNumeric);
  } else {
    ucol_setAttribute(coll_, UCOL_NUMERIC_COLLATION, UCOL_OFF, &errNumeric);
  }
  assert(
      U_SUCCESS(errNumeric) &&
      "failed to set collator numeric-collation attribute");

                                  
                                                                            
                                                                                
                                                                                
                                                         
                                                                              
                                                                  
  UErrorCode errCaseFirst{U_ZERO_ERROR};
  if (!resolvedCaseFirstValue_.empty()) {
    if (resolvedCaseFirstValue_ == constants::opt_value::case_first::upper) {
      ucol_setAttribute(
          coll_, UCOL_CASE_FIRST, UCOL_UPPER_FIRST, &errCaseFirst);
    } else if (
        resolvedCaseFirstValue_ == constants::opt_value::case_first::lower) {
      ucol_setAttribute(
          coll_, UCOL_CASE_FIRST, UCOL_LOWER_FIRST, &errCaseFirst);
    } else {
      ucol_setAttribute(coll_, UCOL_CASE_FIRST, UCOL_OFF, &errCaseFirst);
    }
    assert(
        U_SUCCESS(errCaseFirst) &&
        "failed to set collator case-first attribute");
  } else {
    auto caseFirstAttribute =
        ucol_getAttribute(coll_, UCOL_CASE_FIRST, &errCaseFirst);
    assert(
        U_SUCCESS(errCaseFirst) &&
        "failed to get collator attribute : UCOL_CASE_FIRST");
    if (caseFirstAttribute == UCOL_UPPER_FIRST) {
      resolvedCaseFirstValue_ = constants::opt_value::case_first::upper;
    } else if (caseFirstAttribute == UCOL_LOWER_FIRST) {
      resolvedCaseFirstValue_ = constants::opt_value::case_first::lower;
    } else {
      resolvedCaseFirstValue_ = constants::opt_value::falseStr;
    }
  }

                                
                                                                            
                         

                                                                           
                                   
                                                 
                                                                     
                                   
                                                                          
             
                                   
                                                                        
                                                                               
                              
                                   
                                                                           
                    

                                                                               
                                                                                
              
  UErrorCode errSensitivity{U_ZERO_ERROR};
  if (!resolvedSensitivityValue_.empty()) {
    if (resolvedSensitivityValue_ == constants::opt_value::sensitivity::base) {
      ucol_setAttribute(coll_, UCOL_STRENGTH, UCOL_PRIMARY, &errSensitivity);
    } else if (
        resolvedSensitivityValue_ ==
        constants::opt_value::sensitivity::accent) {
      ucol_setAttribute(coll_, UCOL_STRENGTH, UCOL_SECONDARY, &errSensitivity);
    } else if (
        resolvedSensitivityValue_ ==
        constants::opt_value::sensitivity::caseStr) {
      ucol_setAttribute(coll_, UCOL_STRENGTH, UCOL_PRIMARY, &errSensitivity);
      ucol_setAttribute(coll_, UCOL_CASE_LEVEL, UCOL_ON, &errSensitivity);
    } else if (
        resolvedSensitivityValue_ ==
        constants::opt_value::sensitivity::variant) {
      ucol_setAttribute(coll_, UCOL_STRENGTH, UCOL_TERTIARY, &errSensitivity);
    }
    assert(
        U_SUCCESS(errSensitivity) &&
        "failed to set collator strength attribute");
  } else {
                                                                     
    auto strengthAttribute =
        ucol_getAttribute(coll_, UCOL_STRENGTH, &errSensitivity);
    assert(
        U_SUCCESS(errSensitivity) &&
        "failed to get collator attribute : UCOL_STRENGTH");
    if (strengthAttribute == UCOL_PRIMARY) {
      UErrorCode errCaseLevel{U_ZERO_ERROR};
      auto caseLevelAttribute =
          ucol_getAttribute(coll_, UCOL_CASE_LEVEL, &errCaseLevel);
      assert(
          U_SUCCESS(errCaseLevel) &&
          "failed to get collator attribute: UCOL_CASE_LEVEL");
      if (caseLevelAttribute == UCOL_ON) {
        resolvedSensitivityValue_ = constants::opt_value::sensitivity::caseStr;
      } else {
        resolvedSensitivityValue_ = constants::opt_value::sensitivity::base;
      }
    } else if (strengthAttribute == UCOL_SECONDARY) {
      resolvedSensitivityValue_ = constants::opt_value::sensitivity::accent;
    } else {
      resolvedSensitivityValue_ = constants::opt_value::sensitivity::variant;
    }
  }

                                                
                                                                               
                          
                                                                                         
                                                           
                                                             
  UErrorCode errIgnorePunctuation{U_ZERO_ERROR};
  if (resolvedIgnorePunctuationValue_ == true) {
    ucol_setAttribute(
        coll_, UCOL_ALTERNATE_HANDLING, UCOL_SHIFTED, &errIgnorePunctuation);
  } else {
    ucol_setAttribute(
        coll_,
        UCOL_ALTERNATE_HANDLING,
        UCOL_NON_IGNORABLE,
        &errIgnorePunctuation);
  }
  assert(
      U_SUCCESS(errIgnorePunctuation) &&
      "failed to set collator alternate-handling attribute");
}

vm::ExecutionStatus Collator::initializeCollator(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
                                                                  
  auto requestedLocalesRes =
      LocaleBCP47Object::canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(requestedLocalesRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }

                                                        
                                                                               
                
            
                                                                        
                                                                             
                                        
  auto usageRes = getStringOption(
      runtime,
      options,
      constants::opt_name::usage,
      constants::opt_value::usage::validUsages,
      constants::opt_value::usage::sort);
  if (LLVM_UNLIKELY(usageRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  resolvedUsageValue_ = **usageRes;

                                
                                                           
             
                                                             
    
                                                                    
                                                                        
                                                                    
                                                                    
                                                       
    
                                                                        
                                                                        
                    

                                
                                                                          
                                                                            
                                                                     
                                                                              
                                                                               
                             
  Options opt;
                                                                        
                                         
                    
                                                                           
                                                                              
                       
  auto matcherRes = getStringOption(
      runtime,
      options,
      constants::opt_name::localeMatcher,
      constants::opt_value::locale_matcher::validLocaleMatchers,
      constants::opt_value::locale_matcher::best_fit);
  if (LLVM_UNLIKELY(matcherRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
                                             
  opt.emplace(constants::opt_name::localeMatcher, **matcherRes);

                                                                            
                
  auto collationValueRes = getStringOption(
      runtime, options, constants::opt_name::collation, {}, std::nullopt);
  if (LLVM_UNLIKELY(collationValueRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
                                            
                                                                      
                                               
  if (collationValueRes->has_value()) {
    if (!isUnicodeExtensionType(**collationValueRes)) {
      return runtime.raiseRangeError(
          vm::TwineChar16("Invalid collation: ") +
          vm::TwineChar16((*collationValueRes)->c_str()));
    }
                                       
    opt.emplace(constants::extension_key::co, **collationValueRes);
  }

                                                                         
                
  auto numericValue =
      getBoolOption(options, constants::opt_name::numeric, std::nullopt);
                                          
                                           
                                                                          
                                                                   
                       
                                   
  if (numericValue.has_value()) {
    opt.emplace(constants::extension_key::kn, *numericValue);
  }

                                                                                
                                    
  auto caseFirstValueRes = getStringOption(
      runtime,
      options,
      constants::opt_name::caseFirst,
      constants::opt_value::case_first::validCaseFirsts,
      std::nullopt);
  if (LLVM_UNLIKELY(caseFirstValueRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
                                     
  if (caseFirstValueRes->has_value()) {
    opt.emplace(constants::extension_key::kf, **caseFirstValueRes);
  }

                                                                            
                                                                     
                                                                           
  static constexpr std::u16string_view relevantExtensionKeys[] = {
      constants::extension_key::co,
      constants::extension_key::kn,
      constants::extension_key::kf};
                                                                
                                                               
                                                                             
                                                                            
                                                                         
                                                                    
                                                                    
  ResolvedResult result = resolveLocale(
      *requestedLocalesRes,
      opt,
      relevantExtensionKeys,
      isExtensionTypeSupported);

                                                 
  LocaleBCP47Object resolvedBCP47Locale = result.localeBcp47Object;
  Options resolvedOpt = result.resolvedOpts;
  resolvedLocale_ = resolvedBCP47Locale.getCanonicalizedLocaleId();

                                   
                                                          
                                                 
    
                                                              
                                                                        
                                                                      
                                                                              
                                                   
    
                                                                        
                                                                       
                                                                             
                                                                            
                                                         
                                                                     
  resolvedCollationValue_ = collationTypeDefault;
  std::map<std::u16string, std::u16string> resolvedExtMap =
      resolvedBCP47Locale.getExtensionMap();
  if (resolvedUsageValue_ == constants::opt_value::usage::search) {
                                                                       
    auto nodeHandle = resolvedExtMap.extract(constants::extension_key::co);
    if (!nodeHandle.empty()) {
      resolvedBCP47Locale.updateExtensionMap(resolvedExtMap);
      resolvedLocale_ = resolvedBCP47Locale.getCanonicalizedLocaleId();
    }
    resolvedExtMap[constants::extension_key::co] = collationTypeSearch;
  } else {
    auto collationEntry = resolvedOpt.find(constants::extension_key::co);
    if (collationEntry != resolvedOpt.end()) {
      resolvedCollationValue_ = collationEntry->second.getString();
      resolvedExtMap[constants::extension_key::co] = resolvedCollationValue_;
    }
  }
  resolvedBCP47Locale.updateExtensionMap(resolvedExtMap);
  resolvedInternalLocale_ = resolvedBCP47Locale.getCanonicalizedLocaleId();

                                                     
                                                                  
  resolvedNumericValue_ = false;
  auto numericEntry = resolvedOpt.find(constants::extension_key::kn);
  if (numericEntry != resolvedOpt.end()) {
    if (numericEntry->second.isBool()) {
      resolvedNumericValue_ = numericEntry->second.getBool();
    } else {
      resolvedNumericValue_ = convertToBool(numericEntry->second.getString());
    }
  }

                                                     
                                               
  auto caseFirstEntry = resolvedOpt.find(constants::extension_key::kf);
  if (caseFirstEntry != resolvedOpt.end()) {
    resolvedCaseFirstValue_ = caseFirstEntry->second.getString();
  }

                                                                           
                                                       
                                          
                                
                                     
             
                                           
                                                           
                                                            
                                                     
  auto sensitivitiesValueRes = getStringOption(
      runtime,
      options,
      constants::opt_name::sensitivity,
      constants::opt_value::sensitivity::validSensitivities,
      std::nullopt);
  if (LLVM_UNLIKELY(sensitivitiesValueRes == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  if (resolvedUsageValue_ == constants::opt_value::usage::sort &&
      !(sensitivitiesValueRes->has_value())) {
    resolvedSensitivityValue_ = constants::opt_value::sensitivity::variant;
  } else if (sensitivitiesValueRes->has_value()) {
    resolvedSensitivityValue_ = **sensitivitiesValueRes;
  }                                                                             
                                                                               
                                                                            
                                                                              

                                                                           
                              
                                                                 
                         
  auto ignorePunctuationValue =
      getBoolOption(options, constants::opt_name::ignorePunctuation, false);

  resolvedIgnorePunctuationValue_ = *ignorePunctuationValue;

  return vm::ExecutionStatus::RETURNED;
}

                                                       
double Collator::compare(
    const std::u16string &x,
    const std::u16string &y) noexcept {
                                                                              
                                                                               
                                                                               
                                                         
  auto result = ucol_strcoll(
      coll_,
      (const UChar *)x.data(),
      x.size(),
      (const UChar *)y.data(),
      y.size());

  switch (result) {
    case UCOL_LESS:
      return -1;
    case UCOL_EQUAL:
      return 0;
    case UCOL_GREATER:
      return 1;
  }
  llvm_unreachable("Invalid result from ucol_strcoll");
}

                                                                       
Options Collator::resolvedOptions() noexcept {
  Options finalResolvedOptions;
  finalResolvedOptions.emplace(
      constants::opt_name::locale, Option(resolvedLocale_));
  finalResolvedOptions.emplace(
      constants::opt_name::usage, Option(resolvedUsageValue_));
  finalResolvedOptions.emplace(
      constants::opt_name::sensitivity, Option(resolvedSensitivityValue_));
  finalResolvedOptions.emplace(
      constants::opt_name::ignorePunctuation,
      Option(resolvedIgnorePunctuationValue_));
  finalResolvedOptions.emplace(
      constants::opt_name::collation, Option(resolvedCollationValue_));
  finalResolvedOptions.emplace(
      constants::opt_name::numeric, Option(resolvedNumericValue_));
  finalResolvedOptions.emplace(
      constants::opt_name::caseFirst, Option(resolvedCaseFirstValue_));

  return finalResolvedOptions;
}

vm::CallResult<std::vector<std::u16string>> Collator::supportedLocalesOf(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  return supportedLocales(runtime, locales, options);
}

bool Collator::isExtensionTypeSupported(
    std::u16string_view extensionKey,
    std::u16string_view extensionType,
    const LocaleBCP47Object &localeBCP47Object) {
  if (extensionKey == constants::extension_key::kf) {
    return std::find(
               std::begin(constants::opt_value::case_first::validCaseFirsts),
               std::end(constants::opt_value::case_first::validCaseFirsts),
               extensionType) !=
        std::end(constants::opt_value::case_first::validCaseFirsts);
  }
  if (extensionKey == constants::extension_key::kn) {
    return std::find(
               std::begin(constants::opt_value::numeric::validNumerics),
               std::end(constants::opt_value::numeric::validNumerics),
               extensionType) !=
        std::end(constants::opt_value::numeric::validNumerics);
  }
  if (extensionKey == constants::extension_key::co) {
                                                                     
                          
                                                                       
    if (extensionType == collationTypeStandard ||
        extensionType == collationTypeSearch) {
      return false;
    }
                                                                          
                                                          
                                                                          
                                  
                                                                               
    static constexpr std::pair<std::u16string_view, std::u16string_view>
        aliasMap[] = {
            {u"dictionary", u"dict"},
            {u"gb2312han", u"gb2312"},
            {u"phonebook", u"phonebk"},
            {u"traditional", u"trad"}};
    auto icuLocale =
        convertBCP47toICULocale(localeBCP47Object.getLocaleNoExt());
    UErrorCode status = U_ZERO_ERROR;
    UEnumeration *supportedTypes = ucol_getKeywordValuesForLocale(
        "collation",
        icuLocale.c_str(),
                                                                               
                      
        false,
        &status);
    if (U_FAILURE(status)) {
      return false;
    }
    bool supported = false;
    int32_t length;
    const UChar *type = uenum_unext(supportedTypes, &length, &status);
    while (type != nullptr && U_SUCCESS(status)) {
      std::u16string_view supportedType(
          reinterpret_cast<const char16_t *>(type), length);
      for (const auto &aliasPair : aliasMap) {
        if (supportedType == aliasPair.first) {
          supportedType = aliasPair.second;
          break;
        }
      }
      if (extensionType == supportedType) {
        supported = true;
        break;
      }
      type = uenum_unext(supportedTypes, &length, &status);
    }
    uenum_close(supportedTypes);
    return supported;
  }

  return false;
}

}                      
}                           
}                    
