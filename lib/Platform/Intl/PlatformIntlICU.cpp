/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Platform/Intl/BCP47Parser.h"
#include "hermes/Platform/Intl/PlatformIntl.h"
#include "hermes/Platform/Intl/PlatformIntlShared.h"
#include "impl_icu/Collator.h"
#include "impl_icu/IntlUtils.h"
#include "impl_icu/LocaleBCP47Object.h"
#include "impl_icu/LocaleResolver.h"
#include "impl_icu/OptionHelpers.h"

#include <shared_mutex>
#include <string>
#include <unordered_map>

                                                                         
                                                                            
                                                
#define UCHAR_TYPE char16_t

#include "unicode/dtptngen.h"
#include "unicode/strenum.h"
#include "unicode/timezone.h"
#include "unicode/udat.h"
#include "unicode/unistr.h"

using namespace U_ICU_NAMESPACE;

namespace hermes {
namespace platform_intl {
namespace {

                                                  
class TimeZoneNames {
 public:
                                                                       
                   
  TimeZoneNames() {
    std::unique_ptr<StringEnumeration> icuTimeZones(
        TimeZone::createEnumeration());
    UErrorCode status = U_ZERO_ERROR;
    auto *zoneId = icuTimeZones->unext(nullptr, status);

    while (zoneId != nullptr && status == U_ZERO_ERROR) {
      auto upper = toASCIIUppercase(zoneId);
      timeZoneNamesMap_.emplace(std::move(upper), std::move(zoneId));
      zoneId = icuTimeZones->unext(nullptr, status);
    }
  }

                                               
  bool contains(std::u16string_view tz) const {
    std::shared_lock lock(mutex_);
    return timeZoneNamesMap_.find(toASCIIUppercase(tz)) !=
        timeZoneNamesMap_.end();
  }

                                                                  
                                
  std::u16string getCanonical(std::u16string_view tz) const {
    std::shared_lock lock(mutex_);
    auto ianaTimeZoneIt = timeZoneNamesMap_.find(toASCIIUppercase(tz));
    assert(
        ianaTimeZoneIt != timeZoneNamesMap_.end() &&
        "getCanonical() must be called on valid time zone name.");
    return ianaTimeZoneIt->second;
  }

                                                                        
  void update(std::u16string_view tz) {
    auto upper = toASCIIUppercase(tz);
                                                       
    {
      std::shared_lock lock(mutex_);
      if (timeZoneNamesMap_.find(upper) != timeZoneNamesMap_.end()) {
        return;
      }
    }
                                                     
    {
      std::unique_lock lock(mutex_);
      timeZoneNamesMap_.emplace(upper, tz);
    }
  }

 private:
                                                                     
  std::unordered_map<std::u16string, std::u16string> timeZoneNamesMap_;
  mutable std::shared_mutex mutex_;
};

static TimeZoneNames &validTimeZoneNames() {
  static TimeZoneNames validTimeZoneNames;
  return validTimeZoneNames;
}

                                                                   
static bool isValidTimeZoneName(std::u16string_view tz) {
  return validTimeZoneNames().contains(tz);
}

                                                               
std::u16string getDefaultTimeZone(vm::Runtime &runtime) {
  std::unique_ptr<TimeZone> timeZone(TimeZone::createDefault());
  UnicodeString unicodeTz;
  timeZone->getID(unicodeTz);
  std::u16string tz(unicodeTz.getBuffer(), unicodeTz.length());
  validTimeZoneNames().update(tz);
  return tz;
}

                                                                        
std::u16string canonicalizeTimeZoneName(std::u16string_view tz) {
                                                                                
                                                                              
                                                                  
  auto ianaTimeZone = validTimeZoneNames().getCanonical(tz);
                                                                            
                                                                             
                                                                        
              
                                                                
  if (ianaTimeZone == u"Etc/UTC" || ianaTimeZone == u"Etc/GMT")
    ianaTimeZone = u"UTC";
                            
  return ianaTimeZone;
}

                                                          
                                                              
                                      
                                                               
                                                             
                            
template <typename T, typename BaseT>
vm::CallResult<std::unique_ptr<BaseT>> createInstance(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  auto instance = std::make_unique<T>();
  if (LLVM_UNLIKELY(
          instance->initialize(runtime, locales, options) ==
          vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  return std::move(instance);
}

}             

                       
vm::CallResult<std::u16string> toLocaleLowerCase(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const std::u16string &str) {
  return std::u16string(u"lowered");
}
                       
vm::CallResult<std::u16string> toLocaleUpperCase(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const std::u16string &str) {
  return std::u16string(u"uppered");
}

Collator::Collator() = default;
Collator::~Collator() = default;

vm::CallResult<std::vector<std::u16string>> Collator::supportedLocalesOf(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  return impl_icu::Collator::supportedLocalesOf(runtime, locales, options);
}

vm::CallResult<std::unique_ptr<Collator>> Collator::create(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  return createInstance<impl_icu::Collator, Collator>(
      runtime, locales, options);
}

Options Collator::resolvedOptions() noexcept {
  return static_cast<impl_icu::Collator *>(this)->resolvedOptions();
}

double Collator::compare(
    const std::u16string &x,
    const std::u16string &y) noexcept {
  return static_cast<impl_icu::Collator *>(this)->compare(x, y);
}

namespace {
                     
                                                                  
struct DateTimeFormatICU : DateTimeFormat {
 public:
  DateTimeFormatICU() = default;
  ~DateTimeFormatICU() {
    udat_close(dateTimeFormatter_);
  };

  vm::ExecutionStatus initialize(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales,
      const Options &inputOptions) noexcept;
  Options resolvedOptions() noexcept;

  std::u16string format(double jsTimeValue) noexcept;

 private:
  UDateFormat *getUDateFormatter(vm::Runtime &runtime);
  std::u16string getDefaultHourCycle();

                                                                                             
                                                                         
                    
                                                         
                                                              
                                                 
                                                                            
                                          
  std::u16string locale_;
                                                                               
                                                       
  std::optional<std::u16string> calendar_;
                                                                            
                                                                         
                                                                             
                               
  std::u16string timeZone_;
                                                                        
                                                                        
                                                                             
                                                                             
                                                  
  std::optional<std::u16string> weekday_;
  std::optional<std::u16string> era_;
  std::optional<std::u16string> year_;
  std::optional<std::u16string> month_;
  std::optional<std::u16string> day_;
  std::optional<std::u16string> dayPeriod_;
  std::optional<std::u16string> hour_;
  std::optional<std::u16string> minute_;
  std::optional<std::u16string> second_;
  std::optional<std::u16string> timeZoneName_;
                                                                            
                                                                        
                                                                                
                   
  std::optional<uint8_t> fractionalSecondDigits_;
                                                                           
                                                                               
                                                                                
                                                                                
                                     
  std::optional<std::u16string> hourCycle_;
                                                                               
                                                       
  std::optional<std::u16string> dateStyle_;
  std::optional<std::u16string> timeStyle_;
                                                   
  std::string locale8_;
                                              
  UDateFormat *dateTimeFormatter_;
};
}             

DateTimeFormat::DateTimeFormat() = default;
DateTimeFormat::~DateTimeFormat() = default;

                                                                                      
vm::CallResult<std::vector<std::u16string>> DateTimeFormat::supportedLocalesOf(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  return impl_icu::supportedLocales(runtime, locales, options);
}

vm::ExecutionStatus DateTimeFormatICU::initialize(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &inputOptions) noexcept {
                                                                  
  auto requestedLocalesRes =
      impl_icu::LocaleBCP47Object::canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(requestedLocalesRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                                   
  auto optionsRes = toDateTimeOptions(runtime, inputOptions, u"any", u"date");
  if (LLVM_UNLIKELY(optionsRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto options = *optionsRes;
                                
  Options opt;
                                                                      
                                          
  auto matcherRes = impl_icu::getStringOption(
      runtime,
      options,
      u"localeMatcher",
      {u"lookup", u"best fit"},
      u"best fit");
  if (LLVM_UNLIKELY(matcherRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                             
  auto matcherOpt = *matcherRes;
  opt.emplace(u"localeMatcher", *matcherOpt);
                                                                  
                           
  auto calendarRes =
      impl_icu::getStringOption(runtime, options, u"calendar", {}, {});
                                          
  if (LLVM_UNLIKELY(calendarRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                   
  if (auto calendarOpt = *calendarRes) {
                                                                       
                                                 
    if (!isUnicodeExtensionType(*calendarOpt))
      return runtime.raiseRangeError(
          vm::TwineChar16("Invalid calendar: ") +
          vm::TwineChar16(calendarOpt->c_str()));
    opt.emplace(u"ca", *calendarOpt);
  }
                                                                      
                                     
                                                  
                                                                       
                                                    
                                           
  opt.emplace(u"nu", u"");
                                                                
                           
  auto hour12 = impl_icu::getBoolOption(options, u"hour12", {});
                                                                       
                                              
  auto hourCycleRes = impl_icu::getStringOption(
      runtime, options, u"hourCycle", {u"h11", u"h12", u"h23", u"h24"}, {});
  if (LLVM_UNLIKELY(hourCycleRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto hourCycleOpt = *hourCycleRes;
                                         
  if (hour12.has_value())
                                
                                                                        
                                                                             
                         
    hourCycleOpt = u"";
  if (hourCycleOpt.has_value())
                                       
    opt.emplace(u"hc", *hourCycleOpt);
                                                           
                                                                             
                                                  
                                                                      
                                                                       
                 
  static constexpr std::u16string_view relevantExtensionKeys[] = {
      u"ca", u"nu", u"hc"};
  auto r = impl_icu::resolveLocale(
      *requestedLocalesRes,
      opt,
      relevantExtensionKeys,
      [](auto key, auto type, auto locale) { return true; });
                                                       
  locale_ = r.localeBcp47Object.getCanonicalizedLocaleId();

                                                                          
              
  locale8_ = impl_icu::toUTF8ASCII(locale_);

                                  
  auto caIt = r.resolvedOpts.find(u"ca");
                                                     
  if (caIt != r.resolvedOpts.end())
    calendar_ = caIt->second.getString();
                                                      
  auto hcIt = r.resolvedOpts.find(u"hc");
  if (hcIt != r.resolvedOpts.end())
    hourCycle_ = hcIt->second.getString();
                                                            
                                            
                                                    
  auto timeZoneIt = options.find(u"timeZone");
  std::u16string timeZone;
                                        
  if (timeZoneIt == options.end()) {
                                            
    timeZone = getDefaultTimeZone(runtime);
                
  } else {
                                               
    timeZone = timeZoneIt->second.getString();
                                                                       
    if (!isValidTimeZoneName(timeZone)) {
                                         
      return runtime.raiseRangeError("Incorrect timeZone information provided");
    }
                                                             
    timeZone = canonicalizeTimeZoneName(timeZone);
  }
                                                     
  timeZone_ = timeZone;
                                 
                                                                           
                                                                     
                                                 
                                                                            
                   
                                    
             
                                                                       
                                                         
                                    
                                                           
                                                                         
                                        
                                                                               
                                             
  auto dateStyleRes = impl_icu::getStringOption(
      runtime,
      options,
      u"dateStyle",
      {u"full", u"long", u"medium", u"short"},
      {});
  if (LLVM_UNLIKELY(dateStyleRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                       
  dateStyle_ = *dateStyleRes;
                                                                               
                                             
  auto timeStyleRes = impl_icu::getStringOption(
      runtime,
      options,
      u"timeStyle",
      {u"full", u"long", u"medium", u"short"},
      {});
  if (LLVM_UNLIKELY(timeStyleRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                       
  timeStyle_ = *timeStyleRes;

                                                               
  auto weekdayRes = impl_icu::getStringOption(
      runtime, options, u"weekday", {u"narrow", u"short", u"long"}, {});
  if (LLVM_UNLIKELY(weekdayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  weekday_ = *weekdayRes;

  auto eraRes = impl_icu::getStringOption(
      runtime, options, u"era", {u"narrow", u"short", u"long"}, {});
  if (LLVM_UNLIKELY(eraRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  era_ = *eraRes;

  auto yearRes = impl_icu::getStringOption(
      runtime, options, u"year", {u"2-digit", u"numeric"}, {});
  if (LLVM_UNLIKELY(yearRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  year_ = *yearRes;

  auto monthRes = impl_icu::getStringOption(
      runtime,
      options,
      u"month",
      {u"2-digit", u"numeric", u"narrow", u"short", u"long"},
      {});
  if (LLVM_UNLIKELY(monthRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  month_ = *monthRes;

  auto dayRes = impl_icu::getStringOption(
      runtime, options, u"day", {u"2-digit", u"numeric"}, {});
  if (LLVM_UNLIKELY(dayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  day_ = *dayRes;

  auto dayPeriodRes = impl_icu::getStringOption(
      runtime, options, u"dayPeriod", {u"narrow", u"short", u"long"}, {});
  if (LLVM_UNLIKELY(dayPeriodRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  dayPeriod_ = *dayPeriodRes;

  auto hourRes = impl_icu::getStringOption(
      runtime, options, u"hour", {u"2-digit", u"numeric"}, {});
  if (LLVM_UNLIKELY(hourRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  hour_ = *hourRes;

  auto minuteRes = impl_icu::getStringOption(
      runtime, options, u"minute", {u"2-digit", u"numeric"}, {});
  if (LLVM_UNLIKELY(minuteRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  minute_ = *minuteRes;

  auto secondRes = impl_icu::getStringOption(
      runtime, options, u"second", {u"2-digit", u"numeric"}, {});
  if (LLVM_UNLIKELY(secondRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  second_ = *secondRes;

  auto fractionalSecondDigitsRes = impl_icu::getNumberOption(
      runtime, options, u"fractionalSecondDigits", 1, 3, {});
  if (LLVM_UNLIKELY(
          fractionalSecondDigitsRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  fractionalSecondDigits_ = *fractionalSecondDigitsRes;

                                                                     
                        
                                                      
                                                                
                                                                                    
  auto timeZoneNameRes = impl_icu::getStringOption(
      runtime,
      options,
      u"timeZoneName",
      {u"short",
       u"long",
       u"shortOffset",
       u"longOffset",
       u"shortGeneric",
       u"longGeneric"},
      {});
  if (LLVM_UNLIKELY(timeZoneNameRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  timeZoneName_ = *timeZoneNameRes;
                                                                     
                
                                                                          
                                                          
                                                                     
                                 
                                     
                                    
                                                               
                                                                            
              
                                                                 
                                   
                                                           
             
                                                             
                                                                           
                                     
                                                                     
                           
                                                  
                                       
                                                                      
                                 
                                                      
  if (!hour_.has_value()) {
                                                        
    hourCycle_ = std::nullopt;
                                                
                                                            
                
  } else {
                                                        
    auto hcDefault = getDefaultHourCycle();
                                                 
    auto hc = hourCycle_;
                             
    if (!hc.has_value())
                                
      hc = hcDefault;
                                          
    if (hour12.has_value()) {
                                   
      if (*hour12 == true) {
                                                  
        if (hcDefault == u"h11" || hcDefault == u"h23") {
                                
          hc = u"h11";
                     
        } else {
                                
          hc = u"h12";
        }
                    
      } else {
                                      
                                                  
        if (hcDefault == u"h11" || hcDefault == u"h23") {
                                
          hc = u"h23";
                     
        } else {
                                
          hc = u"h24";
        }
      }
    }
                                                 
    hourCycle_ = hc;
                                                                 
                                                  
                                                               
               
                                                
                                                             
  }
                                                   
                                                               
                               
  dateTimeFormatter_ = getUDateFormatter(runtime);
  return vm::ExecutionStatus::RETURNED;
}

                                                       
UDateFormat *DateTimeFormatICU::getUDateFormatter(vm::Runtime &runtime) {
  static constexpr std::u16string_view kLong = u"long", kShort = u"short",
                                       kNarrow = u"narrow",
                                       keMedium = u"medium", kFull = u"full",
                                       kNumeric = u"numeric",
                                       kTwoDigit = u"2-digit",
                                       kShortOffset = u"shortOffset",
                                       kLongOffset = u"longOffset",
                                       kShortGeneric = u"shortGeneric",
                                       kLongGeneric = u"longGeneric";

                                                                         
             
  if (timeStyle_.has_value() || dateStyle_.has_value()) {
    UDateFormatStyle dateStyleRes = UDAT_NONE;
    UDateFormatStyle timeStyleRes = UDAT_NONE;

    if (dateStyle_.has_value()) {
      if (dateStyle_ == kFull)
        dateStyleRes = UDAT_FULL;
      else if (dateStyle_ == kLong)
        dateStyleRes = UDAT_LONG;
      else if (dateStyle_ == keMedium)
        dateStyleRes = UDAT_MEDIUM;
      else if (dateStyle_ == kShort)
        dateStyleRes = UDAT_SHORT;
    }

    if (timeStyle_.has_value()) {
      if (timeStyle_ == kFull)
        timeStyleRes = UDAT_FULL;
      else if (timeStyle_ == kLong)
        timeStyleRes = UDAT_LONG;
      else if (timeStyle_ == keMedium)
        timeStyleRes = UDAT_MEDIUM;
      else if (timeStyle_ == kShort)
        timeStyleRes = UDAT_SHORT;
    }

    UErrorCode status = U_ZERO_ERROR;
    UDateFormat *dtf;
                                                                   
    if (!timeZone_.empty()) {
      const UChar *timeZoneRes =
          reinterpret_cast<const UChar *>(timeZone_.c_str());
      int32_t timeZoneLength = timeZone_.length();
      dtf = udat_open(
          timeStyleRes,
          dateStyleRes,
          &locale8_[0],
          timeZoneRes,
          timeZoneLength,
          nullptr,
          -1,
          &status);
    } else {
      dtf = udat_open(
          timeStyleRes,
          dateStyleRes,
          &locale8_[0],
          nullptr,
          -1,
          nullptr,
          -1,
          &status);
    }
    assert(status == U_ZERO_ERROR);
    return dtf;
  }

                                   
  std::u16string skeleton = u"";
  if (weekday_.has_value()) {
    if (weekday_ == kNarrow)
      skeleton += u"EEEEE";
    else if (weekday_ == kLong)
      skeleton += u"EEEE";
    else if (weekday_ == kShort)
      skeleton += u"EEE";
  }

  if (timeZoneName_.has_value()) {
    if (timeZoneName_ == kShort)
      skeleton += u"z";
    else if (timeZoneName_ == kLong)
      skeleton += u"zzzz";
    else if (timeZoneName_ == kShortOffset)
      skeleton += u"O";
    else if (timeZoneName_ == kLongOffset)
      skeleton += u"OOOO";
    else if (timeZoneName_ == kShortGeneric)
      skeleton += u"v";
    else if (timeZoneName_ == kLongGeneric)
      skeleton += u"vvvv";
  }

  if (era_.has_value()) {
    if (era_ == kNarrow)
      skeleton += u"GGGGG";
    else if (era_ == kShort)
      skeleton += u"GG";
    else if (era_ == kLong)
      skeleton += u"GGGG";
  }

  if (year_.has_value()) {
    if (year_ == kNumeric)
      skeleton += u"y";
    else if (year_ == kTwoDigit)
      skeleton += u"yy";
  }

  if (month_.has_value()) {
    if (month_ == kTwoDigit)
      skeleton += u"MM";
    else if (month_ == kNumeric)
      skeleton += u'M';
    else if (month_ == kNarrow)
      skeleton += u"MMMMM";
    else if (month_ == kShort)
      skeleton += u"MMM";
    else if (month_ == kLong)
      skeleton += u"MMMM";
  }

  if (day_.has_value()) {
    if (day_ == kNumeric)
      skeleton += u"d";
    else if (day_ == kTwoDigit)
      skeleton += u"dd";
  }

  if (hour_.has_value()) {
    if (hourCycle_ == u"h12") {
      if (hour_ == kNumeric)
        skeleton += u"h";
      else if (hour_ == kTwoDigit)
        skeleton += u"hh";
    } else if (hourCycle_ == u"h24") {
      if (hour_ == kNumeric)
        skeleton += u"k";
      else if (hour_ == kTwoDigit)
        skeleton += u"kk";
    } else if (hourCycle_ == u"h23") {
      if (hour_ == kNumeric)
        skeleton += u"H";
      else if (hour_ == kTwoDigit)
        skeleton += u"HH";
    } else {
      if (hour_ == kNumeric)
        skeleton += u"h";
      else if (hour_ == kTwoDigit)
        skeleton += u"HH";
    }
  }

  if (minute_.has_value()) {
    if (minute_ == kNumeric)
      skeleton += u"m";
    else if (minute_ == kTwoDigit)
      skeleton += u"mm";
  }

  if (second_.has_value()) {
    if (second_ == kNumeric)
      skeleton += u"s";
    else if (second_ == kTwoDigit)
      skeleton += u"ss";
  }

  UErrorCode status = U_ZERO_ERROR;
  std::u16string bestpattern;
  int32_t patternLength;

  std::unique_ptr<UDateTimePatternGenerator, decltype(&udatpg_close)>
      dtpGenerator(udatpg_open(&locale8_[0], &status), &udatpg_close);
  patternLength = udatpg_getBestPatternWithOptions(
      dtpGenerator.get(),
      &skeleton[0],
      -1,
      UDATPG_MATCH_ALL_FIELDS_LENGTH,
      nullptr,
      0,
      &status);

  if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    bestpattern.resize(patternLength);
    udatpg_getBestPatternWithOptions(
        dtpGenerator.get(),
        &skeleton[0],
        skeleton.length(),
        UDATPG_MATCH_ALL_FIELDS_LENGTH,
        &bestpattern[0],
        patternLength,
        &status);
  }

                                                                 
  if (!timeZone_.empty()) {
    const UChar *timeZoneRes =
        reinterpret_cast<const UChar *>(timeZone_.c_str());
    int32_t timeZoneLength = timeZone_.length();
    return udat_open(
        UDAT_PATTERN,
        UDAT_PATTERN,
        &locale8_[0],
        timeZoneRes,
        timeZoneLength,
        &bestpattern[0],
        patternLength,
        &status);
  } else {
    return udat_open(
        UDAT_PATTERN,
        UDAT_PATTERN,
        &locale8_[0],
        nullptr,
        -1,
        &bestpattern[0],
        patternLength,
        &status);
  }
}

std::u16string DateTimeFormatICU::getDefaultHourCycle() {
  UErrorCode status = U_ZERO_ERROR;
  std::u16string myString;
                                                       
  UDateFormat *defaultDTF = udat_open(
      UDAT_DEFAULT,
      UDAT_DEFAULT,
      &locale8_[0],
      nullptr,
      -1,
      nullptr,
      -1,
      &status);
  int32_t size = udat_toPattern(defaultDTF, true, nullptr, 0, &status);
  if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    myString.resize(size + 1);
    udat_toPattern(defaultDTF, true, &myString[0], 40, &status);
    assert(status <= 0);                    
    udat_close(defaultDTF);
                                                
    for (int32_t i = 0; i < size; i++) {
      char16_t ch = myString[i];
      switch (ch) {
        case 'K':
          return u"h11";
          break;
        case 'h':
          return u"h12";
          break;
        case 'H':
          return u"h23";
          break;
        case 'k':
          return u"h24";
          break;
      }
    }
  }

  return u"h24";
}

vm::CallResult<std::unique_ptr<DateTimeFormat>> DateTimeFormat::create(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &inputOptions) noexcept {
  auto instance = std::make_unique<DateTimeFormatICU>();
  if (LLVM_UNLIKELY(
          instance->initialize(runtime, locales, inputOptions) ==
          vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  return instance;
}

                                                        
                                                                                             
Options DateTimeFormatICU::resolvedOptions() noexcept {
  Options options;
  options.emplace(u"locale", Option(locale_));
  options.emplace(u"timeZone", Option(timeZone_));
  if (calendar_)
    options.emplace(u"calendar", Option(*calendar_));
  if (hourCycle_.has_value()) {
    options.emplace(u"hourCycle", *hourCycle_);
    options.emplace(u"hour12", hourCycle_ == u"h11" || hourCycle_ == u"h12");
  }
  if (weekday_.has_value())
    options.emplace(u"weekday", *weekday_);
  if (era_.has_value())
    options.emplace(u"era", *era_);
  if (year_.has_value())
    options.emplace(u"year", *year_);
  if (month_.has_value())
    options.emplace(u"month", *month_);
  if (day_.has_value())
    options.emplace(u"day", *day_);
  if (hour_.has_value())
    options.emplace(u"hour", *hour_);
  if (minute_.has_value())
    options.emplace(u"minute", *minute_);
  if (second_.has_value())
    options.emplace(u"second", *second_);
  if (timeZoneName_.has_value())
    options.emplace(u"timeZoneName", *timeZoneName_);
  if (dateStyle_.has_value())
    options.emplace(u"dateStyle", *dateStyle_);
  if (timeStyle_.has_value())
    options.emplace(u"timeStyle", *timeStyle_);
  return options;
}

Options DateTimeFormat::resolvedOptions() noexcept {
  return static_cast<DateTimeFormatICU *>(this)->resolvedOptions();
}

std::u16string DateTimeFormatICU::format(double jsTimeValue) noexcept {
  auto timeInSeconds = jsTimeValue;
  UDate date = UDate(timeInSeconds);
  UErrorCode status = U_ZERO_ERROR;
  std::u16string formattedDate;
  int32_t myStrlen = 0;

  myStrlen = udat_format(
      dateTimeFormatter_, date, nullptr, myStrlen, nullptr, &status);
  if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    formattedDate.resize(myStrlen);
    udat_format(
        dateTimeFormatter_,
        date,
        &formattedDate[0],
        myStrlen,
        nullptr,
        &status);
  }

  assert(status <= 0);                    
  return formattedDate;
}

std::u16string DateTimeFormat::format(double jsTimeValue) noexcept {
  return static_cast<DateTimeFormatICU *>(this)->format(jsTimeValue);
}

std::vector<std::unordered_map<std::u16string, std::u16string>>
DateTimeFormat::formatToParts(double jsTimeValue) noexcept {
  std::unordered_map<std::u16string, std::u16string> part;
  part[u"type"] = u"integer";
                                                                    
  std::string s = std::to_string(jsTimeValue);
  part[u"value"] = {s.begin(), s.end()};
  return std::vector<std::unordered_map<std::u16string, std::u16string>>{part};
}

namespace {
struct NumberFormatDummy : NumberFormat {
  NumberFormatDummy(const char16_t *l) : locale(l) {}
  std::u16string locale;
};
}             

NumberFormat::NumberFormat() = default;
NumberFormat::~NumberFormat() = default;

vm::CallResult<std::vector<std::u16string>> NumberFormat::supportedLocalesOf(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  return std::vector<std::u16string>{u"en-CA", u"de-DE"};
}

vm::CallResult<std::unique_ptr<NumberFormat>> NumberFormat::create(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  return std::make_unique<NumberFormatDummy>(u"en-US");
}

Options NumberFormat::resolvedOptions() noexcept {
  Options options;
  options.emplace(
      u"locale", Option(static_cast<NumberFormatDummy *>(this)->locale));
  options.emplace(u"numeric", Option(false));
  return options;
}

std::u16string NumberFormat::format(double number) noexcept {
  auto s = std::to_string(number);
  return std::u16string(s.begin(), s.end());
}

std::vector<std::unordered_map<std::u16string, std::u16string>>
NumberFormat::formatToParts(double number) noexcept {
  std::unordered_map<std::u16string, std::u16string> part;
  part[u"type"] = u"integer";
                                                                    
  std::string s = std::to_string(number);
  part[u"value"] = {s.begin(), s.end()};
  return std::vector<std::unordered_map<std::u16string, std::u16string>>{part};
}

}                           
}                    
