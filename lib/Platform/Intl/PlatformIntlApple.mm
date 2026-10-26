/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Platform/Intl/BCP47Parser.h"
#include "hermes/Platform/Intl/PlatformIntl.h"

#import <Foundation/Foundation.h>
#include <shared_mutex>
#include <thread>
#include <unordered_set>

static_assert(__has_feature(objc_arc), "arc must be enabled");

namespace hermes {
namespace platform_intl {
namespace {
NSString *u16StringToNSString(const std::u16string &src) {
  auto size = src.size();
  const auto *cString = (const unichar *)src.c_str();
  return [NSString stringWithCharacters:cString length:size];
}
std::u16string nsStringToU16String(NSString *src) {
  auto size = src.length;
  std::u16string result;
  result.resize(size);
  [src getCharacters:(unichar *)&result[0] range:NSMakeRange(0, size)];
  return result;
}
const std::vector<std::u16string> &getAvailableLocales() {
  static const std::vector<std::u16string> *availableLocales = [] {
    NSArray<NSString *> *availableLocales =
        [NSLocale availableLocaleIdentifiers];
                                                                
    auto *vec = new std::vector<std::u16string>();
    for (id str in availableLocales) {
      auto u16str = nsStringToU16String(str);
                                                                               
                                                                               
                           
      std::replace(u16str.begin(), u16str.end(), u'_', u'-');
                                                                               
                                
                                                                          
                                                       
                                                                        
                                            
      if (auto parsed = ParsedLocaleIdentifier::parse(u16str))
        vec->push_back(parsed->canonicalize());
    }
    return vec;
  }();
  return *availableLocales;
}
const std::u16string &getDefaultLocale() {
  static const std::u16string *defLocale = new std::u16string([] {
                                                 
    const char *testLocale = std::getenv("_HERMES_TEST_LOCALE");
    NSString *nsLocale = testLocale
        ? [NSString stringWithUTF8String:testLocale]
        : [[NSLocale currentLocale] localeIdentifier];
    auto defLocale = nsStringToU16String(nsLocale);

                                                                         
                                                                               
    size_t delimIdx = defLocale.find(u'@');
    if (delimIdx != std::u16string::npos)
      defLocale.resize(delimIdx);

                                              
    std::replace(defLocale.begin(), defLocale.end(), u'_', u'-');
    if (auto parsed = ParsedLocaleIdentifier::parse(defLocale))
      return parsed->canonicalize();
    return std::u16string(u"und");
  }());
  return *defLocale;
}

                                                                   
std::optional<std::u16string> bestAvailableLocale(
    const std::vector<std::u16string> &availableLocales,
    const std::u16string &locale) {
                               
  std::u16string candidate = locale;

              
  while (true) {
                                                                            
                 
    if (llvh::find(availableLocales, candidate) != availableLocales.end())
      return candidate;

                                                                               
                        
    size_t pos = candidate.rfind(u'-');

                                                             
    if (pos == std::u16string::npos)
      return std::nullopt;

                                                                              
                         
    if (pos >= 2 && candidate[pos - 2] == '-')
      pos -= 2;

                                                                      
                                             
    candidate.resize(pos);
  }
}

struct LocaleMatch {
  std::u16string locale;
  std::map<std::u16string, std::u16string> extensions;
};
                                                             
LocaleMatch lookupMatcher(
    const std::vector<std::u16string> &availableLocales,
    const std::vector<std::u16string> &requestedLocales) {
                                   
  LocaleMatch result;
                                                       
  for (const std::u16string &locale : requestedLocales) {
                                                                        
                                                      
                                                                        
                                                                         
                          
                                                                      
                           
    std::optional<std::u16string> availableLocale =
        bestAvailableLocale(availableLocales, locale);
                                                   
    if (availableLocale) {
                                                     
      result.locale = std::move(*availableLocale);
                                                                            
             
                                                                            
                                                             
                                                  
      auto parsed = ParsedLocaleIdentifier::parse(locale);
      result.extensions = std::move(parsed->unicodeExtensionKeywords);
                            
      return result;
    }
  }
                                                                          
  result.locale = getDefaultLocale();
                      
  return result;
}

struct ResolvedLocale {
  std::u16string locale;
  std::u16string dataLocale;
  std::unordered_map<std::u16string, std::u16string> extensions;
};
                                                             
ResolvedLocale resolveLocale(
    const std::vector<std::u16string> &availableLocales,
    const std::vector<std::u16string> &requestedLocales,
    const std::unordered_map<std::u16string, std::u16string> &options,
    llvh::ArrayRef<std::u16string_view> relevantExtensionKeys) {
                                                 
                                    
                                                                   
             
                                                                    
  auto r = lookupMatcher(availableLocales, requestedLocales);
                                        
  auto foundLocale = r.locale;
                                   
  ResolvedLocale result;
                                                 
  result.dataLocale = foundLocale;
                                             
                                                                        
                                                
                                       
  std::u16string supportedExtension = u"-u";
                                                         
  for (const auto &keyView : relevantExtensionKeys) {
                                                                               
                                                                       
    std::u16string key{keyView};
                                                              
                                                                               
                                               
                                                  
                                                         
                                              
                                        
                                                       
                                               
                                               
    auto extIt = r.extensions.find(key);
    std::optional<std::u16string> value;
    std::u16string supportedExtensionAddition;
                                                                                
    if (extIt != r.extensions.end()) {
                                                                             
             
                                                  
                                                           
                                                          
                                        
                                                                               
                             
                                                       
                                
                                                                             
                 
      supportedExtensionAddition.append(u"-").append(key);
      if (extIt->second.empty())
        value = u"true";
      else {
        value = extIt->second;
        supportedExtensionAddition.append(u"-").append(*value);
      }
    }
                                                
    auto optIt = options.find(key);
    if (optIt != options.end()) {
                                                  
      std::u16string optionsValue = optIt->second;
                                                                             
                                                   
                                                                            
                                                                           
                                                                         
                                                                             
                            
                                                                            
                                                                       
                                                                         
                                                                             
                           
                                                     
      if (optionsValue.empty()) {
                                         
        optionsValue = u"true";
      }
                                                         
                                                            
      if (optionsValue != value) {
                                        
        value = optionsValue;
                                                   
        supportedExtensionAddition = u"";
      }
    }
                                        
    if (value)
      result.extensions.emplace(key, std::move(*value));
                                                                  
    supportedExtension.append(supportedExtensionAddition);
  }
                                                                                
  if (supportedExtension.size() > 2) {
                                                                               
                           
    foundLocale.append(supportedExtension);
  }
                                              
  result.locale = std::move(foundLocale);
                       
  return result;
}

                                                                      
vm::CallResult<std::vector<std::u16string>> canonicalizeLocaleList(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales) {
                                     
                                 
                                                                           
                                     
  std::vector<std::u16string> seen;
                                                                                
                                              
            
                                         
                                                                                
                                                                               
                                                     
                                                  
                   
                             
  for (const auto &locale : locales) {
                                                                        
    auto parsedOpt = ParsedLocaleIdentifier::parse(locale);
    if (!parsedOpt)
      return runtime.raiseRangeError(
          vm::TwineChar16("Invalid language tag: ") +
          vm::TwineChar16(locale.c_str()));
    auto canonicalizedTag = parsedOpt->canonicalize();

                                                                     
                                                    
    if (std::find(seen.begin(), seen.end(), canonicalizedTag) == seen.end()) {
      seen.push_back(std::move(canonicalizedTag));
    }
  }
  return seen;
}

vm::CallResult<std::u16string> localeListToLocaleString(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales) {
                                                                  
  vm::CallResult<std::vector<std::u16string>> requestedLocales =
      canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(requestedLocales == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }

                                                      
                                                   
             
                                               
  std::u16string requestedLocale = requestedLocales->empty()
      ? getDefaultLocale()
      : std::move(requestedLocales->front());
                                                                               
                                                            
                                                             
                                                                           
                                                                         
                                                                              
                                                         
                                                                                
                                                          
  const std::vector<std::u16string> &availableLocales = getAvailableLocales();
  std::optional<std::u16string> locale =
      bestAvailableLocale(availableLocales, requestedLocale);
                                                    
  return locale.value_or(u"und");
}

                                                         
                                                                    
vm::CallResult<std::optional<std::u16string>> getOptionString(
    vm::Runtime &runtime,
    const Options &options,
    const std::u16string &property,
    llvh::ArrayRef<std::u16string_view> values,
    std::optional<std::u16string_view> fallback) {
                                      
                                              
  auto valueIt = options.find(property);
                                               
  if (valueIt == options.end())
    return std::optional<std::u16string>(fallback);

  const auto &value = valueIt->second.getString();
                                              
                                  
                                        
                                 
                                       
                                                                               
                                            
  if (!values.empty() && llvh::find(values, value) == values.end())
    return runtime.raiseRangeError(
        vm::TwineChar16(property.c_str()) +
        vm::TwineChar16(" value is invalid."));

                     
  return std::optional<std::u16string>(value);
}

std::optional<bool> getOptionBool(
    vm::Runtime &runtime,
    const Options &options,
    const std::u16string &property,
    std::optional<bool> fallback) {
                                         
                                               
  auto value = options.find(property);
                                                
  if (value == options.end()) {
    return fallback;
  }
                      
  return value->second.getBool();
}

                                                                   
vm::CallResult<std::optional<uint8_t>> defaultNumberOption(
    vm::Runtime &runtime,
    const std::u16string &property,
    std::optional<Option> value,
    const std::uint8_t minimum,
    const std::uint8_t maximum,
    std::optional<uint8_t> fallback) {
                                                
  if (!value) {
    return fallback;
  }
                                        
                                                                              
                           
  if (std::isnan(value->getNumber()) || value->getNumber() < minimum ||
      value->getNumber() > maximum) {
    return runtime.raiseRangeError(
        vm::TwineChar16(property.c_str()) +
        vm::TwineChar16(" value is invalid."));
  }
                             
  return std::optional<uint8_t>(std::floor(value->getNumber()));
}

                                                               
vm::CallResult<std::optional<uint8_t>> getNumberOption(
    vm::Runtime &runtime,
    const Options &options,
    const std::u16string &property,
    const std::uint8_t minimum,
    const std::uint8_t maximum,
    std::optional<uint8_t> fallback) {
                                         
                                               
  std::optional<Option> value;
  auto iter = options.find(property);
  if (iter != options.end()) {
    value = Option(iter->second);
  }
                                                                         
  auto defaultNumber =
      defaultNumberOption(runtime, property, value, minimum, maximum, fallback);
  if (LLVM_UNLIKELY(defaultNumber == vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  return std::optional<uint8_t>(defaultNumber.getValue());
}

                                                                      
std::vector<std::u16string> lookupSupportedLocales(
    const std::vector<std::u16string> &availableLocales,
    const std::vector<std::u16string> &requestedLocales) {
                                       
  std::vector<std::u16string> subset;
                                                                     
  for (const std::u16string &locale : requestedLocales) {
                                                                            
                                                  
                                                               
                                                                      
                           
    std::optional<std::u16string> availableLocale =
        bestAvailableLocale(availableLocales, locale);
                                                                          
              
    if (availableLocale) {
      subset.push_back(locale);
    }
  }
                      
  return subset;
}

                                                                
vm::CallResult<std::vector<std::u16string>> supportedLocales(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &availableLocales,
    const std::vector<std::u16string> &requestedLocales,
    const Options &options) {
                                                        
                                                                        
                                            
  auto matcherRes = getOptionString(
      runtime,
      options,
      u"localeMatcher",
      {u"lookup", u"best fit"},
      u"best fit");
  if (LLVM_UNLIKELY(matcherRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                      
                                                                           
                            
             
                                                                          
                            
                                                     

                                                                            
  return lookupSupportedLocales(availableLocales, requestedLocales);
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

namespace {
                                                  
class TimeZoneNames {
 public:
                                                                       
                 
  TimeZoneNames() {
    auto nsTimeZoneNames = [NSTimeZone.knownTimeZoneNames
        arrayByAddingObjectsFromArray:NSTimeZone.abbreviationDictionary
                                          .allKeys];
    for (NSString *timeZoneName in nsTimeZoneNames) {
      auto canonical = nsStringToU16String(timeZoneName);
      auto upper = toASCIIUppercase(canonical);
      timeZoneNamesMap_.emplace(std::move(upper), std::move(canonical));
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
}             

static TimeZoneNames &validTimeZoneNames() {
  static TimeZoneNames validTimeZoneNames;
  return validTimeZoneNames;
}

                                                              
                                                                 
                                                                         
                                                                
                                                                                
                                                                        
                                                                               
                                                                             
                                                                         
                                                                                
                                            
std::u16string getDefaultTimeZone() {
  std::u16string tz = nsStringToU16String(NSTimeZone.defaultTimeZone.name);
  validTimeZoneNames().update(tz);
  return tz;
}

                                                                       
std::u16string canonicalizeTimeZoneName(std::u16string_view tz) {
                                                                                
                                                                              
                                                                  
  auto ianaTimeZone = validTimeZoneNames().getCanonical(tz);
                                                                            
                                                                             
                                                                        
              
                                                                
  if (ianaTimeZone == u"Etc/UTC" || ianaTimeZone == u"Etc/GMT")
    ianaTimeZone = u"UTC";
                            
  return ianaTimeZone;
}

                                                                  
static bool isValidTimeZoneName(std::u16string_view tz) {
  return validTimeZoneNames().contains(tz);
}

                                                                                       
std::u16string getDefaultHourCycle(NSLocale *locale) {
  auto dateFormatPattern =
      nsStringToU16String([NSDateFormatter dateFormatFromTemplate:@"j"
                                                          options:0
                                                           locale:locale]);
  for (char16_t c16 : dateFormatPattern) {
    if (c16 == u'h') {
      return u"h12";
    } else if (c16 == u'K') {
      return u"h11";
    } else if (c16 == u'H') {
      return u"h23";
    }
  }
  return u"h24";
}

                                                                              
template <typename K, typename V, size_t N>
std::optional<V> pairMapLookup(const std::pair<K, V> (&arr)[N], const K &key) {
  HERMES_SLOW_ASSERT(std::is_sorted(std::begin(arr), std::end(arr)));
  auto it = llvh::lower_bound(
      arr, key, [](const auto &a, const K &b) { return a.first < b; });
  if (it != std::end(arr) && it->first == key)
    return it->second;
  return std::nullopt;
}

template <size_t N, size_t P = 0>
static constexpr bool isSorted(const std::u16string_view (&v)[N]) {
  if constexpr (P < N - 1) {
    return v[P] < v[P + 1] && isSorted<N, P + 1>(v);
  }
  return true;
}

                                                                               
bool isSanctionedSimpleUnitIdentifier(std::u16string_view unitIdentifier) {
  static constexpr std::u16string_view sanctionedIdentifiers[] = {
      u"acre",       u"bit",        u"byte",
      u"celsius",    u"centimeter", u"day",
      u"degree",     u"fahrenheit", u"fluid-ounce",
      u"foot",       u"gallon",     u"gigabit",
      u"gigabyte",   u"gram",       u"hectare",
      u"hour",       u"inch",       u"kilobit",
      u"kilobyte",   u"kilogram",   u"kilometer",
      u"liter",      u"megabit",    u"megabyte",
      u"meter",      u"mile",       u"mile-scandinavian",
      u"milliliter", u"millimeter", u"millisecond",
      u"minute",     u"month",      u"ounce",
      u"percent",    u"petabyte",   u"pound",
      u"second",     u"stone",      u"terabit",
      u"terabyte",   u"week",       u"yard",
      u"year"};

  static_assert(
      isSorted(sanctionedIdentifiers), "keep sanctionedIdentifiers sorted");
                                                                              
                 
                            
  return std::binary_search(
      std::begin(sanctionedIdentifiers),
      std::end(sanctionedIdentifiers),
      unitIdentifier);
}

                                                                         
bool isWellFormedUnitIdentifier(std::u16string_view unitIdentifier) {
                                                                             
                                
  if (isSanctionedSimpleUnitIdentifier(unitIdentifier))
    return true;
                                                                                
                           
  std::u16string_view fractionDelimiter = u"-per-";
  auto foundPos = unitIdentifier.find(fractionDelimiter);
  if (foundPos == std::u16string_view::npos)
    return false;
                                                                               
                          
                                                                               
                           
  auto numerator = unitIdentifier.substr(0, foundPos);
  if (!isSanctionedSimpleUnitIdentifier(numerator))
    return false;
                                                                           
                         
                                                                          
                                  
  const size_t denominatorPos = foundPos + fractionDelimiter.size();
  auto denominator = unitIdentifier.substr(
      denominatorPos, unitIdentifier.length() - denominatorPos);
  if (!isSanctionedSimpleUnitIdentifier(denominator))
    return false;
                     
  return true;
}

                                                                             
                                                           
NSUnit *unitIdentifierToNSUnit(const std::u16string &unitId) {
  static const std::pair<std::u16string_view, NSUnit *> units[] = {
      {u"acre", NSUnitArea.acres},
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_13_0
      {u"bit", NSUnitInformationStorage.bits},
      {u"byte", NSUnitInformationStorage.bytes},
#endif
      {u"celsius", NSUnitTemperature.celsius},
      {u"centimeter", NSUnitLength.centimeters},
      {u"degree", NSUnitAngle.degrees},
      {u"fahrenheit", NSUnitTemperature.fahrenheit},
      {u"fluid-ounce", NSUnitVolume.fluidOunces},
      {u"foot", NSUnitLength.feet},
      {u"gallon", NSUnitVolume.gallons},
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_13_0
      {u"gigabit", NSUnitInformationStorage.gigabits},
      {u"gigabyte", NSUnitInformationStorage.gigabytes},
#endif
      {u"gram", NSUnitMass.grams},
      {u"gram-per-liter", NSUnitConcentrationMass.gramsPerLiter},
      {u"hectare", NSUnitArea.hectares},
      {u"hour", NSUnitDuration.hours},
      {u"inch", NSUnitLength.inches},
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_13_0
      {u"kilobit", NSUnitInformationStorage.kilobits},
      {u"kilobyte", NSUnitInformationStorage.kilobytes},
#endif
      {u"kilogram", NSUnitMass.kilograms},
      {u"kilometer", NSUnitLength.kilometers},
      {u"kilometer-per-hour", NSUnitSpeed.kilometersPerHour},
      {u"liter", NSUnitVolume.liters},
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_13_0
      {u"megabit", NSUnitInformationStorage.megabits},
      {u"megabyte", NSUnitInformationStorage.megabytes},
#endif
      {u"meter", NSUnitLength.meters},
      {u"meter-per-second", NSUnitSpeed.metersPerSecond},
      {u"mile", NSUnitLength.miles},
      {u"mile-per-gallon", NSUnitFuelEfficiency.milesPerGallon},
      {u"mile-per-hour", NSUnitSpeed.milesPerHour},
      {u"mile-scandinavian", NSUnitLength.scandinavianMiles},
      {u"milliliter", NSUnitVolume.milliliters},
      {u"millimeter", NSUnitLength.millimeters},
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_13_0
      {u"millisecond", NSUnitDuration.milliseconds},
#endif
      {u"minute", NSUnitDuration.minutes},
      {u"ounce", NSUnitMass.ounces},
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_13_0
      {u"petabyte", NSUnitInformationStorage.petabytes},
#endif
      {u"pound", NSUnitMass.poundsMass},
      {u"second", NSUnitDuration.seconds},
      {u"stone", NSUnitMass.stones},
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_13_0
      {u"terabit", NSUnitInformationStorage.terabits},
      {u"terabyte", NSUnitInformationStorage.terabytes},
#endif
      {u"yard", NSUnitLength.yards}};
  if (auto nsUnitOpt = pairMapLookup(units, std::u16string_view(unitId)))
    return *nsUnitOpt;
  return [[NSUnit alloc] initWithSymbol:u16StringToNSString(unitId)];
}

                                                                       
bool isWellFormedCurrencyCode(std::u16string_view currencyCode) {
                                                                          
                       
  auto normalized = toASCIIUppercase(currencyCode);
                                                                        
  if (normalized.size() != 3)
    return false;
                                                                             
                                           
  if (!llvh::all_of(normalized, [](auto c) { return c >= u'A' && c <= u'Z'; }))
    return false;
                     
  return true;
}

uint8_t getCurrencyDigits(std::u16string_view code) {
                                                         
  static constexpr std::pair<std::u16string_view, uint8_t> currencies[] = {
      {u"BHD", 3}, {u"BIF", 0}, {u"CLF", 4}, {u"CLP", 0}, {u"DJF", 0},
      {u"GNF", 0}, {u"IQD", 3}, {u"ISK", 0}, {u"JOD", 3}, {u"JPY", 0},
      {u"KMF", 0}, {u"KRW", 0}, {u"KWD", 3}, {u"LYD", 3}, {u"OMR", 3},
      {u"PYG", 0}, {u"RWF", 0}, {u"TND", 3}, {u"UGX", 0}, {u"UYI", 0},
      {u"UYW", 4}, {u"VND", 0}, {u"VUV", 0}, {u"XAF", 0}, {u"XOF", 0},
      {u"XPF", 0}};
                                                                             
                                                                                
                                         
  if (auto digitsOpt = pairMapLookup(currencies, code))
    return *digitsOpt;
  return 2;
}
}             

                                                                        
vm::CallResult<std::vector<std::u16string>> getCanonicalLocales(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales) {
                                                    
                                       
  return canonicalizeLocaleList(runtime, locales);
}

                                                                                  
vm::CallResult<std::u16string> toLocaleLowerCase(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const std::u16string &str) {
  NSString *nsStr = u16StringToNSString(str);
                                            
  vm::CallResult<std::u16string> locale =
      localeListToLocaleString(runtime, locales);
                                                                         
                                                                  
                                                                               
                                                                         
                                                                           
                                                                   
                                                                              
                       
                                                                             
                                                 
  NSString *L = u16StringToNSString(locale.getValue());
                  
  return nsStringToU16String([nsStr
      lowercaseStringWithLocale:[[NSLocale alloc] initWithLocaleIdentifier:L]]);
}

                                                                                  
vm::CallResult<std::u16string> toLocaleUpperCase(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const std::u16string &str) {
  NSString *nsStr = u16StringToNSString(str);
                                            
  vm::CallResult<std::u16string> locale =
      localeListToLocaleString(runtime, locales);
                                                                         
                                                                  
                                                                               
                                                                         
                                                                           
                                                                   
                                                                              
                       
                                                                             
                                                 
  NSString *L = u16StringToNSString(locale.getValue());
                  
  return nsStringToU16String([nsStr
      uppercaseStringWithLocale:[[NSLocale alloc] initWithLocaleIdentifier:L]]);
}

namespace {
class CollatorApple : public Collator {
 public:
  CollatorApple() = default;

  vm::ExecutionStatus initialize(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales,
      const Options &options) noexcept;

  Options resolvedOptions() noexcept;

  double compare(const std::u16string &x, const std::u16string &y) noexcept;

 private:
  NSLocale *nsLocale_;
  NSStringCompareOptions nsCompareOptions_;
  std::u16string locale_;
  std::u16string usage_;
  std::u16string collation_;
  std::u16string caseFirst_;
  std::u16string sensitivity_;
  bool numeric_;
  bool ignorePunctuation_;
};
}             

Collator::Collator() = default;
Collator::~Collator() = default;

                                                                                
vm::CallResult<std::vector<std::u16string>> Collator::supportedLocalesOf(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
                                                                
  const auto &availableLocales = getAvailableLocales();
                                                                  
  auto requestedLocalesRes = canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(requestedLocalesRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                                              
  return supportedLocales(
      runtime, availableLocales, *requestedLocalesRes, options);
}

                                                                  
vm::ExecutionStatus CollatorApple::initialize(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
                                                                  
  auto requestedLocalesRes = canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(requestedLocalesRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                        
                                                                               
                
  static constexpr std::u16string_view usageOpts[] = {u"sort", u"search"};
  auto usageRes =
      getOptionString(runtime, options, u"usage", usageOpts, {u"sort"});
  if (LLVM_UNLIKELY(usageRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                        
  usage_ = std::move(**usageRes);
                                
                                                        
             
                                                          
                                
  std::unordered_map<std::u16string, std::u16string> opt;
                                                                        
                                            
                                             
                                                                       
  static constexpr std::u16string_view localeMatcherOpts[] = {
      u"lookup", u"best fit"};
  auto localeMatcherRes = getOptionString(
      runtime, options, u"localeMatcher", localeMatcherOpts, u"best fit");
  if (LLVM_UNLIKELY(localeMatcherRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                                                
                
  auto collationRes = getOptionString(runtime, options, u"collation", {}, {});
  if (LLVM_UNLIKELY(collationRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                            
                                                                      
                                               
                                     
  if (auto &collationOpt = *collationRes) {
    if (!isUnicodeExtensionType(*collationOpt)) {
      return runtime.raiseRangeError(
          vm::TwineChar16("Invalid collation: ") +
          vm::TwineChar16(collationOpt->c_str()));
    }
    opt.emplace(u"co", std::move(*collationOpt));
  }
                                                                             
                
  auto numericOpt = getOptionBool(runtime, options, u"numeric", {});
                                          
                                           
                                   
  if (numericOpt)
    opt.emplace(u"kn", *numericOpt ? u"true" : u"false");
                                                                                
                                    
  static constexpr std::u16string_view caseFirstOpts[] = {
      u"upper", u"lower", u"false"};
  auto caseFirstRes =
      getOptionString(runtime, options, u"caseFirst", caseFirstOpts, {});
  if (LLVM_UNLIKELY(caseFirstRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                     
  if (auto caseFirstOpt = *caseFirstRes)
    opt.emplace(u"kf", *caseFirstOpt);
                                                                           
  static constexpr std::u16string_view relevantExtensionKeys[] = {
      u"co", u"kf", u"kn"};
  static_assert(
      isSorted(relevantExtensionKeys),
      "keep relevantExtensionKeys sorted for canonical form");
                                                                
                                                              
  auto r = resolveLocale(
      getAvailableLocales(), *requestedLocalesRes, opt, relevantExtensionKeys);
                                                 
  locale_ = std::move(r.locale);
                                                                  
                                                                                
                                                                          
                                                                             
                                                                                
                                                                           
                                 
  if (usage_ == u"search") {
    collation_ = u"default";
                                                               
    auto parsed = ParsedLocaleIdentifier::parse(locale_);
    if (parsed.has_value()) {
      auto nodeHandle = parsed->unicodeExtensionKeywords.extract(u"co");
      if (!nodeHandle.empty()) {
        locale_ = parsed->canonicalize();
      }
    }
  } else {
                                     
    auto coIt = r.extensions.find(u"co");
                                                            
                                                   
    if (coIt == r.extensions.end())
      collation_ = u"default";
    else
      collation_ = std::move(coIt->second);
  }
                                                     
                                                                  
  auto knIt = r.extensions.find(u"kn");
  if (knIt == r.extensions.end())
    numeric_ = false;
  else
    numeric_ = (knIt->second == u"true");

                                                     
                                               
  auto kfIt = r.extensions.find(u"kf");
  if (kfIt == r.extensions.end())
    caseFirst_ = u"false";
  else
    caseFirst_ = kfIt->second;

                                                                           
                                                       
  static constexpr std::u16string_view sensitivityOpts[] = {
      u"base", u"accent", u"case", u"variant"};
  auto sensitivityRes =
      getOptionString(runtime, options, u"sensitivity", sensitivityOpts, {});
  if (LLVM_UNLIKELY(sensitivityRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                          
                                
                                     
             
                                           
                                                           
                                                            
                                                     
  if (auto &sensitivityOpt = *sensitivityRes)
    sensitivity_ = std::move(*sensitivityOpt);
  else
    sensitivity_ = u"variant";

                                                                           
                                 
  auto ignorePunctuationOpt =
      getOptionBool(runtime, options, u"ignorePunctuation", false);
                                                                 
  ignorePunctuation_ = *ignorePunctuationOpt;

                                                  
  NSStringCompareOptions cmpOpts = 0;
  if (numeric_)
    cmpOpts |= NSNumericSearch;
  if (sensitivity_ == u"base")
    cmpOpts |= (NSDiacriticInsensitiveSearch | NSCaseInsensitiveSearch);
  else if (sensitivity_ == u"accent")
    cmpOpts |= NSCaseInsensitiveSearch;
  else if (sensitivity_ == u"case")
    cmpOpts |= NSDiacriticInsensitiveSearch;
  nsCompareOptions_ = cmpOpts;

  std::u16string nsLocaleExtensions;
  if (collation_ != u"default")
    nsLocaleExtensions.append(u"-co-").append(collation_);
  else if (usage_ == u"search")
    nsLocaleExtensions.append(u"-co-search");
  if (caseFirst_ != u"false")
    nsLocaleExtensions.append(u"-kf-").append(caseFirst_);
  auto nsLocaleIdentifier = r.dataLocale;
  if (!nsLocaleExtensions.empty())
    nsLocaleIdentifier.append(u"-u").append(nsLocaleExtensions);
  nsLocale_ = [NSLocale
      localeWithLocaleIdentifier:u16StringToNSString(nsLocaleIdentifier)];
                         
  return vm::ExecutionStatus::RETURNED;
}

vm::CallResult<std::unique_ptr<Collator>> Collator::create(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
  auto instance = std::make_unique<CollatorApple>();
  if (LLVM_UNLIKELY(
          instance->initialize(runtime, locales, options) ==
          vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  return instance;
}

                                                                                       
Options CollatorApple::resolvedOptions() noexcept {
  Options options;
  options.emplace(u"locale", Option(locale_));
  options.emplace(u"usage", Option(usage_));
  options.emplace(u"sensitivity", Option(sensitivity_));
  options.emplace(u"ignorePunctuation", Option(ignorePunctuation_));
  options.emplace(u"collation", Option(collation_));
  options.emplace(u"numeric", Option(numeric_));
  options.emplace(u"caseFirst", Option(caseFirst_));
  return options;
}

Options Collator::resolvedOptions() noexcept {
  return static_cast<CollatorApple *>(this)->resolvedOptions();
}

                                                                               
double CollatorApple::compare(
    const std::u16string &x,
    const std::u16string &y) noexcept {
  NSString *nsX = u16StringToNSString(x);
  NSString *nsY = u16StringToNSString(y);
  if (ignorePunctuation_) {
                                                                          
                                                                        
                  
    auto *set = [NSMutableCharacterSet punctuationCharacterSet];
    [set formUnionWithCharacterSet:[NSCharacterSet
                                       whitespaceAndNewlineCharacterSet]];
    auto removePunctuation = [&](NSString *nsStr) {
      auto *res = [NSMutableString new];
      for (size_t i = 0; i < nsStr.length; ++i)
        if (![set characterIsMember:[nsStr characterAtIndex:i]])
          [res appendFormat:@"%c", [nsStr characterAtIndex:i]];
      return res;
    };
    nsX = removePunctuation(nsX);
    nsY = removePunctuation(nsY);
  }
  return [nsX compare:nsY
              options:nsCompareOptions_
                range:NSMakeRange(0, nsX.length)
               locale:nsLocale_];
}

double Collator::compare(
    const std::u16string &x,
    const std::u16string &y) noexcept {
  return static_cast<CollatorApple *>(this)->compare(x, y);
}

namespace {
                    
                                                                 
class DateTimeFormatApple : public DateTimeFormat {
 public:
  DateTimeFormatApple() = default;

  vm::ExecutionStatus initialize(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales,
      const Options &inputOptions) noexcept;

  Options resolvedOptions() noexcept;

  std::u16string format(double jsTimeValue) noexcept;

  std::vector<Part> formatToParts(double x) noexcept;

 private:
  void initializeNSDateFormatter(NSLocale *nsLocale) noexcept;

                                                                                            
                                                                        
                   
                                                        
                                                             
                                                
                                                                           
                                         
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
                                                          
                                                          
                                                                  
                                                                           
              
                                                                        
                             
  NSDateFormatter *nsDateFormatter_;
};
}             

DateTimeFormat::DateTimeFormat() = default;
DateTimeFormat::~DateTimeFormat() = default;

                    
                                                                                     
vm::CallResult<std::vector<std::u16string>> DateTimeFormat::supportedLocalesOf(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
                                                                      
                                                                  
  auto requestedLocales = getCanonicalLocales(runtime, locales);
  const std::vector<std::u16string> &availableLocales = getAvailableLocales();
                                                               
  return supportedLocales(
      runtime, availableLocales, requestedLocales.getValue(), options);
}

                    
                                                                       
vm::ExecutionStatus DateTimeFormatApple::initialize(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &inputOptions) noexcept {
                                                                  
  auto requestedLocalesRes = canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(requestedLocalesRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                                   
  auto optionsRes = toDateTimeOptions(runtime, inputOptions, u"any", u"date");
  if (LLVM_UNLIKELY(optionsRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto options = *optionsRes;
                                
  std::unordered_map<std::u16string, std::u16string> opt;
                                                                      
                                          
  auto matcherRes = getOptionString(
      runtime,
      options,
      u"localeMatcher",
      {u"lookup", u"best fit"},
      u"best fit");
  if (LLVM_UNLIKELY(matcherRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                             
  auto matcherOpt = *matcherRes;
  opt.emplace(u"localeMatcher", *matcherOpt);
                                                                  
                           
  auto calendarRes = getOptionString(runtime, options, u"calendar", {}, {});
                                          
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
                                                                
                           
  auto hour12 = getOptionBool(runtime, options, u"hour12", {});
                                                                       
                                              
  static constexpr std::u16string_view hourCycles[] = {
      u"h11", u"h12", u"h23", u"h24"};
  auto hourCycleRes =
      getOptionString(runtime, options, u"hourCycle", hourCycles, {});
  if (LLVM_UNLIKELY(hourCycleRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto hourCycleOpt = *hourCycleRes;
                                         
  if (hour12.has_value())
                                
                                                                        
                                                                             
                         
    hourCycleOpt = u"";
  if (hourCycleOpt.has_value())
                                       
    opt.emplace(u"hc", *hourCycleOpt);
                                                           
                                                                             
                                                  
                                                                      
                                                                       
                 
  static constexpr std::u16string_view relevantExtensionKeys[] = {
      u"ca", u"hc", u"nu"};
  static_assert(
      isSorted(relevantExtensionKeys),
      "keep relevantExtensionKeys sorted for canonical form");
  auto r = resolveLocale(
      getAvailableLocales(), *requestedLocalesRes, opt, relevantExtensionKeys);
                                                       
  locale_ = std::move(r.locale);
                                  
  auto caIt = r.extensions.find(u"ca");
                                                     
  if (caIt != r.extensions.end())
    calendar_ = std::move(caIt->second);
                                                      
  auto hcIt = r.extensions.find(u"hc");
  if (hcIt != r.extensions.end())
    hourCycle_ = std::move(hcIt->second);
                                                            
                                            
  auto dataLocale = r.dataLocale;
                                                    
  auto timeZoneIt = options.find(u"timeZone");
  std::u16string timeZone;
                                        
  if (timeZoneIt == options.end()) {
                                            
    timeZone = getDefaultTimeZone();
                
  } else {
                                               
    timeZone = timeZoneIt->second.getString();
                                                                       
    if (!isValidTimeZoneName(timeZone)) {
      if ([[NSTimeZone alloc] initWithName:u16StringToNSString(timeZone)] !=
          nil) {
        validTimeZoneNames().update(timeZone);
      } else {
                                           
        return runtime.raiseRangeError(
            vm::TwineChar16("Incorrect timeZone information provided: ") +
            vm::TwineChar16(timeZone.c_str()));
      }
    }
                                                             
    timeZone = canonicalizeTimeZoneName(timeZone);
  }
                                                     
  timeZone_ = timeZone;
                                 
                                                                           
                                                                     
                                                 
                                                                            
                   
                                    
             
                                                                       
                                                         
                                    
                                                           
                                                                         
                                        
                                                                               
                                             
  static constexpr std::u16string_view dateStyles[] = {
      u"full", u"long", u"medium", u"short"};
  auto dateStyleRes =
      getOptionString(runtime, options, u"dateStyle", dateStyles, {});
  if (LLVM_UNLIKELY(dateStyleRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                       
  dateStyle_ = *dateStyleRes;
                                                                               
                                             
  static constexpr std::u16string_view timeStyles[] = {
      u"full", u"long", u"medium", u"short"};
  auto timeStyleRes =
      getOptionString(runtime, options, u"timeStyle", timeStyles, {});
  if (LLVM_UNLIKELY(timeStyleRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                       
  timeStyle_ = *timeStyleRes;

                                                               
  static constexpr std::u16string_view weekdayValues[] = {
      u"narrow", u"short", u"long"};
  auto weekdayRes =
      getOptionString(runtime, options, u"weekday", weekdayValues, {});
  if (LLVM_UNLIKELY(weekdayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  weekday_ = *weekdayRes;

  static constexpr std::u16string_view eraValues[] = {
      u"narrow", u"short", u"long"};
  auto eraRes = getOptionString(runtime, options, u"era", eraValues, {});
  if (LLVM_UNLIKELY(eraRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  era_ = *eraRes;

  static constexpr std::u16string_view yearValues[] = {u"2-digit", u"numeric"};
  auto yearRes = getOptionString(runtime, options, u"year", yearValues, {});
  if (LLVM_UNLIKELY(yearRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  year_ = *yearRes;

  static constexpr std::u16string_view monthValues[] = {
      u"2-digit", u"numeric", u"narrow", u"short", u"long"};
  auto monthRes = getOptionString(runtime, options, u"month", monthValues, {});
  if (LLVM_UNLIKELY(monthRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  month_ = *monthRes;

  static constexpr std::u16string_view dayValues[] = {u"2-digit", u"numeric"};
  auto dayRes = getOptionString(runtime, options, u"day", dayValues, {});
  if (LLVM_UNLIKELY(dayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  day_ = *dayRes;

  static constexpr std::u16string_view dayPeriodValues[] = {
      u"narrow", u"short", u"long"};
  auto dayPeriodRes =
      getOptionString(runtime, options, u"dayPeriod", dayPeriodValues, {});
  if (LLVM_UNLIKELY(dayPeriodRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  dayPeriod_ = *dayPeriodRes;

  static constexpr std::u16string_view hourValues[] = {u"2-digit", u"numeric"};
  auto hourRes = getOptionString(runtime, options, u"hour", hourValues, {});
  if (LLVM_UNLIKELY(hourRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  hour_ = *hourRes;

  static constexpr std::u16string_view minuteValues[] = {
      u"2-digit", u"numeric"};
  auto minuteRes =
      getOptionString(runtime, options, u"minute", minuteValues, {});
  if (LLVM_UNLIKELY(minuteRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  minute_ = *minuteRes;

  static constexpr std::u16string_view secondValues[] = {
      u"2-digit", u"numeric"};
  auto secondRes =
      getOptionString(runtime, options, u"second", secondValues, {});
  if (LLVM_UNLIKELY(secondRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  second_ = *secondRes;

  auto fractionalSecondDigitsRes =
      getNumberOption(runtime, options, u"fractionalSecondDigits", 1, 3, {});
  if (LLVM_UNLIKELY(
          fractionalSecondDigitsRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  fractionalSecondDigits_ = *fractionalSecondDigitsRes;

                                                                     
                        
                                                      
                                                                
                                                                                    
  static constexpr std::u16string_view timeZoneNameValues[] = {
      u"short",
      u"long",
      u"shortOffset",
      u"longOffset",
      u"shortGeneric",
      u"longGeneric"};
  auto timeZoneNameRes = getOptionString(
      runtime, options, u"timeZoneName", timeZoneNameValues, {});
  if (LLVM_UNLIKELY(timeZoneNameRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  timeZoneName_ = *timeZoneNameRes;
                                                                              
                           
                                                                          
                                                          
                                                                     
                                 
                                     
                                    
                                                               
                                                                            
              
                                                                 
                                   
                                                           
             
                                                             
                                                                           
                                     
                                                                     
                           
                                                  
                                       
                                                                      
                                 
                                                      
  NSLocale *nsLocale =
      [NSLocale localeWithLocaleIdentifier:u16StringToNSString(locale_)];
  if (!hour_.has_value()) {
                                                        
    hourCycle_ = std::nullopt;
                                                
                                                            
                
  } else {
                                                        
    auto hcDefault = getDefaultHourCycle(nsLocale);
                                                 
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
                                                   
                                                               
                               
  initializeNSDateFormatter(nsLocale);
  return vm::ExecutionStatus::RETURNED;
}

vm::CallResult<std::unique_ptr<DateTimeFormat>> DateTimeFormat::create(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &inputOptions) noexcept {
  auto instance = std::make_unique<DateTimeFormatApple>();
  if (LLVM_UNLIKELY(
          instance->initialize(runtime, locales, inputOptions) ==
          vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  return instance;
}

                                                       
                                                                                            
Options DateTimeFormatApple::resolvedOptions() noexcept {
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
  return static_cast<DateTimeFormatApple *>(this)->resolvedOptions();
}

void DateTimeFormatApple::initializeNSDateFormatter(
    NSLocale *nsLocale) noexcept {
  static constexpr std::u16string_view kLong = u"long", kShort = u"short",
                                       kNarrow = u"narrow", kMedium = u"medium",
                                       kFull = u"full", kNumeric = u"numeric",
                                       kTwoDigit = u"2-digit",
                                       kShortOffset = u"shortOffset",
                                       kLongOffset = u"longOffset",
                                       kShortGeneric = u"shortGeneric",
                                       kLongGeneric = u"longGeneric";

  nsDateFormatter_ = [[NSDateFormatter alloc] init];
  if (timeStyle_.has_value()) {
    if (*timeStyle_ == kFull) {
      nsDateFormatter_.timeStyle = NSDateFormatterFullStyle;
    } else if (*timeStyle_ == kLong) {
      nsDateFormatter_.timeStyle = NSDateFormatterLongStyle;
    } else if (*timeStyle_ == kMedium) {
      nsDateFormatter_.timeStyle = NSDateFormatterMediumStyle;
    } else {
      assert(*timeStyle_ == kShort && "No other valid timeStyle.");
      nsDateFormatter_.timeStyle = NSDateFormatterShortStyle;
    }
  }
  if (dateStyle_.has_value()) {
    if (*dateStyle_ == kFull) {
      nsDateFormatter_.dateStyle = NSDateFormatterFullStyle;
    } else if (*dateStyle_ == kLong) {
      nsDateFormatter_.dateStyle = NSDateFormatterLongStyle;
    } else if (*dateStyle_ == kMedium) {
      nsDateFormatter_.dateStyle = NSDateFormatterMediumStyle;
    } else {
      assert(*dateStyle_ == kShort && "No other valid dateStyle.");
      nsDateFormatter_.dateStyle = NSDateFormatterShortStyle;
    }
  }
  nsDateFormatter_.timeZone =
      [[NSTimeZone alloc] initWithName:u16StringToNSString(timeZone_)];
  nsDateFormatter_.locale = nsLocale;
  if (calendar_)
    nsDateFormatter_.calendar = [[NSCalendar alloc]
        initWithCalendarIdentifier:u16StringToNSString(*calendar_)];
  if (timeStyle_.has_value() || dateStyle_.has_value())
    return;
                                                                          
              
                                                                  
                 
  NSMutableString *customFormattedDate = [[NSMutableString alloc] init];
  if (timeZoneName_.has_value()) {
    if (*timeZoneName_ == kShort) {
      [customFormattedDate appendString:@"z"];
    } else if (*timeZoneName_ == kLong) {
      [customFormattedDate appendString:@"zzzz"];
    } else if (*timeZoneName_ == kShortOffset) {
      [customFormattedDate appendString:@"O"];
    } else if (*timeZoneName_ == kLongOffset) {
      [customFormattedDate appendString:@"OOOO"];
    } else if (*timeZoneName_ == kShortGeneric) {
      [customFormattedDate appendString:@"v"];
    } else {
      assert(*timeZoneName_ == kLongGeneric && "No other valid timeZoneName");
      [customFormattedDate appendString:@"vvvv"];
    }
  }
  if (era_.has_value()) {
    if (*era_ == kNarrow) {
      [customFormattedDate appendString:@"GGGGG"];
    } else if (*era_ == kShort) {
      [customFormattedDate appendString:@"GGG"];
    } else {
      assert(*era_ == kLong && "No other valid era.");
      [customFormattedDate appendString:@"GGGG"];
    }
  }
  if (year_.has_value()) {
    if (*year_ == kNumeric) {
      [customFormattedDate appendString:@"yyyy"];
    } else {
      assert(*year_ == kTwoDigit && "No other valid year.");
      [customFormattedDate appendString:@"yy"];
    }
  }
  if (month_.has_value()) {
    if (*month_ == kNarrow) {
      [customFormattedDate appendString:@"MMMMM"];
    } else if (*month_ == kNumeric) {
      [customFormattedDate appendString:@"M"];
    } else if (*month_ == kTwoDigit) {
      [customFormattedDate appendString:@"MM"];
    } else if (*month_ == kShort) {
      [customFormattedDate appendString:@"MMM"];
    } else {
      assert(*month_ == kLong && "No other valid month.");
      [customFormattedDate appendString:@"MMMM"];
    }
  }
  if (weekday_.has_value()) {
    if (*weekday_ == kNarrow) {
      [customFormattedDate appendString:@"EEEEE"];
    } else if (*weekday_ == kShort) {
      [customFormattedDate appendString:@"E"];
    } else {
      assert(*weekday_ == kLong && "No other valid weekday.");
      [customFormattedDate appendString:@"EEEE"];
    }
  }
  if (day_.has_value()) {
    if (*day_ == kNumeric) {
      [customFormattedDate appendString:@"d"];
    } else {
      assert(*day_ == kTwoDigit && "No other valid day.");
      [customFormattedDate appendString:@"dd"];
    }
  }
  if (hour_.has_value()) {
                                                 
                                                                          
                                                                  
                     
                     
                     
                     
    if (hourCycle_ == u"h12") {
      if (*hour_ == kNumeric) {
        [customFormattedDate appendString:@"h"];
      } else {
        assert(*hour_ == kTwoDigit && "No other valid hour.");
        [customFormattedDate appendString:@"hh"];
      }
    } else if (hourCycle_ == u"h24") {
      if (*hour_ == kNumeric) {
        [customFormattedDate appendString:@"k"];
      } else {
        assert(*hour_ == kTwoDigit && "No other valid hour.");
        [customFormattedDate appendString:@"kk"];
      }
    } else if (hourCycle_ == u"h11") {
      if (*hour_ == kNumeric) {
        [customFormattedDate appendString:@"K"];
      } else {
        assert(*hour_ == kTwoDigit && "No other valid hour.");
        [customFormattedDate appendString:@"KK"];
      }
    } else {       
      if (*hour_ == kNumeric) {
        [customFormattedDate appendString:@"H"];
      } else {
        assert(*hour_ == kTwoDigit && "No other valid hour.");
        [customFormattedDate appendString:@"HH"];
      }
    }
  }
  if (minute_.has_value()) {
    if (*minute_ == kNumeric) {
      [customFormattedDate appendString:@"m"];
    } else {
      assert(*minute_ == kTwoDigit && "No other valid minute.");
      [customFormattedDate appendString:@"mm"];
    }
  }
  if (second_.has_value()) {
    if (*second_ == kNumeric) {
      [customFormattedDate appendString:@"s"];
    } else {
      assert(*second_ == kTwoDigit && "No other valid second.");
      [customFormattedDate appendString:@"ss"];
    }
  }
  if (fractionalSecondDigits_.has_value()) {
                                                             
    switch (*fractionalSecondDigits_) {
      case 1:
        [customFormattedDate appendString:@"S"];
      case 2:
        [customFormattedDate appendString:@"SS"];
      case 3:
        [customFormattedDate appendString:@"SSS"];
    }
  }
                                                        
                                                                         
                                                                             
          
  if (customFormattedDate.length > 0) {
    [nsDateFormatter_ setLocalizedDateFormatFromTemplate:customFormattedDate];
  } else {
    nsDateFormatter_.dateStyle = NSDateFormatterShortStyle;
  }
}

std::u16string DateTimeFormatApple::format(double jsTimeValue) noexcept {
  auto timeInSeconds = jsTimeValue / 1000;
  NSDate *date = [NSDate dateWithTimeIntervalSince1970:timeInSeconds];
  return nsStringToU16String([nsDateFormatter_ stringFromDate:date]);
}

std::u16string DateTimeFormat::format(double jsTimeValue) noexcept {
  return static_cast<DateTimeFormatApple *>(this)->format(jsTimeValue);
}

static std::u16string returnTypeOfDate(const char16_t &c16) {
  if (c16 == u'a')
    return u"dayPeriod";
  if (c16 == u'z' || c16 == u'v' || c16 == u'O')
    return u"timeZoneName";
  if (c16 == u'G')
    return u"era";
  if (c16 == u'y')
    return u"year";
  if (c16 == u'M')
    return u"month";
  if (c16 == u'E')
    return u"weekday";
  if (c16 == u'd')
    return u"day";
  if (c16 == u'h' || c16 == u'k' || c16 == u'K' || c16 == u'H')
    return u"hour";
  if (c16 == u'm')
    return u"minute";
  if (c16 == u's')
    return u"second";
  if (c16 == u'S')
    return u"fractionalSecond";
  return u"literal";
}

                                                       
                                                                    
std::vector<Part> DateTimeFormatApple::formatToParts(double x) noexcept {
                                                                     
                                                                   
                                                                   
  auto fmt = nsStringToU16String(nsDateFormatter_.dateFormat);
  std::unique(fmt.begin(), fmt.end());
  auto formattedDate = format(x);
                                     
  std::vector<Part> result;
                   
                                                                 
                                                          
                                                                      
                                                                        
                                                               
                         
  std::u16string currentPart;
  unsigned n = 0;
  static auto alphanumerics = NSCharacterSet.alphanumericCharacterSet;
  for (char16_t c16 : formattedDate) {
    if ([alphanumerics characterIsMember:c16]) {
      currentPart += c16;
      continue;
    }
    if (currentPart != u"") {
      result.push_back(
          {{u"type", returnTypeOfDate(fmt[n])}, {u"value", currentPart}});
      currentPart = u"";
      n++;
    }
    result.push_back({{u"type", u"literal"}, {u"value", {c16}}});
    n++;
  }
                                  
  result.push_back(
      {{u"type", returnTypeOfDate(fmt[n])}, {u"value", currentPart}});
                      
  return result;
}

std::vector<Part> DateTimeFormat::formatToParts(double x) noexcept {
  return static_cast<DateTimeFormatApple *>(this)->formatToParts(x);
}

class NumberFormatApple : public NumberFormat {
 public:
  NumberFormatApple() = default;

  vm::ExecutionStatus initialize(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales,
      const Options &options) noexcept;

  Options resolvedOptions() noexcept;

  std::u16string format(double number) noexcept;

 private:
                                                                                          
                                                                             
          
                                                      
                                                                           
                                         
  std::u16string locale_;
                                                                          
                                                                           
                                                         
  std::u16string dataLocale_;
                                                                           
                                                                        
                                                                       
                                                                               
                                                                          
                         
                                                                               
                                                             
  std::u16string style_;
                                                                          
                                                                                
                                                  
  std::optional<std::u16string> currency_;
                                                                      
                                                                                
                                                                         
                                                                                
                                                  
  std::optional<std::u16string> currencyDisplay_;
                                                                             
                                                                              
                                                                           
                                                        
  std::optional<std::u16string> currencySign_;
                                                                        
                                                                            
                  
  std::optional<std::u16string> unit_;
                                                                              
                                                                          
                                                                             
                                         
  std::optional<std::u16string> unitDisplay_;
                                                                               
                                                                               
                         
  uint8_t minimumIntegerDigits_;

  struct NumDigits {
    uint8_t minimum;
    uint8_t maximum;
  };
                                                                             
                                                                                
                                                                       
                                                                       
                    
  std::optional<NumDigits> fractionDigits_;
                                                                               
                                                                                
                                                                              
                                                                          
                                                                         
  std::optional<NumDigits> significantDigits_;
                                                                               
                    
  bool useGrouping_;
                                                                                
                                                                   
                                                       
                                                                          
                                                                    
                                                                               
                                                                           
                                                                                
                          
  std::u16string roundingType_;
                                                                       
                                                                         
                                                                               
                                                                             
                                                                          
                                                                         
                            
  std::u16string notation_;
                                                                      
                                                                                
                                                                              
                                                            
  std::optional<std::u16string> compactDisplay_;
                                                                              
                                                                                
                                                                                
                                                                          
                                                                             
              
  std::u16string signDisplay_;
                                                                              
                                                                       
                                          
  NSNumberFormatter *nsNumberFormatter_;
  NSMeasurementFormatter *nsMeasurementFormatter_;
  NSUnit *nsUnit_;

  vm::ExecutionStatus setNumberFormatUnitOptions(
      vm::Runtime &runtime,
      const Options &options) noexcept;
  vm::ExecutionStatus setNumberFormatDigitOptions(
      vm::Runtime &runtime,
      const Options &options,
      uint8_t mnfdDefault,
      uint8_t mxfdDefault,
      std::u16string_view notation) noexcept;
  void initializeNSFormatters() noexcept;
};

NumberFormat::NumberFormat() = default;
NumberFormat::~NumberFormat() = default;

                                                                                   
vm::CallResult<std::vector<std::u16string>> NumberFormat::supportedLocalesOf(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
                                                                      
  auto availableLocales = getAvailableLocales();
                                                                  
  auto requestedLocales = getCanonicalLocales(runtime, locales);
                                                               
  return supportedLocales(
      runtime, availableLocales, requestedLocales.getValue(), options);
}

                                                                         
vm::ExecutionStatus NumberFormatApple::setNumberFormatUnitOptions(
    vm::Runtime &runtime,
    const Options &options) noexcept {
                                         
                                         
                                                                          
                                                  
  static constexpr std::u16string_view styleValues[] = {
      u"decimal", u"percent", u"currency", u"unit"};
  auto styleRes =
      getOptionString(runtime, options, u"style", styleValues, u"decimal");
  if (LLVM_UNLIKELY(styleRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto styleOpt = *styleRes;
                                        
  style_ = *styleOpt;
                                                                              
                 
  auto currencyRes = getOptionString(runtime, options, u"currency", {}, {});
  if (LLVM_UNLIKELY(currencyRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto currencyOpt = *currencyRes;
                                       
  if (!currencyOpt) {
                                                               
    if (style_ == u"currency")
      return runtime.raiseTypeError("Currency is undefined");
                
  } else {
                                                                              
                               
    if (!isWellFormedCurrencyCode(*currencyOpt))
      return runtime.raiseRangeError("Currency is invalid");
  }
                                                                       
                                                                        
  static constexpr std::u16string_view currencyDisplayValues[] = {
      u"code", u"symbol", u"narrowSymbol", u"name"};
  auto currencyDisplayRes = getOptionString(
      runtime, options, u"currencyDisplay", currencyDisplayValues, u"symbol");
  if (LLVM_UNLIKELY(currencyDisplayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto currencyDisplayOpt = *currencyDisplayRes;
                                                                             
                                              
  static constexpr std::u16string_view currencySignValues[] = {
      u"standard", u"accounting"};
  auto currencySignRes = getOptionString(
      runtime, options, u"currencySign", currencySignValues, u"standard");
  if (LLVM_UNLIKELY(currencySignRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto currencySignOpt = *currencySignRes;
                                                                       
                 
  auto unitRes = getOptionString(runtime, options, u"unit", {}, {});
  if (LLVM_UNLIKELY(unitRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto unitOpt = *unitRes;
                                    
  if (!unitOpt) {
                                                           
    if (style_ == u"unit")
      return runtime.raiseTypeError("Unit is undefined");
                 
  } else {
                                                                              
                             
    if (!isWellFormedUnitIdentifier(*unitOpt))
      return runtime.raiseRangeError("Unit is invalid");
  }
                                                                            
                                            
  static constexpr std::u16string_view unitDisplayValues[] = {
      u"short", u"narrow", u"long"};
  auto unitDisplayRes = getOptionString(
      runtime, options, u"unitDisplay", unitDisplayValues, u"short");
  if (LLVM_UNLIKELY(unitDisplayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto unitDisplayOpt = *unitDisplayRes;
                                      
  if (style_ == u"currency") {
                                                                             
                         
                                                
    currency_ = toASCIIUppercase(*currencyOpt);
                                                              
    currencyDisplay_ = *currencyDisplayOpt;
                                                        
    currencySign_ = *currencySignOpt;
  }
                                  
  if (style_ == u"unit") {
                                        
                                                      
    unit_ = *unitOpt;
    unitDisplay_ = *unitDisplayOpt;
  }
  return vm::ExecutionStatus::RETURNED;
}

                                                                
vm::ExecutionStatus NumberFormatApple::setNumberFormatDigitOptions(
    vm::Runtime &runtime,
    const Options &options,
    uint8_t mnfdDefault,
    uint8_t mxfdDefault,
    std::u16string_view notation) noexcept {
                                        
                                        
                                            
                                            
                                                                              
        
  auto mnidRes =
      getNumberOption(runtime, options, u"minimumIntegerDigits", 1, 21, 1);
  if (LLVM_UNLIKELY(mnidRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto mnidOpt = *mnidRes;
                                                            
  auto mnfdIt = options.find(u"minimumFractionDigits");
                                                            
  auto mxfdIt = options.find(u"maximumFractionDigits");
                                                               
  auto mnsdIt = options.find(u"minimumSignificantDigits");
                                                               
  auto mxsdIt = options.find(u"maximumSignificantDigits");
                                                      
  minimumIntegerDigits_ = *mnidOpt;
                                                                
  if (mnsdIt != options.end() || mxsdIt != options.end()) {
                                                            
    roundingType_ = u"significantDigits";
                                                            
    auto mnsdValue =
        mnsdIt == options.end() ? std::nullopt : std::optional(mnsdIt->second);
    auto mnsdRes = defaultNumberOption(
        runtime, u"minimumSignificantDigits", mnsdValue, 1, 21, 1);
    if (LLVM_UNLIKELY(mnsdRes == vm::ExecutionStatus::EXCEPTION))
      return vm::ExecutionStatus::EXCEPTION;
    auto mnsdOpt = *mnsdRes;
                                                                
    auto mxsdValue =
        mxsdIt == options.end() ? std::nullopt : std::optional(mxsdIt->second);
    auto mxsdRes = defaultNumberOption(
        runtime, u"maximumSignificantDigits", mxsdValue, *mnsdOpt, 21, 21);
    if (LLVM_UNLIKELY(mxsdRes == vm::ExecutionStatus::EXCEPTION))
      return vm::ExecutionStatus::EXCEPTION;
    auto mxsdOpt = *mxsdRes;
                                                           
                                                           
    significantDigits_ = {*mnsdOpt, *mxsdOpt};
                                                                       
  } else if (mnfdIt != options.end() || mxfdIt != options.end()) {
                                                         
    roundingType_ = u"fractionDigits";
                                                                    
    auto mnfdValue =
        mnfdIt == options.end() ? std::nullopt : std::optional(mnfdIt->second);
    auto mnfdRes = defaultNumberOption(
        runtime, u"minimumFractionDigits", mnfdValue, 0, 20, {});
    if (LLVM_UNLIKELY(mnfdRes == vm::ExecutionStatus::EXCEPTION))
      return vm::ExecutionStatus::EXCEPTION;
    auto mnfdOpt = *mnfdRes;
                                                                    
    auto mxfdValue =
        mxfdIt == options.end() ? std::nullopt : std::optional(mxfdIt->second);
    auto mxfdRes = defaultNumberOption(
        runtime, u"maximumFractionDigits", mxfdValue, 0, 20, {});
    if (LLVM_UNLIKELY(mxfdRes == vm::ExecutionStatus::EXCEPTION))
      return vm::ExecutionStatus::EXCEPTION;
    auto mxfdOpt = *mxfdRes;
                                                                   
    if (!mnfdOpt) {
      mnfdOpt = std::min(mnfdDefault, *mxfdOpt);
                                                                          
    } else if (!mxfdOpt) {
      mxfdOpt = std::max(mxfdDefault, *mnfdOpt);
                                                                            
    } else if (*mnfdOpt > *mxfdOpt) {
      return runtime.raiseRangeError(
          "minimumFractionDigits is greater than maximumFractionDigits");
    }
                                                        
                                                        
    fractionDigits_ = {*mnfdOpt, *mxfdOpt};
                                              
  } else if (notation_ == u"compact") {
                                                          
    roundingType_ = u"compactRounding";
                
  } else {
                                                         
    roundingType_ = u"fractionDigits";
                                                               
                                                               
    fractionDigits_ = {mnfdDefault, mxfdDefault};
  }
  return vm::ExecutionStatus::RETURNED;
}

                                                                     
vm::ExecutionStatus NumberFormatApple::initialize(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept {
                                                                  
  const auto requestedLocales = canonicalizeLocaleList(runtime, locales);
  if (LLVM_UNLIKELY(requestedLocales == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                        
                                
  std::unordered_map<std::u16string, std::u16string> opt;
                                                
                                                                        
                                         
  static constexpr std::u16string_view localeMatcherValues[] = {
      u"lookup", u"best fit"};
  auto matcherRes = getOptionString(
      runtime, options, u"localeMatcher", localeMatcherValues, u"best fit");
  if (LLVM_UNLIKELY(matcherRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto matcherOpt = *matcherRes;
                                             
  opt.emplace(u"localeMatcher", *matcherOpt);
                                                                                
                           
  auto numberingSystemRes =
      getOptionString(runtime, options, u"numberingSystem", {}, {});
  if (LLVM_UNLIKELY(numberingSystemRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto numberingSystemOpt = *numberingSystemRes;
                                                 
                                                                              
                                                 
                                          
  if (numberingSystemOpt) {
    auto numberingSystem = *numberingSystemOpt;
    if (!isUnicodeExtensionType(numberingSystem)) {
      return runtime.raiseRangeError(
          vm::TwineChar16("Invalid numbering system: ") +
          vm::TwineChar16(numberingSystem.c_str()));
    }
    opt.emplace(u"nu", numberingSystem);
  }
                                                        
                                                                    
                                                                     
                 
  static constexpr std::u16string_view relevantExtensionKeys[] = {u"nu"};
  static_assert(
      isSorted(relevantExtensionKeys),
      "keep relevantExtensionKeys sorted for canonical form");
  auto r = resolveLocale(
      getAvailableLocales(), *requestedLocales, opt, relevantExtensionKeys);
                                                     
  locale_ = r.locale;
                                                             
  dataLocale_ = r.dataLocale;
                                                          
                                                                     
  auto setUnitOptionsRes = setNumberFormatUnitOptions(runtime, options);
  if (LLVM_UNLIKELY(setUnitOptionsRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                             
  auto style = style_;
  uint8_t mnfdDefault, mxfdDefault;
                                     
  if (style == u"currency") {
                                                    
                                                  
    auto cDigits = getCurrencyDigits(*currency_);
                                     
    mnfdDefault = cDigits;
                                     
    mxfdDefault = cDigits;
  } else {
                
                               
    mnfdDefault = 0;
                                     
    if (style == u"percent") {
                                 
      mxfdDefault = 0;
    } else {
                 
                                 
      mxfdDefault = 3;
    }
  }
                                                                     
                                                                       
  static constexpr std::u16string_view notationValues[] = {
      u"standard", u"scientific", u"engineering", u"compact"};
  auto notationRes = getOptionString(
      runtime, options, u"notation", notationValues, u"standard");
  if (LLVM_UNLIKELY(notationRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto notationOpt = *notationRes;
                                                   
  notation_ = *notationOpt;
                                                                              
                            
  auto setDigitOptionsRes = setNumberFormatDigitOptions(
      runtime, options, mnfdDefault, mxfdDefault, notation_);
  if (LLVM_UNLIKELY(setDigitOptionsRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
                                                                               
                                   
  static constexpr std::u16string_view compactDisplayValues[] = {
      u"short", u"long"};
  auto compactDisplayRes = getOptionString(
      runtime, options, u"compactDisplay", compactDisplayValues, u"short");
  if (LLVM_UNLIKELY(compactDisplayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto compactDisplayOpt = *compactDisplayRes;
                                       
  if (*notationOpt == u"compact")
                                                                  
    compactDisplay_ = *compactDisplayOpt;
                                                                          
                      
  auto useGroupingOpt = getOptionBool(runtime, options, u"useGrouping", true);
                                                         
  useGrouping_ = *useGroupingOpt;
                                                                           
                                                        
  static constexpr std::u16string_view signDisplayValues[] = {
      u"auto", u"never", u"always", u"exceptZero"};
  auto signDisplayRes = getOptionString(
      runtime, options, u"signDisplay", signDisplayValues, u"auto");
  if (LLVM_UNLIKELY(signDisplayRes == vm::ExecutionStatus::EXCEPTION))
    return vm::ExecutionStatus::EXCEPTION;
  auto signDisplayOpt = *signDisplayRes;
                                                         
  signDisplay_ = *signDisplayOpt;

  initializeNSFormatters();
  return vm::ExecutionStatus::RETURNED;
}

vm::CallResult<std::unique_ptr<NumberFormat>> NumberFormat::create(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &inputOptions) noexcept {
  auto instance = std::make_unique<NumberFormatApple>();
  if (LLVM_UNLIKELY(
          instance->initialize(runtime, locales, inputOptions) ==
          vm::ExecutionStatus::EXCEPTION)) {
    return vm::ExecutionStatus::EXCEPTION;
  }
  return instance;
}

                                                                                          
Options NumberFormatApple::resolvedOptions() noexcept {
  Options options;
  options.emplace(u"locale", locale_);
  options.emplace(u"style", style_);
  if (currency_)
    options.emplace(u"currency", *currency_);
  if (currencyDisplay_)
    options.emplace(u"currencyDisplay", *currencyDisplay_);
  if (currencySign_)
    options.emplace(u"currencySign", *currencySign_);
  if (unit_)
    options.emplace(u"unit", *unit_);
  if (unitDisplay_)
    options.emplace(u"unitDisplay", *unitDisplay_);
  options.emplace(u"minimumIntegerDigits", (double)minimumIntegerDigits_);
  if (fractionDigits_) {
    options.emplace(u"minimumFractionDigits", (double)fractionDigits_->minimum);
    options.emplace(u"maximumFractionDigits", (double)fractionDigits_->maximum);
  }
  if (significantDigits_) {
    options.emplace(
        u"minimumSignificantDigits", (double)significantDigits_->minimum);
    options.emplace(
        u"maximumSignificantDigits", (double)significantDigits_->maximum);
  }
  options.emplace(u"useGrouping", useGrouping_);
  options.emplace(u"roundingType", roundingType_);
  options.emplace(u"notation", notation_);
  if (compactDisplay_)
    options.emplace(u"compactDisplay", *compactDisplay_);
  options.emplace(u"signDisplay", signDisplay_);
  return options;
}

Options NumberFormat::resolvedOptions() noexcept {
  return static_cast<NumberFormatApple *>(this)->resolvedOptions();
}

                                                           
void NumberFormatApple::initializeNSFormatters() noexcept {
                                                       
                                                                              
                                     
                                       
                                    
                                                                         
  std::u16string nsLocaleStr = dataLocale_;
  nsNumberFormatter_ = [NSNumberFormatter new];
  if (style_ == u"decimal") {
    nsNumberFormatter_.numberStyle = NSNumberFormatterDecimalStyle;
    if (notation_ == u"scientific") {
      nsNumberFormatter_.numberStyle = NSNumberFormatterScientificStyle;
    }
  } else if (style_ == u"currency") {
    nsNumberFormatter_.numberStyle = NSNumberFormatterCurrencyStyle;
    nsLocaleStr.append(u"@currency=").append(*currency_);
    if (currencyDisplay_ == u"code") {
      nsNumberFormatter_.numberStyle = NSNumberFormatterCurrencyISOCodeStyle;
    } else if (currencyDisplay_ == u"symbol") {
      nsNumberFormatter_.numberStyle = NSNumberFormatterCurrencyStyle;
    } else if (currencyDisplay_ == u"narrowSymbol") {
      nsNumberFormatter_.numberStyle = NSNumberFormatterCurrencyStyle;
    } else if (currencyDisplay_ == u"name") {
      nsNumberFormatter_.numberStyle = NSNumberFormatterCurrencyPluralStyle;
    }
    if (signDisplay_ != u"never" && currencySign_ == u"accounting") {
      nsNumberFormatter_.numberStyle = NSNumberFormatterCurrencyAccountingStyle;
    }
  } else if (style_ == u"percent") {
    nsNumberFormatter_.numberStyle = NSNumberFormatterPercentStyle;
  } else if (style_ == u"unit") {
    nsNumberFormatter_.numberStyle = NSNumberFormatterNoStyle;
  }
  nsNumberFormatter_.minimumIntegerDigits = minimumIntegerDigits_;
  if (fractionDigits_) {
    nsNumberFormatter_.minimumFractionDigits = fractionDigits_->minimum;
    nsNumberFormatter_.maximumFractionDigits = fractionDigits_->maximum;
  }
  if (significantDigits_) {
    nsNumberFormatter_.minimumSignificantDigits = significantDigits_->minimum;
    nsNumberFormatter_.maximumSignificantDigits = significantDigits_->maximum;
  }
  nsNumberFormatter_.usesGroupingSeparator = useGrouping_;
  auto nsLocale =
      [NSLocale localeWithLocaleIdentifier:u16StringToNSString(nsLocaleStr)];
  nsNumberFormatter_.locale = nsLocale;
  if (style_ == u"unit") {
    nsMeasurementFormatter_ = [NSMeasurementFormatter new];
    nsMeasurementFormatter_.numberFormatter = nsNumberFormatter_;
    nsMeasurementFormatter_.locale = nsLocale;
    if (unitDisplay_ == u"short") {
      nsMeasurementFormatter_.unitStyle = NSFormattingUnitStyleShort;
    } else if (unitDisplay_ == u"narrow") {
      nsMeasurementFormatter_.unitStyle = NSFormattingUnitStyleMedium;
    } else if (unitDisplay_ == u"long") {
      nsMeasurementFormatter_.unitStyle = NSFormattingUnitStyleLong;
    }
    nsUnit_ = unitIdentifierToNSUnit(*unit_);
  }
}

std::u16string NumberFormatApple::format(double number) noexcept {
  if (nsMeasurementFormatter_) {
    assert(style_ == u"unit");
    auto m = [[NSMeasurement alloc] initWithDoubleValue:number unit:nsUnit_];
    return nsStringToU16String(
        [nsMeasurementFormatter_ stringFromMeasurement:m]);
  }
  return nsStringToU16String(
      [nsNumberFormatter_ stringFromNumber:[NSNumber numberWithDouble:number]]);
}

std::u16string NumberFormat::format(double number) noexcept {
  return static_cast<NumberFormatApple *>(this)->format(number);
}

std::vector<std::unordered_map<std::u16string, std::u16string>>
NumberFormat::formatToParts(double number) noexcept {
  llvm_unreachable("formatToParts is unimplemented on Apple platforms");
}

}                           
}                    
