/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSLib/DateUtil.h"
#include "hermes/VM/JSLib/DateCache.h"

#include "hermes/Platform/Unicode/PlatformUnicode.h"
#include "hermes/Support/Compiler.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/SmallXString.h"

#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/raw_ostream.h"

#include <cassert>
#include <cctype>
#include <cmath>
#include <ctime>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                                              
                                                   
                                                            
static void floorDivMod(int64_t x, int64_t y, int64_t *quot, int64_t *rem) {
  int64_t q = x / y;
                                                
  if ((x ^ y) < 0 && q * y != x) {
    q--;
  }
  *quot = q;
  *rem = x - y * q;
}

                                                      
static int64_t floorMod(int64_t x, int64_t y) {
  int64_t quot, rem;
  floorDivMod(x, y, &quot, &rem);
  return rem;
}

                                                                                
                                                
static inline double posfmod(double x, double y) {
  double result = std::fmod(x, y);
  return result < 0 ? result + y : result;
}

                                                                                
               

std::chrono::milliseconds::rep curTime() {
                                                                      
                                  
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

                                                                                
                 

double day(double t) {
  return std::floor(t / MS_PER_DAY);
}

double timeWithinDay(double t) {
  return posfmod(t, MS_PER_DAY);
}

                                                                                
                 

                                             
static bool isLeapYear(double y) {
  if (std::fmod(y, 4) != 0) {
    return false;
  }
               
  if (std::fmod(y, 100) != 0) {
    return true;
  }
                 
  if (std::fmod(y, 400) != 0) {
    return false;
  }
                 
  return true;
}

                                             
static bool isLeapYear(int32_t y) {
  if (y % 4 != 0) {
    return false;
  }
               
  if (y % 100 != 0) {
    return true;
  }
                 
  if (y % 400 != 0) {
    return false;
  }
                 
  return true;
}

uint32_t daysInYear(double y) {
  return isLeapYear(y) ? 366 : 365;
}

double dayFromYear(double y) {
                                                                       
  return 365 * (y - 1970) + std::floor((y - 1969) / 4.0) -
      std::floor((y - 1901) / 100.0) + std::floor((y - 1601) / 400.0);
}

double timeFromYear(double y) {
  return MS_PER_DAY * dayFromYear(y);
}

double yearFromTime(double t) {
  if (!std::isfinite(t)) {
                                                
    return t;
  }

                                              
  double y = std::floor(t / (MS_PER_DAY * 365.2425)) + 1970;

                            
  double yt = timeFromYear(y);

  while (yt > t) {
                                                            
    --y;
    yt = timeFromYear(y);
  }
  while (yt + daysInYear(y) * MS_PER_DAY <= t) {
                                                      
                                       
    ++y;
    yt = timeFromYear(y);
  }

  assert(
      timeFromYear(y) <= t && timeFromYear(y + 1) > t &&
      "yearFromTime incorrect");
  return y;
}

bool inLeapYear(double t) {
  return daysInYear(yearFromTime(t)) == 366;
}

                                                                                
                 

uint32_t monthFromTime(double t) {
  double dayWithinYear = day(t) - dayFromYear(yearFromTime(t));
  constexpr int8_t kDaysInMonthNonLeap[11] = {
      31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30};
  double curDay = 0.0;
  for (uint32_t i = 0; i < 11; ++i) {
    curDay += (i == 1 && inLeapYear(t)) ? kDaysInMonthNonLeap[i] + 1
                                        : kDaysInMonthNonLeap[i];
    if (dayWithinYear < curDay)
      return i;
  }
                      
  return 11;
}

                                                                                
                 

                                                 
                                                       
static uint32_t dayFromMonth(uint32_t m, bool leap) {
  static const uint16_t standardTable[]{
      0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365};
  static const uint16_t leapYearTable[]{
      0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366};
  assert(m < 12 && "invalid month supplied to dayFromMonth");
  return leap ? leapYearTable[m] : standardTable[m];
}

double dateFromTime(double t) {
  double dayWithinYear = day(t) - dayFromYear(yearFromTime(t));
  bool leap = inLeapYear(t);
  return dayWithinYear - dayFromMonth(monthFromTime(t), leap) + 1;
}

                                                                                
                 

int32_t weekDay(double t) {
  return posfmod((day(t) + 4), 7);
}

                                                                                
                 

double localTZA() {
#ifdef _WINDOWS

                                                                              
                             
  _tzset();

  long gmtoff;
  int err = _get_timezone(&gmtoff);
  if (err)
    return 0;

                                           
  return -gmtoff * MS_PER_SECOND;

#else

                                                                          
  std::time_t currentWithDST = std::time(nullptr);

                                         
                                                                                
                                                                             
                                                         
  std::tm tm;
  std::tm *local = ::localtime_r(&currentWithDST, &tm);
  if (!local)
    return 0;

  long gmtoff = local->tm_gmtoff;

                                                                   
  return (gmtoff * MS_PER_SECOND) - (local->tm_isdst ? MS_PER_HOUR : 0);

#endif
}

                                                                                
                 

static const int32_t DAYS_IN_1_YEAR = 365;
static const int32_t DAYS_IN_4_YEARS = DAYS_IN_1_YEAR * 4 + 1;
static const int32_t DAYS_IN_100_YEARS = DAYS_IN_4_YEARS * 25 - 1;
static const int32_t DAYS_IN_400_YEARS = DAYS_IN_100_YEARS * 4 + 1;
                 
                                                                             
                                                                              
                                                     
static const int32_t BASE_YEAR = -274000;
static const int32_t DAYS_FROM_BASE_YEAR_TO_1970 =
    (-BASE_YEAR / 400) * DAYS_IN_400_YEARS + 4 * DAYS_IN_400_YEARS +
    3 * DAYS_IN_100_YEARS + 17 * DAYS_IN_4_YEARS + 2 * DAYS_IN_1_YEAR;

                                                              
                                                                               
                                                                   
                             
                                                                              
                                                                
                                                                        
static void decomposeEpochDays(
    int32_t epochDays,
    int32_t *year,
    int32_t *yearAsEpochDays,
    int32_t *dayOfYear) {
  *year = BASE_YEAR;
  *yearAsEpochDays = -DAYS_FROM_BASE_YEAR_TO_1970;
  *dayOfYear = epochDays + DAYS_FROM_BASE_YEAR_TO_1970;

  int32_t countOf400Years = *dayOfYear / DAYS_IN_400_YEARS;
  *year += countOf400Years * 400;
  *yearAsEpochDays += countOf400Years * DAYS_IN_400_YEARS;
  *dayOfYear -= countOf400Years * DAYS_IN_400_YEARS;

  int32_t countOf100Years = *dayOfYear / DAYS_IN_100_YEARS;
  *year += countOf100Years * 100;
  *yearAsEpochDays += countOf100Years * DAYS_IN_100_YEARS;
  *dayOfYear -= countOf100Years * DAYS_IN_100_YEARS;

  int32_t countOf4Years = *dayOfYear / DAYS_IN_4_YEARS;
  *year += countOf4Years * 4;
  *yearAsEpochDays += countOf4Years * DAYS_IN_4_YEARS;
  *dayOfYear -= countOf4Years * DAYS_IN_4_YEARS;

  int32_t countOf1Year = *dayOfYear / DAYS_IN_1_YEAR;
  *year += countOf1Year * 1;
  *yearAsEpochDays += countOf1Year * DAYS_IN_1_YEAR;
  *dayOfYear -= countOf1Year * DAYS_IN_1_YEAR;
}

static int32_t weekDayFromEpochDays(int32_t epochDays) {
  return floorMod(epochDays + 4, 7);
}

static int32_t epochDaysForYear2006To2033[] = {
    13149, 13514, 13879, 14245, 14610, 14975, 15340, 15706, 16071, 16436,
    16801, 17167, 17532, 17897, 18262, 18628, 18993, 19358, 19723, 20089,
    20454, 20819, 21184, 21550, 21915, 22280, 22645, 23011};

                                                                               
                                                                        
                                    
                                                                
                                                                               
                   
static int32_t equivalentYearAsEpochDays(
    int32_t year,
    int32_t yearAsEpochDays) {
  if (year >= 1970 && year <= 2037) {
                                                                        
                                                          
    return yearAsEpochDays;
  }
  int32_t wkDay = weekDayFromEpochDays(yearAsEpochDays);
                                                  
                                                                          
                                                               
                                                            
                                                             
                                                            
                                            
                                                                
                                                                      
                                       
                                                                         
                                                                        
                        
                                                                         
                                                            
  int32_t eqYear = (isLeapYear(year) ? 2012 : 2006) + (wkDay * 12) % 28;
                                                                     
                                               
  eqYear = 2006 + (eqYear - 2006) % 28;
  return epochDaysForYear2006To2033[eqYear - 2006];
}

                                                                           
                                                           
   
                                                    
                                              
   
                                                                      
                                                                
                                                         
   
                                                         
int32_t detail::equivalentTime(int64_t epochSecs) {
                                                                         
                                                                
  assert(epochSecs >= -TIME_RANGE_SECS && epochSecs <= TIME_RANGE_SECS);
  int64_t epochDays, secsOfDay;
  floorDivMod(epochSecs, SECONDS_PER_DAY, &epochDays, &secsOfDay);
  int32_t year, yearAsEpochDays, dayOfYear;
                                                         
  decomposeEpochDays(epochDays, &year, &yearAsEpochDays, &dayOfYear);
  int32_t eqYearAsEpochDays = equivalentYearAsEpochDays(year, yearAsEpochDays);
  return (eqYearAsEpochDays + dayOfYear) * SECONDS_PER_DAY + secsOfDay;
}

                                                                                
                 

                                          
                                      
double localTime(double t, LocalTimeOffsetCache &localTimeOffsetCache) {
                                                                               
                                                                 
  if (!std::isfinite(t)) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  return t + localTimeOffsetCache.getLocalTimeOffset(t, TimeType::Utc);
}

                                      
                                      
   
                                                                                
                                                                             
                                                                       
                                                                            
                                                                                
                                                       
                                                                        
                                                                     
                                                                              
                                                                        
                                                                            
          
double utcTime(double t, LocalTimeOffsetCache &localTimeOffsetCache) {
  if (!std::isfinite(t)) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  return t - localTimeOffsetCache.getLocalTimeOffset(t, TimeType::Local);
}

                                                                                
                  

double hourFromTime(double t) {
  return posfmod(std::floor(t / MS_PER_HOUR), HOURS_PER_DAY);
}

double minFromTime(double t) {
  return posfmod(std::floor(t / MS_PER_MINUTE), MINUTES_PER_HOUR);
}

double secFromTime(double t) {
  return posfmod(std::floor(t / MS_PER_SECOND), SECONDS_PER_MINUTE);
}

double msFromTime(double t) {
  return posfmod(t, MS_PER_SECOND);
}

                                                                                
                  

double makeTime(double hour, double min, double sec, double ms) {
  if (!std::isfinite(hour) || !std::isfinite(min) || !std::isfinite(sec) ||
      !std::isfinite(ms)) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  double h = std::trunc(hour);
  double m = std::trunc(min);
  double s = std::trunc(sec);
  double milli = trunc(ms);
  return h * MS_PER_HOUR + m * MS_PER_MINUTE + s * MS_PER_SECOND + milli;
}

                                                                                
                  

double makeDay(double year, double month, double date) {
  if (!std::isfinite(year) || !std::isfinite(month) || !std::isfinite(date)) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  double y = std::trunc(year);
  double m = std::trunc(month);
  double dt = std::trunc(date);

                                                                           
                                                                   
  double ym = y + std::floor(m / 12);
  double mn = posfmod(m, 12);

  bool leap = isLeapYear(ym);

                                         
  double yd = std::floor(timeFromYear(ym) / MS_PER_DAY);
                                          
  double md = dayFromMonth(mn, leap);

                                                                            
                                                                
  return yd + md + dt - 1;
}

                                                                                
                  

double makeDate(double day, double t) {
  if (!std::isfinite(day) || !std::isfinite(t)) {
    return std::numeric_limits<double>::quiet_NaN();
  }

                                                                              
                                                                        
                                                                                
                                                                         
                                                                                
                                                
  double dayMs = day * MS_PER_DAY;
  return dayMs + t;
}

                                                                                
                  

double timeClip(double t) {
  if (!std::isfinite(t) || std::abs(t) > 8.64e15) {
    return std::numeric_limits<double>::quiet_NaN();
  }

                                  
  return std::trunc(t) + 0;
}

                                                                                
                     

void dateToISOString(double t, double, llvh::SmallVectorImpl<char> &buf) {
  llvh::raw_svector_ostream os{buf};

                                                                       
                                             
  int32_t y = yearFromTime(t);
  int32_t m = monthFromTime(t) + 1;                                  
  int32_t d = dateFromTime(t);

  if (y < 0 || y > 9999) {
                             
    os << llvh::format("%+07d-%02d-%02d", y, m, d);
  } else {
    os << llvh::format("%04d-%02d-%02d", y, m, d);
  }
}

void timeToISOString(double t, double tza, llvh::SmallVectorImpl<char> &buf) {
  llvh::raw_svector_ostream os{buf};

                                                                              
                                             
  int32_t h = hourFromTime(t);
  int32_t min = minFromTime(t);
  int32_t s = secFromTime(t);
  int32_t ms = msFromTime(t);

  if (tza == 0) {
                                            
    os << llvh::format("%02d:%02d:%02d.%03dZ", h, min, s, ms);
  } else {
                                                                    
                                                                             
    char sign = tza >= 0 ? '+' : '-';
    double tzaPos = std::abs(tza);
    int32_t tzh = hourFromTime(tzaPos);
    int32_t tzm = minFromTime(tzaPos);
    os << llvh::format(
        "%02d:%02d:%02d.%03d%c%02d:%02d", h, min, s, ms, sign, tzh, tzm);
  }
}

static void datetimeToISOString(
    double t,
    double tza,
    llvh::SmallVectorImpl<char> &buf,
    char separator) {
  dateToISOString(t, tza, buf);
  buf.push_back(separator);
  timeToISOString(t, tza, buf);
}

void datetimeToISOString(
    double t,
    double tza,
    llvh::SmallVectorImpl<char> &buf) {
  return datetimeToISOString(t, tza, buf, 'T');
}

void datetimeToLocaleString(double t, llvh::SmallVectorImpl<char16_t> &buf) {
  return platform_unicode::dateFormat(t, true, true, buf);
}

void dateToLocaleString(double t, llvh::SmallVectorImpl<char16_t> &buf) {
  return platform_unicode::dateFormat(t, true, false, buf);
}

void timeToLocaleString(double t, llvh::SmallVectorImpl<char16_t> &buf) {
  return platform_unicode::dateFormat(t, false, true, buf);
}

                 
static const char *const weekdayNames[7]{
    "Sun",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat",
};

                 
static const char *const monthNames[12]{
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
};

void dateString(double t, double, llvh::SmallVectorImpl<char> &buf) {
  llvh::raw_svector_ostream os{buf};

                                                                      
                                            
  int32_t y = yearFromTime(t);
  int32_t m = monthFromTime(t);                                  
  int32_t d = dateFromTime(t);
  int32_t wd = weekDay(t);

                                                                        
                                                                            
                       
                             
  os << llvh::format("%s %s %02d %0.4d", weekdayNames[wd], monthNames[m], d, y);
}

void timeString(double t, double tza, llvh::SmallVectorImpl<char> &buf) {
  llvh::raw_svector_ostream os{buf};

  int32_t hour = hourFromTime(t);
  int32_t minute = minFromTime(t);
  int32_t second = secFromTime(t);

                          
  os << llvh::format("%02d:%02d:%02d GMT", hour, minute, second);
}

void timeZoneString(double t, double tza, llvh::SmallVectorImpl<char> &buf) {
  llvh::raw_svector_ostream os{buf};

                                                               
  double offset = tza;

                                                                                
  char offsetSign = offset >= 0 ? '+' : '-';

                                                                               
                                                                               
               
  int32_t offsetMin = minFromTime(std::abs(offset));

                                                      
                                                                               
                                          
  int32_t offsetHour = hourFromTime(std::abs(offset));

                                                                               
                                                                            
                                                                              
                                                        
                                                       

                                                                             
                
                   
  os << llvh::format("%c%02d%02d", offsetSign, offsetHour, offsetMin);
}

void dateTimeString(double tv, double tza, llvh::SmallVectorImpl<char> &buf) {
  llvh::raw_svector_ostream os{buf};
  dateString(tv, tza, buf);
                                                                           
                                                    
                                               
  os << " ";
  timeString(tv, tza, buf);
  timeZoneString(tv, tza, buf);
}

void dateTimeUTCString(
    double tv,
    double tza,
    llvh::SmallVectorImpl<char> &buf) {
  llvh::raw_svector_ostream os{buf};

                                                                      
                                            
  int32_t y = yearFromTime(tv);
  int32_t m = monthFromTime(tv);                                  
  int32_t d = dateFromTime(tv);
  int32_t wd = weekDay(tv);

                                                                             
                                                                            
                                                                     
                                          
  os << llvh::format(
      "%s, %02d %s %0.4d ", weekdayNames[wd], d, monthNames[m], y);
  timeString(tv, tza, buf);
}

void timeTZString(double tv, double tza, llvh::SmallVectorImpl<char> &buf) {
                                                                             
                               
  timeString(tv, tza, buf);
  timeZoneString(tv, tza, buf);
}

                                                                                
               

                                                         
static inline bool isDigit(char16_t c) {
  return u'0' <= c && c <= u'9';
}

                                                    
static inline bool isAlpha(char16_t c) {
  c |= 'a' ^ 'A';             
  return 'a' <= c && c <= 'z';
}

                                                       
                                                      
                                                                       
               
                                     
                                                          
                                                
template <class InputIter>
static bool scanInt(InputIter &it, const InputIter end, int32_t &x) {
  llvh::SmallString<16> str{};
  if (it == end) {
    return false;
  }
  for (; it != end && isDigit(*it); ++it) {
    str += static_cast<char>(*it);
  }
  llvh::StringRef ref{str};
                                                   
  return !ref.getAsInteger(10, x);
}

static double parseISODate(
    StringView u16str,
    LocalTimeOffsetCache &localTimeOffsetCache) {
  constexpr double nan = std::numeric_limits<double>::quiet_NaN();

  auto it = u16str.begin();
  auto end = u16str.end();

                                                            
                                     
  double sign;

                                               
  int32_t y, m{1}, d{1}, h{0}, min{0}, s{0}, ms{0}, tzh{0}, tzm{0};

  auto consume = [&](char16_t ch) {
    if (it != end && *it == ch) {
      ++it;
      return true;
    }
    return false;
  };

                        
  sign = 1;
  if (consume(u'+')) {
    sign = 1;
  } else if (consume(u'-')) {
    sign = -1;
  }
  if (!scanInt(it, end, y)) {
    return nan;
  }
  y *= sign;
  if (consume(u'-')) {
                             
    if (!scanInt(it, end, m)) {
      return nan;
    }
    if (consume(u'-')) {
                              
      if (!scanInt(it, end, d)) {
        return nan;
      }
    }
  }

                           
  if (consume(u'T') || consume(u' ')) {
                                    
    if (!scanInt(it, end, h)) {
      return nan;
    }
    if (!consume(u':')) {
      return nan;
    }
    if (!scanInt(it, end, min)) {
      return nan;
    }
    if (consume(u':')) {
                             
      if (!scanInt(it, end, s)) {
        return nan;
      }
      if (consume(u'.')) {
                                            
        if (it == end || !isDigit(*it)) {
          return nan;
        }

                                                
                                                                                
                                          
        int32_t pos = 100;

        for (; it != end && isDigit(*it); ++it) {
          ms += pos * (*it - '0');
          pos /= 10;
        }
      }
    }

    if (it == end) {
                                                                               
                                                                                
                         
      double t = makeDate(makeDay(y, m - 1, d), makeTime(h, min, s, ms));
      t = utcTime(t, localTimeOffsetCache);
      return t;
    }

                               
    if (consume(u'Z')) {
      tzh = 0;
      tzm = 0;
    } else {
                                                               
      if (consume(u'+')) {
        sign = 1;
      } else if (consume(u'-')) {
        sign = -1;
      } else {
                           
        return nan;
      }
      if (it > end - 2) {
        return nan;
      }
      if (!scanInt(it, it + 2, tzh)) {
        return nan;
      }
      tzh *= sign;
      consume(u':');
      if (it > end - 2) {
        return nan;
      }
      if (!scanInt(it, it + 2, tzm)) {
        return nan;
      }
      tzm *= sign;
    }
  }

  if (it != end) {
                              
    return nan;
  }

                                                                       
  return makeDate(makeDay(y, m - 1, d), makeTime(h - tzh, min - tzm, s, ms));
}

static double parseESDate(
    StringView str,
    LocalTimeOffsetCache &localTimeOffsetCache) {
  constexpr double nan = std::numeric_limits<double>::quiet_NaN();
  StringView tok = str;

                                               
  int32_t y, m{1}, d{1}, h{0}, min{0}, s{0}, ms{0}, tzh{0}, tzm{0};
  double sign = 1;

                              
                                            
                                  
                                                                   

                                  
  auto it = str.begin();
  auto end = str.end();

                                                
                                                            
                                                  
  auto scanStr = [&str, &tok, &it](int32_t len) -> bool {
    if (it + len > str.end()) {
      return false;
    }
    tok = str.slice(it, it + len);
    it += len;
    return true;
  };

                                                  
                                                                      
                                                                          
          
                                
                                                                               
                                                                               
                                                                               
                                                              
                                                  
  auto scanStrAndSkipWord = [&str, &tok, &it](int32_t len) -> bool {
    if (it + len > str.end())
      return false;
    tok = str.slice(it, it + len);
    while (it != str.end() && !std::isspace(*it) && *it != '-')
      it++;
    return true;
  };

  auto consume = [&](char16_t ch) {
    if (it != str.end() && *it == ch) {
      ++it;
      return true;
    }
    return false;
  };

  auto consumeSpaces = [&]() {
    while (it != str.end() && std::isspace(*it))
      ++it;
  };

                                                                  
                                                
                                         
  auto consumeSpacesOrDash = [&]() {
    auto first = true;
    while (it != str.end()) {
      if (std::isspace(*it) || (first && *it == '-')) {
        ++it;
      } else {
        return;
      }
      first = false;
    }
  };

            
  if (!scanStr(3))
    return nan;
  bool foundWeekday = false;
  for (const char *name : weekdayNames) {
    if (tok.equals(llvh::arrayRefFromStringRef(name))) {
      foundWeekday = true;
      break;
    }
  }
  if (!foundWeekday)
    return nan;

                                                              
  auto tokIsMonth = [&]() -> bool {
    for (uint32_t i = 0; i < sizeof(monthNames) / sizeof(monthNames[0]); ++i) {
      if (tok.equals(llvh::arrayRefFromStringRef(monthNames[i]))) {
                          
        m = i + 1;
        return true;
      }
    }
    return false;
  };

                   
       
                   
  while (it != str.end()) {
    if (isDigit(*it)) {
            
      scanInt(it, end, d);
              
      consumeSpacesOrDash();
                                                  
      if (!scanStrAndSkipWord(3))
        return nan;
                                                 
      if (!tokIsMonth())
        return nan;
      break;
    }
    if (isAlpha(*it)) {
                  
      if (!scanStrAndSkipWord(3))
        return nan;
                                                 
      if (tokIsMonth()) {
              
        consumeSpacesOrDash();
        if (!scanInt(it, end, d))
          return nan;
        break;
      }
                                     
      continue;
    }
                          
    ++it;
  }

         
  consumeSpacesOrDash();
  if (!scanInt(it, end, y))
    return nan;

                        
  consumeSpacesOrDash();

  if (it != end) {
    if (!scanInt(it, end, h))
      return nan;
    if (!consume(':'))
      return nan;
    if (!scanInt(it, end, min))
      return nan;
    if (!consume(':'))
      return nan;
    if (!scanInt(it, end, s))
      return nan;
  }

                         
  consumeSpaces();

  if (it == end) {
                                                          
    double t = makeDate(makeDay(y, m - 1, d), makeTime(h, min, s, ms));
    t = utcTime(t, localTimeOffsetCache);
    return t;
  }

  struct KnownTZ {
    const char *tz;
    int32_t tzh;
  };

                                   
                                                                               
  static constexpr KnownTZ knownTZs[] = {
      {"GMT", 0},
      {"EDT", -4},
      {"EST", -5},
      {"CDT", -5},
      {"CST", -6},
      {"MDT", -6},
      {"MST", -7},
      {"PDT", -7},
      {"PST", -8},
  };

                                                                          
  if ('A' <= *it && *it <= 'Z') {
    if (!scanStr(3))
      return nan;
    for (const KnownTZ &knownTZ : knownTZs) {
      if (tok.equals(llvh::arrayRefFromStringRef(knownTZ.tz))) {
        tzh = knownTZ.tzh;
        break;
      }
    }
  }

  if (it == end)
    goto complete;

                                     
  if (tzh != 0 && it != end)
    return nan;

                                     
  if (consume('+'))
    sign = 1;
  else if (consume('-'))
    sign = -1;
  else
    return nan;

                                            
  if (it > end - 4)
    return nan;
  if (!scanInt(it, it + 2, tzh))
    return nan;
  tzh *= sign;
  if (!scanInt(it, it + 2, tzm))
    return nan;
  tzm *= sign;

  if (it != end) {
                                                                           
    if (!consume(' '))
      return nan;
    if (!consume('('))
      return nan;
    while (it != end && *it != ')')
      ++it;
    if (!consume(')'))
      return nan;
  }

  if (it != end)
    return nan;

complete:
                                                                       
  return makeDate(makeDay(y, m - 1, d), makeTime(h - tzh, min - tzm, s, ms));
}

double parseDate(StringView str, LocalTimeOffsetCache &localTimeOffsetCache) {
  double result = parseISODate(str, localTimeOffsetCache);
  if (!std::isnan(result)) {
    return result;
  }

  return parseESDate(str, localTimeOffsetCache);
}

}                
}                    
