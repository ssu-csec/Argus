/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSLIB_DATEUTIL_H
#define HERMES_VM_JSLIB_DATEUTIL_H

#include "hermes/VM/StringRefUtils.h"
#include "hermes/VM/StringView.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <limits>

#include "llvh/ADT/SmallString.h"

                                                        
                              

namespace hermes {
namespace vm {

class LocalTimeOffsetCache;

                                                                                
                       

constexpr double HOURS_PER_DAY = 24;

constexpr double MINUTES_PER_HOUR = 60;
constexpr double MINUTES_PER_DAY = MINUTES_PER_HOUR * HOURS_PER_DAY;

constexpr double SECONDS_PER_MINUTE = 60;
constexpr double SECONDS_PER_HOUR = SECONDS_PER_MINUTE * MINUTES_PER_HOUR;
constexpr double SECONDS_PER_DAY = SECONDS_PER_HOUR * HOURS_PER_DAY;

constexpr double MS_PER_SECOND = 1000;
constexpr double MS_PER_MINUTE = MS_PER_SECOND * SECONDS_PER_MINUTE;
constexpr double MS_PER_HOUR = MS_PER_MINUTE * MINUTES_PER_HOUR;
constexpr double MS_PER_DAY = MS_PER_HOUR * HOURS_PER_DAY;

                                          
constexpr int64_t TIME_RANGE_SECS = SECONDS_PER_DAY * 100000000LL;
constexpr int64_t TIME_RANGE_MS = TIME_RANGE_SECS * MS_PER_SECOND;

                                                                                
               

                                                              
std::chrono::milliseconds::rep curTime();

                                                                                
                 

                                                                              
double day(double t);

                                                                  
double timeWithinDay(double t);

                                                                                
                 

                                    
                              
uint32_t daysInYear(double y);

                                             
double dayFromYear(double y);

                                                                
double timeFromYear(double y);

                                                            
double yearFromTime(double t);

                                                                         
bool inLeapYear(double t);

                                                                                
                 

                                                                              
                                                                
uint32_t monthFromTime(double t);

                                                                                
                 

                                                                              
              
double dateFromTime(double t);

                                                                                
                 

                                                                             
                                            
int32_t weekDay(double t);

                                                                                
                 

                                                                
                                                           
double localTZA();

                                                                                
                 

namespace detail {
                        
int32_t equivalentTime(int64_t epochSecs);
}                    
                                                                                
                 

                                      
double localTime(double t, LocalTimeOffsetCache &);

                                      
                                              
double utcTime(double t, LocalTimeOffsetCache &);

                                                                                
                  

                                         
double hourFromTime(double t);

                                           
double minFromTime(double t);

                                           
double secFromTime(double t);

                                                
double msFromTime(double t);

                                                                                
                  

                                                                           
double makeTime(double hour, double min, double sec, double ms);

                                                                                
                  

                                                                                
                                    
                                                
                                                  
double makeDay(double year, double month, double date);

                                                                                
                  

                                                                         
               
double makeDate(double day, double t);

                                                                                
                  

                                                     
double timeClip(double t);

                                                                                
                     

                                           
                                           
                                                        
                                                                         
                                                                    
void dateToISOString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                           
                                                                  
                                                        
                                                                     
                                                                    
void timeToISOString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                                                
                                                                             
                                             
                                                                        
                                                        
                                                                     
                                                                    
void datetimeToISOString(
    double t,
    double tza,
    llvh::SmallVectorImpl<char> &buf);

void datetimeToLocaleString(double t, llvh::SmallVectorImpl<char16_t> &buf);

void dateToLocaleString(double t, llvh::SmallVectorImpl<char16_t> &buf);

void timeToLocaleString(double t, llvh::SmallVectorImpl<char16_t> &buf);

                                
                                                                  
                                                        
                                                                         
                                                                    
void dateString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                
                                                                  
                                                        
                                                                     
                                                                    
void timeString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                    
                                                                      
                                                        
                                                                     
                                                                    
void timeZoneString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                  
                                                                      
                                                        
                                                                         
                                                                    
void dateTimeString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                                             
                                                                      
                                                        
                                                                         
                                                                    
void dateTimeUTCString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                
                                                                       
                                                        
                                                                         
                                                                    
void timeTZString(double t, double tza, llvh::SmallVectorImpl<char> &buf);

                                                                                
               

                                                                       
                                                      
                                
                                     
                                            
                                                                               
                                                        
                                                                           
                                                                          
                                     
                                
                                           
                                       
                                                         
                                                                               
                                                                               
                   
                                
                                   
                                   
                                                                           
                                             
double parseDate(StringView str, LocalTimeOffsetCache &);

}                
}                    

#endif
