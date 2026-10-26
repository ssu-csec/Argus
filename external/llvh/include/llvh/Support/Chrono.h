//===- llvm/Support/Chrono.h - Utilities for Timing Manipulation-*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_CHRONO_H
#define LLVM_SUPPORT_CHRONO_H

#include "llvh/Support/Compiler.h"
#include "llvh/Support/FormatProviders.h"

#include <chrono>
#include <ctime>

namespace llvh {

class raw_ostream;

namespace sys {

                                                                       
                                                                            
                                                                                 
                 
                              
                                                                              
                                                                            
                                                                
template <typename D = std::chrono::nanoseconds>
using TimePoint = std::chrono::time_point<std::chrono::system_clock, D>;

                                      
LLVM_ATTRIBUTE_ALWAYS_INLINE inline std::time_t toTimeT(TimePoint<> TP) {
  using namespace std::chrono;
  return system_clock::to_time_t(
      time_point_cast<system_clock::time_point::duration>(TP));
}

                                        
LLVM_ATTRIBUTE_ALWAYS_INLINE inline TimePoint<std::chrono::seconds>
toTimePoint(std::time_t T) {
  using namespace std::chrono;
  return time_point_cast<seconds>(system_clock::from_time_t(T));
}

}                 

raw_ostream &operator<<(raw_ostream &OS, sys::TimePoint<> TP);

                                   
   
                                                                    
                             
                                   
                                          
   
                                                                          
template <>
struct format_provider<sys::TimePoint<>> {
  static void format(const sys::TimePoint<> &TP, llvh::raw_ostream &OS,
                     StringRef Style);
};

                                                            
   
                                                           
   
                                                              
                                                     
                                     
                                                                                
   
              
                                       
                                       
                                       
                                       
                                       
                                       
                                       
                                       
                                       
   
                                                                              
                                                                         
                                                                

namespace detail {
template <typename Period> struct unit { static const char value[]; };
template <typename Period> const char unit<Period>::value[] = "";

template <> struct unit<std::ratio<3600>> { static const char value[]; };
template <> struct unit<std::ratio<60>> { static const char value[]; };
template <> struct unit<std::ratio<1>> { static const char value[]; };
template <> struct unit<std::milli> { static const char value[]; };
template <> struct unit<std::micro> { static const char value[]; };
template <> struct unit<std::nano> { static const char value[]; };
}                    

template <typename Rep, typename Period>
struct format_provider<std::chrono::duration<Rep, Period>> {
private:
  typedef std::chrono::duration<Rep, Period> Dur;
  typedef typename std::conditional<
      std::chrono::treat_as_floating_point<Rep>::value, double, intmax_t>::type
      InternalRep;

  template <typename AsPeriod> static InternalRep getAs(const Dur &D) {
    using namespace std::chrono;
    return duration_cast<duration<InternalRep, AsPeriod>>(D).count();
  }

  static std::pair<InternalRep, StringRef> consumeUnit(StringRef &Style,
                                                        const Dur &D) {
    using namespace std::chrono;
    if (Style.consume_front("ns"))
      return {getAs<std::nano>(D), "ns"};
    if (Style.consume_front("us"))
      return {getAs<std::micro>(D), "us"};
    if (Style.consume_front("ms"))
      return {getAs<std::milli>(D), "ms"};
    if (Style.consume_front("s"))
      return {getAs<std::ratio<1>>(D), "s"};
    if (Style.consume_front("m"))
      return {getAs<std::ratio<60>>(D), "m"};
    if (Style.consume_front("h"))
      return {getAs<std::ratio<3600>>(D), "h"};
    return {D.count(), detail::unit<Period>::value};
  }

  static bool consumeShowUnit(StringRef &Style) {
    if (Style.empty())
      return true;
    if (Style.consume_front("-"))
      return false;
    if (Style.consume_front("+"))
      return true;
    assert(0 && "Unrecognised duration format");
    return true;
  }

public:
  static void format(const Dur &D, llvh::raw_ostream &Stream, StringRef Style) {
    InternalRep count;
    StringRef unit;
    std::tie(count, unit) = consumeUnit(Style, D);
    bool show_unit = consumeShowUnit(Style);

    format_provider<InternalRep>::format(count, Stream, Style);

    if (show_unit) {
      assert(!unit.empty());
      Stream << " " << unit;
    }
  }
};

}                  

#endif                         
