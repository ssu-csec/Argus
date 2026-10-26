//===-- llvm/Support/Timer.h - Interval Timing Support ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TIMER_H
#define LLVM_SUPPORT_TIMER_H

#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/DataTypes.h"
#include <cassert>
#include <string>
#include <utility>
#include <vector>

namespace llvh {

class Timer;
class TimerGroup;
class raw_ostream;

class TimeRecord {
  double WallTime;                                               
  double UserTime;                              
  double SystemTime;                              
  ssize_t MemUsed;                                        
public:
  TimeRecord() : WallTime(0), UserTime(0), SystemTime(0), MemUsed(0) {}

                                                                                
                                                                             
                                                                              
                                       
  static TimeRecord getCurrentTime(bool Start = true);

  double getProcessTime() const { return UserTime + SystemTime; }
  double getUserTime() const { return UserTime; }
  double getSystemTime() const { return SystemTime; }
  double getWallTime() const { return WallTime; }
  ssize_t getMemUsed() const { return MemUsed; }

  bool operator<(const TimeRecord &T) const {
                                                                         
    return WallTime < T.WallTime;
  }

  void operator+=(const TimeRecord &RHS) {
    WallTime   += RHS.WallTime;
    UserTime   += RHS.UserTime;
    SystemTime += RHS.SystemTime;
    MemUsed    += RHS.MemUsed;
  }
  void operator-=(const TimeRecord &RHS) {
    WallTime   -= RHS.WallTime;
    UserTime   -= RHS.UserTime;
    SystemTime -= RHS.SystemTime;
    MemUsed    -= RHS.MemUsed;
  }

                                                                      
                                                
  void print(const TimeRecord &Total, raw_ostream &OS) const;
};

                                                                               
                                                                              
                                                                             
                                                                             
                                                                      
                                                                               
                  
class Timer {
  TimeRecord Time;                                       
  TimeRecord StartTime;                                                
  std::string Name;                                             
  std::string Description;                                         
  bool Running;                                                 
  bool Triggered;                                                  
  TimerGroup *TG = nullptr;                                      

  Timer **Prev;                                                                
  Timer *Next;                                           
public:
  explicit Timer(StringRef Name, StringRef Description) {
    init(Name, Description);
  }
  Timer(StringRef Name, StringRef Description, TimerGroup &tg) {
    init(Name, Description, tg);
  }
  Timer(const Timer &RHS) {
    assert(!RHS.TG && "Can only copy uninitialized timers");
  }
  const Timer &operator=(const Timer &T) {
    assert(!TG && !T.TG && "Can only assign uninit timers");
    return *this;
  }
  ~Timer();

                                                            
  explicit Timer() {}
  void init(StringRef Name, StringRef Description);
  void init(StringRef Name, StringRef Description, TimerGroup &tg);

  const std::string &getName() const { return Name; }
  const std::string &getDescription() const { return Description; }
  bool isInitialized() const { return TG != nullptr; }

                                              
  bool isRunning() const { return Running; }

                                                               
  bool hasTriggered() const { return Triggered; }

                                                                             
                                                                          
             
  void startTimer();

                     
  void stopTimer();

                            
  void clear();

                                                                
  TimeRecord getTotalTime() const { return Time; }

private:
  friend class TimerGroup;
};

                                                                               
                                                                               
                                                                               
                                                                     
class TimeRegion {
  Timer *T;
  TimeRegion(const TimeRegion &) = delete;

public:
  explicit TimeRegion(Timer &t) : T(&t) {
    T->startTimer();
  }
  explicit TimeRegion(Timer *t) : T(t) {
    if (T) T->startTimer();
  }
  ~TimeRegion() {
    if (T) T->stopTimer();
  }
};

                                                                             
                                                                          
                                                                            
                                                            
struct NamedRegionTimer : public TimeRegion {
  explicit NamedRegionTimer(StringRef Name, StringRef Description,
                            StringRef GroupName,
                            StringRef GroupDescription, bool Enabled = true);
};

                                                                               
                                                                              
                                                                           
                                                                             
class TimerGroup {
  struct PrintRecord {
    TimeRecord Time;
    std::string Name;
    std::string Description;

    PrintRecord(const PrintRecord &Other) = default;
    PrintRecord &operator=(const PrintRecord &Other) = default;
    PrintRecord(const TimeRecord &Time, const std::string &Name,
                const std::string &Description)
      : Time(Time), Name(Name), Description(Description) {}

    bool operator <(const PrintRecord &Other) const {
      return Time < Other.Time;
    }
  };
  std::string Name;
  std::string Description;
  Timer *FirstTimer = nullptr;                               
  std::vector<PrintRecord> TimersToPrint;

  TimerGroup **Prev;                                                           
  TimerGroup *Next;                                          
  TimerGroup(const TimerGroup &TG) = delete;
  void operator=(const TimerGroup &TG) = delete;

public:
  explicit TimerGroup(StringRef Name, StringRef Description);

  explicit TimerGroup(StringRef Name, StringRef Description,
                      const StringMap<TimeRecord> &Records);

  ~TimerGroup();

  void setName(StringRef NewName, StringRef NewDescription) {
    Name.assign(NewName.begin(), NewName.end());
    Description.assign(NewDescription.begin(), NewDescription.end());
  }

                                             
  void print(raw_ostream &OS);

                                     
  void clear();

                                           
  static void printAll(raw_ostream &OS);

                                                                    
                                                                            
                                              
  static void clearAll();

  const char *printJSONValues(raw_ostream &OS, const char *delim);

                                                
  static const char *printAllJSONValues(raw_ostream &OS, const char *delim);

                                                                              
                                                                              
                                      
  static void ConstructTimerLists();
private:
  friend class Timer;
  friend void PrintStatisticsJSON(raw_ostream &OS);
  void addTimer(Timer &T);
  void removeTimer(Timer &T);
  void prepareToPrintList();
  void PrintQueuedTimers(raw_ostream &OS);
  void printJSONValue(raw_ostream &OS, const PrintRecord &R,
                      const char *suffix, double Value);
};

}                      

#endif
