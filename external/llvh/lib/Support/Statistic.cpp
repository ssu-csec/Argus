//===-- Statistic.cpp - Easy way to expose stats information --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the 'Statistic' class, which is designed to be an easy
// way to expose various success metrics from passes.  These statistics are
// printed at the end of a run, when the -stats command line option is enabled
// on the command line.
//
// This is useful for reporting information like the number of instructions
// simplified, optimized or removed by various transformations, like this:
//
// static Statistic NumInstEliminated("GCSE", "Number of instructions killed");
//
// Later, in the code: ++NumInstEliminated;
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/Statistic.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/Support/CommandLine.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/ManagedStatic.h"
#include "llvh/Support/Mutex.h"
#include "llvh/Support/Timer.h"
#include "llvh/Support/YAMLTraits.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>
#include <cstring>
using namespace llvh;

                                                                             
                  
   
static cl::opt<bool> Stats(
    "stats",
    cl::desc("Enable statistics output from program (available with Asserts)"),
    cl::Hidden);

static cl::opt<bool> StatsAsJSON("stats-json",
                                 cl::desc("Display statistics as json data"),
                                 cl::Hidden);

static bool Enabled;
static bool PrintOnExit;

namespace {
                                                                               
                                                                           
                                                    
                                                                              
             
class StatisticInfo {
  std::vector<Statistic*> Stats;

  friend void llvh::PrintStatistics();
  friend void llvh::PrintStatistics(raw_ostream &OS);
  friend void llvh::PrintStatisticsJSON(raw_ostream &OS);

                                                    
  void sort();
public:
  using const_iterator = std::vector<Statistic *>::const_iterator;

  StatisticInfo();
  ~StatisticInfo();

  void addStatistic(Statistic *S) {
    Stats.push_back(S);
  }

  const_iterator begin() const { return Stats.begin(); }
  const_iterator end() const { return Stats.end(); }
  iterator_range<const_iterator> statistics() const {
    return {begin(), end()};
  }

  void reset();
};
}                           

static ManagedStatic<StatisticInfo> StatInfo;
static ManagedStatic<sys::SmartMutex<true> > StatLock;

                                                                            
           
void Statistic::RegisterStatistic() {
                                                                        
             
                                                                           
                                                                            
                                                                     
                                                                          
                                                                             
                                       
  if (!Initialized.load(std::memory_order_relaxed)) {
    sys::SmartMutex<true> &Lock = *StatLock;
    StatisticInfo &SI = *StatInfo;
    sys::SmartScopedLock<true> Writer(Lock);
                                                        
    if (Initialized.load(std::memory_order_relaxed))
      return;
    if (Stats || Enabled)
      SI.addStatistic(this);

                                        
    Initialized.store(true, std::memory_order_release);
  }
}

StatisticInfo::StatisticInfo() {
                                                                               
  TimerGroup::ConstructTimerLists();
}

                                                                          
StatisticInfo::~StatisticInfo() {
  if (::Stats || PrintOnExit)
    llvh::PrintStatistics();
}

void llvh::EnableStatistics(bool PrintOnExit) {
  Enabled = true;
  ::PrintOnExit = PrintOnExit;
}

bool llvh::AreStatisticsEnabled() {
  return Enabled || Stats;
}

void StatisticInfo::sort() {
  std::stable_sort(Stats.begin(), Stats.end(),
                   [](const Statistic *LHS, const Statistic *RHS) {
    if (int Cmp = std::strcmp(LHS->getDebugType(), RHS->getDebugType()))
      return Cmp < 0;

    if (int Cmp = std::strcmp(LHS->getName(), RHS->getName()))
      return Cmp < 0;

    return std::strcmp(LHS->getDesc(), RHS->getDesc()) < 0;
  });
}

void StatisticInfo::reset() {
  sys::SmartScopedLock<true> Writer(*StatLock);

                                                                       
                                                                           
                                                                               
               
  for (auto *Stat : Stats) {
                                                                              
                                                             
    Stat->Initialized = false;
    Stat->Value = 0;
  }

                                                                          
                                                                                
                                                                             
                                                                             
                                     
  Stats.clear();
}

void llvh::PrintStatistics(raw_ostream &OS) {
  StatisticInfo &Stats = *StatInfo;

                                                               
  unsigned MaxDebugTypeLen = 0, MaxValLen = 0;
  for (size_t i = 0, e = Stats.Stats.size(); i != e; ++i) {
    MaxValLen = std::max(MaxValLen,
                         (unsigned)utostr(Stats.Stats[i]->getValue()).size());
    MaxDebugTypeLen = std::max(MaxDebugTypeLen,
                         (unsigned)std::strlen(Stats.Stats[i]->getDebugType()));
  }

  Stats.sort();

                                       
  OS << "===" << std::string(73, '-') << "===\n"
     << "                          ... Statistics Collected ...\n"
     << "===" << std::string(73, '-') << "===\n\n";

                                 
  for (size_t i = 0, e = Stats.Stats.size(); i != e; ++i)
    OS << format("%*u %-*s - %s\n",
                 MaxValLen, Stats.Stats[i]->getValue(),
                 MaxDebugTypeLen, Stats.Stats[i]->getDebugType(),
                 Stats.Stats[i]->getDesc());

  OS << '\n';                             
  OS.flush();
}

void llvh::PrintStatisticsJSON(raw_ostream &OS) {
  sys::SmartScopedLock<true> Reader(*StatLock);
  StatisticInfo &Stats = *StatInfo;

  Stats.sort();

                                 
  OS << "{\n";
  const char *delim = "";
  for (const Statistic *Stat : Stats.Stats) {
    OS << delim;
    assert(yaml::needsQuotes(Stat->getDebugType()) == yaml::QuotingType::None &&
           "Statistic group/type name is simple.");
    assert(yaml::needsQuotes(Stat->getName()) == yaml::QuotingType::None &&
           "Statistic name is simple");
    OS << "\t\"" << Stat->getDebugType() << '.' << Stat->getName() << "\": "
       << Stat->getValue();
    delim = ",\n";
  }
                  
  TimerGroup::printAllJSONValues(OS, delim);

  OS << "\n}\n";
  OS.flush();
}

void llvh::PrintStatistics() {
#if LLVM_ENABLE_STATS
  sys::SmartScopedLock<true> Reader(*StatLock);
  StatisticInfo &Stats = *StatInfo;

                            
  if (Stats.Stats.empty()) return;

                                
  std::unique_ptr<raw_ostream> OutStream = CreateInfoOutputFile();
  if (StatsAsJSON)
    PrintStatisticsJSON(*OutStream);
  else
    PrintStatistics(*OutStream);

#else
                                                          
                                                                   
                                               
  if (Stats) {
                                  
    std::unique_ptr<raw_ostream> OutStream = CreateInfoOutputFile();
    (*OutStream) << "Statistics are disabled.  "
                 << "Build with asserts or with -DLLVM_ENABLE_STATS\n";
  }
#endif
}

const std::vector<std::pair<StringRef, unsigned>> llvh::GetStatistics() {
  sys::SmartScopedLock<true> Reader(*StatLock);
  std::vector<std::pair<StringRef, unsigned>> ReturnStats;

  for (const auto &Stat : StatInfo->statistics())
    ReturnStats.emplace_back(Stat->getName(), Stat->getValue());
  return ReturnStats;
}

void llvh::ResetStatistics() {
  StatInfo->reset();
}
