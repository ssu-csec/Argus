//===- PassTimingInfo.h - pass execution timing -----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This header defines classes/functions to handle pass execution timing
/// information with interfaces for both pass managers.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_PASSTIMINGINFO_H
#define LLVM_IR_PASSTIMINGINFO_H

#include "llvh/ADT/Any.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/Timer.h"
#include "llvh/Support/TypeName.h"
#include <memory>
namespace llvh {

class Pass;
class PassInstrumentationCallbacks;

                                                                               
                             
void reportAndResetTimings();

                                                                   
Timer *getPassTimer(Pass *);

                                                                                
                                                                 
                                                    
extern bool TimePassesIsEnabled;

                                                                          
                                                                        
                                                                      
                                                                             
                  
class TimePassesHandler {
                                                                             
                                                                     
                                                                           
  using PassInvocationID = std::pair<StringRef, unsigned>;

                                        
  TimerGroup TG;

                                        
  DenseMap<PassInvocationID, std::unique_ptr<Timer>> TimingData;

                                                                                
  StringMap<unsigned> PassIDCountMap;

                                       
  SmallVector<Timer *, 8> TimerStack;

  bool Enabled;

public:
  TimePassesHandler(bool Enabled = TimePassesIsEnabled);

                                                                            
  ~TimePassesHandler() {
                                                                           
                                                                              
                            
    TimingData.clear();
  }

                                                               
  void print();

                                                                 
  TimePassesHandler(const TimePassesHandler &) = delete;
  void operator=(const TimePassesHandler &) = delete;

  void registerCallbacks(PassInstrumentationCallbacks &PIC);

private:
                                                                          
  LLVM_DUMP_METHOD void dump() const;

                                                         
  Timer &getPassTimer(StringRef PassID);

                                                                           
  unsigned nextPassID(StringRef PassID) { return ++PassIDCountMap[PassID]; }

  void startTimer(StringRef PassID);
  void stopTimer(StringRef PassID);

                                                      
  bool runBeforePass(StringRef PassID, Any IR);
  void runAfterPass(StringRef PassID, Any IR);
};

}                  

#endif
