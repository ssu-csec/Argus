//===- llvm/Support/PrettyStackTrace.h - Pretty Crash Handling --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the PrettyStackTraceEntry class, which is used to make
// crashes give more contextual information about what the program was doing
// when it crashed.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_PRETTYSTACKTRACE_H
#define LLVM_SUPPORT_PRETTYSTACKTRACE_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Compiler.h"

namespace llvh {
  class raw_ostream;

  void EnablePrettyStackTrace();

                                                                            
                                                                                
                                                                             
                                                                          
                                                                        
  class PrettyStackTraceEntry {
    friend PrettyStackTraceEntry *ReverseStackTrace(PrettyStackTraceEntry *);

    PrettyStackTraceEntry *NextEntry;
    PrettyStackTraceEntry(const PrettyStackTraceEntry &) = delete;
    void operator=(const PrettyStackTraceEntry &) = delete;
  public:
    PrettyStackTraceEntry();
    virtual ~PrettyStackTraceEntry();

                                                              
    virtual void print(raw_ostream &OS) const = 0;

                                                                   
    const PrettyStackTraceEntry *getNextEntry() const { return NextEntry; }
  };

                                                                           
                                                                                
             
  class PrettyStackTraceString : public PrettyStackTraceEntry {
    const char *Str;
  public:
    PrettyStackTraceString(const char *str) : Str(str) {}
    void print(raw_ostream &OS) const override;
  };

                                                                         
                                                                            
                                             
  class PrettyStackTraceFormat : public PrettyStackTraceEntry {
    llvh::SmallVector<char, 32> Str;
  public:
    PrettyStackTraceFormat(const char *Format, ...);
    void print(raw_ostream &OS) const override;
  };

                                                                                
                                                           
  class PrettyStackTraceProgram : public PrettyStackTraceEntry {
    int ArgC;
    const char *const *ArgV;
  public:
    PrettyStackTraceProgram(int argc, const char * const*argv)
      : ArgC(argc), ArgV(argv) {
      EnablePrettyStackTrace();
    }
    void print(raw_ostream &OS) const override;
  };

                                                              
  const void *SavePrettyStackState();

                                                                              
                                                                          
                                                                     
                                                                               
                                                                         
                                                                      
                           
  void RestorePrettyStackState(const void *State);

}                      

#endif
