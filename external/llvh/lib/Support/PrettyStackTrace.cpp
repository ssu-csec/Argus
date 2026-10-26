//===- PrettyStackTrace.cpp - Pretty Crash Handling -----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines some helpful functions for dealing with the possibility of
// Unix signals occurring while your program is running.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/PrettyStackTrace.h"
#include "llvh-c/ErrorHandling.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/Config/config.h"                                       
#include "llvh/Support/Compiler.h"
#include "llvh/Support/Signals.h"
#include "llvh/Support/Watchdog.h"
#include "llvh/Support/raw_ostream.h"

#include <cstdarg>
#include <cstdio>
#include <tuple>

#ifdef HAVE_CRASHREPORTERCLIENT_H
#include <CrashReporterClient.h>
#endif

using namespace llvh;

                                                                            
                                                                               
                                      
#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES

                                                                        
                                                                               
                                                                       
                         
static LLVM_THREAD_LOCAL PrettyStackTraceEntry *PrettyStackTraceHead = nullptr;

namespace llvh {
PrettyStackTraceEntry *ReverseStackTrace(PrettyStackTraceEntry *Head) {
  PrettyStackTraceEntry *Prev = nullptr;
  while (Head)
    std::tie(Prev, Head, Head->NextEntry) =
        std::make_tuple(Head, Head->NextEntry, Prev);
  return Prev;
}
}

static void PrintStack(raw_ostream &OS) {
                                                                              
                                                                            
                                                             
  unsigned ID = 0;
  PrettyStackTraceEntry *ReversedStack =
      llvh::ReverseStackTrace(PrettyStackTraceHead);
  for (const PrettyStackTraceEntry *Entry = ReversedStack; Entry;
       Entry = Entry->getNextEntry()) {
    OS << ID++ << ".\t";
    sys::Watchdog W(5);
    Entry->print(OS);
  }
  llvh::ReverseStackTrace(ReversedStack);
}

                                                                               
static void PrintCurStackTrace(raw_ostream &OS) {
                                
  if (!PrettyStackTraceHead) return;

                                                                     
  OS << "Stack dump:\n";

  PrintStack(OS);
  OS.flush();
}

                                           
#if defined (__APPLE__) && defined(HAVE_CRASHREPORTERCLIENT_H)
                                                                              
                                            
extern "C" {
CRASH_REPORTER_CLIENT_HIDDEN
struct crashreporter_annotations_t gCRAnnotations
        __attribute__((section("__DATA," CRASHREPORTER_ANNOTATIONS_SECTION)))
#if CRASHREPORTER_ANNOTATIONS_VERSION < 5
        = { CRASHREPORTER_ANNOTATIONS_VERSION, 0, 0, 0, 0, 0, 0 };
#else
        = { CRASHREPORTER_ANNOTATIONS_VERSION, 0, 0, 0, 0, 0, 0, 0 };
#endif
}
#elif defined(__APPLE__) && HAVE_CRASHREPORTER_INFO
extern "C" const char *__crashreporter_info__
    __attribute__((visibility("hidden"))) = 0;
asm(".desc ___crashreporter_info__, 0x10");
#endif

                                                                             
                                              
static void CrashHandler(void *) {
#ifndef __APPLE__
                                                                     
  PrintCurStackTrace(errs());
#else
                                                                               
                                        
  SmallString<2048> TmpStr;
  {
    raw_svector_ostream Stream(TmpStr);
    PrintCurStackTrace(Stream);
  }

  if (!TmpStr.empty()) {
#ifdef HAVE_CRASHREPORTERCLIENT_H
                                     
    (void)CRSetCrashLogMessage(TmpStr.c_str());
#elif HAVE_CRASHREPORTER_INFO
    __crashreporter_info__ = strdup(TmpStr.c_str());
#endif
    errs() << TmpStr.str();
  }

#endif
}

                                               
#endif

PrettyStackTraceEntry::PrettyStackTraceEntry() {
#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES
                    
  NextEntry = PrettyStackTraceHead;
  PrettyStackTraceHead = this;
#endif
}

PrettyStackTraceEntry::~PrettyStackTraceEntry() {
#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES
  assert(PrettyStackTraceHead == this &&
         "Pretty stack trace entry destruction is out of order");
  PrettyStackTraceHead = NextEntry;
#endif
}

void PrettyStackTraceString::print(raw_ostream &OS) const { OS << Str << "\n"; }

PrettyStackTraceFormat::PrettyStackTraceFormat(const char *Format, ...) {
  va_list AP;
  va_start(AP, Format);
  const int SizeOrError = vsnprintf(nullptr, 0, Format, AP);
  va_end(AP);
  if (SizeOrError < 0) {
    return;
  }

  const int Size = SizeOrError + 1;        
  Str.resize(Size);
  va_start(AP, Format);
  vsnprintf(Str.data(), Size, Format, AP);
  va_end(AP);
}

void PrettyStackTraceFormat::print(raw_ostream &OS) const { OS << Str << "\n"; }

void PrettyStackTraceProgram::print(raw_ostream &OS) const {
  OS << "Program arguments: ";
                             
  for (unsigned i = 0, e = ArgC; i != e; ++i)
    OS << ArgV[i] << ' ';
  OS << '\n';
}

#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES
static bool RegisterCrashPrinter() {
  sys::AddSignalHandler(CrashHandler, nullptr);
  return false;
}
#endif

void llvh::EnablePrettyStackTrace() {
#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES
                                                                  
  static bool HandlerRegistered = RegisterCrashPrinter();
  (void)HandlerRegistered;
#endif
}

const void *llvh::SavePrettyStackState() {
#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES
  return PrettyStackTraceHead;
#else
  return nullptr;
#endif
}

void llvh::RestorePrettyStackState(const void *Top) {
#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES
  PrettyStackTraceHead =
      static_cast<PrettyStackTraceEntry *>(const_cast<void *>(Top));
#endif
}

void LLVHEnablePrettyStackTrace() {
  EnablePrettyStackTrace();
}
