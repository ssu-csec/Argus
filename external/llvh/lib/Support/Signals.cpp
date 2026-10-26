//===- Signals.cpp - Signal Handling support --------------------*- C++ -*-===//
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

#include "llvh/Support/Signals.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Config/llvm-config.h"
#include "llvh/Support/ErrorOr.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/FileUtilities.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/ManagedStatic.h"
#include "llvh/Support/MemoryBuffer.h"
#include "llvh/Support/Mutex.h"
#include "llvh/Support/Program.h"
#include "llvh/Support/StringSaver.h"
#include "llvh/Support/raw_ostream.h"
#include "llvh/Support/Options.h"
#include <vector>

                                                                                
                                                                           
                                
                                                                                

using namespace llvh;

                                                                       
static bool DisableSymbolicationFlag = false;
#if 0
static cl::opt<bool, true>
    DisableSymbolication("disable-symbolication",
                         cl::desc("Disable symbolizing crash backtraces."),
                         cl::location(DisableSymbolicationFlag), cl::Hidden);
#endif

                                                                                
                                                                              
                                               
struct CallbackAndCookie {
  sys::SignalHandlerCallback Callback;
  void *Cookie;
  enum class Status { Empty, Initializing, Initialized, Executing };
  std::atomic<Status> Flag;
};
static constexpr size_t MaxSignalHandlerCallbacks = 8;
static CallbackAndCookie CallBacksToRun[MaxSignalHandlerCallbacks];

               
void sys::RunSignalHandlers() {
  for (size_t I = 0; I < MaxSignalHandlerCallbacks; ++I) {
    auto &RunMe = CallBacksToRun[I];
    auto Expected = CallbackAndCookie::Status::Initialized;
    auto Desired = CallbackAndCookie::Status::Executing;
    if (!RunMe.Flag.compare_exchange_strong(Expected, Desired))
      continue;
    (*RunMe.Callback)(RunMe.Cookie);
    RunMe.Callback = nullptr;
    RunMe.Cookie = nullptr;
    RunMe.Flag.store(CallbackAndCookie::Status::Empty);
  }
}

               
static void insertSignalHandler(sys::SignalHandlerCallback FnPtr,
                                void *Cookie) {
  for (size_t I = 0; I < MaxSignalHandlerCallbacks; ++I) {
    auto &SetMe = CallBacksToRun[I];
    auto Expected = CallbackAndCookie::Status::Empty;
    auto Desired = CallbackAndCookie::Status::Initializing;
    if (!SetMe.Flag.compare_exchange_strong(Expected, Desired))
      continue;
    SetMe.Callback = FnPtr;
    SetMe.Cookie = Cookie;
    SetMe.Flag.store(CallbackAndCookie::Status::Initialized);
    return;
  }
  report_fatal_error("too many signal callbacks already registered");
}

static bool findModulesAndOffsets(void **StackTrace, int Depth,
                                  const char **Modules, intptr_t *Offsets,
                                  const char *MainExecutableName,
                                  StringSaver &StrPool);

                                                                            
               
static FormattedNumber format_ptr(void *PC) {
                                                          
  unsigned PtrWidth = 2 + 2 * sizeof(void *);
  return format_hex((uint64_t)PC, PtrWidth);
}

                                                                    
[[maybe_unused]]
static bool printSymbolizedStackTrace(StringRef Argv0, void **StackTrace,
                                      int Depth, llvh::raw_ostream &OS) {
  if (DisableSymbolicationFlag)
    return false;

                                                         
  if (Argv0.find("llvm-symbolizer") != std::string::npos)
    return false;

                                                                                      
                                       
                                                                              
                                         
  ErrorOr<std::string> LLVMSymbolizerPathOrErr = std::error_code();
  if (!Argv0.empty()) {
    StringRef Parent = llvh::sys::path::parent_path(Argv0);
    if (!Parent.empty())
      LLVMSymbolizerPathOrErr = sys::findProgramByName("llvm-symbolizer", Parent);
  }
  if (!LLVMSymbolizerPathOrErr)
    LLVMSymbolizerPathOrErr = sys::findProgramByName("llvm-symbolizer");
  if (!LLVMSymbolizerPathOrErr)
    return false;
  const std::string &LLVMSymbolizerPath = *LLVMSymbolizerPathOrErr;

                                                                       
                                                          
  std::string MainExecutableName =
      Argv0.empty() ? sys::fs::getMainExecutable(nullptr, nullptr)
                    : (std::string)Argv0;
  BumpPtrAllocator Allocator;
  StringSaver StrPool(Allocator);
  std::vector<const char *> Modules(Depth, nullptr);
  std::vector<intptr_t> Offsets(Depth, 0);
  if (!findModulesAndOffsets(StackTrace, Depth, Modules.data(), Offsets.data(),
                             MainExecutableName.c_str(), StrPool))
    return false;
  int InputFD;
  SmallString<32> InputFile, OutputFile;
  sys::fs::createTemporaryFile("symbolizer-input", "", InputFD, InputFile);
  sys::fs::createTemporaryFile("symbolizer-output", "", OutputFile);
  FileRemover InputRemover(InputFile.c_str());
  FileRemover OutputRemover(OutputFile.c_str());

  {
    raw_fd_ostream Input(InputFD, true);
    for (int i = 0; i < Depth; i++) {
      if (Modules[i])
        Input << Modules[i] << " " << (void*)Offsets[i] << "\n";
    }
  }

  Optional<StringRef> Redirects[] = {StringRef(InputFile),
                                     StringRef(OutputFile), llvh::None};
  StringRef Args[] = {"llvm-symbolizer", "--functions=linkage", "--inlining",
#ifdef _WIN32
                                                                            
                                                            
                                                                          
                      "--relative-address",
#endif
                      "--demangle"};
  int RunResult =
      sys::ExecuteAndWait(LLVMSymbolizerPath, Args, None, Redirects);
  if (RunResult != 0)
    return false;

                                                                           
                                                    
  auto OutputBuf = MemoryBuffer::getFile(OutputFile.c_str());
  if (!OutputBuf)
    return false;
  StringRef Output = OutputBuf.get()->getBuffer();
  SmallVector<StringRef, 32> Lines;
  Output.split(Lines, "\n");
  auto CurLine = Lines.begin();
  int frame_no = 0;
  for (int i = 0; i < Depth; i++) {
    if (!Modules[i]) {
      OS << '#' << frame_no++ << ' ' << format_ptr(StackTrace[i]) << '\n';
      continue;
    }
                                                                      
                            
    for (;;) {
      if (CurLine == Lines.end())
        return false;
      StringRef FunctionName = *CurLine++;
      if (FunctionName.empty())
        break;
      OS << '#' << frame_no++ << ' ' << format_ptr(StackTrace[i]) << ' ';
      if (!FunctionName.startswith("??"))
        OS << FunctionName << ' ';
      if (CurLine == Lines.end())
        return false;
      StringRef FileLineInfo = *CurLine++;
      if (!FileLineInfo.startswith("??"))
        OS << FileLineInfo;
      else
        OS << "(" << Modules[i] << '+' << format_hex(Offsets[i], 0) << ")";
      OS << "\n";
    }
  }
  return true;
}

                                                     
#ifdef LLVM_ON_UNIX
#include "Unix/Signals.inc"
#endif
#ifdef _WIN32
#include "Windows/Signals.inc"
#endif
