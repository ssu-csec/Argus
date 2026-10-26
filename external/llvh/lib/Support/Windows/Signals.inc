//===- Win32/Signals.cpp - Win32 Signals Implementation ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Win32 specific implementation of the Signals class.
//
//===----------------------------------------------------------------------===//
#include "llvh/Support/ConvertUTF.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/Process.h"
#include "llvh/Support/WindowsError.h"
#include <algorithm>
#include <io.h>
#include <signal.h>
#include <stdio.h>

#include "llvh/Support/Format.h"
#include "llvh/Support/raw_ostream.h"

                                                                
#include "WindowsSupport.h"

#ifdef __MINGW32__
 #include <imagehlp.h>
#else
 #include <crtdbg.h>
 #include <dbghelp.h>
#endif
#include <psapi.h>

#ifdef _MSC_VER
 #pragma comment(lib, "psapi.lib")
#elif __MINGW32__
                                                                           
                                                                        
                                                                        
                                                                            
                                                                             
                                                                              
                                                                            
                                   
 #pragma GCC diagnostic ignored "-Wformat"
 #pragma GCC diagnostic ignored "-Wformat-extra-args"

 #if !defined(__MINGW64_VERSION_MAJOR)
                                                                          
                                                                            
                                                                             
                             
 typedef struct _IMAGEHLP_LINE64 {
   DWORD    SizeOfStruct;
   PVOID    Key;
   DWORD    LineNumber;
   PCHAR    FileName;
   DWORD64  Address;
 } IMAGEHLP_LINE64, *PIMAGEHLP_LINE64;

 typedef struct _IMAGEHLP_SYMBOL64 {
   DWORD   SizeOfStruct;
   DWORD64 Address;
   DWORD   Size;
   DWORD   Flags;
   DWORD   MaxNameLength;
   CHAR    Name[1];
 } IMAGEHLP_SYMBOL64, *PIMAGEHLP_SYMBOL64;

 typedef struct _tagADDRESS64 {
   DWORD64       Offset;
   WORD          Segment;
   ADDRESS_MODE  Mode;
 } ADDRESS64, *LPADDRESS64;

 typedef struct _KDHELP64 {
   DWORD64   Thread;
   DWORD   ThCallbackStack;
   DWORD   ThCallbackBStore;
   DWORD   NextCallback;
   DWORD   FramePointer;
   DWORD64   KiCallUserMode;
   DWORD64   KeUserCallbackDispatcher;
   DWORD64   SystemRangeStart;
   DWORD64   KiUserExceptionDispatcher;
   DWORD64   StackBase;
   DWORD64   StackLimit;
   DWORD64   Reserved[5];
 } KDHELP64, *PKDHELP64;

 typedef struct _tagSTACKFRAME64 {
   ADDRESS64   AddrPC;
   ADDRESS64   AddrReturn;
   ADDRESS64   AddrFrame;
   ADDRESS64   AddrStack;
   ADDRESS64   AddrBStore;
   PVOID       FuncTableEntry;
   DWORD64     Params[4];
   BOOL        Far;
   BOOL        Virtual;
   DWORD64     Reserved[3];
   KDHELP64    KdHelp;
 } STACKFRAME64, *LPSTACKFRAME64;
 #endif                                     
#endif               

typedef BOOL (__stdcall *PREAD_PROCESS_MEMORY_ROUTINE64)(HANDLE hProcess,
                      DWORD64 qwBaseAddress, PVOID lpBuffer, DWORD nSize,
                      LPDWORD lpNumberOfBytesRead);

typedef PVOID (__stdcall *PFUNCTION_TABLE_ACCESS_ROUTINE64)( HANDLE ahProcess,
                      DWORD64 AddrBase);

typedef DWORD64 (__stdcall *PGET_MODULE_BASE_ROUTINE64)(HANDLE hProcess,
                      DWORD64 Address);

typedef DWORD64 (__stdcall *PTRANSLATE_ADDRESS_ROUTINE64)(HANDLE hProcess,
                      HANDLE hThread, LPADDRESS64 lpaddr);

typedef BOOL(WINAPI *fpMiniDumpWriteDump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                                          PMINIDUMP_EXCEPTION_INFORMATION,
                                          PMINIDUMP_USER_STREAM_INFORMATION,
                                          PMINIDUMP_CALLBACK_INFORMATION);
static fpMiniDumpWriteDump fMiniDumpWriteDump;

typedef BOOL (WINAPI *fpStackWalk64)(DWORD, HANDLE, HANDLE, LPSTACKFRAME64,
                      PVOID, PREAD_PROCESS_MEMORY_ROUTINE64,
                      PFUNCTION_TABLE_ACCESS_ROUTINE64,
                      PGET_MODULE_BASE_ROUTINE64,
                      PTRANSLATE_ADDRESS_ROUTINE64);
static fpStackWalk64 fStackWalk64;

typedef DWORD64 (WINAPI *fpSymGetModuleBase64)(HANDLE, DWORD64);
static fpSymGetModuleBase64 fSymGetModuleBase64;

typedef BOOL (WINAPI *fpSymGetSymFromAddr64)(HANDLE, DWORD64,
                      PDWORD64, PIMAGEHLP_SYMBOL64);
static fpSymGetSymFromAddr64 fSymGetSymFromAddr64;

typedef BOOL (WINAPI *fpSymGetLineFromAddr64)(HANDLE, DWORD64,
                      PDWORD, PIMAGEHLP_LINE64);
static fpSymGetLineFromAddr64 fSymGetLineFromAddr64;

typedef BOOL(WINAPI *fpSymGetModuleInfo64)(HANDLE hProcess, DWORD64 dwAddr,
                                           PIMAGEHLP_MODULE64 ModuleInfo);
static fpSymGetModuleInfo64 fSymGetModuleInfo64;

typedef PVOID (WINAPI *fpSymFunctionTableAccess64)(HANDLE, DWORD64);
static fpSymFunctionTableAccess64 fSymFunctionTableAccess64;

typedef DWORD (WINAPI *fpSymSetOptions)(DWORD);
static fpSymSetOptions fSymSetOptions;

typedef BOOL (WINAPI *fpSymInitialize)(HANDLE, PCSTR, BOOL);
static fpSymInitialize fSymInitialize;

typedef BOOL (WINAPI *fpEnumerateLoadedModules)(HANDLE,PENUMLOADED_MODULES_CALLBACK64,PVOID);
static fpEnumerateLoadedModules fEnumerateLoadedModules;

static bool load64BitDebugHelp(void) {
  HMODULE hLib = ::LoadLibraryW(L"Dbghelp.dll");
  if (hLib) {
    fMiniDumpWriteDump = (fpMiniDumpWriteDump)
                      ::GetProcAddress(hLib, "MiniDumpWriteDump");
    fStackWalk64 = (fpStackWalk64)
                      ::GetProcAddress(hLib, "StackWalk64");
    fSymGetModuleBase64 = (fpSymGetModuleBase64)
                      ::GetProcAddress(hLib, "SymGetModuleBase64");
    fSymGetSymFromAddr64 = (fpSymGetSymFromAddr64)
                      ::GetProcAddress(hLib, "SymGetSymFromAddr64");
    fSymGetLineFromAddr64 = (fpSymGetLineFromAddr64)
                      ::GetProcAddress(hLib, "SymGetLineFromAddr64");
    fSymGetModuleInfo64 = (fpSymGetModuleInfo64)
                      ::GetProcAddress(hLib, "SymGetModuleInfo64");
    fSymFunctionTableAccess64 = (fpSymFunctionTableAccess64)
                     ::GetProcAddress(hLib, "SymFunctionTableAccess64");
    fSymSetOptions = (fpSymSetOptions)::GetProcAddress(hLib, "SymSetOptions");
    fSymInitialize = (fpSymInitialize)::GetProcAddress(hLib, "SymInitialize");
    fEnumerateLoadedModules = (fpEnumerateLoadedModules)
      ::GetProcAddress(hLib, "EnumerateLoadedModules64");
  }
  return fStackWalk64 && fSymInitialize && fSymSetOptions && fMiniDumpWriteDump;
}

using namespace llvh;

                   
static LONG WINAPI LLVMUnhandledExceptionFilter(LPEXCEPTION_POINTERS ep);
static BOOL WINAPI LLVMConsoleCtrlHandler(DWORD dwCtrlType);

                                             
static void (*InterruptFunction)() = 0;

static std::vector<std::string> *FilesToRemove = NULL;
static bool RegisteredUnhandledExceptionFilter = false;
static bool CleanupExecuted = false;
static PTOP_LEVEL_EXCEPTION_FILTER OldFilter = NULL;

                                                                            
                                                                          
                                                 
static CRITICAL_SECTION CriticalSection;
static bool CriticalSectionInitialized = false;

static StringRef Argv0;

enum {
#if defined(_M_X64)
  NativeMachineType = IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_ARM64)
  NativeMachineType = IMAGE_FILE_MACHINE_ARM64
#elif defined(_M_IX86)
  NativeMachineType = IMAGE_FILE_MACHINE_I386
#elif defined(_M_ARM)
  NativeMachineType = IMAGE_FILE_MACHINE_ARMNT
#else
  NativeMachineType = IMAGE_FILE_MACHINE_UNKNOWN
#endif
};

static bool printStackTraceWithLLVMSymbolizer(llvh::raw_ostream &OS,
                                              HANDLE hProcess, HANDLE hThread,
                                              STACKFRAME64 &StackFrameOrig,
                                              CONTEXT *ContextOrig) {
                                                                             
  STACKFRAME64 StackFrame = StackFrameOrig;

                                                                             
                                                                               
                                                                               
                                                 
  CONTEXT Context = *ContextOrig;
  Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

  static void *StackTrace[256];
  size_t Depth = 0;
  while (fStackWalk64(NativeMachineType, hProcess, hThread, &StackFrame,
                      &Context, 0, fSymFunctionTableAccess64,
                      fSymGetModuleBase64, 0)) {
    if (StackFrame.AddrFrame.Offset == 0)
      break;
    StackTrace[Depth++] = (void *)(uintptr_t)StackFrame.AddrPC.Offset;
    if (Depth >= array_lengthof(StackTrace))
      break;
  }

  return printSymbolizedStackTrace(Argv0, &StackTrace[0], Depth, OS);
}

namespace {
struct FindModuleData {
  void **StackTrace;
  int Depth;
  const char **Modules;
  intptr_t *Offsets;
  StringSaver *StrPool;
};
}

static BOOL CALLBACK findModuleCallback(PCSTR ModuleName,
                                        DWORD64 ModuleBase, ULONG ModuleSize,
                                        void *VoidData) {
  FindModuleData *Data = (FindModuleData*)VoidData;
  intptr_t Beg = ModuleBase;
  intptr_t End = Beg + ModuleSize;
  for (int I = 0; I < Data->Depth; I++) {
    if (Data->Modules[I])
      continue;
    intptr_t Addr = (intptr_t)Data->StackTrace[I];
    if (Beg <= Addr && Addr < End) {
      Data->Modules[I] = Data->StrPool->save(ModuleName).data();
      Data->Offsets[I] = Addr - Beg;
    }
  }
  return TRUE;
}

static bool findModulesAndOffsets(void **StackTrace, int Depth,
                                  const char **Modules, intptr_t *Offsets,
                                  const char *MainExecutableName,
                                  StringSaver &StrPool) {
  if (!fEnumerateLoadedModules)
    return false;
  FindModuleData Data;
  Data.StackTrace = StackTrace;
  Data.Depth = Depth;
  Data.Modules = Modules;
  Data.Offsets = Offsets;
  Data.StrPool = &StrPool;
  fEnumerateLoadedModules(GetCurrentProcess(), findModuleCallback, &Data);
  return true;
}

static void PrintStackTraceForThread(llvh::raw_ostream &OS, HANDLE hProcess,
                                     HANDLE hThread, STACKFRAME64 &StackFrame,
                                     CONTEXT *Context) {
                                   
  fSymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
  fSymInitialize(hProcess, NULL, TRUE);

                                                                                
                                                                           
                      
  if (printStackTraceWithLLVMSymbolizer(OS, hProcess, hThread, StackFrame,
                                        Context)) {
    return;
  }

  while (true) {
    if (!fStackWalk64(NativeMachineType, hProcess, hThread, &StackFrame,
                      Context, 0, fSymFunctionTableAccess64,
                      fSymGetModuleBase64, 0)) {
      break;
    }

    if (StackFrame.AddrFrame.Offset == 0)
      break;

    using namespace llvh;
                                   
    DWORD64 PC = StackFrame.AddrPC.Offset;
#if defined(_M_X64) || defined(_M_ARM64)
    OS << format("0x%016llX", PC);
#elif defined(_M_IX86) || defined(_M_ARM)
    OS << format("0x%08lX", static_cast<DWORD>(PC));
#endif

                                                
#if defined(_M_X64) || defined(_M_ARM64)
    OS << format(" (0x%016llX 0x%016llX 0x%016llX 0x%016llX)",
            StackFrame.Params[0], StackFrame.Params[1], StackFrame.Params[2],
            StackFrame.Params[3]);
#elif defined(_M_IX86) || defined(_M_ARM)
    OS << format(" (0x%08lX 0x%08lX 0x%08lX 0x%08lX)",
            static_cast<DWORD>(StackFrame.Params[0]),
            static_cast<DWORD>(StackFrame.Params[1]),
            static_cast<DWORD>(StackFrame.Params[2]),
            static_cast<DWORD>(StackFrame.Params[3]));
#endif
                                                         
    if (!fSymGetModuleBase64(hProcess, PC)) {
      OS << " <unknown module>\n";
      continue;
    }

                             
    char buffer[512];
    IMAGEHLP_SYMBOL64 *symbol = reinterpret_cast<IMAGEHLP_SYMBOL64 *>(buffer);
    memset(symbol, 0, sizeof(IMAGEHLP_SYMBOL64));
    symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    symbol->MaxNameLength = 512 - sizeof(IMAGEHLP_SYMBOL64);

    DWORD64 dwDisp;
    if (!fSymGetSymFromAddr64(hProcess, PC, &dwDisp, symbol)) {
      OS << '\n';
      continue;
    }

    buffer[511] = 0;
    if (dwDisp > 0)
      OS << format(", %s() + 0x%llX bytes(s)", (const char*)symbol->Name,
                   dwDisp);
    else
      OS << format(", %s", (const char*)symbol->Name);

                                                         
    IMAGEHLP_LINE64 line = {};
    DWORD dwLineDisp;
    line.SizeOfStruct = sizeof(line);
    if (fSymGetLineFromAddr64(hProcess, PC, &dwLineDisp, &line)) {
      OS << format(", %s, line %lu", line.FileName, line.LineNumber);
      if (dwLineDisp > 0)
        OS << format(" + 0x%lX byte(s)", dwLineDisp);
    }

    OS << '\n';
  }
}

namespace llvh {

                                                                                
                                                                        
                                        
                                                                                

#ifdef _MSC_VER
                                                                            
                                                                           
           
static LLVM_ATTRIBUTE_UNUSED int
AvoidMessageBoxHook(int ReportType, char *Message, int *Return) {
                                                                         
                                                                   
                                                                   
  if (Return)
    *Return = 1;
                              
  return TRUE;
}

#endif

extern "C" void HandleAbort(int Sig) {
  if (Sig == SIGABRT) {
    LLVM_BUILTIN_TRAP;
  }
}

static void InitializeThreading() {
  if (CriticalSectionInitialized)
    return;

                                                                          
                                               
  InitializeCriticalSection(&CriticalSection);
  CriticalSectionInitialized = true;
}

static void RegisterHandler() {
                                                                            
                                                                          
                                      
  if (!load64BitDebugHelp()) {
    assert(false && "These APIs should always be available");
    return;
  }

  if (RegisteredUnhandledExceptionFilter) {
    EnterCriticalSection(&CriticalSection);
    return;
  }

  InitializeThreading();

                                                                           
                                                 
  EnterCriticalSection(&CriticalSection);

  RegisteredUnhandledExceptionFilter = true;
  OldFilter = SetUnhandledExceptionFilter(LLVMUnhandledExceptionFilter);
  SetConsoleCtrlHandler(LLVMConsoleCtrlHandler, TRUE);

                                                                               
                                              
}

                 
bool sys::RemoveFileOnSignal(StringRef Filename, std::string* ErrMsg) {
  RegisterHandler();

  if (CleanupExecuted) {
    if (ErrMsg)
      *ErrMsg = "Process terminating -- cannot register for removal";
    return true;
  }

  if (FilesToRemove == NULL)
    FilesToRemove = new std::vector<std::string>;

  FilesToRemove->push_back(Filename);

  LeaveCriticalSection(&CriticalSection);
  return false;
}

                 
void sys::DontRemoveFileOnSignal(StringRef Filename) {
  if (FilesToRemove == NULL)
    return;

  RegisterHandler();

  std::vector<std::string>::reverse_iterator I =
      find(reverse(*FilesToRemove), Filename);
  if (I != FilesToRemove->rend())
    FilesToRemove->erase(I.base()-1);

  LeaveCriticalSection(&CriticalSection);
}

void sys::DisableSystemDialogsOnCrash() {
                                           
  signal(SIGABRT, HandleAbort);

                                                                  
#ifdef _MSC_VER
                                                                     
  _set_abort_behavior(0, _WRITE_ABORT_MSG);
                        
  _set_abort_behavior(0, _CALL_REPORTFAULT);
  _CrtSetReportHook(AvoidMessageBoxHook);
#endif

                                       
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
               SEM_NOOPENFILEERRORBOX);
  _set_error_mode(_OUT_TO_STDERR);
}

                                                                         
                                               
void sys::PrintStackTraceOnErrorSignal(StringRef Argv0,
                                       bool DisableCrashReporting) {
  ::Argv0 = Argv0;

  if (DisableCrashReporting || getenv("LLVM_DISABLE_CRASH_REPORT"))
    Process::PreventCoreFiles();

  DisableSystemDialogsOnCrash();
  RegisterHandler();
  LeaveCriticalSection(&CriticalSection);
}
}

#if defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)
                                                                       
                                   
extern "C" VOID WINAPI RtlCaptureContext(PCONTEXT ContextRecord);
#endif

void llvh::sys::PrintStackTrace(raw_ostream &OS) {
  STACKFRAME64 StackFrame = {};
  CONTEXT Context = {};
  ::RtlCaptureContext(&Context);
#if defined(_M_X64)
  StackFrame.AddrPC.Offset = Context.Rip;
  StackFrame.AddrStack.Offset = Context.Rsp;
  StackFrame.AddrFrame.Offset = Context.Rbp;
#elif defined(_M_IX86)
  StackFrame.AddrPC.Offset = Context.Eip;
  StackFrame.AddrStack.Offset = Context.Esp;
  StackFrame.AddrFrame.Offset = Context.Ebp;
#elif defined(_M_ARM64)
  StackFrame.AddrPC.Offset = Context.Pc;
  StackFrame.AddrStack.Offset = Context.Sp;
  StackFrame.AddrFrame.Offset = Context.Fp;
#elif defined(_M_ARM)
  StackFrame.AddrPC.Offset = Context.Pc;
  StackFrame.AddrStack.Offset = Context.Sp;
  StackFrame.AddrFrame.Offset = Context.R11;
#endif
  StackFrame.AddrPC.Mode = AddrModeFlat;
  StackFrame.AddrStack.Mode = AddrModeFlat;
  StackFrame.AddrFrame.Mode = AddrModeFlat;
  PrintStackTraceForThread(OS, GetCurrentProcess(), GetCurrentThread(),
                           StackFrame, &Context);
}


void llvh::sys::SetInterruptFunction(void (*IF)()) {
  RegisterHandler();
  InterruptFunction = IF;
  LeaveCriticalSection(&CriticalSection);
}


                                                                              
                                                                           
                  
void llvh::sys::AddSignalHandler(sys::SignalHandlerCallback FnPtr,
                                 void *Cookie) {
  insertSignalHandler(FnPtr, Cookie);
  RegisterHandler();
  LeaveCriticalSection(&CriticalSection);
}

static void Cleanup() {
  if (CleanupExecuted)
    return;

  EnterCriticalSection(&CriticalSection);

                                                                        
                                                                             
  CleanupExecuted = true;

                                         
  if (FilesToRemove != NULL)
    while (!FilesToRemove->empty()) {
      llvh::sys::fs::remove(FilesToRemove->back());
      FilesToRemove->pop_back();
    }
  llvh::sys::RunSignalHandlers();
  LeaveCriticalSection(&CriticalSection);
}

void llvh::sys::RunInterruptHandlers() {
                                                                              
                                                                               
                                                                         
                 
  InitializeThreading();
  Cleanup();
}

                                                       
   
                                                            
static HKEY FindWERKey(const llvh::Twine &RegistryLocation) {
  HKEY Key;
  if (ERROR_SUCCESS != ::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                       RegistryLocation.str().c_str(), 0,
                                       KEY_QUERY_VALUE | KEY_READ, &Key))
    return NULL;

  return Key;
}

                                                                        
                         
   
                                                                          
static bool GetDumpFolder(HKEY Key,
                          llvh::SmallVectorImpl<char> &ResultDirectory) {
  using llvh::sys::windows::UTF16ToUTF8;

  if (!Key)
    return false;

  DWORD BufferLengthBytes = 0;

  if (ERROR_SUCCESS != ::RegGetValueW(Key, 0, L"DumpFolder", REG_EXPAND_SZ,
                                      NULL, NULL, &BufferLengthBytes))
    return false;

  SmallVector<wchar_t, MAX_PATH> Buffer(BufferLengthBytes);

  if (ERROR_SUCCESS != ::RegGetValueW(Key, 0, L"DumpFolder", REG_EXPAND_SZ,
                                      NULL, Buffer.data(), &BufferLengthBytes))
    return false;

  DWORD ExpandBufferSize = ::ExpandEnvironmentStringsW(Buffer.data(), NULL, 0);

  if (!ExpandBufferSize)
    return false;

  SmallVector<wchar_t, MAX_PATH> ExpandBuffer(ExpandBufferSize);

  if (ExpandBufferSize != ::ExpandEnvironmentStringsW(Buffer.data(),
                                                      ExpandBuffer.data(),
                                                      ExpandBufferSize))
    return false;

  if (UTF16ToUTF8(ExpandBuffer.data(), ExpandBufferSize - 1, ResultDirectory))
    return false;

  return true;
}

                                                                        
                                                
   
                
                                                                                   
                                  
                      
                    
                    
                                                                          
                                                             
   
                                                                              
static bool GetDumpType(HKEY Key, MINIDUMP_TYPE &ResultType) {
  if (!Key)
    return false;

  DWORD DumpType;
  DWORD TypeSize = sizeof(DumpType);
  if (ERROR_SUCCESS != ::RegGetValueW(Key, NULL, L"DumpType", RRF_RT_REG_DWORD,
                                      NULL, &DumpType,
                                      &TypeSize))
    return false;

  switch (DumpType) {
  case 0: {
    DWORD Flags = 0;
    if (ERROR_SUCCESS != ::RegGetValueW(Key, NULL, L"CustomDumpFlags",
                                        RRF_RT_REG_DWORD, NULL, &Flags,
                                        &TypeSize))
      return false;

    ResultType = static_cast<MINIDUMP_TYPE>(Flags);
    break;
  }
  case 1:
    ResultType = MiniDumpNormal;
    break;
  case 2:
    ResultType = MiniDumpWithFullMemory;
    break;
  default:
    return false;
  }
  return true;
}

                                                                        
                                   
   
                                                                      
              
static std::error_code WINAPI
WriteWindowsDumpFile(PMINIDUMP_EXCEPTION_INFORMATION ExceptionInfo) {
  using namespace llvh;
  using namespace llvh::sys;

  std::string MainExecutableName = fs::getMainExecutable(nullptr, nullptr);
  StringRef ProgramName;

  if (MainExecutableName.empty()) {
                                               
                                                
                                   
    return mapWindowsError(::GetLastError());
  }

  ProgramName = path::filename(MainExecutableName.c_str());

                                                  
                                                                                        
                                                                             
                                   
  StringRef LocalDumpsRegistryLocation =
      "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";

                                                                            
                                                                        
  ScopedRegHandle DefaultLocalDumpsKey(FindWERKey(LocalDumpsRegistryLocation));

                                                               
                                                                        
                               
  ScopedRegHandle AppSpecificKey(
      FindWERKey(Twine(LocalDumpsRegistryLocation) + "\\" + ProgramName));

                                                                            
                                                                              
                                                                              
                                                                     
  MINIDUMP_TYPE DumpType;
  if (!GetDumpType(AppSpecificKey, DumpType))
    if (!GetDumpType(DefaultLocalDumpsKey, DumpType))
      DumpType = MiniDumpNormal;

                                                                                
                                                                              
                                                                           
                                                                              
                                                
  bool ExplicitDumpDirectorySet = true;
  SmallString<MAX_PATH> DumpDirectory;
  if (!GetDumpFolder(AppSpecificKey, DumpDirectory))
    if (!GetDumpFolder(DefaultLocalDumpsKey, DumpDirectory))
      ExplicitDumpDirectorySet = false;

  int FD;
  SmallString<MAX_PATH> DumpPath;

  if (ExplicitDumpDirectorySet) {
    if (std::error_code EC = fs::create_directories(DumpDirectory))
      return EC;
    if (std::error_code EC = fs::createUniqueFile(
            Twine(DumpDirectory) + "\\" + ProgramName + ".%%%%%%.dmp", FD,
            DumpPath))
      return EC;
  } else if (std::error_code EC =
                 fs::createTemporaryFile(ProgramName, "dmp", FD, DumpPath))
    return EC;

                                                                               
  ScopedCommonHandle FileHandle(reinterpret_cast<HANDLE>(_get_osfhandle(FD)));

  if (!fMiniDumpWriteDump(::GetCurrentProcess(), ::GetCurrentProcessId(),
                          FileHandle, DumpType, ExceptionInfo, NULL, NULL))
    return mapWindowsError(::GetLastError());

  llvh::errs() << "Wrote crash dump file \"" << DumpPath << "\"\n";
  return std::error_code();
}

static LONG WINAPI LLVMUnhandledExceptionFilter(LPEXCEPTION_POINTERS ep) {
  Cleanup();

                                                                    
                                                                           
                                                                              
                        
  if (!llvh::sys::Process::AreCoreFilesPrevented()) {
    MINIDUMP_EXCEPTION_INFORMATION ExceptionInfo;
    ExceptionInfo.ThreadId = ::GetCurrentThreadId();
    ExceptionInfo.ExceptionPointers = ep;
    ExceptionInfo.ClientPointers = FALSE;

    if (std::error_code EC = WriteWindowsDumpFile(&ExceptionInfo))
      llvh::errs() << "Could not write crash dump file: " << EC.message()
                   << "\n";
  }

                                         
  STACKFRAME64 StackFrame = {};

#if defined(_M_X64)
  StackFrame.AddrPC.Offset = ep->ContextRecord->Rip;
  StackFrame.AddrPC.Mode = AddrModeFlat;
  StackFrame.AddrStack.Offset = ep->ContextRecord->Rsp;
  StackFrame.AddrStack.Mode = AddrModeFlat;
  StackFrame.AddrFrame.Offset = ep->ContextRecord->Rbp;
  StackFrame.AddrFrame.Mode = AddrModeFlat;
#elif defined(_M_IX86)
  StackFrame.AddrPC.Offset = ep->ContextRecord->Eip;
  StackFrame.AddrPC.Mode = AddrModeFlat;
  StackFrame.AddrStack.Offset = ep->ContextRecord->Esp;
  StackFrame.AddrStack.Mode = AddrModeFlat;
  StackFrame.AddrFrame.Offset = ep->ContextRecord->Ebp;
  StackFrame.AddrFrame.Mode = AddrModeFlat;
#elif defined(_M_ARM64) || defined(_M_ARM)
  StackFrame.AddrPC.Offset = ep->ContextRecord->Pc;
  StackFrame.AddrPC.Mode = AddrModeFlat;
  StackFrame.AddrStack.Offset = ep->ContextRecord->Sp;
  StackFrame.AddrStack.Mode = AddrModeFlat;
#if defined(_M_ARM64)
  StackFrame.AddrFrame.Offset = ep->ContextRecord->Fp;
#else
  StackFrame.AddrFrame.Offset = ep->ContextRecord->R11;
#endif
  StackFrame.AddrFrame.Mode = AddrModeFlat;
#endif

  HANDLE hProcess = GetCurrentProcess();
  HANDLE hThread = GetCurrentThread();
  PrintStackTraceForThread(llvh::errs(), hProcess, hThread, StackFrame,
                           ep->ContextRecord);

  _exit(ep->ExceptionRecord->ExceptionCode);
}

static BOOL WINAPI LLVMConsoleCtrlHandler(DWORD dwCtrlType) {
                                                                
  EnterCriticalSection(&CriticalSection);
  Cleanup();

                                                                         
                      
  void (*IF)() = InterruptFunction;
  InterruptFunction = 0;                                        

  if (IF) {
                                                                            
                                                              
    IF();                                   
    LeaveCriticalSection(&CriticalSection);
    return TRUE;                                        
  }

                                                                   
  LeaveCriticalSection(&CriticalSection);
  return FALSE;
}

#if __MINGW32__
                                                                        
                                                                         
                                                                           
                            
 #pragma GCC diagnostic warning "-Wformat"
 #pragma GCC diagnostic warning "-Wformat-extra-args"
#endif
