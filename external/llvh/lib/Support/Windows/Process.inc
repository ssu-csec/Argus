//===- Win32/Process.cpp - Win32 Process Implementation ------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Win32 specific implementation of the Process class.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/Allocator.h"
#include "llvh/Support/CommandLine.h"
#include "llvh/Support/ConvertUTF.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/StringSaver.h"
#include "llvh/Support/WindowsError.h"
#include <malloc.h>

                                                                
#include "WindowsSupport.h"

#include <direct.h>
#include <io.h>
#include <psapi.h>
#include <shellapi.h>

#if !defined(__MINGW32__)
 #pragma comment(lib, "psapi.lib")
 #pragma comment(lib, "shell32.lib")
#endif

                                                                                
                                                                        
                                        
                                                                                

#ifdef __MINGW32__
                                                                    
#  define _HEAPOK (-2)
#endif

using namespace llvh;

                                                                           
                                                                                
         
static unsigned computePageSize() {
                                                                           
                                                                     
  SYSTEM_INFO info;
  GetNativeSystemInfo(&info);
                                                                              
                                 
  return static_cast<unsigned>(info.dwPageSize);
}

unsigned Process::getPageSize() {
  static unsigned Ret = computePageSize();
  return Ret;
}

size_t
Process::GetMallocUsage()
{
  _HEAPINFO hinfo;
  hinfo._pentry = NULL;

  size_t size = 0;

  while (_heapwalk(&hinfo) == _HEAPOK)
    size += hinfo._size;

  return size;
}

void Process::GetTimeUsage(TimePoint<> &elapsed, std::chrono::nanoseconds &user_time,
                           std::chrono::nanoseconds &sys_time) {
  elapsed = std::chrono::system_clock::now();;

  FILETIME ProcCreate, ProcExit, KernelTime, UserTime;
  if (GetProcessTimes(GetCurrentProcess(), &ProcCreate, &ProcExit, &KernelTime,
                      &UserTime) == 0)
    return;

  user_time = toDuration(UserTime);
  sys_time = toDuration(KernelTime);
}

                                                                             
                                                                           
                                                          
void Process::PreventCoreFiles() {
                                                                             
                                                                               
                                                                       
                                                                          
                                                                            
                                                                          
            
    
                                                                            
                                                                  
  SetErrorMode(SEM_FAILCRITICALERRORS |
               SEM_NOGPFAULTERRORBOX |
               SEM_NOOPENFILEERRORBOX);

  coreFilesPrevented = true;
}

                                                                             
                                                        
Optional<std::string> Process::GetEnv(StringRef Name) {
                                                             
  SmallVector<wchar_t, 128> NameUTF16;
  if (windows::UTF8ToUTF16(Name, NameUTF16))
    return None;

                                                                             
                                                                       
                                                                        
  SmallVector<wchar_t, MAX_PATH> Buf;
  size_t Size = MAX_PATH;
  do {
    Buf.reserve(Size);
    SetLastError(NO_ERROR);
    Size =
      GetEnvironmentVariableW(NameUTF16.data(), Buf.data(), Buf.capacity());
    if (Size == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND)
      return None;

                                    
  } while (Size > Buf.capacity());
  Buf.set_size(Size);

                                             
  SmallVector<char, MAX_PATH> Res;
  if (windows::UTF16ToUTF8(Buf.data(), Size, Res))
    return None;
  return std::string(Res.data());
}

                                                                              
                                              
static std::error_code WildcardExpand(StringRef Arg,
                                      SmallVectorImpl<const char *> &Args,
                                      StringSaver &Saver) {
  std::error_code EC;

                                                                             
                                                                          
            
  if (Arg.find_first_of("*?") == StringRef::npos || Arg == "/?" ||
      Arg == "-?") {
    Args.push_back(Arg.data());
    return EC;
  }

                                                          
  SmallVector<wchar_t, MAX_PATH> ArgW;
  EC = windows::UTF8ToUTF16(Arg, ArgW);
  if (EC)
    return EC;

                               
                                                                              
                                                                        
                                 
  WIN32_FIND_DATAW FileData;
  HANDLE FindHandle = FindFirstFileW(ArgW.data(), &FileData);
  if (FindHandle == INVALID_HANDLE_VALUE) {
    Args.push_back(Arg.data());
    return EC;
  }

                                                
  SmallString<MAX_PATH> Dir = Arg;
  sys::path::remove_filename(Dir);
  const int DirSize = Dir.size();

  do {
    SmallString<MAX_PATH> FileName;
    EC = windows::UTF16ToUTF8(FileData.cFileName, wcslen(FileData.cFileName),
                              FileName);
    if (EC)
      break;

                                                        
    llvh::sys::path::append(Dir, FileName);
    Args.push_back(Saver.save(StringRef(Dir)).data());
    Dir.resize(DirSize);
  } while (FindNextFileW(FindHandle, &FileData));

  FindClose(FindHandle);
  return EC;
}

static std::error_code GetExecutableName(SmallVectorImpl<char> &Filename) {
                                                                          
                                                                       
  wchar_t ModuleName[MAX_PATH];
  size_t Length = ::GetModuleFileNameW(NULL, ModuleName, MAX_PATH);
  if (Length == 0 || Length == MAX_PATH) {
    return mapWindowsError(GetLastError());
  }

                                                                            
                                                                               
                                                        
  Length = GetLongPathNameW(ModuleName, ModuleName, MAX_PATH);
  if (Length == 0)
    return mapWindowsError(GetLastError());
  if (Length > MAX_PATH) {
                                                                               
                                                                           
                                                                  
    return mapWindowsError(ERROR_INSUFFICIENT_BUFFER);
  }

  std::error_code EC = windows::UTF16ToUTF8(ModuleName, Length, Filename);
  if (EC)
    return EC;

  StringRef Base = sys::path::filename(Filename.data());
  Filename.assign(Base.begin(), Base.end());
  return std::error_code();
}

std::error_code
windows::GetCommandLineArguments(SmallVectorImpl<const char *> &Args,
                                 BumpPtrAllocator &Alloc) {
  const wchar_t *CmdW = GetCommandLineW();
  assert(CmdW);
  std::error_code EC;
  SmallString<MAX_PATH> Cmd;
  EC = windows::UTF16ToUTF8(CmdW, wcslen(CmdW), Cmd);
  if (EC)
    return EC;

  SmallVector<const char *, 20> TmpArgs;
  StringSaver Saver(Alloc);
  cl::TokenizeWindowsCommandLine(Cmd, Saver, TmpArgs,              false);

  for (const char *Arg : TmpArgs) {
    EC = WildcardExpand(Arg, Args, Saver);
    if (EC)
      return EC;
  }

  SmallVector<char, MAX_PATH> Arg0(Args[0], Args[0] + strlen(Args[0]));
  SmallVector<char, MAX_PATH> Filename;
  sys::path::remove_filename(Arg0);
  EC = GetExecutableName(Filename);
  if (EC)
    return EC;
  sys::path::append(Arg0, Filename);
  Args[0] = Saver.save(Arg0).data();
  return std::error_code();
}

std::error_code Process::FixupStandardFileDescriptors() {
  return std::error_code();
}

std::error_code Process::SafelyCloseFileDescriptor(int FD) {
  if (::close(FD) < 0)
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

bool Process::StandardInIsUserInput() {
  return FileDescriptorIsDisplayed(0);
}

bool Process::StandardOutIsDisplayed() {
  return FileDescriptorIsDisplayed(1);
}

bool Process::StandardErrIsDisplayed() {
  return FileDescriptorIsDisplayed(2);
}

bool Process::FileDescriptorIsDisplayed(int fd) {
  DWORD Mode;           
  return (GetConsoleMode((HANDLE)_get_osfhandle(fd), &Mode) != 0);
}

unsigned Process::StandardOutColumns() {
  unsigned Columns = 0;
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
    Columns = csbi.dwSize.X;
  return Columns;
}

unsigned Process::StandardErrColumns() {
  unsigned Columns = 0;
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  if (GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &csbi))
    Columns = csbi.dwSize.X;
  return Columns;
}

                                  
bool Process::FileDescriptorHasColors(int fd) {
  return FileDescriptorIsDisplayed(fd);
}

bool Process::StandardOutHasColors() {
  return FileDescriptorHasColors(1);
}

bool Process::StandardErrHasColors() {
  return FileDescriptorHasColors(2);
}

static bool UseANSI = false;
void Process::UseANSIEscapeCodes(bool enable) {
#if defined(ENABLE_VIRTUAL_TERMINAL_PROCESSING)
  if (enable) {
    HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD Mode;
    GetConsoleMode(Console, &Mode);
    Mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(Console, Mode);
  }
#endif
  UseANSI = enable;
}

namespace {
class DefaultColors
{
  private:
    WORD defaultColor;
  public:
    DefaultColors()
     :defaultColor(GetCurrentColor()) {}
    static unsigned GetCurrentColor() {
      CONSOLE_SCREEN_BUFFER_INFO csbi;
      if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
        return csbi.wAttributes;
      return 0;
    }
    WORD operator()() const { return defaultColor; }
};

DefaultColors defaultColors;

WORD fg_color(WORD color) {
  return color & (FOREGROUND_BLUE | FOREGROUND_GREEN |
                  FOREGROUND_INTENSITY | FOREGROUND_RED);
}

WORD bg_color(WORD color) {
  return color & (BACKGROUND_BLUE | BACKGROUND_GREEN |
                  BACKGROUND_INTENSITY | BACKGROUND_RED);
}
}

bool Process::ColorNeedsFlush() {
  return !UseANSI;
}

const char *Process::OutputBold(bool bg) {
  if (UseANSI) return "\033[1m";

  WORD colors = DefaultColors::GetCurrentColor();
  if (bg)
    colors |= BACKGROUND_INTENSITY;
  else
    colors |= FOREGROUND_INTENSITY;
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colors);
  return 0;
}

const char *Process::OutputColor(char code, bool bold, bool bg) {
  if (UseANSI) return colorcodes[bg?1:0][bold?1:0][code&7];

  WORD current = DefaultColors::GetCurrentColor();
  WORD colors;
  if (bg) {
    colors = ((code&1) ? BACKGROUND_RED : 0) |
      ((code&2) ? BACKGROUND_GREEN : 0 ) |
      ((code&4) ? BACKGROUND_BLUE : 0);
    if (bold)
      colors |= BACKGROUND_INTENSITY;
    colors |= fg_color(current);
  } else {
    colors = ((code&1) ? FOREGROUND_RED : 0) |
      ((code&2) ? FOREGROUND_GREEN : 0 ) |
      ((code&4) ? FOREGROUND_BLUE : 0);
    if (bold)
      colors |= FOREGROUND_INTENSITY;
    colors |= bg_color(current);
  }
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colors);
  return 0;
}

static WORD GetConsoleTextAttribute(HANDLE hConsoleOutput) {
  CONSOLE_SCREEN_BUFFER_INFO info;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info);
  return info.wAttributes;
}

const char *Process::OutputReverse() {
  if (UseANSI) return "\033[7m";

  const WORD attributes
   = GetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE));

  const WORD foreground_mask = FOREGROUND_BLUE | FOREGROUND_GREEN |
    FOREGROUND_RED | FOREGROUND_INTENSITY;
  const WORD background_mask = BACKGROUND_BLUE | BACKGROUND_GREEN |
    BACKGROUND_RED | BACKGROUND_INTENSITY;
  const WORD color_mask = foreground_mask | background_mask;

  WORD new_attributes =
    ((attributes & FOREGROUND_BLUE     )?BACKGROUND_BLUE     :0) |
    ((attributes & FOREGROUND_GREEN    )?BACKGROUND_GREEN    :0) |
    ((attributes & FOREGROUND_RED      )?BACKGROUND_RED      :0) |
    ((attributes & FOREGROUND_INTENSITY)?BACKGROUND_INTENSITY:0) |
    ((attributes & BACKGROUND_BLUE     )?FOREGROUND_BLUE     :0) |
    ((attributes & BACKGROUND_GREEN    )?FOREGROUND_GREEN    :0) |
    ((attributes & BACKGROUND_RED      )?FOREGROUND_RED      :0) |
    ((attributes & BACKGROUND_INTENSITY)?FOREGROUND_INTENSITY:0) |
    0;
  new_attributes = (attributes & ~color_mask) | (new_attributes & color_mask);

  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), new_attributes);
  return 0;
}

const char *Process::ResetColor() {
  if (UseANSI) return "\033[0m";
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), defaultColors());
  return 0;
}

                                                   
static void ReportLastErrorFatal(const char *Msg) {
  std::string ErrMsg;
  MakeErrMsg(&ErrMsg, Msg);
  report_fatal_error(ErrMsg);
}

unsigned Process::GetRandomNumber() {
  HCRYPTPROV HCPC;
  if (!::CryptAcquireContextW(&HCPC, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT))
    ReportLastErrorFatal("Could not acquire a cryptographic context");

  ScopedCryptContext CryptoProvider(HCPC);
  unsigned Ret;
  if (!::CryptGenRandom(CryptoProvider, sizeof(Ret),
                        reinterpret_cast<BYTE *>(&Ret)))
    ReportLastErrorFatal("Could not generate a random number");
  return Ret;
}
