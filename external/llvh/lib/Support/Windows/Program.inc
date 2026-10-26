//===- Win32/Program.cpp - Win32 Program Implementation ------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Win32 specific implementation of the Program class.
//
//===----------------------------------------------------------------------===//

#include "WindowsSupport.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/Support/ConvertUTF.h"
#include "llvh/Support/Errc.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/WindowsError.h"
#include "llvh/Support/raw_ostream.h"
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <malloc.h>
#include <numeric>

                                                                                
                                                                        
                                        
                                                                                

namespace llvh {

ProcessInfo::ProcessInfo() : Pid(0), Process(0), ReturnCode(0) {}

ErrorOr<std::string> sys::findProgramByName(StringRef Name,
                                            ArrayRef<StringRef> Paths) {
  assert(!Name.empty() && "Must have a name!");

  if (Name.find_first_of("/\\") != StringRef::npos)
    return std::string(Name);

  const wchar_t *Path = nullptr;
  std::wstring PathStorage;
  if (!Paths.empty()) {
    PathStorage.reserve(Paths.size() * MAX_PATH);
    for (unsigned i = 0; i < Paths.size(); ++i) {
      if (i)
        PathStorage.push_back(L';');
      StringRef P = Paths[i];
      SmallVector<wchar_t, MAX_PATH> TmpPath;
      if (std::error_code EC = windows::UTF8ToUTF16(P, TmpPath))
        return EC;
      PathStorage.append(TmpPath.begin(), TmpPath.end());
    }
    Path = PathStorage.c_str();
  }

  SmallVector<wchar_t, MAX_PATH> U16Name;
  if (std::error_code EC = windows::UTF8ToUTF16(Name, U16Name))
    return EC;

  SmallVector<StringRef, 12> PathExts;
  PathExts.push_back("");
  PathExts.push_back(".exe");                                     
  if (const char *PathExtEnv = std::getenv("PATHEXT"))
    SplitString(PathExtEnv, PathExts, ";");

  SmallVector<wchar_t, MAX_PATH> U16Result;
  DWORD Len = MAX_PATH;
  for (StringRef Ext : PathExts) {
    SmallVector<wchar_t, MAX_PATH> U16Ext;
    if (std::error_code EC = windows::UTF8ToUTF16(Ext, U16Ext))
      return EC;

    do {
      U16Result.reserve(Len);
                                                                     
                                                                              
                                                                                
      SmallVector<wchar_t, MAX_PATH> U16NameExt;
      if (std::error_code EC =
              windows::UTF8ToUTF16(Twine(Name + Ext).str(), U16NameExt))
        return EC;

      Len = ::SearchPathW(Path, c_str(U16NameExt), nullptr,
                          U16Result.capacity(), U16Result.data(), nullptr);
    } while (Len > U16Result.capacity());

    if (Len != 0)
      break;             
  }

  if (Len == 0)
    return mapWindowsError(::GetLastError());

  U16Result.set_size(Len);

  SmallVector<char, MAX_PATH> U8Result;
  if (std::error_code EC =
          windows::UTF16ToUTF8(U16Result.data(), U16Result.size(), U8Result))
    return EC;

  return std::string(U8Result.begin(), U8Result.end());
}

static HANDLE RedirectIO(Optional<StringRef> Path, int fd,
                         std::string *ErrMsg) {
  HANDLE h;
  if (!Path) {
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)_get_osfhandle(fd),
                         GetCurrentProcess(), &h,
                         0, TRUE, DUPLICATE_SAME_ACCESS))
      return INVALID_HANDLE_VALUE;
    return h;
  }

  std::string fname;
  if (Path->empty())
    fname = "NUL";
  else
    fname = *Path;

  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = 0;
  sa.bInheritHandle = TRUE;

  SmallVector<wchar_t, 128> fnameUnicode;
  if (Path->empty()) {
                                            
    if (windows::UTF8ToUTF16(fname, fnameUnicode))
      return INVALID_HANDLE_VALUE;
  } else {
    if (path::widenPath(fname, fnameUnicode))
      return INVALID_HANDLE_VALUE;
  }
  h = CreateFileW(fnameUnicode.data(), fd ? GENERIC_WRITE : GENERIC_READ,
                  FILE_SHARE_READ, &sa, fd == 0 ? OPEN_EXISTING : CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    MakeErrMsg(ErrMsg, fname + ": Can't open file for " +
        (fd ? "input" : "output"));
  }

  return h;
}

}

static bool Execute(ProcessInfo &PI, StringRef Program,
                    ArrayRef<StringRef> Args, Optional<ArrayRef<StringRef>> Env,
                    ArrayRef<Optional<StringRef>> Redirects,
                    unsigned MemoryLimit, std::string *ErrMsg) {
  if (!sys::fs::can_execute(Program)) {
    if (ErrMsg)
      *ErrMsg = "program not executable";
    return false;
  }

                                                                           
                                                                         
                                                                             
                      
  SmallString<64> ProgramStorage;
  if (!sys::fs::exists(Program))
    Program = Twine(Program + ".exe").toStringRef(ProgramStorage);

                                                                           
                                                                           
                                         
  std::string Command = flattenWindowsCommandLine(Args);

                                                              
  std::vector<wchar_t> EnvBlock;

  if (Env) {
                                                                  
                                                                             
                                                  
    for (const auto E : *Env) {
      SmallVector<wchar_t, MAX_PATH> EnvString;
      if (std::error_code ec = windows::UTF8ToUTF16(E, EnvString)) {
        SetLastError(ec.value());
        MakeErrMsg(ErrMsg, "Unable to convert environment variable to UTF-16");
        return false;
      }

      EnvBlock.insert(EnvBlock.end(), EnvString.begin(), EnvString.end());
      EnvBlock.push_back(0);
    }
    EnvBlock.push_back(0);
  }

                            
  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.hStdInput = INVALID_HANDLE_VALUE;
  si.hStdOutput = INVALID_HANDLE_VALUE;
  si.hStdError = INVALID_HANDLE_VALUE;

  if (!Redirects.empty()) {
    si.dwFlags = STARTF_USESTDHANDLES;

    si.hStdInput = RedirectIO(Redirects[0], 0, ErrMsg);
    if (si.hStdInput == INVALID_HANDLE_VALUE) {
      MakeErrMsg(ErrMsg, "can't redirect stdin");
      return false;
    }
    si.hStdOutput = RedirectIO(Redirects[1], 1, ErrMsg);
    if (si.hStdOutput == INVALID_HANDLE_VALUE) {
      CloseHandle(si.hStdInput);
      MakeErrMsg(ErrMsg, "can't redirect stdout");
      return false;
    }
    if (Redirects[1] && Redirects[2] && *Redirects[1] == *Redirects[2]) {
                                                                          
                                               
      if (!DuplicateHandle(GetCurrentProcess(), si.hStdOutput,
                           GetCurrentProcess(), &si.hStdError,
                           0, TRUE, DUPLICATE_SAME_ACCESS)) {
        CloseHandle(si.hStdInput);
        CloseHandle(si.hStdOutput);
        MakeErrMsg(ErrMsg, "can't dup stderr to stdout");
        return false;
      }
    } else {
                             
      si.hStdError = RedirectIO(Redirects[2], 2, ErrMsg);
      if (si.hStdError == INVALID_HANDLE_VALUE) {
        CloseHandle(si.hStdInput);
        CloseHandle(si.hStdOutput);
        MakeErrMsg(ErrMsg, "can't redirect stderr");
        return false;
      }
    }
  }

  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));

  fflush(stdout);
  fflush(stderr);

  SmallVector<wchar_t, MAX_PATH> ProgramUtf16;
  if (std::error_code ec = path::widenPath(Program, ProgramUtf16)) {
    SetLastError(ec.value());
    MakeErrMsg(ErrMsg,
               std::string("Unable to convert application name to UTF-16"));
    return false;
  }

  SmallVector<wchar_t, MAX_PATH> CommandUtf16;
  if (std::error_code ec = windows::UTF8ToUTF16(Command, CommandUtf16)) {
    SetLastError(ec.value());
    MakeErrMsg(ErrMsg,
               std::string("Unable to convert command-line to UTF-16"));
    return false;
  }

  BOOL rc = CreateProcessW(ProgramUtf16.data(), CommandUtf16.data(), 0, 0,
                           TRUE, CREATE_UNICODE_ENVIRONMENT,
                           EnvBlock.empty() ? 0 : EnvBlock.data(), 0, &si,
                           &pi);
  DWORD err = GetLastError();

                                                                           
                                              
  CloseHandle(si.hStdInput);
  CloseHandle(si.hStdOutput);
  CloseHandle(si.hStdError);

                                                           
  if (!rc) {
    SetLastError(err);
    MakeErrMsg(ErrMsg, std::string("Couldn't execute program '") +
               Program.str() + "'");
    return false;
  }

  PI.Pid = pi.dwProcessId;
  PI.Process = pi.hProcess;

                                               
  ScopedCommonHandle hThread(pi.hThread);

                                                              
  ScopedJobHandle hJob;
  if (MemoryLimit != 0) {
    hJob = CreateJobObjectW(0, 0);
    bool success = false;
    if (hJob) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
      memset(&jeli, 0, sizeof(jeli));
      jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
      jeli.ProcessMemoryLimit = uintptr_t(MemoryLimit) * 1048576;
      if (SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                  &jeli, sizeof(jeli))) {
        if (AssignProcessToJobObject(hJob, pi.hProcess))
          success = true;
      }
    }
    if (!success) {
      SetLastError(GetLastError());
      MakeErrMsg(ErrMsg, std::string("Unable to set memory limit"));
      TerminateProcess(pi.hProcess, 1);
      WaitForSingleObject(pi.hProcess, INFINITE);
      return false;
    }
  }

  return true;
}

static bool argNeedsQuotes(StringRef Arg) {
  if (Arg.empty())
    return true;
  return StringRef::npos != Arg.find_first_of("\t \"&\'()*<>\\`^|\n");
}

static std::string quoteSingleArg(StringRef Arg) {
  std::string Result;
  Result.push_back('"');

  while (!Arg.empty()) {
    size_t FirstNonBackslash = Arg.find_first_not_of('\\');
    size_t BackslashCount = FirstNonBackslash;
    if (FirstNonBackslash == StringRef::npos) {
                                                                            
                                 
      BackslashCount = Arg.size();
      Result.append(BackslashCount * 2, '\\');
      break;
    }

    if (Arg[FirstNonBackslash] == '\"') {
                                                                           
                                                          
      Result.append(BackslashCount * 2 + 1, '\\');
      Result.push_back('\"');
    } else {
                                                                            
                                                                      
                   
      Result.append(BackslashCount, '\\');
      Result.push_back(Arg[FirstNonBackslash]);
    }

                                                              
    Arg = Arg.drop_front(FirstNonBackslash + 1);
  }

  Result.push_back('"');
  return Result;
}

namespace llvh {
std::string sys::flattenWindowsCommandLine(ArrayRef<StringRef> Args) {
  std::string Command;
  for (StringRef Arg : Args) {
    if (argNeedsQuotes(Arg))
      Command += quoteSingleArg(Arg);
    else
      Command += Arg;

    Command.push_back(' ');
  }

  return Command;
}

ProcessInfo sys::Wait(const ProcessInfo &PI, unsigned SecondsToWait,
                      bool WaitUntilChildTerminates, std::string *ErrMsg) {
  assert(PI.Pid && "invalid pid to wait on, process not started?");
  assert((PI.Process && PI.Process != INVALID_HANDLE_VALUE) &&
         "invalid process handle to wait on, process not started?");
  DWORD milliSecondsToWait = 0;
  if (WaitUntilChildTerminates)
    milliSecondsToWait = INFINITE;
  else if (SecondsToWait > 0)
    milliSecondsToWait = SecondsToWait * 1000;

  ProcessInfo WaitResult = PI;
  DWORD WaitStatus = WaitForSingleObject(PI.Process, milliSecondsToWait);
  if (WaitStatus == WAIT_TIMEOUT) {
    if (SecondsToWait) {
      if (!TerminateProcess(PI.Process, 1)) {
        if (ErrMsg)
          MakeErrMsg(ErrMsg, "Failed to terminate timed-out program");

                                                                            
        WaitResult.ReturnCode = -2;
        CloseHandle(PI.Process);
        return WaitResult;
      }
      WaitForSingleObject(PI.Process, INFINITE);
      CloseHandle(PI.Process);
    } else {
                           
      return ProcessInfo();
    }
  }

                         
  DWORD status;
  BOOL rc = GetExitCodeProcess(PI.Process, &status);
  DWORD err = GetLastError();
  if (err != ERROR_INVALID_HANDLE)
    CloseHandle(PI.Process);

  if (!rc) {
    SetLastError(err);
    if (ErrMsg)
      MakeErrMsg(ErrMsg, "Failed getting status for program");

                                                                        
    WaitResult.ReturnCode = -2;
    return WaitResult;
  }

  if (!status)
    return WaitResult;

                                                                    
  if ((status & 0xBFFF0000U) == 0x80000000U)
    WaitResult.ReturnCode = static_cast<int>(status);
  else if (status & 0xFF)
    WaitResult.ReturnCode = status & 0x7FFFFFFF;
  else
    WaitResult.ReturnCode = 1;

  return WaitResult;
}

std::error_code sys::ChangeStdinToBinary() {
  int result = _setmode(_fileno(stdin), _O_BINARY);
  if (result == -1)
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

std::error_code sys::ChangeStdoutToBinary() {
  int result = _setmode(_fileno(stdout), _O_BINARY);
  if (result == -1)
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

std::error_code
llvh::sys::writeFileWithEncoding(StringRef FileName, StringRef Contents,
                                 WindowsEncodingMethod Encoding) {
  std::error_code EC;
  llvh::raw_fd_ostream OS(FileName, EC, llvh::sys::fs::F_Text);
  if (EC)
    return EC;

  if (Encoding == WEM_UTF8) {
    OS << Contents;
  } else if (Encoding == WEM_CurrentCodePage) {
    SmallVector<wchar_t, 1> ArgsUTF16;
    SmallVector<char, 1> ArgsCurCP;

    if ((EC = windows::UTF8ToUTF16(Contents, ArgsUTF16)))
      return EC;

    if ((EC = windows::UTF16ToCurCP(
             ArgsUTF16.data(), ArgsUTF16.size(), ArgsCurCP)))
      return EC;

    OS.write(ArgsCurCP.data(), ArgsCurCP.size());
  } else if (Encoding == WEM_UTF16) {
    SmallVector<wchar_t, 1> ArgsUTF16;

    if ((EC = windows::UTF8ToUTF16(Contents, ArgsUTF16)))
      return EC;

                          
    char BOM[2];
    uint16_t src = UNI_UTF16_BYTE_ORDER_MARK_NATIVE;
    memcpy(BOM, &src, 2);
    OS.write(BOM, 2);
    OS.write((char *)ArgsUTF16.data(), ArgsUTF16.size() << 1);
  } else {
    llvm_unreachable("Unknown encoding");
  }

  if (OS.has_error())
    return make_error_code(errc::io_error);

  return EC;
}

bool llvh::sys::commandLineFitsWithinSystemLimits(StringRef Program,
                                                  ArrayRef<StringRef> Args) {
                                                                           
  static const size_t MaxCommandStringLength = 32768;
  SmallVector<StringRef, 8> FullArgs;
  FullArgs.push_back(Program);
  FullArgs.append(Args.begin(), Args.end());
  std::string Result = flattenWindowsCommandLine(FullArgs);
  return (Result.size() + 1) <= MaxCommandStringLength;
}
}
