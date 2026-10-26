//===- llvm/Support/Unix/Program.cpp -----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Unix specific portion of the Program class.
//
//===----------------------------------------------------------------------===//

                                                                                
                                                                           
                                                            
                                                                                

#include "Unix.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/Config/config.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/Errc.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/StringSaver.h"
#include "llvh/Support/raw_ostream.h"
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#ifdef HAVE_POSIX_SPAWN
#include <spawn.h>

#if defined(__APPLE__) && !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
#define USE_NSGETENVIRON 1
#else
#define USE_NSGETENVIRON 0
#endif

#if !USE_NSGETENVIRON
  extern char **environ;
#else
#include <crt_externs.h>                 
#endif
#endif

namespace llvh {

using namespace sys;

ProcessInfo::ProcessInfo() : Pid(0), ReturnCode(0) {}

ErrorOr<std::string> sys::findProgramByName(StringRef Name,
                                            ArrayRef<StringRef> Paths) {
  assert(!Name.empty() && "Must have a name!");
                                                                         
                                       
  if (Name.find('/') != StringRef::npos)
    return std::string(Name);

  SmallVector<StringRef, 16> EnvironmentPaths;
  if (Paths.empty())
    if (const char *PathEnv = std::getenv("PATH")) {
      SplitString(PathEnv, EnvironmentPaths, ":");
      Paths = EnvironmentPaths;
    }

  for (auto Path : Paths) {
    if (Path.empty())
      continue;

                                                                      
    SmallString<128> FilePath(Path);
    sys::path::append(FilePath, Name);
    if (sys::fs::can_execute(FilePath.c_str()))
      return std::string(FilePath.str());                         
  }
  return errc::no_such_file_or_directory;
}

static bool RedirectIO(Optional<StringRef> Path, int FD, std::string* ErrMsg) {
  if (!Path)        
    return false;
  std::string File;
  if (Path->empty())
                                        
    File = "/dev/null";
  else
    File = *Path;

                  
  int InFD = open(File.c_str(), FD == 0 ? O_RDONLY : O_WRONLY|O_CREAT, 0666);
  if (InFD == -1) {
    MakeErrMsg(ErrMsg, "Cannot open file '" + File + "' for "
              + (FD == 0 ? "input" : "output"));
    return true;
  }

                                   
  if (dup2(InFD, FD) == -1) {
    MakeErrMsg(ErrMsg, "Cannot dup2");
    close(InFD);
    return true;
  }
  close(InFD);                              
  return false;
}

#ifdef HAVE_POSIX_SPAWN
static bool RedirectIO_PS(const std::string *Path, int FD, std::string *ErrMsg,
                          posix_spawn_file_actions_t *FileActions) {
  if (!Path)        
    return false;
  const char *File;
  if (Path->empty())
                                        
    File = "/dev/null";
  else
    File = Path->c_str();

  if (int Err = posix_spawn_file_actions_addopen(
          FileActions, FD, File,
          FD == 0 ? O_RDONLY : O_WRONLY | O_CREAT, 0666))
    return MakeErrMsg(ErrMsg, "Cannot dup2", Err);
  return false;
}
#endif

static void TimeOutHandler(int Sig) {
}

static void SetMemoryLimits(unsigned size) {
#if HAVE_SYS_RESOURCE_H && HAVE_GETRLIMIT && HAVE_SETRLIMIT
  struct rlimit r;
  __typeof__ (r.rlim_cur) limit = (__typeof__ (r.rlim_cur)) (size) * 1048576;

              
  getrlimit (RLIMIT_DATA, &r);
  r.rlim_cur = limit;
  setrlimit (RLIMIT_DATA, &r);
#ifdef RLIMIT_RSS
                       
  getrlimit (RLIMIT_RSS, &r);
  r.rlim_cur = limit;
  setrlimit (RLIMIT_RSS, &r);
#endif
#endif
}

}

static std::vector<const char *>
toNullTerminatedCStringArray(ArrayRef<StringRef> Strings, StringSaver &Saver) {
  std::vector<const char *> Result;
  for (StringRef S : Strings)
    Result.push_back(Saver.save(S).data());
  Result.push_back(nullptr);
  return Result;
}

static bool Execute(ProcessInfo &PI, StringRef Program,
                    ArrayRef<StringRef> Args, Optional<ArrayRef<StringRef>> Env,
                    ArrayRef<Optional<StringRef>> Redirects,
                    unsigned MemoryLimit, std::string *ErrMsg) {
                                                                             
          
#if defined(TARGET_OS_TV) && TARGET_OS_TV
  if (ErrMsg)
    *ErrMsg = "Executing another program is unsupported on this platform";
  return false;
#else
  if (!llvh::sys::fs::exists(Program)) {
    if (ErrMsg)
      *ErrMsg = std::string("Executable \"") + Program.str() +
                std::string("\" doesn't exist!");
    return false;
  }

  BumpPtrAllocator Allocator;
  StringSaver Saver(Allocator);
  std::vector<const char *> ArgVector, EnvVector;
  const char **Argv = nullptr;
  const char **Envp = nullptr;
  ArgVector = toNullTerminatedCStringArray(Args, Saver);
  Argv = ArgVector.data();
  if (Env) {
    EnvVector = toNullTerminatedCStringArray(*Env, Saver);
    Envp = EnvVector.data();
  }

                                                                               
                                                       
#ifdef HAVE_POSIX_SPAWN
  if (MemoryLimit == 0) {
    posix_spawn_file_actions_t FileActionsStore;
    posix_spawn_file_actions_t *FileActions = nullptr;

                                                                           
                                                                        
                                                    
    std::string RedirectsStorage[3];

    if (!Redirects.empty()) {
      assert(Redirects.size() == 3);
      std::string *RedirectsStr[3] = {nullptr, nullptr, nullptr};
      for (int I = 0; I < 3; ++I) {
        if (Redirects[I]) {
          RedirectsStorage[I] = *Redirects[I];
          RedirectsStr[I] = &RedirectsStorage[I];
        }
      }

      FileActions = &FileActionsStore;
      posix_spawn_file_actions_init(FileActions);

                               
      if (RedirectIO_PS(RedirectsStr[0], 0, ErrMsg, FileActions) ||
          RedirectIO_PS(RedirectsStr[1], 1, ErrMsg, FileActions))
        return false;
      if (!Redirects[1] || !Redirects[2] || *Redirects[1] != *Redirects[2]) {
                               
        if (RedirectIO_PS(RedirectsStr[2], 2, ErrMsg, FileActions))
          return false;
      } else {
                                                                            
                                             
        if (int Err = posix_spawn_file_actions_adddup2(FileActions, 1, 2))
          return !MakeErrMsg(ErrMsg, "Can't redirect stderr to stdout", Err);
      }
    }

    if (!Envp)
#if !USE_NSGETENVIRON
      Envp = const_cast<const char **>(environ);
#else
                                      
      Envp = const_cast<const char **>(*_NSGetEnviron());
#endif

                                                                            
                
    pid_t PID = 0;
    int Err = posix_spawn(&PID, Program.str().c_str(), FileActions,
                                    nullptr, const_cast<char **>(Argv),
                          const_cast<char **>(Envp));

    if (FileActions)
      posix_spawn_file_actions_destroy(FileActions);

    if (Err)
     return !MakeErrMsg(ErrMsg, "posix_spawn failed", Err);

    PI.Pid = PID;
    PI.Process = PID;

    return true;
  }
#endif

                            
  int child = fork();
  switch (child) {
                                                
    case -1:
      MakeErrMsg(ErrMsg, "Couldn't fork");
      return false;

                                          
    case 0: {
                                     
      if (!Redirects.empty()) {
                         
        if (RedirectIO(Redirects[0], 0, ErrMsg)) { return false; }
                          
        if (RedirectIO(Redirects[1], 1, ErrMsg)) { return false; }
        if (Redirects[1] && Redirects[2] && *Redirects[1] == *Redirects[2]) {
                                                                              
                                               
          if (-1 == dup2(1,2)) {
            MakeErrMsg(ErrMsg, "Can't redirect stderr to stdout");
            return false;
          }
        } else {
                                 
          if (RedirectIO(Redirects[2], 2, ErrMsg)) { return false; }
        }
      }

                          
      if (MemoryLimit!=0) {
        SetMemoryLimits(MemoryLimit);
      }

                 
      std::string PathStr = Program;
      if (Envp != nullptr)
        execve(PathStr.c_str(), const_cast<char **>(Argv),
               const_cast<char **>(Envp));
      else
        execv(PathStr.c_str(), const_cast<char **>(Argv));
                                                                         
                                                                       
                                                                       
                                                                 
                                                                        
                                                               
      _exit(errno == ENOENT ? 127 : 126);
    }

                                                                    
    default:
      break;
  }

  PI.Pid = child;
  PI.Process = child;

  return true;
#endif                
}

namespace llvh {

ProcessInfo sys::Wait(const ProcessInfo &PI, unsigned SecondsToWait,
                      bool WaitUntilTerminates, std::string *ErrMsg) {
  struct sigaction Act, Old;
  assert(PI.Pid && "invalid pid to wait on, process not started?");

  int WaitPidOptions = 0;
  pid_t ChildPid = PI.Pid;
  if (WaitUntilTerminates) {
    SecondsToWait = 0;
  } else if (SecondsToWait) {
                                                                           
                                                                             
                                             
    memset(&Act, 0, sizeof(Act));
    Act.sa_handler = TimeOutHandler;
    sigemptyset(&Act.sa_mask);
    sigaction(SIGALRM, &Act, &Old);
    alarm(SecondsToWait);
  } else if (SecondsToWait == 0)
    WaitPidOptions = WNOHANG;

                                                             
  int status;
  ProcessInfo WaitResult;

  do {
    WaitResult.Pid = waitpid(ChildPid, &status, WaitPidOptions);
  } while (WaitUntilTerminates && WaitResult.Pid == -1 && errno == EINTR);

  if (WaitResult.Pid != PI.Pid) {
    if (WaitResult.Pid == 0) {
                           
      return WaitResult;
    } else {
      if (SecondsToWait && errno == EINTR) {
                          
        kill(PI.Pid, SIGKILL);

                                                            
        alarm(0);
        sigaction(SIGALRM, &Old, nullptr);

                                
        if (wait(&status) != ChildPid)
          MakeErrMsg(ErrMsg, "Child timed out but wouldn't die");
        else
          MakeErrMsg(ErrMsg, "Child timed out", 0);

        WaitResult.ReturnCode = -2;                    
        return WaitResult;
      } else if (errno != EINTR) {
        MakeErrMsg(ErrMsg, "Error waiting for child process");
        WaitResult.ReturnCode = -1;
        return WaitResult;
      }
    }
  }

                                                               
  if (SecondsToWait && !WaitUntilTerminates) {
    alarm(0);
    sigaction(SIGALRM, &Old, nullptr);
  }

                                                           
                                                               
  int result = 0;
  if (WIFEXITED(status)) {
    result = WEXITSTATUS(status);
    WaitResult.ReturnCode = result;

    if (result == 127) {
      if (ErrMsg)
        *ErrMsg = llvh::sys::StrError(ENOENT);
      WaitResult.ReturnCode = -1;
      return WaitResult;
    }
    if (result == 126) {
      if (ErrMsg)
        *ErrMsg = "Program could not be executed";
      WaitResult.ReturnCode = -1;
      return WaitResult;
    }
  } else if (WIFSIGNALED(status)) {
    if (ErrMsg) {
      *ErrMsg = strsignal(WTERMSIG(status));
#ifdef WCOREDUMP
      if (WCOREDUMP(status))
        *ErrMsg += " (core dumped)";
#endif
    }
                                                                                
                                                                
    WaitResult.ReturnCode = -2;
  }
  return WaitResult;
}

std::error_code sys::ChangeStdinToBinary() {
                                                                       
  return std::error_code();
}

std::error_code sys::ChangeStdoutToBinary() {
                                                                       
  return std::error_code();
}

std::error_code
llvh::sys::writeFileWithEncoding(StringRef FileName, StringRef Contents,
                                 WindowsEncodingMethod Encoding           ) {
  std::error_code EC;
  llvh::raw_fd_ostream OS(FileName, EC, llvh::sys::fs::OpenFlags::F_Text);

  if (EC)
    return EC;

  OS << Contents;

  if (OS.has_error())
    return make_error_code(errc::io_error);

  return EC;
}

bool llvh::sys::commandLineFitsWithinSystemLimits(StringRef Program,
                                                  ArrayRef<StringRef> Args) {
  static long ArgMax = sysconf(_SC_ARG_MAX);
                                                                             
                                                   
  static long ArgMin = _POSIX_ARG_MAX;

                                          
  long EffectiveArgMax = 128 * 1024;

  if (EffectiveArgMax > ArgMax)
    EffectiveArgMax = ArgMax;
  else if (EffectiveArgMax < ArgMin)
    EffectiveArgMax = ArgMin;

                                    
  if (ArgMax == -1)
    return true;

                                                                        
  long HalfArgMax = EffectiveArgMax / 2;

  size_t ArgLength = Program.size() + 1;
  for (StringRef Arg : Args) {
                                                                               
                                                                        
                                                                  
                                                                             
                  
    if (Arg.size() >= (32 * 4096))
      return false;

    ArgLength += Arg.size() + 1;
    if (ArgLength > size_t(HalfArgMax)) {
      return false;
    }
  }

  return true;
}
}
