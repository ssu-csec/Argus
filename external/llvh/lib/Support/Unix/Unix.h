//===- llvm/Support/Unix/Unix.h - Common Unix Include File -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines things specific to Unix implementations.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_SUPPORT_UNIX_UNIX_H
#define LLVM_LIB_SUPPORT_UNIX_UNIX_H

                                                                                
                                                                           
                                                          
                                                                                

#include "llvh/Config/config.h"                                       
#include "llvh/Support/Chrono.h"
#include "llvh/Support/Errno.h"
#include <algorithm>
#include <assert.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <time.h>

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

                                                                            
                                                                             
                                            
                         
   
                                                                
                                  
static inline bool MakeErrMsg(
  std::string* ErrMsg, const std::string& prefix, int errnum = -1) {
  if (!ErrMsg)
    return true;
  if (errnum == -1)
    errnum = errno;
  *ErrMsg = prefix + ": " + llvh::sys::StrError(errnum);
  return true;
}

namespace llvh {
namespace sys {

                                                                              
                                                                               
inline std::chrono::microseconds toDuration(const struct timeval &TV) {
  return std::chrono::seconds(TV.tv_sec) +
         std::chrono::microseconds(TV.tv_usec);
}

                                            
inline struct timespec toTimeSpec(TimePoint<> TP) {
  using namespace std::chrono;

  struct timespec RetVal;
  RetVal.tv_sec = toTimeT(TP);
  RetVal.tv_nsec = (TP.time_since_epoch() % seconds(1)).count();
  return RetVal;
}

                                           
inline struct timeval toTimeVal(TimePoint<std::chrono::microseconds> TP) {
  using namespace std::chrono;

  struct timeval RetVal;
  RetVal.tv_sec = toTimeT(TP);
  RetVal.tv_usec = (TP.time_since_epoch() % seconds(1)).count();
  return RetVal;
}

}                 
}                  

#endif
