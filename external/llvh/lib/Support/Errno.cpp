//===- Errno.cpp - errno support --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the errno wrappers.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/Errno.h"
#include "llvh/Config/config.h"                                       
#include "llvh/Support/raw_ostream.h"
#include <string.h>

#if HAVE_ERRNO_H
#include <errno.h>
#endif

                                                                                
                                                                           
                                
                                                                                

namespace llvh {
namespace sys {

#if HAVE_ERRNO_H
std::string StrError() {
  return StrError(errno);
}
#endif                 

std::string StrError(int errnum) {
  std::string str;
  if (errnum == 0)
    return str;
#if defined(HAVE_STRERROR_R) || HAVE_DECL_STRERROR_S
  const int MaxErrStrLen = 2000;
  char buffer[MaxErrStrLen];
  buffer[0] = '\0';
#endif

#ifdef HAVE_STRERROR_R
                               
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
                                                             
                                           
  str = strerror_r(errnum, buffer, MaxErrStrLen - 1);
#else
  strerror_r(errnum, buffer, MaxErrStrLen - 1);
  str = buffer;
#endif
#elif HAVE_DECL_STRERROR_S                        
  strerror_s(buffer, MaxErrStrLen - 1, errnum);
  str = buffer;
#elif defined(HAVE_STRERROR)
                                                    
                                                      
                                                  
  str = strerror(errnum);
#else
                                                        
                                             
  raw_string_ostream stream(str);
  stream << "Error #" << errnum;
  stream.flush();
#endif
  return str;
}

}                  
}                   
