//===- llvm/Support/Errno.h - Portable+convenient errno handling -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares some portable and convenient functions to deal with errno.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ERRNO_H
#define LLVM_SUPPORT_ERRNO_H

#include <cerrno>
#include <string>
#include <type_traits>

namespace llvh {
namespace sys {

                                                                      
                                                                         
                                                                         
                                       
std::string StrError();

                                                                            
std::string StrError(int errnum);

template <typename FailT, typename Fun, typename... Args>
inline auto RetryAfterSignal(const FailT &Fail, const Fun &F,
                             const Args &... As) -> decltype(F(As...)) {
  decltype(F(As...)) Res;
  do {
    errno = 0;
    Res = F(As...);
  } while (Res == Fail && errno == EINTR);
  return Res;
}

}                  
}                   

#endif                        
