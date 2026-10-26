//===--- Watchdog.h - Watchdog timer ----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file declares the llvh::sys::Watchdog class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_WATCHDOG_H
#define LLVM_SUPPORT_WATCHDOG_H

#include "llvh/Support/Compiler.h"

namespace llvh {
  namespace sys {

                                                                            
                                                                                
                                                                              
                                  
    class Watchdog {
    public:
      Watchdog(unsigned int seconds);
      ~Watchdog();
    private:
                     
      Watchdog(const Watchdog &other) = delete;
      Watchdog &operator=(const Watchdog &other) = delete;
    };
  }
}

#endif
