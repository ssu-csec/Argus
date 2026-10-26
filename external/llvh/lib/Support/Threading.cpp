//===-- llvm/Support/Threading.cpp- Control multithreading mode --*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines helper functions for running LLVM in a multi-threaded
// environment.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/Threading.h"
#include "llvh/Config/config.h"
#include "llvh/Support/Host.h"

#include <cassert>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

using namespace llvh;

                                                                                
                                                                           
                                
                                                                                

bool llvh::llvm_is_multithreaded() {
#if LLVM_ENABLE_THREADS != 0
  return true;
#else
  return false;
#endif
}

#if LLVM_ENABLE_THREADS == 0 ||                                                \
    (!defined(_WIN32) && !defined(HAVE_PTHREAD_H))
                                                     
void llvh::llvm_execute_on_thread(void (*Fn)(void *), void *UserData,
                                  unsigned RequestedStackSize) {
  (void)RequestedStackSize;
  Fn(UserData);
}

unsigned llvh::heavyweight_hardware_concurrency() { return 1; }

unsigned llvh::hardware_concurrency() { return 1; }

uint64_t llvh::get_threadid() { return 0; }

uint32_t llvh::get_max_thread_name_length() { return 0; }

void llvh::set_thread_name(const Twine &Name) {}

void llvh::get_thread_name(SmallVectorImpl<char> &Name) { Name.clear(); }

#else

#include <thread>
unsigned llvh::heavyweight_hardware_concurrency() {
                                                                               
                                                                           
                                                                            
                                                                           
                                                                             
         
  int NumPhysical = sys::getHostNumPhysicalCores();
  if (NumPhysical == -1)
    return std::thread::hardware_concurrency();
  return NumPhysical;
}

unsigned llvh::hardware_concurrency() {
#if defined(HAVE_SCHED_GETAFFINITY) && defined(HAVE_CPU_COUNT)
  cpu_set_t Set;
  if (sched_getaffinity(0, sizeof(Set), &Set))
    return CPU_COUNT(&Set);
#endif
                                                                   
  if (unsigned Val = std::thread::hardware_concurrency())
    return Val;
  return 1;
}

                                                     
#ifdef LLVM_ON_UNIX
#include "Unix/Threading.inc"
#endif
#ifdef _WIN32
#include "Windows/Threading.inc"
#endif

#endif
