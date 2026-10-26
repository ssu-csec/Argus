//===-- Valgrind.cpp - Implement Valgrind communication ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  Defines Valgrind communication methods, if HAVE_VALGRIND_VALGRIND_H is
//  defined.  If we have valgrind.h but valgrind isn't running, its macros are
//  no-ops.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/Valgrind.h"
#include "llvh/Config/config.h"
#include <cstddef>

#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>

static bool InitNotUnderValgrind() {
  return !RUNNING_ON_VALGRIND;
}

                                                                            
                                                                             
                                                                  
                            
static const bool NotUnderValgrind = InitNotUnderValgrind();

bool llvh::sys::RunningOnValgrind() {
  if (NotUnderValgrind)
    return false;
  return RUNNING_ON_VALGRIND;
}

void llvh::sys::ValgrindDiscardTranslations(const void *Addr, size_t Len) {
  if (NotUnderValgrind)
    return;

  VALGRIND_DISCARD_TRANSLATIONS(Addr, Len);
}

#else                              

bool llvh::sys::RunningOnValgrind() {
  return false;
}

void llvh::sys::ValgrindDiscardTranslations(const void *Addr, size_t Len) {
}

#endif                              
