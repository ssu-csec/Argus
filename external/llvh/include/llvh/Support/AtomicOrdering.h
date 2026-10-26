//===-- llvm/Support/AtomicOrdering.h ---Atomic Ordering---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Atomic ordering constants.
///
/// These values are used by LLVM to represent atomic ordering for C++11's
/// memory model and more, as detailed in docs/Atomics.rst.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ATOMICORDERING_H
#define LLVM_SUPPORT_ATOMICORDERING_H

#include <cstddef>

namespace llvh {

                                                    
   
                                                                            
                                                    
enum class AtomicOrderingCABI {
  relaxed = 0,
  consume = 1,
  acquire = 2,
  release = 3,
  acq_rel = 4,
  seq_cst = 5,
};

bool operator<(AtomicOrderingCABI, AtomicOrderingCABI) = delete;
bool operator>(AtomicOrderingCABI, AtomicOrderingCABI) = delete;
bool operator<=(AtomicOrderingCABI, AtomicOrderingCABI) = delete;
bool operator>=(AtomicOrderingCABI, AtomicOrderingCABI) = delete;

                                                                              
                                 
template <typename Int> inline bool isValidAtomicOrderingCABI(Int I) {
  return (Int)AtomicOrderingCABI::relaxed <= I &&
         I <= (Int)AtomicOrderingCABI::seq_cst;
}

                                            
   
                                                                               
                                                   
   
                                                                               
                                                              
enum class AtomicOrdering {
  NotAtomic = 0,
  Unordered = 1,
  Monotonic = 2,                                
                                        
  Acquire = 4,
  Release = 5,
  AcquireRelease = 6,
  SequentiallyConsistent = 7
};

bool operator<(AtomicOrdering, AtomicOrdering) = delete;
bool operator>(AtomicOrdering, AtomicOrdering) = delete;
bool operator<=(AtomicOrdering, AtomicOrdering) = delete;
bool operator>=(AtomicOrdering, AtomicOrdering) = delete;

                                                                              
                             
template <typename Int> inline bool isValidAtomicOrdering(Int I) {
  return static_cast<Int>(AtomicOrdering::NotAtomic) <= I &&
         I <= static_cast<Int>(AtomicOrdering::SequentiallyConsistent);
}

                                                        
inline const char *toIRString(AtomicOrdering ao) {
  static const char *names[8] = {"not_atomic", "unordered", "monotonic",
                                 "consume",    "acquire",   "release",
                                 "acq_rel",    "seq_cst"};
  return names[static_cast<size_t>(ao)];
}

                                                                              
                                                
inline bool isStrongerThan(AtomicOrdering ao, AtomicOrdering other) {
  static const bool lookup[8][8] = {
                                                                          
                      {false, false, false, false, false, false, false, false},
                      { true, false, false, false, false, false, false, false},
                      { true,  true, false, false, false, false, false, false},
                      { true,  true,  true, false, false, false, false, false},
                      { true,  true,  true,  true, false, false, false, false},
                      { true,  true,  true, false, false, false, false, false},
                      { true,  true,  true,  true,  true,  true, false, false},
                      { true,  true,  true,  true,  true,  true,  true, false},
  };
  return lookup[static_cast<size_t>(ao)][static_cast<size_t>(other)];
}

inline bool isAtLeastOrStrongerThan(AtomicOrdering ao, AtomicOrdering other) {
  static const bool lookup[8][8] = {
                                                                          
                      { true, false, false, false, false, false, false, false},
                      { true,  true, false, false, false, false, false, false},
                      { true,  true,  true, false, false, false, false, false},
                      { true,  true,  true,  true, false, false, false, false},
                      { true,  true,  true,  true,  true, false, false, false},
                      { true,  true,  true, false, false,  true, false, false},
                      { true,  true,  true,  true,  true,  true,  true, false},
                      { true,  true,  true,  true,  true,  true,  true,  true},
  };
  return lookup[static_cast<size_t>(ao)][static_cast<size_t>(other)];
}

inline bool isStrongerThanUnordered(AtomicOrdering ao) {
  return isStrongerThan(ao, AtomicOrdering::Unordered);
}

inline bool isStrongerThanMonotonic(AtomicOrdering ao) {
  return isStrongerThan(ao, AtomicOrdering::Monotonic);
}

inline bool isAcquireOrStronger(AtomicOrdering ao) {
  return isAtLeastOrStrongerThan(ao, AtomicOrdering::Acquire);
}

inline bool isReleaseOrStronger(AtomicOrdering ao) {
  return isAtLeastOrStrongerThan(ao, AtomicOrdering::Release);
}

inline AtomicOrderingCABI toCABI(AtomicOrdering ao) {
  static const AtomicOrderingCABI lookup[8] = {
                      AtomicOrderingCABI::relaxed,
                      AtomicOrderingCABI::relaxed,
                      AtomicOrderingCABI::relaxed,
                      AtomicOrderingCABI::consume,
                      AtomicOrderingCABI::acquire,
                      AtomicOrderingCABI::release,
                      AtomicOrderingCABI::acq_rel,
                      AtomicOrderingCABI::seq_cst,
  };
  return lookup[static_cast<size_t>(ao)];
}

}                      

#endif                                 
