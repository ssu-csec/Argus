//===- raw_os_ostream.h - std::ostream adaptor for raw_ostream --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the raw_os_ostream class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_RAW_OS_OSTREAM_H
#define LLVM_SUPPORT_RAW_OS_OSTREAM_H

#include "llvh/Support/raw_ostream.h"
#include <iosfwd>

namespace llvh {

                                                                             
                                                                              
                                               
class raw_os_ostream : public raw_ostream {
  std::ostream &OS;

                                               
  void write_impl(const char *Ptr, size_t Size) override;

                                                                      
                                                 
  uint64_t current_pos() const override;

public:
  raw_os_ostream(std::ostream &O) : OS(O) {}
  ~raw_os_ostream() override;
};

}                      

#endif
