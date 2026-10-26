//===- llvm/Support/Unix/Host.inc -------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the UNIX Host support.
//
//===----------------------------------------------------------------------===//

                                                                                
                                                                           
                                                            
                                                                                

#include "Unix.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Config/config.h"
#include <cctype>
#include <string>
#include <sys/utsname.h>

using namespace llvh;

static std::string getOSVersion() {
  struct utsname info;

  if (uname(&info))
    return "";

  return info.release;
}

static std::string updateTripleOSVersion(std::string TargetTripleString) {
                                                                          
  std::string::size_type DarwinDashIdx = TargetTripleString.find("-darwin");
  if (DarwinDashIdx != std::string::npos) {
    TargetTripleString.resize(DarwinDashIdx + strlen("-darwin"));
    TargetTripleString += getOSVersion();
    return TargetTripleString;
  }
  std::string::size_type MacOSDashIdx = TargetTripleString.find("-macos");
  if (MacOSDashIdx != std::string::npos) {
    TargetTripleString.resize(MacOSDashIdx);
                                                                            
                            
    TargetTripleString += "-darwin";
    TargetTripleString += getOSVersion();
  }
  return TargetTripleString;
}

std::string sys::getDefaultTargetTriple() {
  std::string TargetTripleString =
      updateTripleOSVersion(LLVM_DEFAULT_TARGET_TRIPLE);

                                                                      
                            
#if defined(LLVM_TARGET_TRIPLE_ENV)
  if (const char *EnvTriple = std::getenv(LLVM_TARGET_TRIPLE_ENV))
    TargetTripleString = EnvTriple;
#endif

  return TargetTripleString;
}
