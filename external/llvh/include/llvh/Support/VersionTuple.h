//===- VersionTuple.h - Version Number Handling -----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Defines the llvh::VersionTuple class, which represents a version in
/// the form major[.minor[.subminor]].
///
//===----------------------------------------------------------------------===//
#ifndef LLVM_SUPPORT_VERSIONTUPLE_H
#define LLVM_SUPPORT_VERSIONTUPLE_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/raw_ostream.h"
#include <string>
#include <tuple>

namespace llvh {

                                                                             
class VersionTuple {
  unsigned Major : 32;

  unsigned Minor : 31;
  unsigned HasMinor : 1;

  unsigned Subminor : 31;
  unsigned HasSubminor : 1;

  unsigned Build : 31;
  unsigned HasBuild : 1;

public:
  VersionTuple()
      : Major(0), Minor(0), HasMinor(false), Subminor(0), HasSubminor(false),
        Build(0), HasBuild(false) {}

  explicit VersionTuple(unsigned Major)
      : Major(Major), Minor(0), HasMinor(false), Subminor(0),
        HasSubminor(false), Build(0), HasBuild(false) {}

  explicit VersionTuple(unsigned Major, unsigned Minor)
      : Major(Major), Minor(Minor), HasMinor(true), Subminor(0),
        HasSubminor(false), Build(0), HasBuild(false) {}

  explicit VersionTuple(unsigned Major, unsigned Minor, unsigned Subminor)
      : Major(Major), Minor(Minor), HasMinor(true), Subminor(Subminor),
        HasSubminor(true), Build(0), HasBuild(false) {}

  explicit VersionTuple(unsigned Major, unsigned Minor, unsigned Subminor,
                        unsigned Build)
      : Major(Major), Minor(Minor), HasMinor(true), Subminor(Subminor),
        HasSubminor(true), Build(Build), HasBuild(true) {}

                                                         
                                              
  bool empty() const {
    return Major == 0 && Minor == 0 && Subminor == 0 && Build == 0;
  }

                                        
  unsigned getMajor() const { return Major; }

                                                     
  Optional<unsigned> getMinor() const {
    if (!HasMinor)
      return None;
    return Minor;
  }

                                                        
  Optional<unsigned> getSubminor() const {
    if (!HasSubminor)
      return None;
    return Subminor;
  }

                                                     
  Optional<unsigned> getBuild() const {
    if (!HasBuild)
      return None;
    return Build;
  }

                                                             
                                                                             
  friend bool operator==(const VersionTuple &X, const VersionTuple &Y) {
    return X.Major == Y.Major && X.Minor == Y.Minor &&
           X.Subminor == Y.Subminor && X.Build == Y.Build;
  }

                                                          
     
                                                                              
           
  friend bool operator!=(const VersionTuple &X, const VersionTuple &Y) {
    return !(X == Y);
  }

                                                            
     
                                                                              
           
  friend bool operator<(const VersionTuple &X, const VersionTuple &Y) {
    return std::tie(X.Major, X.Minor, X.Subminor, X.Build) <
           std::tie(Y.Major, Y.Minor, Y.Subminor, Y.Build);
  }

                                                           
     
                                                                              
           
  friend bool operator>(const VersionTuple &X, const VersionTuple &Y) {
    return Y < X;
  }

                                                         
                            
     
                                                                              
           
  friend bool operator<=(const VersionTuple &X, const VersionTuple &Y) {
    return !(Y < X);
  }

                                                        
                            
     
                                                                              
           
  friend bool operator>=(const VersionTuple &X, const VersionTuple &Y) {
    return !(X < Y);
  }

                                                             
  std::string getAsString() const;

                                                        
                                                                          
                             
  bool tryParse(StringRef string);
};

                           
raw_ostream &operator<<(raw_ostream &Out, const VersionTuple &V);

}                      
#endif                               
