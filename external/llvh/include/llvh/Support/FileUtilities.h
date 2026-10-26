//===- llvm/Support/FileUtilities.h - File System Utilities -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a family of utility functions which are useful for doing
// various things with files.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FILEUTILITIES_H
#define LLVM_SUPPORT_FILEUTILITIES_H

#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Path.h"

namespace llvh {

                                                                              
                                                                               
                                                                                
                                                                            
                                                                               
                                 
     
  int DiffFilesWithTolerance(StringRef FileA,
                             StringRef FileB,
                             double AbsTol, double RelTol,
                             std::string *Error = nullptr);


                                                                              
                                                                              
                                      
     
  class FileRemover {
    SmallString<128> Filename;
    bool DeleteIt;
  public:
    FileRemover() : DeleteIt(false) {}

    explicit FileRemover(const Twine& filename, bool deleteIt = true)
      : DeleteIt(deleteIt) {
      filename.toVector(Filename);
    }

    ~FileRemover() {
      if (DeleteIt) {
                                             
        sys::fs::remove(Filename);
      }
    }

                                                                          
                                                                            
                                                 
    void setFile(const Twine& filename, bool deleteIt = true) {
      if (DeleteIt) {
                                             
        sys::fs::remove(Filename);
      }

      Filename.clear();
      filename.toVector(Filename);
      DeleteIt = deleteIt;
    }

                                                                                
                                                         
    void releaseFile() { DeleteIt = false; }
  };
}                      

#endif
