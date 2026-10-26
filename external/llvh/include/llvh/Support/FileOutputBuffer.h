//=== FileOutputBuffer.h - File Output Buffer -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Utility for creating a in-memory buffer that will be written to a file.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FILEOUTPUTBUFFER_H
#define LLVM_SUPPORT_FILEOUTPUTBUFFER_H

#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/DataTypes.h"
#include "llvh/Support/Error.h"
#include "llvh/Support/FileSystem.h"

namespace llvh {
                                                                                
                                                                        
                                                                              
                                                                            
                                                                               
                                                                             
                                                                               
class FileOutputBuffer {
public:
  enum {
                                             
    F_executable = 1,

                                                                              
                                                                              
                      
    F_modify = 2
  };

                                                                                
                                                                              
                                        
     
                                                                              
                                                                           
                                                                             
                                                                             
                     
  static Expected<std::unique_ptr<FileOutputBuffer>>
  create(StringRef FilePath, size_t Size, unsigned Flags = 0);

                                                   
  virtual uint8_t *getBufferStart() const = 0;

                                                 
  virtual uint8_t *getBufferEnd() const = 0;

                                 
  virtual size_t getBufferSize() const = 0;

                                                                  
  StringRef getPath() const { return FinalPath; }

                                                                       
                                                                        
                                                                              
                                                                       
                          
  virtual Error commit() = 0;

                                                                          
                                                                    
                                                                  
  virtual ~FileOutputBuffer() {}

                                                                       
                                         
  virtual void discard() {}

protected:
  FileOutputBuffer(StringRef Path) : FinalPath(Path) {}

  std::string FinalPath;
};
}                      

#endif
