//===- SmallVectorMemoryBuffer.h --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares a wrapper class to hold the memory into which an
// object will be generated.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_EXECUTIONENGINE_OBJECTMEMORYBUFFER_H
#define LLVM_EXECUTIONENGINE_OBJECTMEMORYBUFFER_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/MemoryBuffer.h"
#include "llvh/Support/raw_ostream.h"

namespace llvh {

                                             
   
                                                                               
                                                                                
                                                                     
                  
class SmallVectorMemoryBuffer : public MemoryBuffer {
public:
                                                                     
              
     
                                                                             
                                                                              
                                                                        
                                                                              
                        
  SmallVectorMemoryBuffer(SmallVectorImpl<char> &&SV)
      : SV(std::move(SV)), BufferName("<in-memory object>") {
    init(this->SV.begin(), this->SV.end(), false);
  }

                                                              
                                        
  SmallVectorMemoryBuffer(SmallVectorImpl<char> &&SV, StringRef Name)
      : SV(std::move(SV)), BufferName(Name) {
    init(this->SV.begin(), this->SV.end(), false);
  }

                  
  ~SmallVectorMemoryBuffer() override;

  StringRef getBufferIdentifier() const override { return BufferName; }

  BufferKind getBufferKind() const override { return MemoryBuffer_Malloc; }

private:
  SmallVector<char, 0> SV;
  std::string BufferName;
};

}                  

#endif
