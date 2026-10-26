//===-- llvm/Support/FormattedStream.h - Formatted streams ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains raw_ostream implementations for streams to do
// things like pretty-print comments.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FORMATTEDSTREAM_H
#define LLVM_SUPPORT_FORMATTEDSTREAM_H

#include "llvh/Support/raw_ostream.h"
#include <utility>

namespace llvh {

                                                                                
                                                                        
                                                                      
   
class formatted_raw_ostream : public raw_ostream {
                                                               
                                                              
     
  raw_ostream *TheStream;

                                                                      
                                                            
                                                         
     
  std::pair<unsigned, unsigned> Position;

                                                                 
                           
     
  const char *Scanned;

  void write_impl(const char *Ptr, size_t Size) override;

                                                                  
                                                     
  uint64_t current_pos() const override {
                                                                             
                                                                          
                          
    return TheStream->tell();
  }

                                                                              
                            
     
  void ComputePosition(const char *Ptr, size_t size);

  void setStream(raw_ostream &Stream) {
    releaseStream();

    TheStream = &Stream;

                                                                            
                                                                         
                                                                         
                                                                      
    if (size_t BufferSize = TheStream->GetBufferSize())
      SetBufferSize(BufferSize);
    else
      SetUnbuffered();
    TheStream->SetUnbuffered();

    Scanned = nullptr;
  }

public:
                                                         
                                                                 
                                                              
                                                               
     
                                                                 
                                                                   
                                                                   
                    
     
  formatted_raw_ostream(raw_ostream &Stream)
      : TheStream(nullptr), Position(0, 0) {
    setStream(Stream);
  }
  explicit formatted_raw_ostream() : TheStream(nullptr), Position(0, 0) {
    Scanned = nullptr;
  }

  ~formatted_raw_ostream() override {
    flush();
    releaseStream();
  }

                                                                           
                                                                             
            
     
                                            
  formatted_raw_ostream &PadToColumn(unsigned NewCol);

                                          
  unsigned getColumn() { return Position.first; }

                                      
  unsigned getLine() { return Position.second; }

  raw_ostream &resetColor() override {
    TheStream->resetColor();
    return *this;
  }

  raw_ostream &reverseColor() override {
    TheStream->reverseColor();
    return *this;
  }

  raw_ostream &changeColor(enum Colors Color, bool Bold, bool BG) override {
    TheStream->changeColor(Color, Bold, BG);
    return *this;
  }

  bool is_displayed() const override {
    return TheStream->is_displayed();
  }

private:
  void releaseStream() {
                                                                                
              
    if (!TheStream)
      return;
    if (size_t BufferSize = GetBufferSize())
      TheStream->SetBufferSize(BufferSize);
    else
      TheStream->SetUnbuffered();
  }
};

                                                                     
                                                             
formatted_raw_ostream &fouts();

                                                                     
                                                            
formatted_raw_ostream &ferrs();

                                                                     
                                                          
formatted_raw_ostream &fdbgs();

}                      


#endif
