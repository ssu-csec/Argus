//===-- llvm/Support/circular_raw_ostream.h - Buffered streams --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains raw_ostream implementations for streams to do circular
// buffering of their output.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_CIRCULAR_RAW_OSTREAM_H
#define LLVM_SUPPORT_CIRCULAR_RAW_OSTREAM_H

#include "llvh/Support/raw_ostream.h"

namespace llvh {
                                                                    
                                                                 
                                                           
     
  class circular_raw_ostream : public raw_ostream {
  public:
                                                                     
                                                                
                    
       
    static const bool TAKE_OWNERSHIP = true;

                                                                  
                    
       
    static const bool REFERENCE_ONLY = false;

  private:
                                                                 
                                                                
       
    raw_ostream *TheStream;

                                                                   
               
       
    bool OwnsStream;

                                                     
       
    size_t BufferSize;

                                                
       
    char *BufferArray;

                                                                 
       
    char *Cur;

                                                                
                                                 
       
    bool Filled;

                                                                  
            
       
    const char *Banner;

                                                                
       
    void flushBuffer() {
      if (Filled)
                                                 
        TheStream->write(Cur, BufferArray + BufferSize - Cur);
                                               
      TheStream->write(BufferArray, Cur - BufferArray);
      Cur = BufferArray;
      Filled = false;
    }

    void write_impl(const char *Ptr, size_t Size) override;

                                                                    
                                                       
       
    uint64_t current_pos() const override {
                                                                     
                                       
      return TheStream->tell() - TheStream->GetNumBytesInBuffer();
    }

  public:
                                                      
                                                                    
                             
       
                                                                     
                                                                   
                                                                   
                                                
       
                                                           
                                                              
                              
       
    circular_raw_ostream(raw_ostream &Stream, const char *Header,
                         size_t BuffSize = 0, bool Owns = REFERENCE_ONLY)
        : raw_ostream(               true), TheStream(nullptr),
          OwnsStream(Owns), BufferSize(BuffSize), BufferArray(nullptr),
          Filled(false), Banner(Header) {
      if (BufferSize != 0)
        BufferArray = new char[BufferSize];
      Cur = BufferArray;
      setStream(Stream, Owns);
    }

    ~circular_raw_ostream() override {
      flush();
      flushBufferWithBanner();
      releaseStream();
      delete[] BufferArray;
    }

                                                             
                                                                    
                                                                 
               
       
    void setStream(raw_ostream &Stream, bool Owns = REFERENCE_ONLY) {
      releaseStream();
      TheStream = &Stream;
      OwnsStream = Owns;
    }

                                                                     
                       
       
    void flushBufferWithBanner();

  private:
                                                                    
                                                                   
                                      
       
    void releaseStream() {
      if (!TheStream)
        return;
      if (OwnsStream)
        delete TheStream;
    }
  };
}                      

#endif
