//===-- DataExtractor.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_DATAEXTRACTOR_H
#define LLVM_SUPPORT_DATAEXTRACTOR_H

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/DataTypes.h"

namespace llvh {

                                                                  
struct Uint24 {
  uint8_t Bytes[3];
  Uint24(uint8_t U) {
    Bytes[0] = Bytes[1] = Bytes[2] = U;
  }
  Uint24(uint8_t U0, uint8_t U1, uint8_t U2) {
    Bytes[0] = U0; Bytes[1] = U1; Bytes[2] = U2;
  }
  uint32_t getAsUint32(bool IsLittleEndian) const {
    int LoIx = IsLittleEndian ? 0 : 2;
    return Bytes[LoIx] + (Bytes[1] << 8) + (Bytes[2-LoIx] << 16);
  }
};

using uint24_t = Uint24;
static_assert(sizeof(uint24_t) == 3, "sizeof(uint24_t) != 3");

                              
inline uint24_t getSwappedBytes(uint24_t C) {
  return uint24_t(C.Bytes[2], C.Bytes[1], C.Bytes[0]);
}

class DataExtractor {
  StringRef Data;
  uint8_t IsLittleEndian;
  uint8_t AddressSize;
public:
                                                          
     
                                                                 
                                                                 
            
  DataExtractor(StringRef Data, bool IsLittleEndian, uint8_t AddressSize)
    : Data(Data), IsLittleEndian(IsLittleEndian), AddressSize(AddressSize) {}

                                                
  StringRef getData() const { return Data; }
                                            
  bool isLittleEndian() const { return IsLittleEndian; }
                                              
  uint8_t getAddressSize() const { return AddressSize; }
                                              
  void setAddressSize(uint8_t Size) { AddressSize = Size; }

                                             
     
                                                                 
                                                                      
                                                            
                                                               
                      
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                                                    
                                                                 
                                                                  
                                
  const char *getCStr(uint32_t *offset_ptr) const;

                                            
     
                                                                      
                                                                     
                                                           
                                                               
                      
     
                              
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                                                       
                                                                
                                                                  
                                                           
  StringRef getCStrRef(uint32_t *OffsetPtr) const;

                                                              
                  
     
                                                                   
                                                                    
                                                                    
                                                                      
                                                          
                                                                      
                                                       
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
                          
                                                     
     
             
                                                                   
                  
  uint64_t getUnsigned(uint32_t *offset_ptr, uint32_t byte_size) const;

                                                                         
     
                                                                        
                                                                    
                                                                      
                                                                   
                                                                  
                                                                    
                                                                        
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
                     
                                                      
     
             
                                                                    
                             
  int64_t getSigned(uint32_t *offset_ptr, uint32_t size) const;

                                                                      
                                             
     
                                                                  
                                                                    
                                                           
                                                           
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                                      
  uint64_t getAddress(uint32_t *offset_ptr) const {
    return getUnsigned(offset_ptr, AddressSize);
  }

                                                  
     
                                                                 
                                                                     
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                      
  uint8_t getU8(uint32_t *offset_ptr) const;

                                                          
     
                                                                 
                                                                   
                                                           
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
                     
                                                                    
                                                     
     
                      
                                                  
     
             
                                                                  
                        
  uint8_t *getU8(uint32_t *offset_ptr, uint8_t *dst, uint32_t count) const;

                                                                      
                                                   
     
                                                                  
                                                                    
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                       
                                                                      
  uint16_t getU16(uint32_t *offset_ptr) const;

                                                           
     
                                                                  
                                                                   
                                                           
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
                     
                                                                     
                                                     
     
                      
                                                   
     
             
                                                                  
                        
  uint16_t *getU16(uint32_t *offset_ptr, uint16_t *dst, uint32_t count) const;

                                                                       
                    
     
                                                                      
                                                                         
                 
     
                               
                                                                      
                                                                           
                                                                               
                                             
     
             
                                                               
  uint32_t getU24(uint32_t *offset_ptr) const;

                                                   
     
                                                                  
                                                                    
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                       
  uint32_t getU32(uint32_t *offset_ptr) const;

                                                           
     
                                                                  
                                                                   
                                                           
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
                     
                                                                     
                                                     
     
                      
                                                   
     
             
                                                                  
                        
  uint32_t *getU32(uint32_t *offset_ptr, uint32_t *dst, uint32_t count) const;

                                                   
     
                                                                  
                                                                    
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                       
  uint64_t getU64(uint32_t *offset_ptr) const;

                                                           
     
                                                                  
                                                                   
                                                           
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
                     
                                                                     
                                                     
     
                      
                                                   
     
             
                                                                  
                        
  uint64_t *getU64(uint32_t *offset_ptr, uint64_t *dst, uint32_t count) const;

                                                        
     
                                                              
                                                                    
                                                                    
                                                 
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                             
  int64_t getSLEB128(uint32_t *offset_ptr) const;

                                                          
     
                                                                
                                                                    
                                                                    
                                                 
     
                               
                                                                      
                                                                      
                                                                    
                                                                     
                     
     
             
                                               
  uint64_t getULEB128(uint32_t *offset_ptr) const;

                                     
     
             
                                                                      
                                     
  bool isValidOffset(uint32_t offset) const { return Data.size() > offset; }

                                                                      
     
             
                                                                 
                                                                    
  bool isValidOffsetForDataOfSize(uint32_t offset, uint32_t length) const {
    return offset + length >= offset && isValidOffset(offset + length - 1);
  }

                                                                      
                                                              
     
             
                                                                     
                                                                
                    
  bool isValidOffsetForAddress(uint32_t offset) const {
    return isValidOffsetForDataOfSize(offset, AddressSize);
  }
};

}                  

#endif
