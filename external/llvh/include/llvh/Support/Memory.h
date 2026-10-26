//===- llvm/Support/Memory.h - Memory Support -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the llvh::sys::Memory class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_MEMORY_H
#define LLVM_SUPPORT_MEMORY_H

#include "llvh/Support/DataTypes.h"
#include <string>
#include <system_error>

namespace llvh {
namespace sys {

                                                                               
                                                                            
                                           
                 
                               
  class MemoryBlock {
  public:
    MemoryBlock() : Address(nullptr), Size(0) { }
    MemoryBlock(void *addr, size_t size) : Address(addr), Size(size) { }
    void *base() const { return Address; }
    size_t size() const { return Size; }

  private:
    void *Address;                                             
    size_t Size;                                            
    friend class Memory;
  };

                                                                           
                            
                
                                           
  class Memory {
  public:
    enum ProtectionFlags {
      MF_READ  = 0x1000000,
      MF_WRITE = 0x2000000,
      MF_EXEC  = 0x4000000
    };

                                                                            
                                                                     
                                                    
                                                                      
                                                                           
                                                                               
                
                                                                          
                      
                                                                       
       
                                                                              
                                                                     
                    
       
                                                                 
                                                                           
                                                                           
                                                               
       
                                                                 
                                                                        
       
                               
    static MemoryBlock allocateMappedMemory(size_t NumBytes,
                                            const MemoryBlock *const NearBlock,
                                            unsigned Flags,
                                            std::error_code &EC);

                                                                          
                                                                         
                                             
                                                     
       
                                                                         
                                                    
       
                              
    static std::error_code releaseMappedMemory(MemoryBlock &Block);

                                                                          
                                                                          
                                                                       
                                                            
                                                                                
                                                                            
       
                                                           
                                                                              
                                                                          
       
                                                                         
                                                    
       
                                    
    static std::error_code protectMappedMemory(const MemoryBlock &Block,
                                               unsigned Flags);

                                                                           
                                                                              
                  
    static void InvalidateInstructionCache(const void *Addr, size_t Len);
  };

                                    
  class OwningMemoryBlock {
  public:
    OwningMemoryBlock() = default;
    explicit OwningMemoryBlock(MemoryBlock M) : M(M) {}
    OwningMemoryBlock(OwningMemoryBlock &&Other) {
      M = Other.M;
      Other.M = MemoryBlock();
    }
    OwningMemoryBlock& operator=(OwningMemoryBlock &&Other) {
      M = Other.M;
      Other.M = MemoryBlock();
      return *this;
    }
    ~OwningMemoryBlock() {
      Memory::releaseMappedMemory(M);
    }
    void *base() const { return M.base(); }
    size_t size() const { return M.size(); }
    MemoryBlock getMemoryBlock() const { return M; }
  private:
    MemoryBlock M;
  };

}
}

#endif
