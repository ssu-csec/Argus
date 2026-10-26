//===- Win32/Memory.cpp - Win32 Memory Implementation -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Win32 specific implementation of various Memory
// management utilities
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/DataTypes.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/Process.h"
#include "llvh/Support/WindowsError.h"

                                                      
#include "WindowsSupport.h"

namespace {

DWORD getWindowsProtectionFlags(unsigned Flags) {
  switch (Flags) {
                                                                         
                                                
  case llvh::sys::Memory::MF_READ:
    return PAGE_READONLY;
  case llvh::sys::Memory::MF_WRITE:
                                                          
    return PAGE_READWRITE;
  case llvh::sys::Memory::MF_READ|llvh::sys::Memory::MF_WRITE:
    return PAGE_READWRITE;
  case llvh::sys::Memory::MF_READ|llvh::sys::Memory::MF_EXEC:
    return PAGE_EXECUTE_READ;
  case llvh::sys::Memory::MF_READ |
         llvh::sys::Memory::MF_WRITE |
         llvh::sys::Memory::MF_EXEC:
    return PAGE_EXECUTE_READWRITE;
  case llvh::sys::Memory::MF_EXEC:
    return PAGE_EXECUTE;
  default:
    llvm_unreachable("Illegal memory protection flag specified!");
  }
                                                                  
  return PAGE_NOACCESS;
}

size_t getAllocationGranularity() {
  SYSTEM_INFO  Info;
  ::GetSystemInfo(&Info);
  if (Info.dwPageSize > Info.dwAllocationGranularity)
    return Info.dwPageSize;
  else
    return Info.dwAllocationGranularity;
}

}             

namespace llvh {
namespace sys {

                                                                                
                                                                        
                                        
                                                                                

MemoryBlock Memory::allocateMappedMemory(size_t NumBytes,
                                         const MemoryBlock *const NearBlock,
                                         unsigned Flags,
                                         std::error_code &EC) {
  EC = std::error_code();
  if (NumBytes == 0)
    return MemoryBlock();

                                                                         
                                                                          
                                                                             
                                                                          
                                  
  static volatile size_t GranularityCached;
  size_t Granularity = GranularityCached;
  if (Granularity == 0) {
    Granularity = getAllocationGranularity();
    GranularityCached = Granularity;
  }

  const size_t NumBlocks = (NumBytes+Granularity-1)/Granularity;

  uintptr_t Start = NearBlock ? reinterpret_cast<uintptr_t>(NearBlock->base()) +
                                NearBlock->size()
                           : 0;

                                                                           
                                                                            
  if (Start && Start % Granularity != 0)
    Start += Granularity - Start % Granularity;

  DWORD Protect = getWindowsProtectionFlags(Flags);

  void *PA = ::VirtualAlloc(reinterpret_cast<void*>(Start),
                            NumBlocks*Granularity,
                            MEM_RESERVE | MEM_COMMIT, Protect);
  if (PA == NULL) {
    if (NearBlock) {
                                             
      return allocateMappedMemory(NumBytes, NULL, Flags, EC);
    }
    EC = mapWindowsError(::GetLastError());
    return MemoryBlock();
  }

  MemoryBlock Result;
  Result.Address = PA;
  Result.Size = NumBlocks*Granularity;

  if (Flags & MF_EXEC)
    Memory::InvalidateInstructionCache(Result.Address, Result.Size);

  return Result;
}

  std::error_code Memory::releaseMappedMemory(MemoryBlock &M) {
  if (M.Address == 0 || M.Size == 0)
    return std::error_code();

  if (!VirtualFree(M.Address, 0, MEM_RELEASE))
    return mapWindowsError(::GetLastError());

  M.Address = 0;
  M.Size = 0;

  return std::error_code();
}

  std::error_code Memory::protectMappedMemory(const MemoryBlock &M,
                                       unsigned Flags) {
  if (M.Address == 0 || M.Size == 0)
    return std::error_code();

  DWORD Protect = getWindowsProtectionFlags(Flags);

  DWORD OldFlags;
  if (!VirtualProtect(M.Address, M.Size, Protect, &OldFlags))
    return mapWindowsError(::GetLastError());

  if (Flags & MF_EXEC)
    Memory::InvalidateInstructionCache(M.Address, M.Size);

  return std::error_code();
}

                                                                       
                                                                          
              
void Memory::InvalidateInstructionCache(
    const void *Addr, size_t Len) {
  FlushInstructionCache(GetCurrentProcess(), Addr, Len);
}

}                 
}                  
