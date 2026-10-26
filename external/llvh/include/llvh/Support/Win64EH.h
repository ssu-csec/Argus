//===-- llvm/Support/Win64EH.h ---Win64 EH Constants-------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains constants and structures used for implementing
// exception handling on Win64 platforms. For more information, see
// http://msdn.microsoft.com/en-us/library/1eyas8tf.aspx
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_WIN64EH_H
#define LLVM_SUPPORT_WIN64EH_H

#include "llvh/Support/DataTypes.h"
#include "llvh/Support/Endian.h"

namespace llvh {
namespace Win64EH {

                                                                          
                             
enum UnwindOpcodes {
  UOP_PushNonVol = 0,
  UOP_AllocLarge,
  UOP_AllocSmall,
  UOP_SetFPReg,
  UOP_SaveNonVol,
  UOP_SaveNonVolBig,
  UOP_SaveXMM128 = 8,
  UOP_SaveXMM128Big,
  UOP_PushMachFrame
};

                                                                              
                    
union UnwindCode {
  struct {
    uint8_t CodeOffset;
    uint8_t UnwindOpAndOpInfo;
  } u;
  support::ulittle16_t FrameOffset;

  uint8_t getUnwindOp() const {
    return u.UnwindOpAndOpInfo & 0x0F;
  }
  uint8_t getOpInfo() const {
    return (u.UnwindOpAndOpInfo >> 4) & 0x0F;
  }
};

enum {
                                                                          
              
  UNW_ExceptionHandler = 0x01,
                                                                           
              
  UNW_TerminateHandler = 0x02,
                                                                            
                  
  UNW_ChainInfo = 0x04
};

                                                                          
struct RuntimeFunction {
  support::ulittle32_t StartAddress;
  support::ulittle32_t EndAddress;
  support::ulittle32_t UnwindInfoOffset;
};

                                                 
struct UnwindInfo {
  uint8_t VersionAndFlags;
  uint8_t PrologSize;
  uint8_t NumCodes;
  uint8_t FrameRegisterAndOffset;
  UnwindCode UnwindCodes[1];

  uint8_t getVersion() const {
    return VersionAndFlags & 0x07;
  }
  uint8_t getFlags() const {
    return (VersionAndFlags >> 3) & 0x1f;
  }
  uint8_t getFrameRegister() const {
    return FrameRegisterAndOffset & 0x0f;
  }
  uint8_t getFrameOffset() const {
    return (FrameRegisterAndOffset >> 4) & 0x0f;
  }

                                                 
                                                                        
                                                            
                                                                         
                             
                                             
                                                          

                                                                  
  void *getLanguageSpecificData() {
    return reinterpret_cast<void *>(&UnwindCodes[(NumCodes+1) & ~1]);
  }

                                                                  
  const void *getLanguageSpecificData() const {
    return reinterpret_cast<const void *>(&UnwindCodes[(NumCodes + 1) & ~1]);
  }

                                                                          
  uint32_t getLanguageSpecificHandlerOffset() const {
    return *reinterpret_cast<const support::ulittle32_t *>(
               getLanguageSpecificData());
  }

                                                                       
  void setLanguageSpecificHandlerOffset(uint32_t offset) {
    *reinterpret_cast<support::ulittle32_t *>(getLanguageSpecificData()) =
        offset;
  }

                                                
  void *getExceptionData() {
    return reinterpret_cast<void *>(reinterpret_cast<uint32_t *>(
                                                  getLanguageSpecificData())+1);
  }

                                            
  RuntimeFunction *getChainedFunctionEntry() {
    return reinterpret_cast<RuntimeFunction *>(getLanguageSpecificData());
  }

                                            
  const RuntimeFunction *getChainedFunctionEntry() const {
    return reinterpret_cast<const RuntimeFunction *>(getLanguageSpecificData());
  }
};


}                            
}                         

#endif
