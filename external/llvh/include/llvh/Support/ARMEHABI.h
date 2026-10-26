//===--- ARMEHABI.h - ARM Exception Handling ABI ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the constants for the ARM unwind opcodes and exception
// handling table entry kinds.
//
// The enumerations and constants in this file reflect the ARM EHABI
// Specification as published by ARM.
//
// Exception Handling ABI for the ARM Architecture r2.09 - November 30, 2012
//
// http://infocenter.arm.com/help/topic/com.arm.doc.ihi0038a/IHI0038A_ehabi.pdf
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ARMEHABI_H
#define LLVM_SUPPORT_ARMEHABI_H

namespace llvh {
namespace ARM {
namespace EHABI {
                                              
  enum EHTEntryKind {
    EHT_GENERIC = 0x00,
    EHT_COMPACT = 0x80
  };

  enum {
                                                   
    EXIDX_CANTUNWIND = 0x1
  };

                                         
  enum UnwindOpcodes {
                       
                                          
    UNWIND_OPCODE_INC_VSP = 0x00,

                       
                                          
    UNWIND_OPCODE_DEC_VSP = 0x40,

                                
                                
    UNWIND_OPCODE_REFUSE = 0x8000,

                                
                                     
                         
    UNWIND_OPCODE_POP_REG_MASK_R4 = 0x8000,

                       
                          
                                     
    UNWIND_OPCODE_SET_VSP = 0x90,

                       
                              
    UNWIND_OPCODE_POP_REG_RANGE_R4 = 0xa0,

                       
                                   
    UNWIND_OPCODE_POP_REG_RANGE_R4_R14 = 0xa8,

                       
                      
    UNWIND_OPCODE_FINISH = 0xb0,

                                
                          
                         
    UNWIND_OPCODE_POP_REG_MASK = 0xb100,

                                  
                                              
    UNWIND_OPCODE_INC_VSP_ULEB128 = 0xb2,

                                
                              
    UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDX = 0xb300,

                       
                              
    UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDX_D8 = 0xb8,

                       
                                 
    UNWIND_OPCODE_POP_WIRELESS_MMX_REG_RANGE_WR10 = 0xc0,

                                
                               
    UNWIND_OPCODE_POP_WIRELESS_MMX_REG_RANGE = 0xc600,

                                
                             
                         
    UNWIND_OPCODE_POP_WIRELESS_MMX_REG_MASK = 0xc700,

                                
                                      
    UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDD_D16 = 0xc800,

                                
                              
    UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDD = 0xc900,

                       
                              
    UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDD_D8 = 0xd0
  };

                                           
  enum PersonalityRoutineIndex {
                                                                            
                                                                    
                                                                              
                                                
    AEABI_UNWIND_CPP_PR0 = 0,
    AEABI_UNWIND_CPP_PR1 = 1,
    AEABI_UNWIND_CPP_PR2 = 2,

    NUM_PERSONALITY_INDEX
  };
}
}
}

#endif
