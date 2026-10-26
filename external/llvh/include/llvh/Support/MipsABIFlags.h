//===--- MipsABIFlags.h - MIPS ABI flags ----------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the constants for the ABI flags structure contained
// in the .MIPS.abiflags section.
//
// https://dmz-portal.mips.com/wiki/MIPS_O32_ABI_-_FR0_and_FR1_Interlinking
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_MIPSABIFLAGS_H
#define LLVM_SUPPORT_MIPSABIFLAGS_H

namespace llvh {
namespace Mips {

                                                           
enum AFL_REG {
  AFL_REG_NONE = 0x00,                
  AFL_REG_32 = 0x01,                      
  AFL_REG_64 = 0x02,                      
  AFL_REG_128 = 0x03                       
};

                                                     
enum AFL_ASE {
  AFL_ASE_DSP = 0x00000001,                 
  AFL_ASE_DSPR2 = 0x00000002,                  
  AFL_ASE_EVA = 0x00000004,                            
  AFL_ASE_MCU = 0x00000008,                                   
  AFL_ASE_MDMX = 0x00000010,                 
  AFL_ASE_MIPS3D = 0x00000020,                  
  AFL_ASE_MT = 0x00000040,                 
  AFL_ASE_SMARTMIPS = 0x00000080,                 
  AFL_ASE_VIRT = 0x00000100,               
  AFL_ASE_MSA = 0x00000200,                 
  AFL_ASE_MIPS16 = 0x00000400,                 
  AFL_ASE_MICROMIPS = 0x00000800,                 
  AFL_ASE_XPA = 0x00001000,                 
  AFL_ASE_CRC = 0x00008000,                 
  AFL_ASE_GINV = 0x00020000                  
};

                                                         
enum AFL_EXT {
  AFL_EXT_NONE = 0,                
  AFL_EXT_XLR = 1,                                
  AFL_EXT_OCTEON2 = 2,                                
  AFL_EXT_OCTEONP = 3,                                
  AFL_EXT_LOONGSON_3A = 4,                
  AFL_EXT_OCTEON = 5,                                
  AFL_EXT_5900 = 6,                                  
  AFL_EXT_4650 = 7,                                  
  AFL_EXT_4010 = 8,                                 
  AFL_EXT_4100 = 9,                                  
  AFL_EXT_3900 = 10,                                    
  AFL_EXT_10000 = 11,                                 
  AFL_EXT_SB1 = 12,                                     
  AFL_EXT_4111 = 13,                                        
  AFL_EXT_4120 = 14,                                 
  AFL_EXT_5400 = 15,                                 
  AFL_EXT_5500 = 16,                                 
  AFL_EXT_LOONGSON_2E = 17,                                   
  AFL_EXT_LOONGSON_2F = 18,                                   
  AFL_EXT_OCTEON3 = 19                                
};

                                                        
enum AFL_FLAGS1 { AFL_FLAGS1_ODDSPREG = 1 };

                             
enum {
  Tag_GNU_MIPS_ABI_FP = 4,                                                
  Tag_GNU_MIPS_ABI_MSA = 8,                                    
};

                                                       
                                                 
enum Val_GNU_MIPS_ABI_FP {
  Val_GNU_MIPS_ABI_FP_ANY = 0,                 
  Val_GNU_MIPS_ABI_FP_DOUBLE = 1,                               
  Val_GNU_MIPS_ABI_FP_SINGLE = 2,                               
  Val_GNU_MIPS_ABI_FP_SOFT = 3,                
  Val_GNU_MIPS_ABI_FP_OLD_64 = 4,                    
  Val_GNU_MIPS_ABI_FP_XX = 5,              
  Val_GNU_MIPS_ABI_FP_64 = 6,                        
  Val_GNU_MIPS_ABI_FP_64A = 7                                       
};

                                                     
enum Val_GNU_MIPS_ABI_MSA {
  Val_GNU_MIPS_ABI_MSA_ANY = 0,              
  Val_GNU_MIPS_ABI_MSA_128 = 1                
};
}
}

#endif
