//===-- ARMBuildAttributes.h - ARM Build Attributes -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains enumerations and support routines for ARM build attributes
// as defined in ARM ABI addenda document (ABI release 2.08).
//
// ELF for the ARM Architecture r2.09 - November 30, 2012
//
// http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ARMBUILDATTRIBUTES_H
#define LLVM_SUPPORT_ARMBUILDATTRIBUTES_H

namespace llvh {
class StringRef;

namespace ARMBuildAttrs {

enum SpecialAttr {
                                                                  
                                                                        
  SEL_CPU
};

enum AttrType {
                                           
  File                      = 1,
  CPU_raw_name              = 4,
  CPU_name                  = 5,
  CPU_arch                  = 6,
  CPU_arch_profile          = 7,
  ARM_ISA_use               = 8,
  THUMB_ISA_use             = 9,
  FP_arch                   = 10,
  WMMX_arch                 = 11,
  Advanced_SIMD_arch        = 12,
  PCS_config                = 13,
  ABI_PCS_R9_use            = 14,
  ABI_PCS_RW_data           = 15,
  ABI_PCS_RO_data           = 16,
  ABI_PCS_GOT_use           = 17,
  ABI_PCS_wchar_t           = 18,
  ABI_FP_rounding           = 19,
  ABI_FP_denormal           = 20,
  ABI_FP_exceptions         = 21,
  ABI_FP_user_exceptions    = 22,
  ABI_FP_number_model       = 23,
  ABI_align_needed          = 24,
  ABI_align_preserved       = 25,
  ABI_enum_size             = 26,
  ABI_HardFP_use            = 27,
  ABI_VFP_args              = 28,
  ABI_WMMX_args             = 29,
  ABI_optimization_goals    = 30,
  ABI_FP_optimization_goals = 31,
  compatibility             = 32,
  CPU_unaligned_access      = 34,
  FP_HP_extension           = 36,
  ABI_FP_16bit_format       = 38,
  MPextension_use           = 42,                               
  DIV_use                   = 44,
  DSP_extension             = 46,
  also_compatible_with      = 65,
  conformance               = 67,
  Virtualization_use        = 68,

                 
  Section                   = 2,                           
  Symbol                    = 3,                           
  ABI_align8_needed         = 24,                                           
  ABI_align8_preserved      = 25,                                              
  nodefaults                = 64,                          
  T2EE_use                  = 66,                          
  MPextension_use_old       = 70                                           
};

StringRef AttrTypeAsString(unsigned Attr, bool HasTagPrefix = true);
StringRef AttrTypeAsString(AttrType Attr, bool HasTagPrefix = true);
int AttrTypeFromString(StringRef Tag);

                                    
enum AttrMagic {
  Format_Version  = 0x41
};

                                           
enum CPUArch {
  Pre_v4   = 0,
  v4       = 1,                
  v4T      = 2,                   
  v5T      = 3,                   
  v5TE     = 4,                    
  v5TEJ    = 5,                     
  v6       = 6,                     
  v6KZ     = 7,                      
  v6T2     = 8,                      
  v6K      = 9,                      
  v7       = 10,                              
  v6_M     = 11,                   
  v6S_M    = 12,                                    
  v7E_M    = 13,                             
  v8_A     = 14,                 
  v8_R     = 15,                    
  v8_M_Base= 16,                      
  v8_M_Main= 17,                      
};

enum CPUArchProfile {                               
  Not_Applicable          = 0,                                      
  ApplicationProfile      = (0x41),                            
  RealTimeProfile         = (0x52),                            
  MicroControllerProfile  = (0x4D),                            
  SystemProfile           = (0x53)                                         
};

                                               
enum {
  Not_Allowed = 0,
  Allowed = 1,

                                  

                                     
  AllowThumb32 = 2,                                              
  AllowThumbDerived = 3,                                            

                                                            
  AllowFPv2  = 2,                                                          
  AllowFPv3A = 3,                                                          
  AllowFPv3B = 4,                                                    
  AllowFPv4A = 5,                                                      
  AllowFPv4B = 6,                                                        
  AllowFPARMv8A = 7,                                             
  AllowFPARMv8B = 8,                                                       
                                       

                                  
  AllowWMMXv1 = 1,                                                  
  AllowWMMXv2 = 2,                                                  

                                           
  AllowNeon = 1,                             
  AllowNeon2 = 2,                                                                
  AllowNeonARMv8 = 3,                               
  AllowNeonARMv8_1a = 4,                                       

                                       
  R9IsGPR = 0,                                                             
  R9IsSB = 1,                                                   
  R9IsTLSPointer = 2,                                             
  R9Reserved = 3,                                                             

                                        
  AddressRWPCRel = 1,                                      
  AddressRWSBRel = 2,                                      
  AddressRWNone = 3,                               

                                        
  AddressROPCRel = 1,                                      
  AddressRONone = 2,                               

                                        
  AddressDirect = 1,                                  
  AddressGOT = 2,                                              

                                        
  WCharProhibited = 0,                        
  WCharWidth2Bytes = 2,                        
  WCharWidth4Bytes = 4,                        

                                         
  Align8Byte = 1,
  Align4Byte = 2,
  AlignReserved = 3,

                                         
  AlignNotPreserved = 0,
  AlignPreserve8Byte = 1,
  AlignPreserveAll = 2,

                                        
  PositiveZero = 0,
  IEEEDenormals = 1,
  PreserveFPSign = 2,                                          

                                            
  AllowIEEENormal = 1,
  AllowRTABI = 2,                                                         
  AllowIEEE754 = 3,                                                          

                                      
  EnumProhibited = 0,                                                      
                                     
  EnumSmallest = 1,                                                       
                                
  Enum32Bit = 2,                                  
  Enum32BitABI = 3,                                                       
                                                                             
                                                              

                                       
  HardFPImplied = 0,                                                    
  HardFPSinglePrecision = 1,                          

                                     
  BaseAAPCS = 0,
  HardFPAAPCS = 1,
  ToolChainFPPCS = 2,
  CompatibleFPAAPCS = 3,

                                        
  AllowHPFP = 1,                                  

                                        
  FP16FormatIEEE = 1,
  FP16VFP3 = 2,

                                        
  AllowMP = 1,                              

                                
                                                                           
                                                                             
  AllowDIVIfExists = 0,                                                     
                                       
  DisallowDIV = 1,                                               
  AllowDIVExt = 2,                                                       
                                                                     
                                                                 

                                           
  AllowTZ = 1,
  AllowVirtualization = 2,
  AllowTZVirtualization = 3
};

}                           
}                  

#endif
