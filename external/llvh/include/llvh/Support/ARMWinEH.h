//===-- llvm/Support/WinARMEH.h - Windows on ARM EH Constants ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ARMWINEH_H
#define LLVM_SUPPORT_ARMWINEH_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/Support/Endian.h"

namespace llvh {
namespace ARM {
namespace WinEH {
enum class RuntimeFunctionFlag {
  RFF_Unpacked,                         
  RFF_Packed,                         
  RFF_PackedFragment,                                         
  RFF_Reserved,                   
};

enum class ReturnType {
  RT_POP,                                                         
  RT_B,                                
  RT_BW,                               
  RT_NoEpilogue,                                
};

                                                                      
   
                                                                    
                                                                    
                                                                     
                                                                     
                                                                     
                                                                     
                                                                     
   
                                                   
                                                                               
                               
                                                                             
                                                                                
                     
                     
                                                                              
                                                                             
                                                                    
                                                         
                                                        
                                     
                                     
                                                                               
                                                   
                                                                                
                                                           
                                                                         
                                                                              
                                                                            
                                                                          
                                                                               
                                                     
                                                                               
                                                                              
                                                                             
                                                 
                                                                          
                     
                                                                              
                                                                             
                                                                             
                                                                                
                                                                              
                                                                           
                                                                                
                            
                                                                               
                          
                                                                            
                          
                                                                           
   
                 
                    
                                                                     
                                                                           
                    
                            

                                                                               
                                                                             
                                                                                
                                                                              
                                                                            
                                                               

class RuntimeFunction {
public:
  const support::ulittle32_t BeginAddress;
  const support::ulittle32_t UnwindData;

  RuntimeFunction(const support::ulittle32_t *Data)
    : BeginAddress(Data[0]), UnwindData(Data[1]) {}

  RuntimeFunction(const support::ulittle32_t BeginAddress,
                  const support::ulittle32_t UnwindData)
    : BeginAddress(BeginAddress), UnwindData(UnwindData) {}

  RuntimeFunctionFlag Flag() const {
    return RuntimeFunctionFlag(UnwindData & 0x3);
  }

  uint32_t ExceptionInformationRVA() const {
    assert(Flag() == RuntimeFunctionFlag::RFF_Unpacked &&
           "unpacked form required for this operation");
    return (UnwindData & ~0x3);
  }

  uint32_t PackedUnwindData() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    return (UnwindData & ~0x3);
  }
  uint32_t FunctionLength() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    return (((UnwindData & 0x00001ffc) >> 2) << 1);
  }
  ReturnType Ret() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    assert(((UnwindData & 0x00006000) || L()) && "L must be set to 1");
    return ReturnType((UnwindData & 0x00006000) >> 13);
  }
  bool H() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    return ((UnwindData & 0x00008000) >> 15);
  }
  uint8_t Reg() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    return ((UnwindData & 0x00070000) >> 16);
  }
  bool R() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    return ((UnwindData & 0x00080000) >> 19);
  }
  bool L() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    return ((UnwindData & 0x00100000) >> 20);
  }
  bool C() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    assert(((~UnwindData & 0x00200000) || L()) &&
           "L flag must be set, chaining requires r11 and LR");
    assert(((~UnwindData & 0x00200000) || (Reg() < 7) || R()) &&
           "r11 must not be included in Reg; C implies r11");
    return ((UnwindData & 0x00200000) >> 21);
  }
  uint16_t StackAdjust() const {
    assert((Flag() == RuntimeFunctionFlag::RFF_Packed ||
            Flag() == RuntimeFunctionFlag::RFF_PackedFragment) &&
           "packed form required for this operation");
    return ((UnwindData & 0xffc00000) >> 22);
  }
};

                                                                               
                                                        
inline bool PrologueFolding(const RuntimeFunction &RF) {
  return RF.StackAdjust() >= 0x3f4 && (RF.StackAdjust() & 0x4);
}
                                                                        
                                                       
inline bool EpilogueFolding(const RuntimeFunction &RF) {
  return RF.StackAdjust() >= 0x3f4 && (RF.StackAdjust() & 0x8);
}
                                                                      
                                                                                
                                                             
inline uint16_t StackAdjustment(const RuntimeFunction &RF) {
  uint16_t Adjustment = RF.StackAdjust();
  if (Adjustment >= 0x3f4)
    return (Adjustment & 0x3) ? ((Adjustment & 0x3) << 2) - 1 : 0;
  return Adjustment;
}

                                                                              
                                                
std::pair<uint16_t, uint32_t> SavedRegisterMask(const RuntimeFunction &RF);

                                                                          
   
                                                                    
                                                                    
                                                                     
                                                                     
                                                                     
                                                                     
                                                                     
   
                                                                              
                                                                          
                                                                                
                                                                               
                                                                         
                                                             
                                                                          
              
                                                                            
                                                                               
                
                                                                              
   
                                                                            
                                                                      
   
                                                                            
                                                                               
                                                                                
                                                   
                                                                              
                                                                              
                                                                            
                                                                               
                             
                                                  
                                                                               
                                                                            
                                                                 
   
                                                                    
                                                                    
                                                                     
                                                                     
                                                                     
   
                                                                              
                                                      
   
                                                                                
                                                                               
                                                                      
                                                                               
                                                                                
                                                                               
                                                                             
                                    
                                                                             
                                                              
   
                                                                    
                                                                    
                                                                     
                                                                     
                                                                     
   
                                                                         
                                                                                
                  
   
                                                                    
                                                                    
                                                                     
                                                                     
                                                                     
                                                                     
                                                                     
   
                                                                              
                                                                               
                                                                              
                                                               
   

struct EpilogueScope {
  const support::ulittle32_t ES;

  EpilogueScope(const support::ulittle32_t Data) : ES(Data) {}
  uint32_t EpilogueStartOffset() const {
    return (ES & 0x0003ffff);
  }
  uint8_t Res() const {
    return ((ES & 0x000c0000) >> 18);
  }
  uint8_t Condition() const {
    return ((ES & 0x00f00000) >> 20);
  }
  uint8_t EpilogueStartIndex() const {
    return ((ES & 0xff000000) >> 24);
  }
};

struct ExceptionDataRecord;
inline size_t HeaderWords(const ExceptionDataRecord &XR);

struct ExceptionDataRecord {
  const support::ulittle32_t *Data;

  ExceptionDataRecord(const support::ulittle32_t *Data) : Data(Data) {}

  uint32_t FunctionLength() const {
    return (Data[0] & 0x0003ffff);
  }

  uint8_t Vers() const {
    return (Data[0] & 0x000C0000) >> 18;
  }

  bool X() const {
    return ((Data[0] & 0x00100000) >> 20);
  }

  bool E() const {
    return ((Data[0] & 0x00200000) >> 21);
  }

  bool F() const {
    return ((Data[0] & 0x00400000) >> 22);
  }

  uint8_t EpilogueCount() const {
    if (HeaderWords(*this) == 1)
      return (Data[0] & 0x0f800000) >> 23;
    return Data[1] & 0x0000ffff;
  }

  uint8_t CodeWords() const {
    if (HeaderWords(*this) == 1)
      return (Data[0] & 0xf0000000) >> 28;
    return (Data[1] & 0x00ff0000) >> 16;
  }

  ArrayRef<support::ulittle32_t> EpilogueScopes() const {
    assert(E() == 0 && "epilogue scopes are only present when the E bit is 0");
    size_t Offset = HeaderWords(*this);
    return makeArrayRef(&Data[Offset], EpilogueCount());
  }

  ArrayRef<uint8_t> UnwindByteCode() const {
    const size_t Offset = HeaderWords(*this)
                        + (E() ? 0 :  EpilogueCount());
    const uint8_t *ByteCode =
      reinterpret_cast<const uint8_t *>(&Data[Offset]);
    return makeArrayRef(ByteCode, CodeWords() * sizeof(uint32_t));
  }

  uint32_t ExceptionHandlerRVA() const {
    assert(X() && "Exception Handler RVA is only valid if the X bit is set");
    return Data[HeaderWords(*this) + EpilogueCount() + CodeWords()];
  }

  uint32_t ExceptionHandlerParameter() const {
    assert(X() && "Exception Handler RVA is only valid if the X bit is set");
    return Data[HeaderWords(*this) + EpilogueCount() + CodeWords() + 1];
  }
};

inline size_t HeaderWords(const ExceptionDataRecord &XR) {
  return (XR.Data[0] & 0xff800000) ? 1 : 2;
}
}
}
}

#endif
