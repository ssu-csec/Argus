//===--- AMDGPUMetadata.h ---------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// \file
/// AMDGPU metadata definitions and in-memory representations.
///
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_AMDGPUMETADATA_H
#define LLVM_SUPPORT_AMDGPUMETADATA_H

#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

namespace llvh {
namespace AMDGPU {

                                                                                
                
                                                                                
namespace HSAMD {

                               
constexpr uint32_t VersionMajor = 1;
                               
constexpr uint32_t VersionMinor = 0;

                                               
constexpr char AssemblerDirectiveBegin[] = ".amd_amdgpu_hsa_metadata";
                                            
constexpr char AssemblerDirectiveEnd[] = ".end_amd_amdgpu_hsa_metadata";

                      
enum class AccessQualifier : uint8_t {
  Default   = 0,
  ReadOnly  = 1,
  WriteOnly = 2,
  ReadWrite = 3,
  Unknown   = 0xff
};

                             
enum class AddressSpaceQualifier : uint8_t {
  Private  = 0,
  Global   = 1,
  Constant = 2,
  Local    = 3,
  Generic  = 4,
  Region   = 5,
  Unknown  = 0xff
};

                
enum class ValueKind : uint8_t {
  ByValue                = 0,
  GlobalBuffer           = 1,
  DynamicSharedPointer   = 2,
  Sampler                = 3,
  Image                  = 4,
  Pipe                   = 5,
  Queue                  = 6,
  HiddenGlobalOffsetX    = 7,
  HiddenGlobalOffsetY    = 8,
  HiddenGlobalOffsetZ    = 9,
  HiddenNone             = 10,
  HiddenPrintfBuffer     = 11,
  HiddenDefaultQueue     = 12,
  HiddenCompletionAction = 13,
  Unknown                = 0xff
};

                
enum class ValueType : uint8_t {
  Struct  = 0,
  I8      = 1,
  U8      = 2,
  I16     = 3,
  U16     = 4,
  F16     = 5,
  I32     = 6,
  U32     = 7,
  F32     = 8,
  I64     = 9,
  U64     = 10,
  F64     = 11,
  Unknown = 0xff
};

                                                                                
                   
                                                                                
namespace Kernel {

                                                                                
                              
                                                                                
namespace Attrs {

namespace Key {
                                                       
constexpr char ReqdWorkGroupSize[] = "ReqdWorkGroupSize";
                                                       
constexpr char WorkGroupSizeHint[] = "WorkGroupSizeHint";
                                                 
constexpr char VecTypeHint[] = "VecTypeHint";
                                                   
constexpr char RuntimeHandle[] = "RuntimeHandle";
}                     

                                                           
struct Metadata final {
                                                 
  std::vector<uint32_t> mReqdWorkGroupSize = std::vector<uint32_t>();
                                                 
  std::vector<uint32_t> mWorkGroupSizeHint = std::vector<uint32_t>();
                                          
  std::string mVecTypeHint = std::string();
                                                                    
                          
  std::string mRuntimeHandle = std::string();

                          
  Metadata() = default;

                                                                            
  bool empty() const {
    return !notEmpty();
  }

                                                                                
  bool notEmpty() const {
    return !mReqdWorkGroupSize.empty() || !mWorkGroupSizeHint.empty() ||
           !mVecTypeHint.empty() || !mRuntimeHandle.empty();
  }
};

}                       

                                                                                
                            
                                                                                
namespace Arg {

namespace Key {
                                         
constexpr char Name[] = "Name";
                                             
constexpr char TypeName[] = "TypeName";
                                         
constexpr char Size[] = "Size";
                                          
constexpr char Align[] = "Align";
                                              
constexpr char ValueKind[] = "ValueKind";
                                              
constexpr char ValueType[] = "ValueType";
                                                 
constexpr char PointeeAlign[] = "PointeeAlign";
                                                  
constexpr char AddrSpaceQual[] = "AddrSpaceQual";
                                            
constexpr char AccQual[] = "AccQual";
                                                  
constexpr char ActualAccQual[] = "ActualAccQual";
                                            
constexpr char IsConst[] = "IsConst";
                                               
constexpr char IsRestrict[] = "IsRestrict";
                                               
constexpr char IsVolatile[] = "IsVolatile";
                                           
constexpr char IsPipe[] = "IsPipe";
}                     

                                                         
struct Metadata final {
                     
  std::string mName = std::string();
                          
  std::string mTypeName = std::string();
                              
  uint32_t mSize = 0;
                                   
  uint32_t mAlign = 0;
                           
  ValueKind mValueKind = ValueKind::Unknown;
                           
  ValueType mValueType = ValueType::Unknown;
                                           
  uint32_t mPointeeAlign = 0;
                                        
  AddressSpaceQualifier mAddrSpaceQual = AddressSpaceQualifier::Unknown;
                                 
  AccessQualifier mAccQual = AccessQualifier::Unknown;
                                        
  AccessQualifier mActualAccQual = AccessQualifier::Unknown;
                                                       
  bool mIsConst = false;
                                                          
  bool mIsRestrict = false;
                                                          
  bool mIsVolatile = false;
                                                      
  bool mIsPipe = false;

                          
  Metadata() = default;
};

}                     

                                                                                
                                   
                                                                                
namespace CodeProps {

namespace Key {
                                                             
constexpr char KernargSegmentSize[] = "KernargSegmentSize";
                                                                
constexpr char GroupSegmentFixedSize[] = "GroupSegmentFixedSize";
                                                                  
constexpr char PrivateSegmentFixedSize[] = "PrivateSegmentFixedSize";
                                                              
constexpr char KernargSegmentAlign[] = "KernargSegmentAlign";
                                                        
constexpr char WavefrontSize[] = "WavefrontSize";
                                                   
constexpr char NumSGPRs[] = "NumSGPRs";
                                                   
constexpr char NumVGPRs[] = "NumVGPRs";
                                                               
constexpr char MaxFlatWorkGroupSize[] = "MaxFlatWorkGroupSize";
                                                             
constexpr char IsDynamicCallStack[] = "IsDynamicCallStack";
                                                         
constexpr char IsXNACKEnabled[] = "IsXNACKEnabled";
                                                          
constexpr char NumSpilledSGPRs[] = "NumSpilledSGPRs";
                                                          
constexpr char NumSpilledVGPRs[] = "NumSpilledVGPRs";
}                     

                                                                
struct Metadata final {
                                                                         
                                                                
  uint64_t mKernargSegmentSize = 0;
                                                                        
                                                                                
                                                                
  uint32_t mGroupSegmentFixedSize = 0;
                                                                         
                                                                                
  uint32_t mPrivateSegmentFixedSize = 0;
                                                                   
                                       
  uint32_t mKernargSegmentAlign = 0;
                               
  uint32_t mWavefrontSize = 0;
                                                          
  uint16_t mNumSGPRs = 0;
                                                         
  uint16_t mNumVGPRs = 0;
                                                                     
  uint32_t mMaxFlatWorkGroupSize = 0;
                                                                     
                           
  bool mIsDynamicCallStack = false;
                                                                        
               
  bool mIsXNACKEnabled = false;
                                                       
  uint16_t mNumSpilledSGPRs = 0;
                                                      
  uint16_t mNumSpilledVGPRs = 0;

                          
  Metadata() = default;

                                                                      
                
  bool empty() const {
    return !notEmpty();
  }

                                                                          
                
  bool notEmpty() const {
    return true;
  }
};

}                           

                                                                                
                                    
                                                                                
namespace DebugProps {

namespace Key {
                                                              
constexpr char DebuggerABIVersion[] = "DebuggerABIVersion";
                                                            
constexpr char ReservedNumVGPRs[] = "ReservedNumVGPRs";
                                                             
constexpr char ReservedFirstVGPR[] = "ReservedFirstVGPR";
                                                                    
constexpr char PrivateSegmentBufferSGPR[] = "PrivateSegmentBufferSGPR";
           
                                                                         
constexpr char WavefrontPrivateSegmentOffsetSGPR[] =
    "WavefrontPrivateSegmentOffsetSGPR";
}                     

                                                                 
struct Metadata final {
                                     
  std::vector<uint32_t> mDebuggerABIVersion = std::vector<uint32_t>();
                                                                         
                                               
  uint16_t mReservedNumVGPRs = 0;
                                                        
                                                                          
  uint16_t mReservedFirstVGPR = uint16_t(-1);
                                                                         
                                                              
                                                                             
  uint16_t mPrivateSegmentBufferSGPR = uint16_t(-1);
                                                                    
                                                                              
                                                 
  uint16_t mWavefrontPrivateSegmentOffsetSGPR = uint16_t(-1);

                          
  Metadata() = default;

                                                                       
                
  bool empty() const {
    return !notEmpty();
  }

                                                                           
                
  bool notEmpty() const {
    return !mDebuggerABIVersion.empty();
  }
};

}                            

namespace Key {
                                    
constexpr char Name[] = "Name";
                                          
constexpr char SymbolName[] = "SymbolName";
                                        
constexpr char Language[] = "Language";
                                               
constexpr char LanguageVersion[] = "LanguageVersion";
                                     
constexpr char Attrs[] = "Attrs";
                                    
constexpr char Args[] = "Args";
                                         
constexpr char CodeProps[] = "CodeProps";
                                          
constexpr char DebugProps[] = "DebugProps";
}                     

                                                
struct Metadata final {
                                   
  std::string mName = std::string();
                                       
  std::string mSymbolName = std::string();
                         
  std::string mLanguage = std::string();
                                 
  std::vector<uint32_t> mLanguageVersion = std::vector<uint32_t>();
                                    
  Attrs::Metadata mAttrs = Attrs::Metadata();
                                   
  std::vector<Arg::Metadata> mArgs = std::vector<Arg::Metadata>();
                                         
  CodeProps::Metadata mCodeProps = CodeProps::Metadata();
                                          
  DebugProps::Metadata mDebugProps = DebugProps::Metadata();

                          
  Metadata() = default;
};

}                        

namespace Key {
                                    
constexpr char Version[] = "Version";
                                   
constexpr char Printf[] = "Printf";
                                    
constexpr char Kernels[] = "Kernels";
}                     

                                             
struct Metadata final {
                                     
  std::vector<uint32_t> mVersion = std::vector<uint32_t>();
                                
  std::vector<std::string> mPrintf = std::vector<std::string>();
                                 
  std::vector<Kernel::Metadata> mKernels = std::vector<Kernel::Metadata>();

                          
  Metadata() = default;
};

                                         
std::error_code fromString(std::string String, Metadata &HSAMetadata);

                                         
std::error_code toString(Metadata HSAMetadata, std::string &String);

}                       

                                                                                
                
                                                                                
namespace PALMD {

                                     
constexpr char AssemblerDirective[] = ".amd_amdgpu_pal_metadata";

                      
enum Key : uint32_t {
  LS_NUM_USED_VGPRS = 0x10000021,
  HS_NUM_USED_VGPRS = 0x10000022,
  ES_NUM_USED_VGPRS = 0x10000023,
  GS_NUM_USED_VGPRS = 0x10000024,
  VS_NUM_USED_VGPRS = 0x10000025,
  PS_NUM_USED_VGPRS = 0x10000026,
  CS_NUM_USED_VGPRS = 0x10000027,

  LS_NUM_USED_SGPRS = 0x10000028,
  HS_NUM_USED_SGPRS = 0x10000029,
  ES_NUM_USED_SGPRS = 0x1000002a,
  GS_NUM_USED_SGPRS = 0x1000002b,
  VS_NUM_USED_SGPRS = 0x1000002c,
  PS_NUM_USED_SGPRS = 0x1000002d,
  CS_NUM_USED_SGPRS = 0x1000002e,

  LS_SCRATCH_SIZE = 0x10000044,
  HS_SCRATCH_SIZE = 0x10000045,
  ES_SCRATCH_SIZE = 0x10000046,
  GS_SCRATCH_SIZE = 0x10000047,
  VS_SCRATCH_SIZE = 0x10000048,
  PS_SCRATCH_SIZE = 0x10000049,
  CS_SCRATCH_SIZE = 0x1000004a
};

                                         
typedef std::vector<uint32_t> Metadata;

                                         
std::error_code toString(const Metadata &PALMetadata, std::string &String);

}                       
}                        
}                      

#endif                                 
