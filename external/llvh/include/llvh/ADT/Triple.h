//===-- llvm/ADT/Triple.h - Target triple helper class ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_TRIPLE_H
#define LLVM_ADT_TRIPLE_H

#include "llvh/ADT/Twine.h"

                                                                            
                                  
#undef NetBSD
#undef mips
#undef sparc

namespace llvh {

                                                                            
                                                                          
                          
   
                                                          
                                          
      
                                                      
   
                                                                  
                                                                   
                                                                           
                                                                    
   
                                                                         
                                                                           
                                                                          
                                            
   
                                                                         
                          
class Triple {
public:
  enum ArchType {
    UnknownArch,

    arm,                                                       
    armeb,                                    
    aarch64,                                           
    aarch64_be,                                        
    arc,                                
    avr,                                             
    bpfel,                                                               
    bpfeb,                                                            
    hexagon,                           
    mips,                                              
    mipsel,                                                   
    mips64,                                                        
    mips64el,                                                                
    msp430,                          
    nios2,                          
    ppc,                           
    ppc64,                                  
    ppc64le,                               
    r600,                                            
    amdgcn,                                
    riscv32,                                   
    riscv64,                                   
    sparc,                         
    sparcv9,                           
    sparcel,                                                                       
    systemz,                         
    tce,                                               
    tcele,                                                             
    thumb,                                                   
    thumbeb,                                      
    x86,                            
    x86_64,                                 
    xcore,                         
    nvptx,                          
    nvptx64,                        
    le32,                                                            
    le64,                                                            
    amdil,                  
    amdil64,                                     
    hsail,                      
    hsail64,                                         
    spir,                                                                  
    spir64,                                                                
    kalimba,                                   
    shave,                                                   
    lanai,                                
    wasm32,                                            
    wasm64,                                            
    renderscript32,                       
    renderscript64,                       
    LastArchType = renderscript64
  };
  enum SubArchType {
    NoSubArch,

    ARMSubArch_v8_5a,
    ARMSubArch_v8_4a,
    ARMSubArch_v8_3a,
    ARMSubArch_v8_2a,
    ARMSubArch_v8_1a,
    ARMSubArch_v8,
    ARMSubArch_v8r,
    ARMSubArch_v8m_baseline,
    ARMSubArch_v8m_mainline,
    ARMSubArch_v7,
    ARMSubArch_v7em,
    ARMSubArch_v7m,
    ARMSubArch_v7s,
    ARMSubArch_v7k,
    ARMSubArch_v7ve,
    ARMSubArch_v6,
    ARMSubArch_v6m,
    ARMSubArch_v6k,
    ARMSubArch_v6t2,
    ARMSubArch_v5,
    ARMSubArch_v5te,
    ARMSubArch_v4t,

    KalimbaSubArch_v3,
    KalimbaSubArch_v4,
    KalimbaSubArch_v5,

    MipsSubArch_r6
  };
  enum VendorType {
    UnknownVendor,

    Apple,
    PC,
    SCEI,
    BGP,
    BGQ,
    Freescale,
    IBM,
    ImaginationTechnologies,
    MipsTechnologies,
    NVIDIA,
    CSR,
    Myriad,
    AMD,
    Mesa,
    SUSE,
    OpenEmbedded,
    LastVendorType = OpenEmbedded
  };
  enum OSType {
    UnknownOS,

    Ananas,
    CloudABI,
    Darwin,
    DragonFly,
    FreeBSD,
    Fuchsia,
    IOS,
    KFreeBSD,
    Linux,
    Lv2,              
    MacOSX,
    NetBSD,
    OpenBSD,
    Solaris,
    Win32,
    Haiku,
    Minix,
    RTEMS,
    NaCl,                       
    CNK,                                   
    AIX,
    CUDA,                     
    NVCL,                       
    AMDHSA,                       
    PS4,
    ELFIAMCU,
    TvOS,                    
    WatchOS,                    
    Mesa3D,
    Contiki,
    AMDPAL,                       
    HermitCore,                                    
    LastOSType = HermitCore
  };
  enum EnvironmentType {
    UnknownEnvironment,

    GNU,
    GNUABIN32,
    GNUABI64,
    GNUEABI,
    GNUEABIHF,
    GNUX32,
    CODE16,
    EABI,
    EABIHF,
    Android,
    Musl,
    MuslEABI,
    MuslEABIHF,

    MSVC,
    Itanium,
    Cygnus,
    CoreCLR,
    Simulator,                                                           
    LastEnvironmentType = Simulator
  };
  enum ObjectFormatType {
    UnknownObjectFormat,

    COFF,
    ELF,
    MachO,
    Wasm,
  };

private:
  std::string Data;

                           
  ArchType Arch;

                                      
  SubArchType SubArch;

                             
  VendorType Vendor;

                         
  OSType OS;

                                  
  EnvironmentType Environment;

                             
  ObjectFormatType ObjectFormat;

public:
                        
        

                                                                       
                            
  Triple()
      : Data(), Arch(), SubArch(), Vendor(), OS(), Environment(),
        ObjectFormat() {}

  explicit Triple(const Twine &Str);
  Triple(const Twine &ArchStr, const Twine &VendorStr, const Twine &OSStr);
  Triple(const Twine &ArchStr, const Twine &VendorStr, const Twine &OSStr,
         const Twine &EnvironmentStr);

  bool operator==(const Triple &Other) const {
    return Arch == Other.Arch && SubArch == Other.SubArch &&
           Vendor == Other.Vendor && OS == Other.OS &&
           Environment == Other.Environment &&
           ObjectFormat == Other.ObjectFormat;
  }

  bool operator!=(const Triple &Other) const {
    return !(*this == Other);
  }

        
                         
        

                                                                            
                                                                             
                                                                            
                                                                             
  static std::string normalize(StringRef Str);

                                                         
  std::string normalize() const { return normalize(Data); }

        
                                  
        

                                                                
  ArchType getArch() const { return Arch; }

                                                                       
  SubArchType getSubArch() const { return SubArch; }

                                                            
  VendorType getVendor() const { return Vendor; }

                                                                  
  OSType getOS() const { return OS; }

                                                                     
                         
  bool hasEnvironment() const {
    return getEnvironmentName() != "";
  }

                                                                      
  EnvironmentType getEnvironment() const { return Environment; }

                                                                
                         
     
                                                       
     
                                                           
  void getEnvironmentVersion(unsigned &Major, unsigned &Minor,
                             unsigned &Micro) const;

                                                        
  ObjectFormatType getObjectFormat() const { return ObjectFormat; }

                                                                               
                         
     
                                                       
     
                                                           
  void getOSVersion(unsigned &Major, unsigned &Minor, unsigned &Micro) const;

                                                                       
                                               
  unsigned getOSMajorVersion() const {
    unsigned Maj, Min, Micro;
    getOSVersion(Maj, Min, Micro);
    return Maj;
  }

                                                                               
                                                                             
                                                                             
                                                                              
  bool getMacOSXVersion(unsigned &Major, unsigned &Minor,
                        unsigned &Micro) const;

                                                                                 
                                                 
  void getiOSVersion(unsigned &Major, unsigned &Minor,
                     unsigned &Micro) const;

                                                                              
                                                            
  void getWatchOSVersion(unsigned &Major, unsigned &Minor,
                         unsigned &Micro) const;

        
                                   
        

  const std::string &str() const { return Data; }

  const std::string &getTriple() const { return Data; }

                                                                 
             
  StringRef getArchName() const;

                                                                      
  StringRef getVendorName() const;

                                                                   
             
  StringRef getOSName() const;

                                                                
                                              
  StringRef getEnvironmentName() const;

                                                                     
                                                                   
                                               
  StringRef getOSAndEnvironmentName() const;

        
                                  
        

                                             
     
                                                                           
                                                                             
                                                                             
                                                                            
                         
  bool isArch64Bit() const;

                                             
     
                                                                      
  bool isArch32Bit() const;

                                             
     
                                                                      
  bool isArch16Bit() const;

                                                                           
                                            
  bool isOSVersionLT(unsigned Major, unsigned Minor = 0,
                     unsigned Micro = 0) const {
    unsigned LHS[3];
    getOSVersion(LHS[0], LHS[1], LHS[2]);

    if (LHS[0] != Major)
      return LHS[0] < Major;
    if (LHS[1] != Minor)
      return LHS[1] < Minor;
    if (LHS[2] != Micro)
      return LHS[1] < Micro;

    return false;
  }

  bool isOSVersionLT(const Triple &Other) const {
    unsigned RHS[3];
    Other.getOSVersion(RHS[0], RHS[1], RHS[2]);
    return isOSVersionLT(RHS[0], RHS[1], RHS[2]);
  }

                                                                       
                                                                              
                                   
  bool isMacOSXVersionLT(unsigned Major, unsigned Minor = 0,
                         unsigned Micro = 0) const {
    assert(isMacOSX() && "Not an OS X triple!");

                                                     
    if (getOS() == Triple::MacOSX)
      return isOSVersionLT(Major, Minor, Micro);

                                                 
    assert(Major == 10 && "Unexpected major version");
    return isOSVersionLT(Minor + 4, Micro, 0);
  }

                                                                               
                                         
  bool isMacOSX() const {
    return getOS() == Triple::Darwin || getOS() == Triple::MacOSX;
  }

                            
                                                                  
                                                                          
                                                            
                                                                             
  bool isiOS() const {
    return getOS() == Triple::IOS || isTvOS();
  }

                                   
  bool isTvOS() const {
    return getOS() == Triple::TvOS;
  }

                                      
  bool isWatchOS() const {
    return getOS() == Triple::WatchOS;
  }

  bool isWatchABI() const {
    return getSubArch() == Triple::ARMSubArch_v7k;
  }

                                                                 
  bool isOSDarwin() const {
    return isMacOSX() || isiOS() || isWatchOS();
  }

  bool isSimulatorEnvironment() const {
    return getEnvironment() == Triple::Simulator;
  }

  bool isOSNetBSD() const {
    return getOS() == Triple::NetBSD;
  }

  bool isOSOpenBSD() const {
    return getOS() == Triple::OpenBSD;
  }

  bool isOSFreeBSD() const {
    return getOS() == Triple::FreeBSD;
  }

  bool isOSFuchsia() const {
    return getOS() == Triple::Fuchsia;
  }

  bool isOSDragonFly() const { return getOS() == Triple::DragonFly; }

  bool isOSSolaris() const {
    return getOS() == Triple::Solaris;
  }

  bool isOSIAMCU() const {
    return getOS() == Triple::ELFIAMCU;
  }

  bool isOSUnknown() const { return getOS() == Triple::UnknownOS; }

  bool isGNUEnvironment() const {
    EnvironmentType Env = getEnvironment();
    return Env == Triple::GNU || Env == Triple::GNUABIN32 ||
           Env == Triple::GNUABI64 || Env == Triple::GNUEABI ||
           Env == Triple::GNUEABIHF || Env == Triple::GNUX32;
  }

  bool isOSContiki() const {
    return getOS() == Triple::Contiki;
  }

                                    
  bool isOSHaiku() const {
    return getOS() == Triple::Haiku;
  }

                                              
  bool isWindowsMSVCEnvironment() const {
    return getOS() == Triple::Win32 &&
           (getEnvironment() == Triple::UnknownEnvironment ||
            getEnvironment() == Triple::MSVC);
  }

                                        
  bool isKnownWindowsMSVCEnvironment() const {
    return getOS() == Triple::Win32 && getEnvironment() == Triple::MSVC;
  }

  bool isWindowsCoreCLREnvironment() const {
    return getOS() == Triple::Win32 && getEnvironment() == Triple::CoreCLR;
  }

  bool isWindowsItaniumEnvironment() const {
    return getOS() == Triple::Win32 && getEnvironment() == Triple::Itanium;
  }

  bool isWindowsCygwinEnvironment() const {
    return getOS() == Triple::Win32 && getEnvironment() == Triple::Cygnus;
  }

  bool isWindowsGNUEnvironment() const {
    return getOS() == Triple::Win32 && getEnvironment() == Triple::GNU;
  }

                                         
  bool isOSCygMing() const {
    return isWindowsCygwinEnvironment() || isWindowsGNUEnvironment();
  }

                                                                  
  bool isOSMSVCRT() const {
    return isWindowsMSVCEnvironment() || isWindowsGNUEnvironment() ||
           isWindowsItaniumEnvironment();
  }

                                      
  bool isOSWindows() const {
    return getOS() == Triple::Win32;
  }

                                                  
  bool isOSNaCl() const {
    return getOS() == Triple::NaCl;
  }

                                    
  bool isOSLinux() const {
    return getOS() == Triple::Linux;
  }

                                       
  bool isOSKFreeBSD() const {
    return getOS() == Triple::KFreeBSD;
  }

                                      
  bool isOSGlibc() const {
    return (getOS() == Triple::Linux || getOS() == Triple::KFreeBSD) &&
           !isAndroid();
  }

                                                      
  bool isOSBinFormatELF() const {
    return getObjectFormat() == Triple::ELF;
  }

                                                       
  bool isOSBinFormatCOFF() const {
    return getObjectFormat() == Triple::COFF;
  }

                                             
  bool isOSBinFormatMachO() const {
    return getObjectFormat() == Triple::MachO;
  }

                                                       
  bool isOSBinFormatWasm() const {
    return getObjectFormat() == Triple::Wasm;
  }

                                             
  bool isPS4CPU() const {
    return getArch() == Triple::x86_64 &&
           getVendor() == Triple::SCEI &&
           getOS() == Triple::PS4;
  }

                                                  
  bool isPS4() const {
    return getVendor() == Triple::SCEI &&
           getOS() == Triple::PS4;
  }

                                         
  bool isAndroid() const { return getEnvironment() == Triple::Android; }

  bool isAndroidVersionLT(unsigned Major) const {
    assert(isAndroid() && "Not an Android triple!");

    unsigned Env[3];
    getEnvironmentVersion(Env[0], Env[1], Env[2]);

                                                                   
    if (isArch64Bit() && Env[0] < 21)
      Env[0] = 21;

    return Env[0] < Major;
  }

                                                
  bool isMusl() const {
    return getEnvironment() == Triple::Musl ||
           getEnvironment() == Triple::MuslEABI ||
           getEnvironment() == Triple::MuslEABIHF;
  }

                                                        
  bool isNVPTX() const {
    return getArch() == Triple::nvptx || getArch() == Triple::nvptx64;
  }

                                                                
  bool isThumb() const {
    return getArch() == Triple::thumb || getArch() == Triple::thumbeb;
  }

                                                              
  bool isARM() const {
    return getArch() == Triple::arm || getArch() == Triple::armeb;
  }

                                                                  
  bool isAArch64() const {
    return getArch() == Triple::aarch64 || getArch() == Triple::aarch64_be;
  }

                                                                      
  bool isMIPS32() const {
    return getArch() == Triple::mips || getArch() == Triple::mipsel;
  }

                                                                      
  bool isMIPS64() const {
    return getArch() == Triple::mips64 || getArch() == Triple::mips64el;
  }

                                                                              
  bool isMIPS() const {
    return isMIPS32() || isMIPS64();
  }

                                              
  bool supportsCOMDAT() const {
    return !isOSBinFormatMachO();
  }

                                                            
  bool hasDefaultEmulatedTLS() const {
    return isAndroid() || isOSOpenBSD() || isWindowsCygwinEnvironment();
  }

        
                    
        

                                                                    
                      
  void setArch(ArchType Kind);

                                                                      
                 
  void setVendor(VendorType Kind);

                                                                      
                      
  void setOS(OSType Kind);

                                                                           
                      
  void setEnvironment(EnvironmentType Kind);

                                                  
  void setObjectFormat(ObjectFormatType Kind);

                                                              
  void setTriple(const Twine &Str);

                                                                 
                     
  void setArchName(StringRef Str);

                                                                     
              
  void setVendorName(StringRef Str);

                                                                   
                     
  void setOSName(StringRef Str);

                                                                
                                      
  void setEnvironmentName(StringRef Str);

                                                                     
                                                  
  void setOSAndEnvironmentName(StringRef Str);

        
                                                             
        

                                                                      
     
                                                                               
     
                                                                    
                                                            
  llvh::Triple get32BitArchVariant() const;

                                                                      
     
                                                                               
     
                                                                    
                                                            
  llvh::Triple get64BitArchVariant() const;

                                                                          
     
                                                                               
     
                                                                        
                                                            
  llvh::Triple getBigEndianArchVariant() const;

                                                                             
     
                                                                               
     
                                                                           
                                                            
  llvh::Triple getLittleEndianArchVariant() const;

                                                                               
     
                                                                           
                                                 
  StringRef getARMCPUForArch(StringRef Arch = StringRef()) const;

                                                       
     
                                                                    
  bool isLittleEndian() const;

                                                 
  bool isCompatibleWith(const Triple &Other) const;

                           
  std::string merge(const Triple &Other) const;

        
                                   
        

                                                                            
  static StringRef getArchTypeName(ArchType Kind);

                                                                         
                                                                        
                                                   
                                             
     
                                                                 
  static StringRef getArchTypePrefix(ArchType Kind);

                                                                        
  static StringRef getVendorTypeName(VendorType Kind);

                                                                              
  static StringRef getOSTypeName(OSType Kind);

                                                                     
                  
  static StringRef getEnvironmentTypeName(EnvironmentType Kind);

        
                                                                       
        

                                                                    
                                      
  static ArchType getArchTypeForLLVMName(StringRef Str);

        
};

}                      


#endif
