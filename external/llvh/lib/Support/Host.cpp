//===-- Host.cpp - Implement OS Host Concept --------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements the operating system Host concept.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/Host.h"
#include "llvh/Support/TargetParser.h"
#include "llvh/ADT/SmallSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/StringSwitch.h"
#include "llvh/ADT/Triple.h"
#include "llvh/Config/llvm-config.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/MemoryBuffer.h"
#include "llvh/Support/raw_ostream.h"
#include <assert.h>
#include <string.h>

                                                     
#ifdef LLVM_ON_UNIX
#include "Unix/Host.inc"
#endif
#ifdef _WIN32
#include "Windows/Host.inc"
#endif
#ifdef _MSC_VER
#include <intrin.h>
#endif
#if defined(__APPLE__) && (defined(__ppc__) || defined(__powerpc__))
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/machine.h>
#endif

#define DEBUG_TYPE "host-detection"

                                                                                
  
                                                 
  
                                                                                

using namespace llvh;

static std::unique_ptr<llvh::MemoryBuffer>
    LLVM_ATTRIBUTE_UNUSED getProcCpuinfoContent() {
  llvh::ErrorOr<std::unique_ptr<llvh::MemoryBuffer>> Text =
      llvh::MemoryBuffer::getFileAsStream("/proc/cpuinfo");
  if (std::error_code EC = Text.getError()) {
    llvh::errs() << "Can't read "
                 << "/proc/cpuinfo: " << EC.message() << "\n";
    return nullptr;
  }
  return std::move(*Text);
}

StringRef sys::detail::getHostCPUNameForPowerPC(StringRef ProcCpuinfoContent) {
                                                                             
                                                                              
                                                                              
  const char *generic = "generic";

                                                                       
                                                                  
  StringRef::const_iterator CPUInfoStart = ProcCpuinfoContent.begin();
  StringRef::const_iterator CPUInfoEnd = ProcCpuinfoContent.end();

  StringRef::const_iterator CIP = CPUInfoStart;

  StringRef::const_iterator CPUStart = nullptr;
  size_t CPULen = 0;

                                                                               
                                                                                
  while (CIP < CPUInfoEnd && CPUStart == nullptr) {
    if (CIP < CPUInfoEnd && *CIP == '\n')
      ++CIP;

    if (CIP < CPUInfoEnd && *CIP == 'c') {
      ++CIP;
      if (CIP < CPUInfoEnd && *CIP == 'p') {
        ++CIP;
        if (CIP < CPUInfoEnd && *CIP == 'u') {
          ++CIP;
          while (CIP < CPUInfoEnd && (*CIP == ' ' || *CIP == '\t'))
            ++CIP;

          if (CIP < CPUInfoEnd && *CIP == ':') {
            ++CIP;
            while (CIP < CPUInfoEnd && (*CIP == ' ' || *CIP == '\t'))
              ++CIP;

            if (CIP < CPUInfoEnd) {
              CPUStart = CIP;
              while (CIP < CPUInfoEnd && (*CIP != ' ' && *CIP != '\t' &&
                                          *CIP != ',' && *CIP != '\n'))
                ++CIP;
              CPULen = CIP - CPUStart;
            }
          }
        }
      }
    }

    if (CPUStart == nullptr)
      while (CIP < CPUInfoEnd && *CIP != '\n')
        ++CIP;
  }

  if (CPUStart == nullptr)
    return generic;

  return StringSwitch<const char *>(StringRef(CPUStart, CPULen))
      .Case("604e", "604e")
      .Case("604", "604")
      .Case("7400", "7400")
      .Case("7410", "7400")
      .Case("7447", "7400")
      .Case("7455", "7450")
      .Case("G4", "g4")
      .Case("POWER4", "970")
      .Case("PPC970FX", "970")
      .Case("PPC970MP", "970")
      .Case("G5", "g5")
      .Case("POWER5", "g5")
      .Case("A2", "a2")
      .Case("POWER6", "pwr6")
      .Case("POWER7", "pwr7")
      .Case("POWER8", "pwr8")
      .Case("POWER8E", "pwr8")
      .Case("POWER8NVL", "pwr8")
      .Case("POWER9", "pwr9")
      .Default(generic);
}

StringRef sys::detail::getHostCPUNameForARM(StringRef ProcCpuinfoContent) {
                                                                           
                                                  

                                                                             
                  
  SmallVector<StringRef, 32> Lines;
  ProcCpuinfoContent.split(Lines, "\n");

                                       
  StringRef Implementer;
  StringRef Hardware;
  for (unsigned I = 0, E = Lines.size(); I != E; ++I) {
    if (Lines[I].startswith("CPU implementer"))
      Implementer = Lines[I].substr(15).ltrim("\t :");
    if (Lines[I].startswith("Hardware"))
      Hardware = Lines[I].substr(8).ltrim("\t :");
  }

  if (Implementer == "0x41") {            
                                                                                 
                                                                                  
    if (Hardware.endswith("MSM8994") || Hardware.endswith("MSM8996"))
      return "cortex-a53";


                                  
    for (unsigned I = 0, E = Lines.size(); I != E; ++I)
      if (Lines[I].startswith("CPU part"))
                                                                             
                                                                              
                                                                   
        return StringSwitch<const char *>(Lines[I].substr(8).ltrim("\t :"))
            .Case("0x926", "arm926ej-s")
            .Case("0xb02", "mpcore")
            .Case("0xb36", "arm1136j-s")
            .Case("0xb56", "arm1156t2-s")
            .Case("0xb76", "arm1176jz-s")
            .Case("0xc08", "cortex-a8")
            .Case("0xc09", "cortex-a9")
            .Case("0xc0f", "cortex-a15")
            .Case("0xc20", "cortex-m0")
            .Case("0xc23", "cortex-m3")
            .Case("0xc24", "cortex-m4")
            .Case("0xd04", "cortex-a35")
            .Case("0xd03", "cortex-a53")
            .Case("0xd07", "cortex-a57")
            .Case("0xd08", "cortex-a72")
            .Case("0xd09", "cortex-a73")
            .Default("generic");
  }

  if (Implementer == "0x42" || Implementer == "0x43") {                      
    for (unsigned I = 0, E = Lines.size(); I != E; ++I) {
      if (Lines[I].startswith("CPU part")) {
        return StringSwitch<const char *>(Lines[I].substr(8).ltrim("\t :"))
          .Case("0x516", "thunderx2t99")
          .Case("0x0516", "thunderx2t99")
          .Case("0xaf", "thunderx2t99")
          .Case("0x0af", "thunderx2t99")
          .Case("0xa1", "thunderxt88")
          .Case("0x0a1", "thunderxt88")
          .Default("generic");
      }
    }
  }

  if (Implementer == "0x51")                               
                                  
    for (unsigned I = 0, E = Lines.size(); I != E; ++I)
      if (Lines[I].startswith("CPU part"))
                                                                             
                                                                              
                                                                   
        return StringSwitch<const char *>(Lines[I].substr(8).ltrim("\t :"))
            .Case("0x06f", "krait")           
            .Case("0x201", "kryo")
            .Case("0x205", "kryo")
            .Case("0x211", "kryo")
            .Case("0x800", "cortex-a73")
            .Case("0x801", "cortex-a73")
            .Case("0xc00", "falkor")
            .Case("0xc01", "saphira")
            .Default("generic");

  if (Implementer == "0x53") {                                 
                                                                               
                                                        
    unsigned Variant = 0, Part = 0;

                                                                          
                                                                         
    for (auto I : Lines)
      if (I.consume_front("CPU variant"))
        I.ltrim("\t :").getAsInteger(0, Variant);

                                                                       
                                                                         
    for (auto I : Lines)
      if (I.consume_front("CPU part"))
        I.ltrim("\t :").getAsInteger(0, Part);

    unsigned Exynos = (Variant << 12) | Part;
    switch (Exynos) {
    default:
                                                 
      LLVM_FALLTHROUGH;

    case 0x1001:
      return "exynos-m1";

    case 0x4001:
      return "exynos-m2";
    }
  }

  return "generic";
}

StringRef sys::detail::getHostCPUNameForS390x(StringRef ProcCpuinfoContent) {
                                                                   

                                                                            
                                                            
  SmallVector<StringRef, 32> Lines;
  ProcCpuinfoContent.split(Lines, "\n");

                               
  SmallVector<StringRef, 32> CPUFeatures;
  for (unsigned I = 0, E = Lines.size(); I != E; ++I)
    if (Lines[I].startswith("features")) {
      size_t Pos = Lines[I].find(":");
      if (Pos != StringRef::npos) {
        Lines[I].drop_front(Pos + 1).split(CPUFeatures, ' ');
        break;
      }
    }

                                                                         
                                                                         
                                              
  bool HaveVectorSupport = false;
  for (unsigned I = 0, E = CPUFeatures.size(); I != E; ++I) {
    if (CPUFeatures[I] == "vx")
      HaveVectorSupport = true;
  }

                                          
  for (unsigned I = 0, E = Lines.size(); I != E; ++I) {
    if (Lines[I].startswith("processor ")) {
      size_t Pos = Lines[I].find("machine = ");
      if (Pos != StringRef::npos) {
        Pos += sizeof("machine = ") - 1;
        unsigned int Id;
        if (!Lines[I].drop_front(Pos).getAsInteger(10, Id)) {
          if (Id >= 3906 && HaveVectorSupport)
            return "z14";
          if (Id >= 2964 && HaveVectorSupport)
            return "z13";
          if (Id >= 2827)
            return "zEC12";
          if (Id >= 2817)
            return "z196";
        }
      }
      break;
    }
  }

  return "generic";
}

StringRef sys::detail::getHostCPUNameForBPF() {
#if !defined(__linux__) || !defined(__x86_64__)
  return "generic";
#else
  uint8_t insns[40] __attribute__ ((aligned (8))) =
                                       
    { 0xb7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                       
      0xb7, 0x2, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
                                                         
      0xad, 0x20, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                                       
      0xb7, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
                           
      0x95, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

  struct bpf_prog_load_attr {
    uint32_t prog_type;
    uint32_t insn_cnt;
    uint64_t insns;
    uint64_t license;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buf;
    uint32_t kern_version;
    uint32_t prog_flags;
  } attr = {};
  attr.prog_type = 1;                                  
  attr.insn_cnt = 5;
  attr.insns = (uint64_t)insns;
  attr.license = (uint64_t)"DUMMY";

  int fd = syscall(321               , 5                    , &attr, sizeof(attr));
  if (fd >= 0) {
    close(fd);
    return "v2";
  }
  return "v1";
#endif
}

#if defined(__i386__) || defined(_M_IX86) || \
    defined(__x86_64__) || defined(_M_X64)

enum VendorSignatures {
  SIG_INTEL = 0x756e6547           ,
  SIG_AMD = 0x68747541           
};

                                                                              
                                                                            
                                                                          
                                    
                                                 
                                                                                
                                                                  
static bool isCpuIdSupported() {
#if defined(__GNUC__) || defined(__clang__)
#if defined(__i386__)
  int __cpuid_supported;
  __asm__("  pushfl\n"
          "  popl   %%eax\n"
          "  movl   %%eax,%%ecx\n"
          "  xorl   $0x00200000,%%eax\n"
          "  pushl  %%eax\n"
          "  popfl\n"
          "  pushfl\n"
          "  popl   %%eax\n"
          "  movl   $0,%0\n"
          "  cmpl   %%eax,%%ecx\n"
          "  je     1f\n"
          "  movl   $1,%0\n"
          "1:"
          : "=r"(__cpuid_supported)
          :
          : "eax", "ecx");
  if (!__cpuid_supported)
    return false;
#endif
  return true;
#endif
  return true;
}

                                                                               
                                                                             
static bool getX86CpuIDAndInfo(unsigned value, unsigned *rEAX, unsigned *rEBX,
                               unsigned *rECX, unsigned *rEDX) {
#if defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__)
                                                                        
                                          
  __asm__("movq\t%%rbx, %%rsi\n\t"
          "cpuid\n\t"
          "xchgq\t%%rbx, %%rsi\n\t"
          : "=a"(*rEAX), "=S"(*rEBX), "=c"(*rECX), "=d"(*rEDX)
          : "a"(value));
  return false;
#elif defined(__i386__)
  __asm__("movl\t%%ebx, %%esi\n\t"
          "cpuid\n\t"
          "xchgl\t%%ebx, %%esi\n\t"
          : "=a"(*rEAX), "=S"(*rEBX), "=c"(*rECX), "=d"(*rEDX)
          : "a"(value));
  return false;
#else
  return true;
#endif
#elif defined(_MSC_VER)
                                                       
  int registers[4];
  __cpuid(registers, value);
  *rEAX = registers[0];
  *rEBX = registers[1];
  *rECX = registers[2];
  *rEDX = registers[3];
  return false;
#else
  return true;
#endif
}

                                                                              
                                                                                
                
static bool getX86CpuIDAndInfoEx(unsigned value, unsigned subleaf,
                                 unsigned *rEAX, unsigned *rEBX, unsigned *rECX,
                                 unsigned *rEDX) {
#if defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__)
                                                                        
                                          
  __asm__("movq\t%%rbx, %%rsi\n\t"
          "cpuid\n\t"
          "xchgq\t%%rbx, %%rsi\n\t"
          : "=a"(*rEAX), "=S"(*rEBX), "=c"(*rECX), "=d"(*rEDX)
          : "a"(value), "c"(subleaf));
  return false;
#elif defined(__i386__)
  __asm__("movl\t%%ebx, %%esi\n\t"
          "cpuid\n\t"
          "xchgl\t%%ebx, %%esi\n\t"
          : "=a"(*rEAX), "=S"(*rEBX), "=c"(*rECX), "=d"(*rEDX)
          : "a"(value), "c"(subleaf));
  return false;
#else
  return true;
#endif
#elif defined(_MSC_VER)
  int registers[4];
  __cpuidex(registers, value, subleaf);
  *rEAX = registers[0];
  *rEBX = registers[1];
  *rECX = registers[2];
  *rEDX = registers[3];
  return false;
#else
  return true;
#endif
}

                                                                       
static bool getX86XCR0(unsigned *rEAX, unsigned *rEDX) {
#if defined(__GNUC__) || defined(__clang__)
                                                                        
                                                                            
                                                                               
  __asm__(".byte 0x0f, 0x01, 0xd0" : "=a"(*rEAX), "=d"(*rEDX) : "c"(0));
  return false;
#elif defined(_MSC_FULL_VER) && defined(_XCR_XFEATURE_ENABLED_MASK)
  unsigned long long Result = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
  *rEAX = Result;
  *rEDX = Result >> 32;
  return false;
#else
  return true;
#endif
}

static void detectX86FamilyModel(unsigned EAX, unsigned *Family,
                                 unsigned *Model) {
  *Family = (EAX >> 8) & 0xf;               
  *Model = (EAX >> 4) & 0xf;               
  if (*Family == 6 || *Family == 0xf) {
    if (*Family == 0xf)
                                                      
      *Family += (EAX >> 20) & 0xff;                
                                                        
    *Model += ((EAX >> 16) & 0xf) << 4;                
  }
}

static void
getIntelProcessorTypeAndSubtype(unsigned Family, unsigned Model,
                                unsigned Brand_id, unsigned Features,
                                unsigned Features2, unsigned *Type,
                                unsigned *Subtype) {
  if (Brand_id != 0)
    return;
  switch (Family) {
  case 3:
    *Type = X86::INTEL_i386;
    break;
  case 4:
    *Type = X86::INTEL_i486;
    break;
  case 5:
    if (Features & (1 << X86::FEATURE_MMX)) {
      *Type = X86::INTEL_PENTIUM_MMX;
      break;
    }
    *Type = X86::INTEL_PENTIUM;
    break;
  case 6:
    switch (Model) {
    case 0x01:                         
      *Type = X86::INTEL_PENTIUM_PRO;
      break;
    case 0x03:                                                               
                          
    case 0x05:                                                              
                                                                 
    case 0x06:                               
      *Type = X86::INTEL_PENTIUM_II;
      break;
    case 0x07:                                                         
                                     
    case 0x08:                                                                
                                                           
    case 0x0a:                                         
    case 0x0b:                                    
      *Type = X86::INTEL_PENTIUM_III;
      break;
    case 0x09:                                                                  
    case 0x0d:                                                               
                                                                               
    case 0x15:                                                        
                                                                        
      *Type = X86::INTEL_PENTIUM_M;
      break;
    case 0x0e:                                                              
                                                                               
      *Type = X86::INTEL_CORE_DUO;
      break;           
    case 0x0f:                                                       
                                                                           
                                                                         
                                                                          
                                                                               
    case 0x16:                                                         
                                                      
      *Type = X86::INTEL_CORE2;           
      *Subtype = X86::INTEL_CORE2_65;
      break;
    case 0x17:                                                               
                                                                               
                 
                                                         
    case 0x1d:                                                                  
                                    
      *Type = X86::INTEL_CORE2;            
      *Subtype = X86::INTEL_CORE2_45;
      break;
    case 0x1a:                                                         
                                                                      
    case 0x1e:                                                    
                                                       
    case 0x1f:
    case 0x2e:                          
      *Type = X86::INTEL_COREI7;             
      *Subtype = X86::INTEL_COREI7_NEHALEM;
      break;
    case 0x25:                                  
    case 0x2c:                                                         
                                                                      
    case 0x2f:               
      *Type = X86::INTEL_COREI7;              
      *Subtype = X86::INTEL_COREI7_WESTMERE;
      break;
    case 0x2a:                                                            
                                          
    case 0x2d:
      *Type = X86::INTEL_COREI7;                
      *Subtype = X86::INTEL_COREI7_SANDYBRIDGE;
      break;
    case 0x3a:
    case 0x3e:                             
      *Type = X86::INTEL_COREI7;               
      *Subtype = X86::INTEL_COREI7_IVYBRIDGE;
      break;

               
    case 0x3c:
    case 0x3f:
    case 0x45:
    case 0x46:
      *Type = X86::INTEL_COREI7;             
      *Subtype = X86::INTEL_COREI7_HASWELL;
      break;

                 
    case 0x3d:
    case 0x47:
    case 0x4f:
    case 0x56:
      *Type = X86::INTEL_COREI7;               
      *Subtype = X86::INTEL_COREI7_BROADWELL;
      break;

               
    case 0x4e:                  
    case 0x5e:                   
    case 0x8e:                    
    case 0x9e:                     
      *Type = X86::INTEL_COREI7;             
      *Subtype = X86::INTEL_COREI7_SKYLAKE;
      break;

                    
    case 0x55:
      *Type = X86::INTEL_COREI7;
      *Subtype = X86::INTEL_COREI7_SKYLAKE_AVX512;                    
      break;

                  
    case 0x66:
      *Type = X86::INTEL_COREI7;
      *Subtype = X86::INTEL_COREI7_CANNONLAKE;                
      break;

    case 0x1c:                                    
    case 0x26:                       
    case 0x27:                       
    case 0x35:                      
    case 0x36:                      
      *Type = X86::INTEL_BONNELL;
      break;             

                                                                        
    case 0x37:
    case 0x4a:
    case 0x4d:
    case 0x5a:
    case 0x5d:
    case 0x4c:                  
      *Type = X86::INTEL_SILVERMONT;
      break;                
                
    case 0x5c:               
    case 0x5f:             
      *Type = X86::INTEL_GOLDMONT;
      break;              
    case 0x7a:
      *Type = X86::INTEL_GOLDMONT_PLUS;
      break;
    case 0x57:
      *Type = X86::INTEL_KNL;       
      break;
    case 0x85:
      *Type = X86::INTEL_KNM;       
      break;

    default:                                       
      if (Features & (1 << X86::FEATURE_AVX512VBMI)) {
        *Type = X86::INTEL_COREI7;
        *Subtype = X86::INTEL_COREI7_CANNONLAKE;
        break;
      }

      if (Features & (1 << X86::FEATURE_AVX512VL)) {
        *Type = X86::INTEL_COREI7;
        *Subtype = X86::INTEL_COREI7_SKYLAKE_AVX512;
        break;
      }

      if (Features & (1 << X86::FEATURE_AVX512ER)) {
        *Type = X86::INTEL_KNL;       
        break;
      }

      if (Features2 & (1 << (X86::FEATURE_CLFLUSHOPT - 32))) {
        if (Features2 & (1 << (X86::FEATURE_SHA - 32))) {
          *Type = X86::INTEL_GOLDMONT;
        } else {
          *Type = X86::INTEL_COREI7;
          *Subtype = X86::INTEL_COREI7_SKYLAKE;
        }
        break;
      }
      if (Features2 & (1 << (X86::FEATURE_ADX - 32))) {
        *Type = X86::INTEL_COREI7;
        *Subtype = X86::INTEL_COREI7_BROADWELL;
        break;
      }
      if (Features & (1 << X86::FEATURE_AVX2)) {
        *Type = X86::INTEL_COREI7;
        *Subtype = X86::INTEL_COREI7_HASWELL;
        break;
      }
      if (Features & (1 << X86::FEATURE_AVX)) {
        *Type = X86::INTEL_COREI7;
        *Subtype = X86::INTEL_COREI7_SANDYBRIDGE;
        break;
      }
      if (Features & (1 << X86::FEATURE_SSE4_2)) {
        if (Features2 & (1 << (X86::FEATURE_MOVBE - 32))) {
          *Type = X86::INTEL_SILVERMONT;
        } else {
          *Type = X86::INTEL_COREI7;
          *Subtype = X86::INTEL_COREI7_NEHALEM;
        }
        break;
      }
      if (Features & (1 << X86::FEATURE_SSE4_1)) {
        *Type = X86::INTEL_CORE2;            
        *Subtype = X86::INTEL_CORE2_45;
        break;
      }
      if (Features & (1 << X86::FEATURE_SSSE3)) {
        if (Features2 & (1 << (X86::FEATURE_MOVBE - 32))) {
          *Type = X86::INTEL_BONNELL;             
        } else {
          *Type = X86::INTEL_CORE2;           
          *Subtype = X86::INTEL_CORE2_65;
        }
        break;
      }
      if (Features2 & (1 << (X86::FEATURE_EM64T - 32))) {
        *Type = X86::INTEL_CORE2;           
        *Subtype = X86::INTEL_CORE2_65;
        break;
      }
      if (Features & (1 << X86::FEATURE_SSE3)) {
        *Type = X86::INTEL_CORE_DUO;
        break;
      }
      if (Features & (1 << X86::FEATURE_SSE2)) {
        *Type = X86::INTEL_PENTIUM_M;
        break;
      }
      if (Features & (1 << X86::FEATURE_SSE)) {
        *Type = X86::INTEL_PENTIUM_III;
        break;
      }
      if (Features & (1 << X86::FEATURE_MMX)) {
        *Type = X86::INTEL_PENTIUM_II;
        break;
      }
      *Type = X86::INTEL_PENTIUM_PRO;
      break;
    }
    break;
  case 15: {
    if (Features2 & (1 << (X86::FEATURE_EM64T - 32))) {
      *Type = X86::INTEL_NOCONA;
      break;
    }
    if (Features & (1 << X86::FEATURE_SSE3)) {
      *Type = X86::INTEL_PRESCOTT;
      break;
    }
    *Type = X86::INTEL_PENTIUM_IV;
    break;
  }
  default:
    break;              
  }
}

static void getAMDProcessorTypeAndSubtype(unsigned Family, unsigned Model,
                                          unsigned Features, unsigned *Type,
                                          unsigned *Subtype) {
                                                                              
                                                                              
                                              
  switch (Family) {
  case 4:
    *Type = X86::AMD_i486;
    break;
  case 5:
    *Type = X86::AMDPENTIUM;
    switch (Model) {
    case 6:
    case 7:
      *Subtype = X86::AMDPENTIUM_K6;
      break;        
    case 8:
      *Subtype = X86::AMDPENTIUM_K62;
      break;          
    case 9:
    case 13:
      *Subtype = X86::AMDPENTIUM_K63;
      break;          
    case 10:
      *Subtype = X86::AMDPENTIUM_GEODE;
      break;           
    }
    break;
  case 6:
    if (Features & (1 << X86::FEATURE_SSE)) {
      *Type = X86::AMD_ATHLON_XP;
      break;               
    }
    *Type = X86::AMD_ATHLON;
    break;            
  case 15:
    if (Features & (1 << X86::FEATURE_SSE3)) {
      *Type = X86::AMD_K8SSE3;
      break;             
    }
    *Type = X86::AMD_K8;
    break;        
  case 16:
    *Type = X86::AMDFAM10H;              
    switch (Model) {
    case 2:
      *Subtype = X86::AMDFAM10H_BARCELONA;
      break;
    case 4:
      *Subtype = X86::AMDFAM10H_SHANGHAI;
      break;
    case 8:
      *Subtype = X86::AMDFAM10H_ISTANBUL;
      break;
    }
    break;
  case 20:
    *Type = X86::AMD_BTVER1;
    break;             
  case 21:
    *Type = X86::AMDFAM15H;
    if (Model >= 0x60 && Model <= 0x7f) {
      *Subtype = X86::AMDFAM15H_BDVER4;
      break;                                
    }
    if (Model >= 0x30 && Model <= 0x3f) {
      *Subtype = X86::AMDFAM15H_BDVER3;
      break;                                  
    }
    if ((Model >= 0x10 && Model <= 0x1f) || Model == 0x02) {
      *Subtype = X86::AMDFAM15H_BDVER2;
      break;                                      
    }
    if (Model <= 0x0f) {
      *Subtype = X86::AMDFAM15H_BDVER1;
      break;                                
    }
    break;
  case 22:
    *Type = X86::AMD_BTVER2;
    break;            
  case 23:
    *Type = X86::AMDFAM17H;
    *Subtype = X86::AMDFAM17H_ZNVER1;
    break;
  default:
    break;             
  }
}

static void getAvailableFeatures(unsigned ECX, unsigned EDX, unsigned MaxLeaf,
                                 unsigned *FeaturesOut,
                                 unsigned *Features2Out) {
  unsigned Features = 0;
  unsigned Features2 = 0;
  unsigned EAX, EBX;

  if ((EDX >> 15) & 1)
    Features |= 1 << X86::FEATURE_CMOV;
  if ((EDX >> 23) & 1)
    Features |= 1 << X86::FEATURE_MMX;
  if ((EDX >> 25) & 1)
    Features |= 1 << X86::FEATURE_SSE;
  if ((EDX >> 26) & 1)
    Features |= 1 << X86::FEATURE_SSE2;

  if ((ECX >> 0) & 1)
    Features |= 1 << X86::FEATURE_SSE3;
  if ((ECX >> 1) & 1)
    Features |= 1 << X86::FEATURE_PCLMUL;
  if ((ECX >> 9) & 1)
    Features |= 1 << X86::FEATURE_SSSE3;
  if ((ECX >> 12) & 1)
    Features |= 1 << X86::FEATURE_FMA;
  if ((ECX >> 19) & 1)
    Features |= 1 << X86::FEATURE_SSE4_1;
  if ((ECX >> 20) & 1)
    Features |= 1 << X86::FEATURE_SSE4_2;
  if ((ECX >> 23) & 1)
    Features |= 1 << X86::FEATURE_POPCNT;
  if ((ECX >> 25) & 1)
    Features |= 1 << X86::FEATURE_AES;

  if ((ECX >> 22) & 1)
    Features2 |= 1 << (X86::FEATURE_MOVBE - 32);

                                                                       
                                                                           
                                           
  const unsigned AVXBits = (1 << 27) | (1 << 28);
  bool HasAVX = ((ECX & AVXBits) == AVXBits) && !getX86XCR0(&EAX, &EDX) &&
                ((EAX & 0x6) == 0x6);
  bool HasAVX512Save = HasAVX && ((EAX & 0xe0) == 0xe0);

  if (HasAVX)
    Features |= 1 << X86::FEATURE_AVX;

  bool HasLeaf7 =
      MaxLeaf >= 0x7 && !getX86CpuIDAndInfoEx(0x7, 0x0, &EAX, &EBX, &ECX, &EDX);

  if (HasLeaf7 && ((EBX >> 3) & 1))
    Features |= 1 << X86::FEATURE_BMI;
  if (HasLeaf7 && ((EBX >> 5) & 1) && HasAVX)
    Features |= 1 << X86::FEATURE_AVX2;
  if (HasLeaf7 && ((EBX >> 9) & 1))
    Features |= 1 << X86::FEATURE_BMI2;
  if (HasLeaf7 && ((EBX >> 16) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512F;
  if (HasLeaf7 && ((EBX >> 17) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512DQ;
  if (HasLeaf7 && ((EBX >> 19) & 1))
    Features2 |= 1 << (X86::FEATURE_ADX - 32);
  if (HasLeaf7 && ((EBX >> 21) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512IFMA;
  if (HasLeaf7 && ((EBX >> 23) & 1))
    Features2 |= 1 << (X86::FEATURE_CLFLUSHOPT - 32);
  if (HasLeaf7 && ((EBX >> 26) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512PF;
  if (HasLeaf7 && ((EBX >> 27) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512ER;
  if (HasLeaf7 && ((EBX >> 28) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512CD;
  if (HasLeaf7 && ((EBX >> 29) & 1))
    Features2 |= 1 << (X86::FEATURE_SHA - 32);
  if (HasLeaf7 && ((EBX >> 30) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512BW;
  if (HasLeaf7 && ((EBX >> 31) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512VL;

  if (HasLeaf7 && ((ECX >> 1) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512VBMI;
  if (HasLeaf7 && ((ECX >> 14) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX512VPOPCNTDQ;

  if (HasLeaf7 && ((EDX >> 2) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX5124VNNIW;
  if (HasLeaf7 && ((EDX >> 3) & 1) && HasAVX512Save)
    Features |= 1 << X86::FEATURE_AVX5124FMAPS;

  unsigned MaxExtLevel;
  getX86CpuIDAndInfo(0x80000000, &MaxExtLevel, &EBX, &ECX, &EDX);

  bool HasExtLeaf1 = MaxExtLevel >= 0x80000001 &&
                     !getX86CpuIDAndInfo(0x80000001, &EAX, &EBX, &ECX, &EDX);
  if (HasExtLeaf1 && ((ECX >> 6) & 1))
    Features |= 1 << X86::FEATURE_SSE4_A;
  if (HasExtLeaf1 && ((ECX >> 11) & 1))
    Features |= 1 << X86::FEATURE_XOP;
  if (HasExtLeaf1 && ((ECX >> 16) & 1))
    Features |= 1 << X86::FEATURE_FMA4;

  if (HasExtLeaf1 && ((EDX >> 29) & 1))
    Features2 |= 1 << (X86::FEATURE_EM64T - 32);

  *FeaturesOut  = Features;
  *Features2Out = Features2;
}

StringRef sys::getHostCPUName() {
  unsigned EAX = 0, EBX = 0, ECX = 0, EDX = 0;
  unsigned MaxLeaf, Vendor;

#if defined(__GNUC__) || defined(__clang__)
                                                                  
                                                               
                                          
                                  
  if(!isCpuIdSupported())
    return "generic";
#endif
  if (getX86CpuIDAndInfo(0, &MaxLeaf, &Vendor, &ECX, &EDX) || MaxLeaf < 1)
    return "generic";
  getX86CpuIDAndInfo(0x1, &EAX, &EBX, &ECX, &EDX);

  unsigned Brand_id = EBX & 0xff;
  unsigned Family = 0, Model = 0;
  unsigned Features = 0, Features2 = 0;
  detectX86FamilyModel(EAX, &Family, &Model);
  getAvailableFeatures(ECX, EDX, MaxLeaf, &Features, &Features2);

  unsigned Type = 0;
  unsigned Subtype = 0;

  if (Vendor == SIG_INTEL) {
    getIntelProcessorTypeAndSubtype(Family, Model, Brand_id, Features,
                                    Features2, &Type, &Subtype);
  } else if (Vendor == SIG_AMD) {
    getAMDProcessorTypeAndSubtype(Family, Model, Features, &Type, &Subtype);
  }

                                                        
#define X86_CPU_SUBTYPE(ARCHNAME, ENUM) \
  if (Subtype == X86::ENUM) \
    return ARCHNAME;
#include "llvh/Support/X86TargetParser.def"

                     
#define X86_CPU_TYPE(ARCHNAME, ENUM) \
  if (Type == X86::ENUM) \
    return ARCHNAME;
#include "llvh/Support/X86TargetParser.def"

  return "generic";
}

#elif defined(__APPLE__) && (defined(__ppc__) || defined(__powerpc__))
StringRef sys::getHostCPUName() {
  host_basic_info_data_t hostInfo;
  mach_msg_type_number_t infoCount;

  infoCount = HOST_BASIC_INFO_COUNT;
  mach_port_t hostPort = mach_host_self();
  host_info(hostPort, HOST_BASIC_INFO, (host_info_t)&hostInfo,
            &infoCount);
  mach_port_deallocate(mach_task_self(), hostPort);

  if (hostInfo.cpu_type != CPU_TYPE_POWERPC)
    return "generic";

  switch (hostInfo.cpu_subtype) {
  case CPU_SUBTYPE_POWERPC_601:
    return "601";
  case CPU_SUBTYPE_POWERPC_602:
    return "602";
  case CPU_SUBTYPE_POWERPC_603:
    return "603";
  case CPU_SUBTYPE_POWERPC_603e:
    return "603e";
  case CPU_SUBTYPE_POWERPC_603ev:
    return "603ev";
  case CPU_SUBTYPE_POWERPC_604:
    return "604";
  case CPU_SUBTYPE_POWERPC_604e:
    return "604e";
  case CPU_SUBTYPE_POWERPC_620:
    return "620";
  case CPU_SUBTYPE_POWERPC_750:
    return "750";
  case CPU_SUBTYPE_POWERPC_7400:
    return "7400";
  case CPU_SUBTYPE_POWERPC_7450:
    return "7450";
  case CPU_SUBTYPE_POWERPC_970:
    return "970";
  default:;
  }

  return "generic";
}
#elif defined(__linux__) && (defined(__ppc__) || defined(__powerpc__))
StringRef sys::getHostCPUName() {
  std::unique_ptr<llvh::MemoryBuffer> P = getProcCpuinfoContent();
  StringRef Content = P ? P->getBuffer() : "";
  return detail::getHostCPUNameForPowerPC(Content);
}
#elif defined(__linux__) && (defined(__arm__) || defined(__aarch64__))
StringRef sys::getHostCPUName() {
  std::unique_ptr<llvh::MemoryBuffer> P = getProcCpuinfoContent();
  StringRef Content = P ? P->getBuffer() : "";
  return detail::getHostCPUNameForARM(Content);
}
#elif defined(__linux__) && defined(__s390x__)
StringRef sys::getHostCPUName() {
  std::unique_ptr<llvh::MemoryBuffer> P = getProcCpuinfoContent();
  StringRef Content = P ? P->getBuffer() : "";
  return detail::getHostCPUNameForS390x(Content);
}
#else
StringRef sys::getHostCPUName() { return "generic"; }
#endif

#if defined(__linux__) && defined(__x86_64__)
                                                                             
                                                                   
                                                                     
static int computeHostNumPhysicalCores() {
                                                                     
                                               
  llvh::ErrorOr<std::unique_ptr<llvh::MemoryBuffer>> Text =
      llvh::MemoryBuffer::getFileAsStream("/proc/cpuinfo");
  if (std::error_code EC = Text.getError()) {
    llvh::errs() << "Can't read "
                 << "/proc/cpuinfo: " << EC.message() << "\n";
    return -1;
  }
  SmallVector<StringRef, 8> strs;
  (*Text)->getBuffer().split(strs, "\n",              -1,
                                           false);
  int CurPhysicalId = -1;
  int CurCoreId = -1;
  SmallSet<std::pair<int, int>, 32> UniqueItems;
  for (auto &Line : strs) {
    Line = Line.trim();
    if (!Line.startswith("physical id") && !Line.startswith("core id"))
      continue;
    std::pair<StringRef, StringRef> Data = Line.split(':');
    auto Name = Data.first.trim();
    auto Val = Data.second.trim();
    if (Name == "physical id") {
      assert(CurPhysicalId == -1 &&
             "Expected a core id before seeing another physical id");
      Val.getAsInteger(10, CurPhysicalId);
    }
    if (Name == "core id") {
      assert(CurCoreId == -1 &&
             "Expected a physical id before seeing another core id");
      Val.getAsInteger(10, CurCoreId);
    }
    if (CurPhysicalId != -1 && CurCoreId != -1) {
      UniqueItems.insert(std::make_pair(CurPhysicalId, CurCoreId));
      CurPhysicalId = -1;
      CurCoreId = -1;
    }
  }
  return UniqueItems.size();
}
#elif defined(__APPLE__) && defined(__x86_64__)
#include <sys/param.h>
#include <sys/sysctl.h>

                                                      
static int computeHostNumPhysicalCores() {
  uint32_t count;
  size_t len = sizeof(count);
  sysctlbyname("hw.physicalcpu", &count, &len, NULL, 0);
  if (count < 1) {
    int nm[2];
    nm[0] = CTL_HW;
    nm[1] = HW_AVAILCPU;
    sysctl(nm, 2, &count, &len, NULL, 0);
    if (count < 1)
      return -1;
  }
  return count;
}
#else
                                                   
static int computeHostNumPhysicalCores() { return -1; }
#endif

int sys::getHostNumPhysicalCores() {
  static int NumCores = computeHostNumPhysicalCores();
  return NumCores;
}

#if defined(__i386__) || defined(_M_IX86) || \
    defined(__x86_64__) || defined(_M_X64)
bool sys::getHostCPUFeatures(StringMap<bool> &Features) {
  unsigned EAX = 0, EBX = 0, ECX = 0, EDX = 0;
  unsigned MaxLevel;
  union {
    unsigned u[3];
    char c[12];
  } text;

  if (getX86CpuIDAndInfo(0, &MaxLevel, text.u + 0, text.u + 2, text.u + 1) ||
      MaxLevel < 1)
    return false;

  getX86CpuIDAndInfo(1, &EAX, &EBX, &ECX, &EDX);

  Features["cmov"]   = (EDX >> 15) & 1;
  Features["mmx"]    = (EDX >> 23) & 1;
  Features["sse"]    = (EDX >> 25) & 1;
  Features["sse2"]   = (EDX >> 26) & 1;

  Features["sse3"]   = (ECX >>  0) & 1;
  Features["pclmul"] = (ECX >>  1) & 1;
  Features["ssse3"]  = (ECX >>  9) & 1;
  Features["cx16"]   = (ECX >> 13) & 1;
  Features["sse4.1"] = (ECX >> 19) & 1;
  Features["sse4.2"] = (ECX >> 20) & 1;
  Features["movbe"]  = (ECX >> 22) & 1;
  Features["popcnt"] = (ECX >> 23) & 1;
  Features["aes"]    = (ECX >> 25) & 1;
  Features["rdrnd"]  = (ECX >> 30) & 1;

                                                                       
                                                                           
                                           
  bool HasAVXSave = ((ECX >> 27) & 1) && ((ECX >> 28) & 1) &&
                    !getX86XCR0(&EAX, &EDX) && ((EAX & 0x6) == 0x6);
                                                              
  bool HasAVX512Save = HasAVXSave && ((EAX & 0xe0) == 0xe0);

  Features["avx"]   = HasAVXSave;
  Features["fma"]   = ((ECX >> 12) & 1) && HasAVXSave;
                                                                      
  Features["xsave"] = ((ECX >> 26) & 1) && HasAVXSave;
  Features["f16c"]  = ((ECX >> 29) & 1) && HasAVXSave;

  unsigned MaxExtLevel;
  getX86CpuIDAndInfo(0x80000000, &MaxExtLevel, &EBX, &ECX, &EDX);

  bool HasExtLeaf1 = MaxExtLevel >= 0x80000001 &&
                     !getX86CpuIDAndInfo(0x80000001, &EAX, &EBX, &ECX, &EDX);
  Features["sahf"]   = HasExtLeaf1 && ((ECX >>  0) & 1);
  Features["lzcnt"]  = HasExtLeaf1 && ((ECX >>  5) & 1);
  Features["sse4a"]  = HasExtLeaf1 && ((ECX >>  6) & 1);
  Features["prfchw"] = HasExtLeaf1 && ((ECX >>  8) & 1);
  Features["xop"]    = HasExtLeaf1 && ((ECX >> 11) & 1) && HasAVXSave;
  Features["lwp"]    = HasExtLeaf1 && ((ECX >> 15) & 1);
  Features["fma4"]   = HasExtLeaf1 && ((ECX >> 16) & 1) && HasAVXSave;
  Features["tbm"]    = HasExtLeaf1 && ((ECX >> 21) & 1);
  Features["mwaitx"] = HasExtLeaf1 && ((ECX >> 29) & 1);

  Features["64bit"]  = HasExtLeaf1 && ((EDX >> 29) & 1);

                                                       
                                                       
  bool HasExtLeaf8 = MaxExtLevel >= 0x80000008 &&
                     !getX86CpuIDAndInfo(0x80000008, &EAX, &EBX, &ECX, &EDX);
  Features["clzero"]   = HasExtLeaf8 && ((EBX >> 0) & 1);
  Features["wbnoinvd"] = HasExtLeaf8 && ((EBX >> 9) & 1);

  bool HasLeaf7 =
      MaxLevel >= 7 && !getX86CpuIDAndInfoEx(0x7, 0x0, &EAX, &EBX, &ECX, &EDX);

  Features["fsgsbase"]   = HasLeaf7 && ((EBX >>  0) & 1);
  Features["sgx"]        = HasLeaf7 && ((EBX >>  2) & 1);
  Features["bmi"]        = HasLeaf7 && ((EBX >>  3) & 1);
                                                                    
  Features["avx2"]       = HasLeaf7 && ((EBX >>  5) & 1) && HasAVXSave;
  Features["bmi2"]       = HasLeaf7 && ((EBX >>  8) & 1);
  Features["invpcid"]    = HasLeaf7 && ((EBX >> 10) & 1);
  Features["rtm"]        = HasLeaf7 && ((EBX >> 11) & 1);
                                                                         
  Features["avx512f"]    = HasLeaf7 && ((EBX >> 16) & 1) && HasAVX512Save;
  Features["avx512dq"]   = HasLeaf7 && ((EBX >> 17) & 1) && HasAVX512Save;
  Features["rdseed"]     = HasLeaf7 && ((EBX >> 18) & 1);
  Features["adx"]        = HasLeaf7 && ((EBX >> 19) & 1);
  Features["avx512ifma"] = HasLeaf7 && ((EBX >> 21) & 1) && HasAVX512Save;
  Features["clflushopt"] = HasLeaf7 && ((EBX >> 23) & 1);
  Features["clwb"]       = HasLeaf7 && ((EBX >> 24) & 1);
  Features["avx512pf"]   = HasLeaf7 && ((EBX >> 26) & 1) && HasAVX512Save;
  Features["avx512er"]   = HasLeaf7 && ((EBX >> 27) & 1) && HasAVX512Save;
  Features["avx512cd"]   = HasLeaf7 && ((EBX >> 28) & 1) && HasAVX512Save;
  Features["sha"]        = HasLeaf7 && ((EBX >> 29) & 1);
  Features["avx512bw"]   = HasLeaf7 && ((EBX >> 30) & 1) && HasAVX512Save;
  Features["avx512vl"]   = HasLeaf7 && ((EBX >> 31) & 1) && HasAVX512Save;

  Features["prefetchwt1"]     = HasLeaf7 && ((ECX >>  0) & 1);
  Features["avx512vbmi"]      = HasLeaf7 && ((ECX >>  1) & 1) && HasAVX512Save;
  Features["pku"]             = HasLeaf7 && ((ECX >>  4) & 1);
  Features["waitpkg"]         = HasLeaf7 && ((ECX >>  5) & 1);
  Features["avx512vbmi2"]     = HasLeaf7 && ((ECX >>  6) & 1) && HasAVX512Save;
  Features["shstk"]           = HasLeaf7 && ((ECX >>  7) & 1);
  Features["gfni"]            = HasLeaf7 && ((ECX >>  8) & 1);
  Features["vaes"]            = HasLeaf7 && ((ECX >>  9) & 1) && HasAVXSave;
  Features["vpclmulqdq"]      = HasLeaf7 && ((ECX >> 10) & 1) && HasAVXSave;
  Features["avx512vnni"]      = HasLeaf7 && ((ECX >> 11) & 1) && HasAVX512Save;
  Features["avx512bitalg"]    = HasLeaf7 && ((ECX >> 12) & 1) && HasAVX512Save;
  Features["avx512vpopcntdq"] = HasLeaf7 && ((ECX >> 14) & 1) && HasAVX512Save;
  Features["rdpid"]           = HasLeaf7 && ((ECX >> 22) & 1);
  Features["cldemote"]        = HasLeaf7 && ((ECX >> 25) & 1);
  Features["movdiri"]         = HasLeaf7 && ((ECX >> 27) & 1);
  Features["movdir64b"]       = HasLeaf7 && ((ECX >> 28) & 1);

                                                                            
                 
                                                                                 
                                                                    
                                            
                                                                       
                                                                       
                                                                
                                                       
                                     
  Features["pconfig"] = HasLeaf7 && ((EDX >> 18) & 1);

  bool HasLeafD = MaxLevel >= 0xd &&
                  !getX86CpuIDAndInfoEx(0xd, 0x1, &EAX, &EBX, &ECX, &EDX);

                                                                      
  Features["xsaveopt"] = HasLeafD && ((EAX >> 0) & 1) && HasAVXSave;
  Features["xsavec"]   = HasLeafD && ((EAX >> 1) & 1) && HasAVXSave;
  Features["xsaves"]   = HasLeafD && ((EAX >> 3) & 1) && HasAVXSave;

  bool HasLeaf14 = MaxLevel >= 0x14 &&
                  !getX86CpuIDAndInfoEx(0x14, 0x0, &EAX, &EBX, &ECX, &EDX);

  Features["ptwrite"] = HasLeaf14 && ((EBX >> 4) & 1);

  return true;
}
#elif defined(__linux__) && (defined(__arm__) || defined(__aarch64__))
bool sys::getHostCPUFeatures(StringMap<bool> &Features) {
  std::unique_ptr<llvh::MemoryBuffer> P = getProcCpuinfoContent();
  if (!P)
    return false;

  SmallVector<StringRef, 32> Lines;
  P->getBuffer().split(Lines, "\n");

  SmallVector<StringRef, 32> CPUFeatures;

                               
  for (unsigned I = 0, E = Lines.size(); I != E; ++I)
    if (Lines[I].startswith("Features")) {
      Lines[I].split(CPUFeatures, ' ');
      break;
    }

#if defined(__aarch64__)
                                                     
  enum { CAP_AES = 0x1, CAP_PMULL = 0x2, CAP_SHA1 = 0x4, CAP_SHA2 = 0x8 };
  uint32_t crypto = 0;
#endif

  for (unsigned I = 0, E = CPUFeatures.size(); I != E; ++I) {
    StringRef LLVMFeatureStr = StringSwitch<StringRef>(CPUFeatures[I])
#if defined(__aarch64__)
                                   .Case("asimd", "neon")
                                   .Case("fp", "fp-armv8")
                                   .Case("crc32", "crc")
#else
                                   .Case("half", "fp16")
                                   .Case("neon", "neon")
                                   .Case("vfpv3", "vfp3")
                                   .Case("vfpv3d16", "d16")
                                   .Case("vfpv4", "vfp4")
                                   .Case("idiva", "hwdiv-arm")
                                   .Case("idivt", "hwdiv")
#endif
                                   .Default("");

#if defined(__aarch64__)
                                                                         
                                                 
    if (CPUFeatures[I] == "aes")
      crypto |= CAP_AES;
    else if (CPUFeatures[I] == "pmull")
      crypto |= CAP_PMULL;
    else if (CPUFeatures[I] == "sha1")
      crypto |= CAP_SHA1;
    else if (CPUFeatures[I] == "sha2")
      crypto |= CAP_SHA2;
#endif

    if (LLVMFeatureStr != "")
      Features[LLVMFeatureStr] = true;
  }

#if defined(__aarch64__)
                                                      
  if (crypto == (CAP_AES | CAP_PMULL | CAP_SHA1 | CAP_SHA2))
    Features["crypto"] = true;
#endif

  return true;
}
#else
bool sys::getHostCPUFeatures(StringMap<bool> &Features) { return false; }
#endif

std::string sys::getProcessTriple() {
  std::string TargetTripleString = updateTripleOSVersion(LLVM_HOST_TRIPLE);
  Triple PT(Triple::normalize(TargetTripleString));

  if (sizeof(void *) == 8 && PT.isArch32Bit())
    PT = PT.get64BitArchVariant();
  if (sizeof(void *) == 4 && PT.isArch64Bit())
    PT = PT.get32BitArchVariant();

  return PT.str();
}
