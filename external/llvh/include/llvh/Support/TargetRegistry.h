//===- Support/TargetRegistry.h - Target Registration -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file exposes the TargetRegistry interface, which tools can use to access
// the appropriate target specific classes (TargetMachine, AsmPrinter, etc.)
// which have been registered.
//
// Target specific class implementations should register themselves using the
// appropriate TargetRegistry interfaces.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TARGETREGISTRY_H
#define LLVM_SUPPORT_TARGETREGISTRY_H

#include "llvh-c/DisassemblerTypes.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Triple.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/Support/CodeGen.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/FormattedStream.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <memory>
#include <string>

namespace llvh {

class AsmPrinter;
class MCAsmBackend;
class MCAsmInfo;
class MCAsmParser;
class MCCodeEmitter;
class MCContext;
class MCDisassembler;
class MCInstPrinter;
class MCInstrAnalysis;
class MCInstrInfo;
class MCObjectWriter;
class MCRegisterInfo;
class MCRelocationInfo;
class MCStreamer;
class MCSubtargetInfo;
class MCSymbolizer;
class MCTargetAsmParser;
class MCTargetOptions;
class MCTargetStreamer;
class raw_ostream;
class raw_pwrite_stream;
class TargetMachine;
class TargetOptions;

MCStreamer *createNullStreamer(MCContext &Ctx);
                                       

                                                                               
                                                           
   
                                                                             
                                                                              
              
   
                                                                       
                                                                            
   
                                                                        
                                                                           
                        
   
                                                                           
                 
MCStreamer *
createAsmStreamer(MCContext &Ctx, std::unique_ptr<formatted_raw_ostream> OS,
                  bool isVerboseAsm, bool useDwarfDirectory,
                  MCInstPrinter *InstPrint, std::unique_ptr<MCCodeEmitter> &&CE,
                  std::unique_ptr<MCAsmBackend> &&TAB, bool ShowInst);

MCStreamer *createELFStreamer(MCContext &Ctx,
                              std::unique_ptr<MCAsmBackend> &&TAB,
                              std::unique_ptr<MCObjectWriter> &&OW,
                              std::unique_ptr<MCCodeEmitter> &&CE,
                              bool RelaxAll);
MCStreamer *createMachOStreamer(MCContext &Ctx,
                                std::unique_ptr<MCAsmBackend> &&TAB,
                                std::unique_ptr<MCObjectWriter> &&OW,
                                std::unique_ptr<MCCodeEmitter> &&CE,
                                bool RelaxAll, bool DWARFMustBeAtTheEnd,
                                bool LabelSections = false);
MCStreamer *createWasmStreamer(MCContext &Ctx,
                               std::unique_ptr<MCAsmBackend> &&TAB,
                               std::unique_ptr<MCObjectWriter> &&OW,
                               std::unique_ptr<MCCodeEmitter> &&CE,
                               bool RelaxAll);

MCRelocationInfo *createMCRelocationInfo(const Triple &TT, MCContext &Ctx);

MCSymbolizer *createMCSymbolizer(const Triple &TT, LLVMOpInfoCallback GetOpInfo,
                                 LLVMSymbolLookupCallback SymbolLookUp,
                                 void *DisInfo, MCContext *Ctx,
                                 std::unique_ptr<MCRelocationInfo> &&RelInfo);

                                                     
   
                                                                        
                                                      
   
                                                                          
                                                                              
                                 
class Target {
public:
  friend struct TargetRegistry;

  using ArchMatchFnTy = bool (*)(Triple::ArchType Arch);

  using MCAsmInfoCtorFnTy = MCAsmInfo *(*)(const MCRegisterInfo &MRI,
                                           const Triple &TT);
  using MCInstrInfoCtorFnTy = MCInstrInfo *(*)();
  using MCInstrAnalysisCtorFnTy = MCInstrAnalysis *(*)(const MCInstrInfo *Info);
  using MCRegInfoCtorFnTy = MCRegisterInfo *(*)(const Triple &TT);
  using MCSubtargetInfoCtorFnTy = MCSubtargetInfo *(*)(const Triple &TT,
                                                       StringRef CPU,
                                                       StringRef Features);
  using TargetMachineCtorTy = TargetMachine
      *(*)(const Target &T, const Triple &TT, StringRef CPU, StringRef Features,
           const TargetOptions &Options, Optional<Reloc::Model> RM,
           Optional<CodeModel::Model> CM, CodeGenOpt::Level OL, bool JIT);
                                                                           
                                                                              
               
  using AsmPrinterCtorTy = AsmPrinter *(*)(
      TargetMachine &TM, std::unique_ptr<MCStreamer> &&Streamer);
  using MCAsmBackendCtorTy = MCAsmBackend *(*)(const Target &T,
                                               const MCSubtargetInfo &STI,
                                               const MCRegisterInfo &MRI,
                                               const MCTargetOptions &Options);
  using MCAsmParserCtorTy = MCTargetAsmParser *(*)(
      const MCSubtargetInfo &STI, MCAsmParser &P, const MCInstrInfo &MII,
      const MCTargetOptions &Options);
  using MCDisassemblerCtorTy = MCDisassembler *(*)(const Target &T,
                                                   const MCSubtargetInfo &STI,
                                                   MCContext &Ctx);
  using MCInstPrinterCtorTy = MCInstPrinter *(*)(const Triple &T,
                                                 unsigned SyntaxVariant,
                                                 const MCAsmInfo &MAI,
                                                 const MCInstrInfo &MII,
                                                 const MCRegisterInfo &MRI);
  using MCCodeEmitterCtorTy = MCCodeEmitter *(*)(const MCInstrInfo &II,
                                                 const MCRegisterInfo &MRI,
                                                 MCContext &Ctx);
  using ELFStreamerCtorTy =
      MCStreamer *(*)(const Triple &T, MCContext &Ctx,
                      std::unique_ptr<MCAsmBackend> &&TAB,
                      std::unique_ptr<MCObjectWriter> &&OW,
                      std::unique_ptr<MCCodeEmitter> &&Emitter, bool RelaxAll);
  using MachOStreamerCtorTy =
      MCStreamer *(*)(MCContext &Ctx, std::unique_ptr<MCAsmBackend> &&TAB,
                      std::unique_ptr<MCObjectWriter> &&OW,
                      std::unique_ptr<MCCodeEmitter> &&Emitter, bool RelaxAll,
                      bool DWARFMustBeAtTheEnd);
  using COFFStreamerCtorTy =
      MCStreamer *(*)(MCContext &Ctx, std::unique_ptr<MCAsmBackend> &&TAB,
                      std::unique_ptr<MCObjectWriter> &&OW,
                      std::unique_ptr<MCCodeEmitter> &&Emitter, bool RelaxAll,
                      bool IncrementalLinkerCompatible);
  using WasmStreamerCtorTy =
      MCStreamer *(*)(const Triple &T, MCContext &Ctx,
                      std::unique_ptr<MCAsmBackend> &&TAB,
                      std::unique_ptr<MCObjectWriter> &&OW,
                      std::unique_ptr<MCCodeEmitter> &&Emitter, bool RelaxAll);
  using NullTargetStreamerCtorTy = MCTargetStreamer *(*)(MCStreamer &S);
  using AsmTargetStreamerCtorTy = MCTargetStreamer *(*)(
      MCStreamer &S, formatted_raw_ostream &OS, MCInstPrinter *InstPrint,
      bool IsVerboseAsm);
  using ObjectTargetStreamerCtorTy = MCTargetStreamer *(*)(
      MCStreamer &S, const MCSubtargetInfo &STI);
  using MCRelocationInfoCtorTy = MCRelocationInfo *(*)(const Triple &TT,
                                                       MCContext &Ctx);
  using MCSymbolizerCtorTy = MCSymbolizer *(*)(
      const Triple &TT, LLVMOpInfoCallback GetOpInfo,
      LLVMSymbolLookupCallback SymbolLookUp, void *DisInfo, MCContext *Ctx,
      std::unique_ptr<MCRelocationInfo> &&RelInfo);

private:
                                                                             
                     
  Target *Next;

                                                                       
  ArchMatchFnTy ArchMatchFn;

                             
  const char *Name;

                                                    
  const char *ShortDesc;

                                                                               
                                                   
  const char *BackendName;

                                                    
  bool HasJIT;

                                                                            
                 
  MCAsmInfoCtorFnTy MCAsmInfoCtorFn;

                                                                             
                    
  MCInstrInfoCtorFnTy MCInstrInfoCtorFn;

                                                                    
                                     
  MCInstrAnalysisCtorFnTy MCInstrAnalysisCtorFn;

                                                                              
                    
  MCRegInfoCtorFnTy MCRegInfoCtorFn;

                                                                    
                                     
  MCSubtargetInfoCtorFnTy MCSubtargetInfoCtorFn;

                                                                   
                                   
  TargetMachineCtorTy TargetMachineCtorFn;

                                                                  
                                  
  MCAsmBackendCtorTy MCAsmBackendCtorFn;

                                                                 
                                       
  MCAsmParserCtorTy MCAsmParserCtorFn;

                                                                            
                    
  AsmPrinterCtorTy AsmPrinterCtorFn;

                                                                    
                                    
  MCDisassemblerCtorTy MCDisassemblerCtorFn;

                                                                   
                                   
  MCInstPrinterCtorTy MCInstPrinterCtorFn;

                                                                   
                                 
  MCCodeEmitterCtorTy MCCodeEmitterCtorFn;

                                                                          
  COFFStreamerCtorTy COFFStreamerCtorFn = nullptr;
  MachOStreamerCtorTy MachOStreamerCtorFn = nullptr;
  ELFStreamerCtorTy ELFStreamerCtorFn = nullptr;
  WasmStreamerCtorTy WasmStreamerCtorFn = nullptr;

                                                                     
                                     
  NullTargetStreamerCtorTy NullTargetStreamerCtorFn = nullptr;

                                                                    
                                     
  AsmTargetStreamerCtorTy AsmTargetStreamerCtorFn = nullptr;

                                                                    
                                     
  ObjectTargetStreamerCtorTy ObjectTargetStreamerCtorFn = nullptr;

                                                                      
                                                                              
  MCRelocationInfoCtorTy MCRelocationInfoCtorFn = nullptr;

                                                                  
                                                                      
  MCSymbolizerCtorTy MCSymbolizerCtorFn = nullptr;

public:
  Target() = default;

                              
        

                                                 
  const Target *getNext() const { return Next; }

                                    
  const char *getName() const { return Name; }

                                                                  
  const char *getShortDescription() const { return ShortDesc; }

                                            
  const char *getBackendName() const { return BackendName; }

        
                              
        

                                                                           
  bool hasJIT() const { return HasJIT; }

                                                                       
  bool hasTargetMachine() const { return TargetMachineCtorFn != nullptr; }

                                                                    
  bool hasMCAsmBackend() const { return MCAsmBackendCtorFn != nullptr; }

                                                                      
  bool hasMCAsmParser() const { return MCAsmParserCtorFn != nullptr; }

        
                                
        

                                                                           
                    
     
                                                                            
                                                                         
                                                                           
                                  
  MCAsmInfo *createMCAsmInfo(const MCRegisterInfo &MRI,
                             StringRef TheTriple) const {
    if (!MCAsmInfoCtorFn)
      return nullptr;
    return MCAsmInfoCtorFn(MRI, Triple(TheTriple));
  }

                                                              
     
  MCInstrInfo *createMCInstrInfo() const {
    if (!MCInstrInfoCtorFn)
      return nullptr;
    return MCInstrInfoCtorFn();
  }

                                                                      
     
  MCInstrAnalysis *createMCInstrAnalysis(const MCInstrInfo *Info) const {
    if (!MCInstrAnalysisCtorFn)
      return nullptr;
    return MCInstrAnalysisCtorFn(Info);
  }

                                                               
     
  MCRegisterInfo *createMCRegInfo(StringRef TT) const {
    if (!MCRegInfoCtorFn)
      return nullptr;
    return MCRegInfoCtorFn(Triple(TT));
  }

                                                                      
     
                                                                            
                                                                         
                                                                           
                                  
                                                           
                                                                     
                                 
  MCSubtargetInfo *createMCSubtargetInfo(StringRef TheTriple, StringRef CPU,
                                         StringRef Features) const {
    if (!MCSubtargetInfoCtorFn)
      return nullptr;
    return MCSubtargetInfoCtorFn(Triple(TheTriple), CPU, Features);
  }

                                                                           
                                  
     
                                                                     
                                                                         
                                                                           
                                  
  TargetMachine *createTargetMachine(StringRef TT, StringRef CPU,
                                     StringRef Features,
                                     const TargetOptions &Options,
                                     Optional<Reloc::Model> RM,
                                     Optional<CodeModel::Model> CM = None,
                                     CodeGenOpt::Level OL = CodeGenOpt::Default,
                                     bool JIT = false) const {
    if (!TargetMachineCtorFn)
      return nullptr;
    return TargetMachineCtorFn(*this, Triple(TT), CPU, Features, Options, RM,
                               CM, OL, JIT);
  }

                                                                    
  MCAsmBackend *createMCAsmBackend(const MCSubtargetInfo &STI,
                                   const MCRegisterInfo &MRI,
                                   const MCTargetOptions &Options) const {
    if (!MCAsmBackendCtorFn)
      return nullptr;
    return MCAsmBackendCtorFn(*this, STI, MRI, Options);
  }

                                                                   
     
                                                                           
                         
  MCTargetAsmParser *createMCAsmParser(const MCSubtargetInfo &STI,
                                       MCAsmParser &Parser,
                                       const MCInstrInfo &MII,
                                       const MCTargetOptions &Options) const {
    if (!MCAsmParserCtorFn)
      return nullptr;
    return MCAsmParserCtorFn(STI, Parser, MII, Options);
  }

                                                                              
                                               
  AsmPrinter *createAsmPrinter(TargetMachine &TM,
                               std::unique_ptr<MCStreamer> &&Streamer) const {
    if (!AsmPrinterCtorFn)
      return nullptr;
    return AsmPrinterCtorFn(TM, std::move(Streamer));
  }

  MCDisassembler *createMCDisassembler(const MCSubtargetInfo &STI,
                                       MCContext &Ctx) const {
    if (!MCDisassemblerCtorFn)
      return nullptr;
    return MCDisassemblerCtorFn(*this, STI, Ctx);
  }

  MCInstPrinter *createMCInstPrinter(const Triple &T, unsigned SyntaxVariant,
                                     const MCAsmInfo &MAI,
                                     const MCInstrInfo &MII,
                                     const MCRegisterInfo &MRI) const {
    if (!MCInstPrinterCtorFn)
      return nullptr;
    return MCInstPrinterCtorFn(T, SyntaxVariant, MAI, MII, MRI);
  }

                                                                  
  MCCodeEmitter *createMCCodeEmitter(const MCInstrInfo &II,
                                     const MCRegisterInfo &MRI,
                                     MCContext &Ctx) const {
    if (!MCCodeEmitterCtorFn)
      return nullptr;
    return MCCodeEmitterCtorFn(II, MRI, Ctx);
  }

                                          
     
                                 
                                    
                                                                      
                                  
                                                                             
                                       
  MCStreamer *createMCObjectStreamer(const Triple &T, MCContext &Ctx,
                                     std::unique_ptr<MCAsmBackend> &&TAB,
                                     std::unique_ptr<MCObjectWriter> &&OW,
                                     std::unique_ptr<MCCodeEmitter> &&Emitter,
                                     const MCSubtargetInfo &STI, bool RelaxAll,
                                     bool IncrementalLinkerCompatible,
                                     bool DWARFMustBeAtTheEnd) const {
    MCStreamer *S;
    switch (T.getObjectFormat()) {
    default:
      llvm_unreachable("Unknown object format");
    case Triple::COFF:
      assert(T.isOSWindows() && "only Windows COFF is supported");
      S = COFFStreamerCtorFn(Ctx, std::move(TAB), std::move(OW),
                             std::move(Emitter), RelaxAll,
                             IncrementalLinkerCompatible);
      break;
    case Triple::MachO:
      if (MachOStreamerCtorFn)
        S = MachOStreamerCtorFn(Ctx, std::move(TAB), std::move(OW),
                                std::move(Emitter), RelaxAll,
                                DWARFMustBeAtTheEnd);
      else
        S = createMachOStreamer(Ctx, std::move(TAB), std::move(OW),
                                std::move(Emitter), RelaxAll,
                                DWARFMustBeAtTheEnd);
      break;
    case Triple::ELF:
      if (ELFStreamerCtorFn)
        S = ELFStreamerCtorFn(T, Ctx, std::move(TAB), std::move(OW),
                              std::move(Emitter), RelaxAll);
      else
        S = createELFStreamer(Ctx, std::move(TAB), std::move(OW),
                              std::move(Emitter), RelaxAll);
      break;
    case Triple::Wasm:
      if (WasmStreamerCtorFn)
        S = WasmStreamerCtorFn(T, Ctx, std::move(TAB), std::move(OW),
                               std::move(Emitter), RelaxAll);
      else
        S = createWasmStreamer(Ctx, std::move(TAB), std::move(OW),
                               std::move(Emitter), RelaxAll);
      break;
    }
    if (ObjectTargetStreamerCtorFn)
      ObjectTargetStreamerCtorFn(*S, STI);
    return S;
  }

  MCStreamer *createAsmStreamer(MCContext &Ctx,
                                std::unique_ptr<formatted_raw_ostream> OS,
                                bool IsVerboseAsm, bool UseDwarfDirectory,
                                MCInstPrinter *InstPrint,
                                std::unique_ptr<MCCodeEmitter> &&CE,
                                std::unique_ptr<MCAsmBackend> &&TAB,
                                bool ShowInst) const {
    formatted_raw_ostream &OSRef = *OS;
    MCStreamer *S = llvh::createAsmStreamer(
        Ctx, std::move(OS), IsVerboseAsm, UseDwarfDirectory, InstPrint,
        std::move(CE), std::move(TAB), ShowInst);
    createAsmTargetStreamer(*S, OSRef, InstPrint, IsVerboseAsm);
    return S;
  }

  MCTargetStreamer *createAsmTargetStreamer(MCStreamer &S,
                                            formatted_raw_ostream &OS,
                                            MCInstPrinter *InstPrint,
                                            bool IsVerboseAsm) const {
    if (AsmTargetStreamerCtorFn)
      return AsmTargetStreamerCtorFn(S, OS, InstPrint, IsVerboseAsm);
    return nullptr;
  }

  MCStreamer *createNullStreamer(MCContext &Ctx) const {
    MCStreamer *S = llvh::createNullStreamer(Ctx);
    createNullTargetStreamer(*S);
    return S;
  }

  MCTargetStreamer *createNullTargetStreamer(MCStreamer &S) const {
    if (NullTargetStreamerCtorFn)
      return NullTargetStreamerCtorFn(S);
    return nullptr;
  }

                                                                         
     
                                  
                                    
  MCRelocationInfo *createMCRelocationInfo(StringRef TT, MCContext &Ctx) const {
    MCRelocationInfoCtorTy Fn = MCRelocationInfoCtorFn
                                    ? MCRelocationInfoCtorFn
                                    : llvh::createMCRelocationInfo;
    return Fn(Triple(TT), Ctx);
  }

                                                                 
     
                                  
                                                                       
               
                                                               
                                                                               
          
           
                                    
                                                                      
                
  MCSymbolizer *
  createMCSymbolizer(StringRef TT, LLVMOpInfoCallback GetOpInfo,
                     LLVMSymbolLookupCallback SymbolLookUp, void *DisInfo,
                     MCContext *Ctx,
                     std::unique_ptr<MCRelocationInfo> &&RelInfo) const {
    MCSymbolizerCtorTy Fn =
        MCSymbolizerCtorFn ? MCSymbolizerCtorFn : llvh::createMCSymbolizer;
    return Fn(Triple(TT), GetOpInfo, SymbolLookUp, DisInfo, Ctx,
              std::move(RelInfo));
  }

        
};

                                                                   
struct TargetRegistry {
                                                                       
                                                                             
                                                                    
               
  TargetRegistry() = delete;

  class iterator {
    friend struct TargetRegistry;

    const Target *Current = nullptr;

    explicit iterator(Target *T) : Current(T) {}

  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = Target;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    iterator() = default;

    bool operator==(const iterator &x) const { return Current == x.Current; }
    bool operator!=(const iterator &x) const { return !operator==(x); }

                                                 
    iterator &operator++() {                
      assert(Current && "Cannot increment end iterator!");
      Current = Current->getNext();
      return *this;
    }
    iterator operator++(int) {                 
      iterator tmp = *this;
      ++*this;
      return tmp;
    }

    const Target &operator*() const {
      assert(Current && "Cannot dereference end iterator!");
      return *Current;
    }

    const Target *operator->() const { return &operator*(); }
  };

                                                                     
                                                             
  static void printRegisteredTargetsForVersion(raw_ostream &OS);

                           
        

  static iterator_range<iterator> targets();

                                                              
     
                                                             
                                                                             
            
  static const Target *lookupTarget(const std::string &Triple,
                                    std::string &Error);

                                                                  
                                                                  
                                                                     
                     
     
                                                                     
                                                                     
                                                                    
                              
                                                                             
            
  static const Target *lookupTarget(const std::string &ArchName,
                                    Triple &TheTriple, std::string &Error);

        
                               
        

                                                                        
                                                               
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                    
                                                                            
             
                                                                           
                                                                  
                                                                                
               
                                                                            
                                                          
                 
  static void RegisterTarget(Target &T, const char *Name, const char *ShortDesc,
                             const char *BackendName,
                             Target::ArchMatchFnTy ArchMatchFn,
                             bool HasJIT = false);

                                                                     
                   
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                     
  static void RegisterMCAsmInfo(Target &T, Target::MCAsmInfoCtorFnTy Fn) {
    T.MCAsmInfoCtorFn = Fn;
  }

                                                                         
                   
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                       
  static void RegisterMCInstrInfo(Target &T, Target::MCInstrInfoCtorFnTy Fn) {
    T.MCInstrInfoCtorFn = Fn;
  }

                                                                             
                       
  static void RegisterMCInstrAnalysis(Target &T,
                                      Target::MCInstrAnalysisCtorFnTy Fn) {
    T.MCInstrAnalysisCtorFn = Fn;
  }

                                                                          
                   
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                          
  static void RegisterMCRegInfo(Target &T, Target::MCRegInfoCtorFnTy Fn) {
    T.MCRegInfoCtorFn = Fn;
  }

                                                                             
                       
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                           
  static void RegisterMCSubtargetInfo(Target &T,
                                      Target::MCSubtargetInfoCtorFnTy Fn) {
    T.MCSubtargetInfoCtorFn = Fn;
  }

                                                                             
                   
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                         
  static void RegisterTargetMachine(Target &T, Target::TargetMachineCtorTy Fn) {
    T.TargetMachineCtorFn = Fn;
  }

                                                                           
                   
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                       
  static void RegisterMCAsmBackend(Target &T, Target::MCAsmBackendCtorTy Fn) {
    T.MCAsmBackendCtorFn = Fn;
  }

                                                                           
                       
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                              
  static void RegisterMCAsmParser(Target &T, Target::MCAsmParserCtorTy Fn) {
    T.MCAsmParserCtorFn = Fn;
  }

                                                                              
             
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                       
  static void RegisterAsmPrinter(Target &T, Target::AsmPrinterCtorTy Fn) {
    T.AsmPrinterCtorFn = Fn;
  }

                                                                           
                       
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                           
  static void RegisterMCDisassembler(Target &T,
                                     Target::MCDisassemblerCtorTy Fn) {
    T.MCDisassemblerCtorFn = Fn;
  }

                                                                             
                   
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                          
  static void RegisterMCInstPrinter(Target &T, Target::MCInstPrinterCtorTy Fn) {
    T.MCInstPrinterCtorFn = Fn;
  }

                                                                             
                   
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                          
  static void RegisterMCCodeEmitter(Target &T, Target::MCCodeEmitterCtorTy Fn) {
    T.MCCodeEmitterCtorFn = Fn;
  }

  static void RegisterCOFFStreamer(Target &T, Target::COFFStreamerCtorTy Fn) {
    T.COFFStreamerCtorFn = Fn;
  }

  static void RegisterMachOStreamer(Target &T, Target::MachOStreamerCtorTy Fn) {
    T.MachOStreamerCtorFn = Fn;
  }

  static void RegisterELFStreamer(Target &T, Target::ELFStreamerCtorTy Fn) {
    T.ELFStreamerCtorFn = Fn;
  }

  static void RegisterWasmStreamer(Target &T, Target::WasmStreamerCtorTy Fn) {
    T.WasmStreamerCtorFn = Fn;
  }

  static void RegisterNullTargetStreamer(Target &T,
                                         Target::NullTargetStreamerCtorTy Fn) {
    T.NullTargetStreamerCtorFn = Fn;
  }

  static void RegisterAsmTargetStreamer(Target &T,
                                        Target::AsmTargetStreamerCtorTy Fn) {
    T.AsmTargetStreamerCtorFn = Fn;
  }

  static void
  RegisterObjectTargetStreamer(Target &T,
                               Target::ObjectTargetStreamerCtorTy Fn) {
    T.ObjectTargetStreamerCtorFn = Fn;
  }

                                                             
                                          
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                             
  static void RegisterMCRelocationInfo(Target &T,
                                       Target::MCRelocationInfoCtorTy Fn) {
    T.MCRelocationInfoCtorFn = Fn;
  }

                                                     
                                          
     
                                                                          
                                                                          
                                                                  
     
                                             
                                                                         
  static void RegisterMCSymbolizer(Target &T, Target::MCSymbolizerCtorTy Fn) {
    T.MCSymbolizerCtorFn = Fn;
  }

        
};

                                                                              

                                                                             
                                            
   
   
                                                              
                                 
                          
     
                                                   
                                                                  
                                              
     
template <Triple::ArchType TargetArchType = Triple::UnknownArch,
          bool HasJIT = false>
struct RegisterTarget {
  RegisterTarget(Target &T, const char *Name, const char *Desc,
                 const char *BackendName) {
    TargetRegistry::RegisterTarget(T, Name, Desc, BackendName, &getArchMatch,
                                   HasJIT);
  }

  static bool getArchMatch(Triple::ArchType Arch) {
    return Arch == TargetArchType;
  }
};

                                                                              
                                                                            
                                         
   
                                               
                                 
                                                      
     
template <class MCAsmInfoImpl> struct RegisterMCAsmInfo {
  RegisterMCAsmInfo(Target &T) {
    TargetRegistry::RegisterMCAsmInfo(T, &Allocator);
  }

private:
  static MCAsmInfo *Allocator(const MCRegisterInfo &        ,
                              const Triple &TT) {
    return new MCAsmInfoImpl(TT);
  }
};

                                                                                
                                                                  
                         
   
                                               
                                 
                                                       
     
struct RegisterMCAsmInfoFn {
  RegisterMCAsmInfoFn(Target &T, Target::MCAsmInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCAsmInfo(T, Fn);
  }
};

                                                                              
                                                                              
                                            
   
                                               
                                 
                                                          
     
template <class MCInstrInfoImpl> struct RegisterMCInstrInfo {
  RegisterMCInstrInfo(Target &T) {
    TargetRegistry::RegisterMCInstrInfo(T, &Allocator);
  }

private:
  static MCInstrInfo *Allocator() { return new MCInstrInfoImpl(); }
};

                                                                    
                                                                            
                                
   
                                               
                                 
                                                         
     
struct RegisterMCInstrInfoFn {
  RegisterMCInstrInfoFn(Target &T, Target::MCInstrInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCInstrInfo(T, Fn);
  }
};

                                                                      
                                                                          
                                                                
   
                                               
                                 
                                                                  
     
template <class MCInstrAnalysisImpl> struct RegisterMCInstrAnalysis {
  RegisterMCInstrAnalysis(Target &T) {
    TargetRegistry::RegisterMCInstrAnalysis(T, &Allocator);
  }

private:
  static MCInstrAnalysis *Allocator(const MCInstrInfo *Info) {
    return new MCInstrAnalysisImpl(Info);
  }
};

                                                                        
                                                                             
                                   
   
                                               
                                 
                                                             
     
struct RegisterMCInstrAnalysisFn {
  RegisterMCInstrAnalysisFn(Target &T, Target::MCInstrAnalysisCtorFnTy Fn) {
    TargetRegistry::RegisterMCInstrAnalysis(T, Fn);
  }
};

                                                                              
                                                                            
                                         
   
                                               
                                 
                                                      
     
template <class MCRegisterInfoImpl> struct RegisterMCRegInfo {
  RegisterMCRegInfo(Target &T) {
    TargetRegistry::RegisterMCRegInfo(T, &Allocator);
  }

private:
  static MCRegisterInfo *Allocator(const Triple &       ) {
    return new MCRegisterInfoImpl();
  }
};

                                                                           
                                                                       
                         
   
                                               
                                 
                                                       
     
struct RegisterMCRegInfoFn {
  RegisterMCRegInfoFn(Target &T, Target::MCRegInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCRegInfo(T, Fn);
  }
};

                                                                      
                                                                           
                                                         
   
                                               
                                 
                                                                  
     
template <class MCSubtargetInfoImpl> struct RegisterMCSubtargetInfo {
  RegisterMCSubtargetInfo(Target &T) {
    TargetRegistry::RegisterMCSubtargetInfo(T, &Allocator);
  }

private:
  static MCSubtargetInfo *Allocator(const Triple &       , StringRef        ,
                                    StringRef       ) {
    return new MCSubtargetInfoImpl();
  }
};

                                                                        
                                                                          
                                
   
                                               
                                 
                                                             
     
struct RegisterMCSubtargetInfoFn {
  RegisterMCSubtargetInfoFn(Target &T, Target::MCSubtargetInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCSubtargetInfo(T, Fn);
  }
};

                                                                            
                                                                
                    
   
                                               
                                 
                                                              
     
template <class TargetMachineImpl> struct RegisterTargetMachine {
  RegisterTargetMachine(Target &T) {
    TargetRegistry::RegisterTargetMachine(T, &Allocator);
  }

private:
  static TargetMachine *
  Allocator(const Target &T, const Triple &TT, StringRef CPU, StringRef FS,
            const TargetOptions &Options, Optional<Reloc::Model> RM,
            Optional<CodeModel::Model> CM, CodeGenOpt::Level OL, bool JIT) {
    return new TargetMachineImpl(T, TT, CPU, FS, Options, RM, CM, OL, JIT);
  }
};

                                                                            
                             
   
                                                     
                                 
                                                        
     
template <class MCAsmBackendImpl> struct RegisterMCAsmBackend {
  RegisterMCAsmBackend(Target &T) {
    TargetRegistry::RegisterMCAsmBackend(T, &Allocator);
  }

private:
  static MCAsmBackend *Allocator(const Target &T, const MCSubtargetInfo &STI,
                                 const MCRegisterInfo &MRI,
                                 const MCTargetOptions &Options) {
    return new MCAsmBackendImpl(T, STI, MRI);
  }
};

                                                                           
                                                                 
                    
   
                                                    
                                 
                                                        
     
template <class MCAsmParserImpl> struct RegisterMCAsmParser {
  RegisterMCAsmParser(Target &T) {
    TargetRegistry::RegisterMCAsmParser(T, &Allocator);
  }

private:
  static MCTargetAsmParser *Allocator(const MCSubtargetInfo &STI,
                                      MCAsmParser &P, const MCInstrInfo &MII,
                                      const MCTargetOptions &Options) {
    return new MCAsmParserImpl(STI, P, MII, Options);
  }
};

                                                                          
                                                                  
                    
   
                                                   
                                 
                                                        
     
template <class AsmPrinterImpl> struct RegisterAsmPrinter {
  RegisterAsmPrinter(Target &T) {
    TargetRegistry::RegisterAsmPrinter(T, &Allocator);
  }

private:
  static AsmPrinter *Allocator(TargetMachine &TM,
                               std::unique_ptr<MCStreamer> &&Streamer) {
    return new AsmPrinterImpl(TM, std::move(Streamer));
  }
};

                                                                             
                                                              
                    
   
                                                      
                                 
                                                            
     
template <class MCCodeEmitterImpl> struct RegisterMCCodeEmitter {
  RegisterMCCodeEmitter(Target &T) {
    TargetRegistry::RegisterMCCodeEmitter(T, &Allocator);
  }

private:
  static MCCodeEmitter *Allocator(const MCInstrInfo &       ,
                                  const MCRegisterInfo &        ,
                                  MCContext &        ) {
    return new MCCodeEmitterImpl();
  }
};

}                      

#endif                                 
