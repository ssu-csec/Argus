//===- llvm/IR/DiagnosticInfo.h - Diagnostic Declaration --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the different classes involved in low level diagnostics.
//
// Diagnostics reporting is still done as part of the LLVMContext.
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DIAGNOSTICINFO_H
#define LLVM_IR_DIAGNOSTICINFO_H

#include "llvh-c/Types.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/IR/DebugLoc.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/YAMLTraits.h"
#include <algorithm>
#include <cstdint>
#include <functional>
#include <iterator>
#include <string>

namespace llvh {

                        
class DiagnosticPrinter;
class Function;
class Instruction;
class LLVMContext;
class Module;
class SMDiagnostic;

                                                             
enum DiagnosticSeverity : char {
  DS_Error,
  DS_Warning,
  DS_Remark,
                                                                             
           
  DS_Note
};

                                                         
                                                                                
enum DiagnosticKind {
  DK_InlineAsm,
  DK_ResourceLimit,
  DK_StackSize,
  DK_Linker,
  DK_DebugMetadataVersion,
  DK_DebugMetadataInvalid,
  DK_ISelFallback,
  DK_SampleProfile,
  DK_OptimizationRemark,
  DK_OptimizationRemarkMissed,
  DK_OptimizationRemarkAnalysis,
  DK_OptimizationRemarkAnalysisFPCommute,
  DK_OptimizationRemarkAnalysisAliasing,
  DK_OptimizationFailure,
  DK_FirstRemark = DK_OptimizationRemark,
  DK_LastRemark = DK_OptimizationFailure,
  DK_MachineOptimizationRemark,
  DK_MachineOptimizationRemarkMissed,
  DK_MachineOptimizationRemarkAnalysis,
  DK_FirstMachineRemark = DK_MachineOptimizationRemark,
  DK_LastMachineRemark = DK_MachineOptimizationRemarkAnalysis,
  DK_MIRParser,
  DK_PGOProfile,
  DK_Unsupported,
  DK_FirstPluginKind
};

                                                           
                                                                     
                                                                
                                                                           
                                         
                                                                        
                                                           
                          
int getNextAvailablePluginDiagnosticKind();

                                                               
                
                                                                    
                                                                        
              
class DiagnosticInfo {
private:
                                                    
  const                      int Kind;
                                                    
  const DiagnosticSeverity Severity;

public:
  DiagnosticInfo(                     int Kind, DiagnosticSeverity Severity)
      : Kind(Kind), Severity(Severity) {}

  virtual ~DiagnosticInfo() = default;

                       int getKind() const { return Kind; }
  DiagnosticSeverity getSeverity() const { return Severity; }

                                                          
                                                                   
                                                                   
                                                               
                                                                         
              
  virtual void print(DiagnosticPrinter &DP) const = 0;
};

using DiagnosticHandlerFunction = std::function<void(const DiagnosticInfo &)>;

                                                    
                                                         
class DiagnosticInfoInlineAsm : public DiagnosticInfo {
private:
                                              
  unsigned LocCookie = 0;
                             
  const Twine &MsgStr;
                                     
  const Instruction *Instr = nullptr;

public:
                                                              
                                                                               
                                                
  DiagnosticInfoInlineAsm(const Twine &MsgStr,
                          DiagnosticSeverity Severity = DS_Error)
      : DiagnosticInfo(DK_InlineAsm, Severity), MsgStr(MsgStr) {}

                                                                     
                                  
                                                                               
                                                
  DiagnosticInfoInlineAsm(unsigned LocCookie, const Twine &MsgStr,
                          DiagnosticSeverity Severity = DS_Error)
      : DiagnosticInfo(DK_InlineAsm, Severity), LocCookie(LocCookie),
        MsgStr(MsgStr) {}

                                                                            
                                  
                                                                               
                                                
                    
  DiagnosticInfoInlineAsm(const Instruction &I, const Twine &MsgStr,
                          DiagnosticSeverity Severity = DS_Error);

  unsigned getLocCookie() const { return LocCookie; }
  const Twine &getMsgStr() const { return MsgStr; }
  const Instruction *getInstruction() const { return Instr; }

                                 
  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_InlineAsm;
  }
};

                                                         
                                            
class DiagnosticInfoResourceLimit : public DiagnosticInfo {
private:
                                                                       
  const Function &Fn;

                                                        
  const char *ResourceName;

                             
  uint64_t ResourceSize;

                      
  uint64_t ResourceLimit;

public:
                                                                      
                                 
  DiagnosticInfoResourceLimit(const Function &Fn, const char *ResourceName,
                              uint64_t ResourceSize,
                              DiagnosticSeverity Severity = DS_Warning,
                              DiagnosticKind Kind = DK_ResourceLimit,
                              uint64_t ResourceLimit = 0)
      : DiagnosticInfo(Kind, Severity), Fn(Fn), ResourceName(ResourceName),
        ResourceSize(ResourceSize), ResourceLimit(ResourceLimit) {}

  const Function &getFunction() const { return Fn; }
  const char *getResourceName() const { return ResourceName; }
  uint64_t getResourceSize() const { return ResourceSize; }
  uint64_t getResourceLimit() const { return ResourceLimit; }

                                 
  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_ResourceLimit || DI->getKind() == DK_StackSize;
  }
};

class DiagnosticInfoStackSize : public DiagnosticInfoResourceLimit {
public:
  DiagnosticInfoStackSize(const Function &Fn, uint64_t StackSize,
                          DiagnosticSeverity Severity = DS_Warning,
                          uint64_t StackLimit = 0)
      : DiagnosticInfoResourceLimit(Fn, "stack size", StackSize, Severity,
                                    DK_StackSize, StackLimit) {}

  uint64_t getStackSize() const { return getResourceSize(); }
  uint64_t getStackLimit() const { return getResourceLimit(); }

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_StackSize;
  }
};

                                                                
                                             
class DiagnosticInfoDebugMetadataVersion : public DiagnosticInfo {
private:
                                                                             
  const Module &M;
                                  
  unsigned MetadataVersion;

public:
                                                                                
                                     
  DiagnosticInfoDebugMetadataVersion(const Module &M, unsigned MetadataVersion,
                                     DiagnosticSeverity Severity = DS_Warning)
      : DiagnosticInfo(DK_DebugMetadataVersion, Severity), M(M),
        MetadataVersion(MetadataVersion) {}

  const Module &getModule() const { return M; }
  unsigned getMetadataVersion() const { return MetadataVersion; }

                                 
  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_DebugMetadataVersion;
  }
};

                                                                
class DiagnosticInfoIgnoringInvalidDebugMetadata : public DiagnosticInfo {
private:
                                                                             
  const Module &M;

public:
                                                                                
  DiagnosticInfoIgnoringInvalidDebugMetadata(
      const Module &M, DiagnosticSeverity Severity = DS_Warning)
      : DiagnosticInfo(DK_DebugMetadataVersion, Severity), M(M) {}

  const Module &getModule() const { return M; }

                                 
  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_DebugMetadataInvalid;
  }
};

                                                   
class DiagnosticInfoSampleProfile : public DiagnosticInfo {
public:
  DiagnosticInfoSampleProfile(StringRef FileName, unsigned LineNum,
                              const Twine &Msg,
                              DiagnosticSeverity Severity = DS_Error)
      : DiagnosticInfo(DK_SampleProfile, Severity), FileName(FileName),
        LineNum(LineNum), Msg(Msg) {}
  DiagnosticInfoSampleProfile(StringRef FileName, const Twine &Msg,
                              DiagnosticSeverity Severity = DS_Error)
      : DiagnosticInfo(DK_SampleProfile, Severity), FileName(FileName),
        Msg(Msg) {}
  DiagnosticInfoSampleProfile(const Twine &Msg,
                              DiagnosticSeverity Severity = DS_Error)
      : DiagnosticInfo(DK_SampleProfile, Severity), Msg(Msg) {}

                                 
  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_SampleProfile;
  }

  StringRef getFileName() const { return FileName; }
  unsigned getLineNum() const { return LineNum; }
  const Twine &getMsg() const { return Msg; }

private:
                                                             
  StringRef FileName;

                                                                          
                                
  unsigned LineNum = 0;

                        
  const Twine &Msg;
};

                                                
class DiagnosticInfoPGOProfile : public DiagnosticInfo {
public:
  DiagnosticInfoPGOProfile(const char *FileName, const Twine &Msg,
                           DiagnosticSeverity Severity = DS_Error)
      : DiagnosticInfo(DK_PGOProfile, Severity), FileName(FileName), Msg(Msg) {}

                                 
  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_PGOProfile;
  }

  const char *getFileName() const { return FileName; }
  const Twine &getMsg() const { return Msg; }

private:
                                                             
  const char *FileName;

                        
  const Twine &Msg;
};

class DiagnosticLocation {
  StringRef Filename;
  unsigned Line = 0;
  unsigned Column = 0;

public:
  DiagnosticLocation() = default;
  DiagnosticLocation(const DebugLoc &DL);
  DiagnosticLocation(const DISubprogram *SP);

  bool isValid() const { return !Filename.empty(); }
  StringRef getFilename() const { return Filename; }
  unsigned getLine() const { return Line; }
  unsigned getColumn() const { return Column; }
};

                                                                
class DiagnosticInfoWithLocationBase : public DiagnosticInfo {
public:
                                                                            
                                                        
  DiagnosticInfoWithLocationBase(enum DiagnosticKind Kind,
                                 enum DiagnosticSeverity Severity,
                                 const Function &Fn,
                                 const DiagnosticLocation &Loc)
      : DiagnosticInfo(Kind, Severity), Fn(Fn), Loc(Loc) {}

                                                                           
  bool isLocationAvailable() const { return Loc.isValid(); }

                                                                       
                                                                              
                                 
  const std::string getLocationStr() const;

                                                                     
                                                   
  void getLocation(StringRef *Filename, unsigned *Line, unsigned *Column) const;

  const Function &getFunction() const { return Fn; }
  DiagnosticLocation getLocation() const { return Loc; }

private:
                                                  
  const Function &Fn;

                                                        
  DiagnosticLocation Loc;
};

                                                                     
                                            
class DiagnosticInfoOptimizationBase : public DiagnosticInfoWithLocationBase {
public:
                                                     
  struct setIsVerbose {};

                                                                         
                                                                            
                                                       
                                   
  struct setExtraArgs {};

                                                                       
                                                           
  struct Argument {
    std::string Key;
    std::string Val;
                                                             
    DiagnosticLocation Loc;

    explicit Argument(StringRef Str = "") : Key("String"), Val(Str) {}
    Argument(StringRef Key, const Value *V);
    Argument(StringRef Key, const Type *T);
    Argument(StringRef Key, StringRef S);
    Argument(StringRef Key, const char *S) : Argument(Key, StringRef(S)) {};
    Argument(StringRef Key, int N);
    Argument(StringRef Key, float N);
    Argument(StringRef Key, long N);
    Argument(StringRef Key, long long N);
    Argument(StringRef Key, unsigned N);
    Argument(StringRef Key, unsigned long N);
    Argument(StringRef Key, unsigned long long N);
    Argument(StringRef Key, bool B) : Key(Key), Val(B ? "true" : "false") {}
    Argument(StringRef Key, DebugLoc dl);
  };

                                                                      
                                                                     
                                                                               
                                                                                
                                                                           
               
  DiagnosticInfoOptimizationBase(enum DiagnosticKind Kind,
                                 enum DiagnosticSeverity Severity,
                                 const char *PassName, StringRef RemarkName,
                                 const Function &Fn,
                                 const DiagnosticLocation &Loc)
      : DiagnosticInfoWithLocationBase(Kind, Severity, Fn, Loc),
        PassName(PassName), RemarkName(RemarkName) {}

  void insert(StringRef S);
  void insert(Argument A);
  void insert(setIsVerbose V);
  void insert(setExtraArgs EA);

                                 
  void print(DiagnosticPrinter &DP) const override;

                                                                  
                                                                          
                                                                      
                                                                     
                                                     
  virtual bool isEnabled() const = 0;

  StringRef getPassName() const { return PassName; }
  std::string getMsg() const;
  Optional<uint64_t> getHotness() const { return Hotness; }
  void setHotness(Optional<uint64_t> H) { Hotness = H; }

  bool isVerbose() const { return IsVerbose; }

  static bool classof(const DiagnosticInfo *DI) {
    return (DI->getKind() >= DK_FirstRemark &&
            DI->getKind() <= DK_LastRemark) ||
           (DI->getKind() >= DK_FirstMachineRemark &&
            DI->getKind() <= DK_LastMachineRemark);
  }

  bool isPassed() const {
    return (getKind() == DK_OptimizationRemark ||
            getKind() == DK_MachineOptimizationRemark);
  }

  bool isMissed() const {
    return (getKind() == DK_OptimizationRemarkMissed ||
            getKind() == DK_MachineOptimizationRemarkMissed);
  }

  bool isAnalysis() const {
    return (getKind() == DK_OptimizationRemarkAnalysis ||
            getKind() == DK_MachineOptimizationRemarkAnalysis);
  }

protected:
                                                                     
                                                                     
                 
  const char *PassName;

                                                                              
                                                                                
                          
  StringRef RemarkName;

                                                                          
                                                                       
  Optional<uint64_t> Hotness;

                                                      
  SmallVector<Argument, 4> Args;

                                         
  bool IsVerbose = false;

                                                                      
                                                                            
             
  int FirstExtraArgIndex = -1;

  friend struct yaml::MappingTraits<DiagnosticInfoOptimizationBase *>;
};

                                                                               
                                                                         
                                                                             
template <class RemarkT>
RemarkT &
operator<<(RemarkT &R,
           typename std::enable_if<
               std::is_base_of<DiagnosticInfoOptimizationBase, RemarkT>::value,
               StringRef>::type S) {
  R.insert(S);
  return R;
}

                                                               
                                   
template <class RemarkT>
RemarkT &
operator<<(RemarkT &&R,
           typename std::enable_if<
               std::is_base_of<DiagnosticInfoOptimizationBase, RemarkT>::value,
               StringRef>::type S) {
  R.insert(S);
  return R;
}

template <class RemarkT>
RemarkT &
operator<<(RemarkT &R,
           typename std::enable_if<
               std::is_base_of<DiagnosticInfoOptimizationBase, RemarkT>::value,
               DiagnosticInfoOptimizationBase::Argument>::type A) {
  R.insert(A);
  return R;
}

template <class RemarkT>
RemarkT &
operator<<(RemarkT &&R,
           typename std::enable_if<
               std::is_base_of<DiagnosticInfoOptimizationBase, RemarkT>::value,
               DiagnosticInfoOptimizationBase::Argument>::type A) {
  R.insert(A);
  return R;
}

template <class RemarkT>
RemarkT &
operator<<(RemarkT &R,
           typename std::enable_if<
               std::is_base_of<DiagnosticInfoOptimizationBase, RemarkT>::value,
               DiagnosticInfoOptimizationBase::setIsVerbose>::type V) {
  R.insert(V);
  return R;
}

template <class RemarkT>
RemarkT &
operator<<(RemarkT &&R,
           typename std::enable_if<
               std::is_base_of<DiagnosticInfoOptimizationBase, RemarkT>::value,
               DiagnosticInfoOptimizationBase::setIsVerbose>::type V) {
  R.insert(V);
  return R;
}

template <class RemarkT>
RemarkT &
operator<<(RemarkT &R,
           typename std::enable_if<
               std::is_base_of<DiagnosticInfoOptimizationBase, RemarkT>::value,
               DiagnosticInfoOptimizationBase::setExtraArgs>::type EA) {
  R.insert(EA);
  return R;
}

                                                                     
                               
class DiagnosticInfoIROptimization : public DiagnosticInfoOptimizationBase {
public:
                                                                      
                                                                     
                                                                               
                                                                                
                                                                           
                                                                          
                                                                          
                                   
  DiagnosticInfoIROptimization(enum DiagnosticKind Kind,
                               enum DiagnosticSeverity Severity,
                               const char *PassName, StringRef RemarkName,
                               const Function &Fn,
                               const DiagnosticLocation &Loc,
                               const Value *CodeRegion = nullptr)
      : DiagnosticInfoOptimizationBase(Kind, Severity, PassName, RemarkName, Fn,
                                       Loc),
        CodeRegion(CodeRegion) {}

                                                                        
                              
     
                                                                               
                                                                               
                                                                        
              
  DiagnosticInfoIROptimization(const char *PassName, StringRef Prepend,
                               const DiagnosticInfoIROptimization &Orig)
      : DiagnosticInfoOptimizationBase(
            (DiagnosticKind)Orig.getKind(), Orig.getSeverity(), PassName,
            Orig.RemarkName, Orig.getFunction(), Orig.getLocation()),
        CodeRegion(Orig.getCodeRegion()) {
    *this << Prepend;
    std::copy(Orig.Args.begin(), Orig.Args.end(), std::back_inserter(Args));
  }

                       
                                                                   
                                                                            
                                                                      
                                                                           
                                                                            
                                                                                
                        
  DiagnosticInfoIROptimization(enum DiagnosticKind Kind,
                               enum DiagnosticSeverity Severity,
                               const char *PassName, const Function &Fn,
                               const DiagnosticLocation &Loc, const Twine &Msg)
      : DiagnosticInfoOptimizationBase(Kind, Severity, PassName, "", Fn, Loc) {
    *this << Msg.str();
  }

  const Value *getCodeRegion() const { return CodeRegion; }

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() >= DK_FirstRemark && DI->getKind() <= DK_LastRemark;
  }

private:
                                                                             
                                                                              
  const Value *CodeRegion;
};

                                                            
class OptimizationRemark : public DiagnosticInfoIROptimization {
public:
                                                                                
                                                                               
                                                                               
                                                                              
                                                                       
                 
  OptimizationRemark(const char *PassName, StringRef RemarkName,
                     const DiagnosticLocation &Loc, const Value *CodeRegion);

                                                                               
            
  OptimizationRemark(const char *PassName, StringRef RemarkName,
                     const Instruction *Inst);

                                                                               
           
  OptimizationRemark(const char *PassName, StringRef RemarkName,
                     const Function *Func);

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_OptimizationRemark;
  }

                                                     
  bool isEnabled() const override;

private:
                                                                     
                                                                      
                                                                         
                                                                            
                                                                        
                                                                        
                                                                           
                                                                        
                                                              
  OptimizationRemark(const char *PassName, const Function &Fn,
                     const DiagnosticLocation &Loc, const Twine &Msg)
      : DiagnosticInfoIROptimization(DK_OptimizationRemark, DS_Remark, PassName,
                                     Fn, Loc, Msg) {}
};

                                                           
class OptimizationRemarkMissed : public DiagnosticInfoIROptimization {
public:
                                                                                
                                                                      
                                                                               
                                                                           
                                                                                
                          
  OptimizationRemarkMissed(const char *PassName, StringRef RemarkName,
                           const DiagnosticLocation &Loc,
                           const Value *CodeRegion);

                                                                       
               
  OptimizationRemarkMissed(const char *PassName, StringRef RemarkName,
                           const Instruction *Inst);

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_OptimizationRemarkMissed;
  }

                                                     
  bool isEnabled() const override;

private:
                                                                     
                                                                      
                                                                                
                                                                            
                                                                        
                                                                        
                                                                           
                                                                        
                                                              
  OptimizationRemarkMissed(const char *PassName, const Function &Fn,
                           const DiagnosticLocation &Loc, const Twine &Msg)
      : DiagnosticInfoIROptimization(DK_OptimizationRemarkMissed, DS_Remark,
                                     PassName, Fn, Loc, Msg) {}
};

                                                             
class OptimizationRemarkAnalysis : public DiagnosticInfoIROptimization {
public:
                                                                                
                                                                        
                                                                               
                                                                           
                                                                                
                          
  OptimizationRemarkAnalysis(const char *PassName, StringRef RemarkName,
                             const DiagnosticLocation &Loc,
                             const Value *CodeRegion);

                                                                        
                              
     
                                                                               
                                                                               
                                                                        
              
  OptimizationRemarkAnalysis(const char *PassName, StringRef Prepend,
                             const OptimizationRemarkAnalysis &Orig)
      : DiagnosticInfoIROptimization(PassName, Prepend, Orig) {}

                                                                       
               
  OptimizationRemarkAnalysis(const char *PassName, StringRef RemarkName,
                             const Instruction *Inst);

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_OptimizationRemarkAnalysis;
  }

                                                     
  bool isEnabled() const override;

  static const char *AlwaysPrint;

  bool shouldAlwaysPrint() const { return getPassName() == AlwaysPrint; }

protected:
  OptimizationRemarkAnalysis(enum DiagnosticKind Kind, const char *PassName,
                             const Function &Fn, const DiagnosticLocation &Loc,
                             const Twine &Msg)
      : DiagnosticInfoIROptimization(Kind, DS_Remark, PassName, Fn, Loc, Msg) {}

  OptimizationRemarkAnalysis(enum DiagnosticKind Kind, const char *PassName,
                             StringRef RemarkName,
                             const DiagnosticLocation &Loc,
                             const Value *CodeRegion);

private:
                                                                     
                                                                      
                                                                              
                                                                                
                                                                        
                                                                             
                                                                                
                                                                                
                                            
  OptimizationRemarkAnalysis(const char *PassName, const Function &Fn,
                             const DiagnosticLocation &Loc, const Twine &Msg)
      : DiagnosticInfoIROptimization(DK_OptimizationRemarkAnalysis, DS_Remark,
                                     PassName, Fn, Loc, Msg) {}
};

                                                                       
                                     
class OptimizationRemarkAnalysisFPCommute : public OptimizationRemarkAnalysis {
public:
                                                                                
                                                                        
                                                                               
                                                                           
                                                                                
                                                                               
                                                            
  OptimizationRemarkAnalysisFPCommute(const char *PassName,
                                      StringRef RemarkName,
                                      const DiagnosticLocation &Loc,
                                      const Value *CodeRegion)
      : OptimizationRemarkAnalysis(DK_OptimizationRemarkAnalysisFPCommute,
                                   PassName, RemarkName, Loc, CodeRegion) {}

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_OptimizationRemarkAnalysisFPCommute;
  }

private:
                                                                     
                                                                      
                                                                              
                                                                                
                                                                        
                                                                             
                                                                          
                                                                           
                                                                               
                                                                             
                 
  OptimizationRemarkAnalysisFPCommute(const char *PassName, const Function &Fn,
                                      const DiagnosticLocation &Loc,
                                      const Twine &Msg)
      : OptimizationRemarkAnalysis(DK_OptimizationRemarkAnalysisFPCommute,
                                   PassName, Fn, Loc, Msg) {}
};

                                                                       
                     
class OptimizationRemarkAnalysisAliasing : public OptimizationRemarkAnalysis {
public:
                                                                                
                                                                        
                                                                               
                                                                           
                                                                                
                                                                               
                                                     
  OptimizationRemarkAnalysisAliasing(const char *PassName, StringRef RemarkName,
                                     const DiagnosticLocation &Loc,
                                     const Value *CodeRegion)
      : OptimizationRemarkAnalysis(DK_OptimizationRemarkAnalysisAliasing,
                                   PassName, RemarkName, Loc, CodeRegion) {}

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_OptimizationRemarkAnalysisAliasing;
  }

private:
                                                                     
                                                                      
                                                                              
                                                                                
                                                                        
                                                                             
                                                                          
                                                                           
                                                                        
                                                                             
                 
  OptimizationRemarkAnalysisAliasing(const char *PassName, const Function &Fn,
                                     const DiagnosticLocation &Loc,
                                     const Twine &Msg)
      : OptimizationRemarkAnalysis(DK_OptimizationRemarkAnalysisAliasing,
                                   PassName, Fn, Loc, Msg) {}
};

                                                 
class DiagnosticInfoMIRParser : public DiagnosticInfo {
  const SMDiagnostic &Diagnostic;

public:
  DiagnosticInfoMIRParser(DiagnosticSeverity Severity,
                          const SMDiagnostic &Diagnostic)
      : DiagnosticInfo(DK_MIRParser, Severity), Diagnostic(Diagnostic) {}

  const SMDiagnostic &getDiagnostic() const { return Diagnostic; }

  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_MIRParser;
  }
};

                                                  
class DiagnosticInfoISelFallback : public DiagnosticInfo {
                                                        
  const Function &Fn;

public:
  DiagnosticInfoISelFallback(const Function &Fn,
                             DiagnosticSeverity Severity = DS_Warning)
      : DiagnosticInfo(DK_ISelFallback, Severity), Fn(Fn) {}

  const Function &getFunction() const { return Fn; }

  void print(DiagnosticPrinter &DP) const override;

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_ISelFallback;
  }
};

                                                                
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(DiagnosticInfo, LLVMDiagnosticInfoRef)

                                                     
class DiagnosticInfoOptimizationFailure : public DiagnosticInfoIROptimization {
public:
                                                                            
                                                                      
                                                                           
                                                                            
                                                                                
                        
  DiagnosticInfoOptimizationFailure(const Function &Fn,
                                    const DiagnosticLocation &Loc,
                                    const Twine &Msg)
      : DiagnosticInfoIROptimization(DK_OptimizationFailure, DS_Warning,
                                     nullptr, Fn, Loc, Msg) {}

                                                                       
                                                                     
                                                                         
                                                                        
                 
  DiagnosticInfoOptimizationFailure(const char *PassName, StringRef RemarkName,
                                    const DiagnosticLocation &Loc,
                                    const Value *CodeRegion);

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_OptimizationFailure;
  }

                                                     
  bool isEnabled() const override;
};

                                                              
class DiagnosticInfoUnsupported : public DiagnosticInfoWithLocationBase {
private:
  Twine Msg;

public:
                                                                            
                                                                      
                                                                           
                                                                            
                                                                                
                        
  DiagnosticInfoUnsupported(
      const Function &Fn, const Twine &Msg,
      const DiagnosticLocation &Loc = DiagnosticLocation(),
      DiagnosticSeverity Severity = DS_Error)
      : DiagnosticInfoWithLocationBase(DK_Unsupported, Severity, Fn, Loc),
        Msg(Msg) {}

  static bool classof(const DiagnosticInfo *DI) {
    return DI->getKind() == DK_Unsupported;
  }

  const Twine &getMessage() const { return Msg; }

  void print(DiagnosticPrinter &DP) const override;
};

namespace yaml {
template <> struct MappingTraits<DiagnosticInfoOptimizationBase *> {
  static void mapping(IO &io, DiagnosticInfoOptimizationBase *&OptDiag);
};
}                  

}                      

#endif                            
