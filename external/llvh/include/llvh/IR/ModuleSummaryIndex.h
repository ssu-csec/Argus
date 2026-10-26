//===- llvm/ModuleSummaryIndex.h - Module Summary Index ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// @file
/// ModuleSummaryIndex.h This file contains the declarations the classes that
///  hold the module index and summary for function importing.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_MODULESUMMARYINDEX_H
#define LLVM_IR_MODULESUMMARYINDEX_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/TinyPtrVector.h"
#include "llvh/IR/GlobalValue.h"
#include "llvh/IR/Module.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/ScaledNumber.h"
#include "llvh/Support/StringSaver.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace llvh {

namespace yaml {

template <typename T> struct MappingTraits;

}                      

                                                            
struct CalleeInfo {
  enum class HotnessType : uint8_t {
    Unknown = 0,
    Cold = 1,
    None = 2,
    Hot = 3,
    Critical = 4
  };

                                                                           
                               
  uint32_t Hotness : 3;

                                                                             
                                                     
  uint32_t RelBlockFreq : 29;
  static constexpr int32_t ScaleShift = 8;
  static constexpr uint64_t MaxRelBlockFreq = (1 << 29) - 1;

  CalleeInfo()
      : Hotness(static_cast<uint32_t>(HotnessType::Unknown)), RelBlockFreq(0) {}
  explicit CalleeInfo(HotnessType Hotness, uint64_t RelBF)
      : Hotness(static_cast<uint32_t>(Hotness)), RelBlockFreq(RelBF) {}

  void updateHotness(const HotnessType OtherHotness) {
    Hotness = std::max(Hotness, static_cast<uint32_t>(OtherHotness));
  }

  HotnessType getHotness() const { return HotnessType(Hotness); }

                                                               
     
                                                                               
                                                                               
                           
  void updateRelBlockFreq(uint64_t BlockFreq, uint64_t EntryFreq) {
    if (EntryFreq == 0)
      return;
    using Scaled64 = ScaledNumber<uint64_t>;
    Scaled64 Temp(BlockFreq, ScaleShift);
    Temp /= Scaled64::get(EntryFreq);

    uint64_t Sum =
        SaturatingAdd<uint64_t>(Temp.toInt<uint64_t>(), RelBlockFreq);
    Sum = std::min(Sum, uint64_t(MaxRelBlockFreq));
    RelBlockFreq = static_cast<uint32_t>(Sum);
  }
};

inline const char *getHotnessName(CalleeInfo::HotnessType HT) {
  switch (HT) {
  case CalleeInfo::HotnessType::Unknown:
    return "unknown";
  case CalleeInfo::HotnessType::Cold:
    return "cold";
  case CalleeInfo::HotnessType::None:
    return "none";
  case CalleeInfo::HotnessType::Hot:
    return "hot";
  case CalleeInfo::HotnessType::Critical:
    return "critical";
  }
  llvm_unreachable("invalid hotness");
}

class GlobalValueSummary;

using GlobalValueSummaryList = std::vector<std::unique_ptr<GlobalValueSummary>>;

struct GlobalValueSummaryInfo {
  union NameOrGV {
    NameOrGV(bool HaveGVs) {
      if (HaveGVs)
        GV = nullptr;
      else
        Name = "";
    }

                                                                           
                                                                           
                                                                          
                      
    const GlobalValue *GV;

                                                                         
                                                                        
                                                                        
                                                                            
                                                               
    StringRef Name;
  } U;

  GlobalValueSummaryInfo(bool HaveGVs) : U(HaveGVs) {}

                                                                         
                                                                      
                                     
  GlobalValueSummaryList SummaryList;
};

                                                                         
                                                                            
                                                                                
                                                                                
                                                                      
                            
using GlobalValueSummaryMapTy =
    std::map<GlobalValue::GUID, GlobalValueSummaryInfo>;

                                                                        
            
struct ValueInfo {
  PointerIntPair<const GlobalValueSummaryMapTy::value_type *, 1, bool>
      RefAndFlag;

  ValueInfo() = default;
  ValueInfo(bool HaveGVs, const GlobalValueSummaryMapTy::value_type *R) {
    RefAndFlag.setPointer(R);
    RefAndFlag.setInt(HaveGVs);
  }

  operator bool() const { return getRef(); }

  GlobalValue::GUID getGUID() const { return getRef()->first; }
  const GlobalValue *getValue() const {
    assert(haveGVs());
    return getRef()->second.U.GV;
  }

  ArrayRef<std::unique_ptr<GlobalValueSummary>> getSummaryList() const {
    return getRef()->second.SummaryList;
  }

  StringRef name() const {
    return haveGVs() ? getRef()->second.U.GV->getName()
                     : getRef()->second.U.Name;
  }

  bool haveGVs() const { return RefAndFlag.getInt(); }

  const GlobalValueSummaryMapTy::value_type *getRef() const {
    return RefAndFlag.getPointer();
  }

  bool isDSOLocal() const;
};

inline raw_ostream &operator<<(raw_ostream &OS, const ValueInfo &VI) {
  OS << VI.getGUID();
  if (!VI.name().empty())
    OS << " (" << VI.name() << ")";
  return OS;
}

inline bool operator==(const ValueInfo &A, const ValueInfo &B) {
  assert(A.getRef() && B.getRef() &&
         "Need ValueInfo with non-null Ref for comparison");
  return A.getRef() == B.getRef();
}

inline bool operator!=(const ValueInfo &A, const ValueInfo &B) {
  assert(A.getRef() && B.getRef() &&
         "Need ValueInfo with non-null Ref for comparison");
  return A.getRef() != B.getRef();
}

inline bool operator<(const ValueInfo &A, const ValueInfo &B) {
  assert(A.getRef() && B.getRef() &&
         "Need ValueInfo with non-null Ref to compare GUIDs");
  return A.getGUID() < B.getGUID();
}

template <> struct DenseMapInfo<ValueInfo> {
  static inline ValueInfo getEmptyKey() {
    return ValueInfo(false, (GlobalValueSummaryMapTy::value_type *)-8);
  }

  static inline ValueInfo getTombstoneKey() {
    return ValueInfo(false, (GlobalValueSummaryMapTy::value_type *)-16);
  }

  static inline bool isSpecialKey(ValueInfo V) {
    return V == getTombstoneKey() || V == getEmptyKey();
  }

  static bool isEqual(ValueInfo L, ValueInfo R) {
                                                                          
                           
    assert(isSpecialKey(L) || isSpecialKey(R) || (L.haveGVs() == R.haveGVs()));
    return L.getRef() == R.getRef();
  }
  static unsigned getHashValue(ValueInfo I) { return (uintptr_t)I.getRef(); }
};

                                                                  
                                
class GlobalValueSummary {
public:
                                                      
  enum SummaryKind : unsigned { AliasKind, FunctionKind, GlobalVarKind };

                                                                     
  struct GVFlags {
                                                        
       
                                                                           
                                                                        
                                                                    
                                                                      
                                                     
    unsigned Linkage : 4;

                                                                       
                                                                  
    unsigned NotEligibleToImport : 1;

                                                                                
                                                                            
                                                                             
       
                                                                    
    unsigned Live : 1;

                                                                          
                                     
    unsigned DSOLocal : 1;

                                
    explicit GVFlags(GlobalValue::LinkageTypes Linkage,
                     bool NotEligibleToImport, bool Live, bool IsLocal)
        : Linkage(Linkage), NotEligibleToImport(NotEligibleToImport),
          Live(Live), DSOLocal(IsLocal) {}
  };

private:
                                                  
  SummaryKind Kind;

  GVFlags Flags;

                                                                            
                                                                               
                                                    
  GlobalValue::GUID OriginalName = 0;

                                                                     
                              
     
                                                                     
                                                                              
                                                                        
                               
  StringRef ModulePath;

                                                                 
                                                                    
                                                                            
                                                       
  std::vector<ValueInfo> RefEdgeList;

protected:
  GlobalValueSummary(SummaryKind K, GVFlags Flags, std::vector<ValueInfo> Refs)
      : Kind(K), Flags(Flags), RefEdgeList(std::move(Refs)) {
    assert((K != AliasKind || Refs.empty()) &&
           "Expect no references for AliasSummary");
  }

public:
  virtual ~GlobalValueSummary() = default;

                                                                            
                                                         
  GlobalValue::GUID getOriginalName() const { return OriginalName; }

                                                        
  void setOriginalName(GlobalValue::GUID Name) { OriginalName = Name; }

                                             
  SummaryKind getSummaryKind() const { return Kind; }

                                                                     
                         
  void setModulePath(StringRef ModPath) { ModulePath = ModPath; }

                                                          
  StringRef modulePath() const { return ModulePath; }

                                                                 
  GVFlags flags() const { return Flags; }

                                                         
  GlobalValue::LinkageTypes linkage() const {
    return static_cast<GlobalValue::LinkageTypes>(Flags.Linkage);
  }

                                                                      
                                                            
  void setLinkage(GlobalValue::LinkageTypes Linkage) {
    Flags.Linkage = Linkage;
  }

                                                         
  bool notEligibleToImport() const { return Flags.NotEligibleToImport; }

  bool isLive() const { return Flags.Live; }

  void setLive(bool Live) { Flags.Live = Live; }

  void setDSOLocal(bool Local) { Flags.DSOLocal = Local; }

  bool isDSOLocal() const { return Flags.DSOLocal; }

                                                     
  void setNotEligibleToImport() { Flags.NotEligibleToImport = true; }

                                                                           
  ArrayRef<ValueInfo> refs() const { return RefEdgeList; }

                                                                               
                                                             
  GlobalValueSummary *getBaseObject();
  const GlobalValueSummary *getBaseObject() const;

  friend class ModuleSummaryIndex;
};

                              
class AliasSummary : public GlobalValueSummary {
  GlobalValueSummary *AliaseeSummary;
                                                                               
                           
  GlobalValue::GUID AliaseeGUID;

public:
  AliasSummary(GVFlags Flags)
      : GlobalValueSummary(AliasKind, Flags, ArrayRef<ValueInfo>{}),
        AliaseeSummary(nullptr), AliaseeGUID(0) {}

                                        
  static bool classof(const GlobalValueSummary *GVS) {
    return GVS->getSummaryKind() == AliasKind;
  }

  void setAliasee(GlobalValueSummary *Aliasee) { AliaseeSummary = Aliasee; }
  void setAliaseeGUID(GlobalValue::GUID GUID) { AliaseeGUID = GUID; }

  bool hasAliasee() const { return !!AliaseeSummary; }

  const GlobalValueSummary &getAliasee() const {
    assert(AliaseeSummary && "Unexpected missing aliasee summary");
    return *AliaseeSummary;
  }

  GlobalValueSummary &getAliasee() {
    return const_cast<GlobalValueSummary &>(
                         static_cast<const AliasSummary *>(this)->getAliasee());
  }
  const GlobalValue::GUID &getAliaseeGUID() const {
    assert(AliaseeGUID && "Unexpected missing aliasee GUID");
    return AliaseeGUID;
  }
};

const inline GlobalValueSummary *GlobalValueSummary::getBaseObject() const {
  if (auto *AS = dyn_cast<AliasSummary>(this))
    return &AS->getAliasee();
  return this;
}

inline GlobalValueSummary *GlobalValueSummary::getBaseObject() {
  if (auto *AS = dyn_cast<AliasSummary>(this))
    return &AS->getAliasee();
  return this;
}

                                                                       
              
class FunctionSummary : public GlobalValueSummary {
public:
                                                   
  using EdgeTy = std::pair<ValueInfo, CalleeInfo>;

                                                           
  enum ForceSummaryHotnessType : unsigned {
    FSHT_None,
    FSHT_AllNonCritical,
    FSHT_All
  };

                                                                               
                                                                                
                                                                               
                                                                       
  struct VFuncId {
    GlobalValue::GUID GUID;
    uint64_t Offset;
  };

                                                                           
                                                                            
              
  struct ConstVCall {
    VFuncId VFunc;
    std::vector<uint64_t> Args;
  };

                                                                       
                                                                       
  struct TypeIdInfo {
                                                                        
                                                                               
                             
    std::vector<GlobalValue::GUID> TypeTests;

                                                                        
                                                                                
                                                
    std::vector<VFuncId> TypeTestAssumeVCalls, TypeCheckedLoadVCalls;

                                                                        
                                                                             
                                       
    std::vector<ConstVCall> TypeTestAssumeConstVCalls,
        TypeCheckedLoadConstVCalls;
  };

                                                                            
                          
  struct FFlags {
    unsigned ReadNone : 1;
    unsigned ReadOnly : 1;
    unsigned NoRecurse : 1;
    unsigned ReturnDoesNotAlias : 1;
  };

                                                                  
                                                               
  static FunctionSummary
  makeDummyFunctionSummary(std::vector<FunctionSummary::EdgeTy> Edges) {
    return FunctionSummary(
        FunctionSummary::GVFlags(
            GlobalValue::LinkageTypes::AvailableExternallyLinkage,
                                    true,          true,             false),
        0, FunctionSummary::FFlags{}, std::vector<ValueInfo>(),
        std::move(Edges), std::vector<GlobalValue::GUID>(),
        std::vector<FunctionSummary::VFuncId>(),
        std::vector<FunctionSummary::VFuncId>(),
        std::vector<FunctionSummary::ConstVCall>(),
        std::vector<FunctionSummary::ConstVCall>());
  }

                                                                           
  static FunctionSummary ExternalNode;

private:
                                                                         
                                                                            
  unsigned InstCount;

                                                                            
                          
  FFlags FunFlags;

                                                                               
  std::vector<EdgeTy> CallGraphEdgeList;

  std::unique_ptr<TypeIdInfo> TIdInfo;

public:
  FunctionSummary(GVFlags Flags, unsigned NumInsts, FFlags FunFlags,
                  std::vector<ValueInfo> Refs, std::vector<EdgeTy> CGEdges,
                  std::vector<GlobalValue::GUID> TypeTests,
                  std::vector<VFuncId> TypeTestAssumeVCalls,
                  std::vector<VFuncId> TypeCheckedLoadVCalls,
                  std::vector<ConstVCall> TypeTestAssumeConstVCalls,
                  std::vector<ConstVCall> TypeCheckedLoadConstVCalls)
      : GlobalValueSummary(FunctionKind, Flags, std::move(Refs)),
        InstCount(NumInsts), FunFlags(FunFlags),
        CallGraphEdgeList(std::move(CGEdges)) {
    if (!TypeTests.empty() || !TypeTestAssumeVCalls.empty() ||
        !TypeCheckedLoadVCalls.empty() || !TypeTestAssumeConstVCalls.empty() ||
        !TypeCheckedLoadConstVCalls.empty())
      TIdInfo = llvh::make_unique<TypeIdInfo>(TypeIdInfo{
          std::move(TypeTests), std::move(TypeTestAssumeVCalls),
          std::move(TypeCheckedLoadVCalls),
          std::move(TypeTestAssumeConstVCalls),
          std::move(TypeCheckedLoadConstVCalls)});
  }

                                          
  static bool classof(const GlobalValueSummary *GVS) {
    return GVS->getSummaryKind() == FunctionKind;
  }

                                   
  FFlags fflags() const { return FunFlags; }

                                                           
  unsigned instCount() const { return InstCount; }

                                                             
  ArrayRef<EdgeTy> calls() const { return CallGraphEdgeList; }

                                                                   
                                                                       
                           
  ArrayRef<GlobalValue::GUID> type_tests() const {
    if (TIdInfo)
      return TIdInfo->TypeTests;
    return {};
  }

                                                                   
                                                                          
                        
  ArrayRef<VFuncId> type_test_assume_vcalls() const {
    if (TIdInfo)
      return TIdInfo->TypeTestAssumeVCalls;
    return {};
  }

                                                                   
                                                                             
                
  ArrayRef<VFuncId> type_checked_load_vcalls() const {
    if (TIdInfo)
      return TIdInfo->TypeCheckedLoadVCalls;
    return {};
  }

                                                                   
                                                                      
                
  ArrayRef<ConstVCall> type_test_assume_const_vcalls() const {
    if (TIdInfo)
      return TIdInfo->TypeTestAssumeConstVCalls;
    return {};
  }

                                                                   
                                                                            
  ArrayRef<ConstVCall> type_checked_load_const_vcalls() const {
    if (TIdInfo)
      return TIdInfo->TypeCheckedLoadConstVCalls;
    return {};
  }

                                                                              
                                                 
  void addTypeTest(GlobalValue::GUID Guid) {
    if (!TIdInfo)
      TIdInfo = llvh::make_unique<TypeIdInfo>();
    TIdInfo->TypeTests.push_back(Guid);
  }

  const TypeIdInfo *getTypeIdInfo() const { return TIdInfo.get(); };

  friend struct GraphTraits<ValueInfo>;
};

template <> struct DenseMapInfo<FunctionSummary::VFuncId> {
  static FunctionSummary::VFuncId getEmptyKey() { return {0, uint64_t(-1)}; }

  static FunctionSummary::VFuncId getTombstoneKey() {
    return {0, uint64_t(-2)};
  }

  static bool isEqual(FunctionSummary::VFuncId L, FunctionSummary::VFuncId R) {
    return L.GUID == R.GUID && L.Offset == R.Offset;
  }

  static unsigned getHashValue(FunctionSummary::VFuncId I) { return I.GUID; }
};

template <> struct DenseMapInfo<FunctionSummary::ConstVCall> {
  static FunctionSummary::ConstVCall getEmptyKey() {
    return {{0, uint64_t(-1)}, {}};
  }

  static FunctionSummary::ConstVCall getTombstoneKey() {
    return {{0, uint64_t(-2)}, {}};
  }

  static bool isEqual(FunctionSummary::ConstVCall L,
                      FunctionSummary::ConstVCall R) {
    return DenseMapInfo<FunctionSummary::VFuncId>::isEqual(L.VFunc, R.VFunc) &&
           L.Args == R.Args;
  }

  static unsigned getHashValue(FunctionSummary::ConstVCall I) {
    return I.VFunc.GUID;
  }
};

                                                            
                                
   
                                                                          
                                                                       
                  
class GlobalVarSummary : public GlobalValueSummary {

public:
  GlobalVarSummary(GVFlags Flags, std::vector<ValueInfo> Refs)
      : GlobalValueSummary(GlobalVarKind, Flags, std::move(Refs)) {}

                                                 
  static bool classof(const GlobalValueSummary *GVS) {
    return GVS->getSummaryKind() == GlobalVarKind;
  }
};

struct TypeTestResolution {
                                                                            
                                                                             
                                                                       
                                 
  enum Kind {
    Unsat,                                                                    
    ByteArray,                                       
    Inline,                                                        
    Single,                                                                    
    AllOnes,                                                               
                                          
  } TheKind = Unsat;

                                                                              
                                                                                
                            
  unsigned SizeM1BitWidth = 0;

                                                                              
                                                                               
                                                                    
                        

  uint64_t AlignLog2 = 0;
  uint64_t SizeM1 = 0;
  uint8_t BitMask = 0;
  uint64_t InlineBits = 0;
};

struct WholeProgramDevirtResolution {
  enum Kind {
    Indir,                                           
    SingleImpl,                                              
    BranchFunnel,                                                               
                                                                              
                             
  } TheKind = Indir;

  std::string SingleImplName;

  struct ByArg {
    enum Kind {
      Indir,                                               
      UniformRetVal,                                          
      UniqueRetVal,                                          
      VirtualConstProp,                                  
    } TheKind = Indir;

                                                  
                                                  
                                                                                
             
    uint64_t Info = 0;

                                                                                
                                              

    uint32_t Byte = 0;
    uint32_t Bit = 0;
  };

                                                                              
                                                                    
  std::map<std::vector<uint64_t>, ByArg> ResByArg;
};

struct TypeIdSummary {
  TypeTestResolution TTRes;

                                                                          
                                 
  std::map<uint64_t, WholeProgramDevirtResolution> WPDRes;
};

                 
using ModuleHash = std::array<uint32_t, 5>;

                                                                 
using const_gvsummary_iterator = GlobalValueSummaryMapTy::const_iterator;
using gvsummary_iterator = GlobalValueSummaryMapTy::iterator;

                                                                              
                                                                               
                                                                           
using ModulePathStringTableTy = StringMap<std::pair<uint64_t, ModuleHash>>;

                                                                               
                                                                       
using GVSummaryMapTy = DenseMap<GlobalValue::GUID, GlobalValueSummary *>;

                                                                   
                               
using TypeIdSummaryMapTy =
    std::multimap<GlobalValue::GUID, std::pair<std::string, TypeIdSummary>>;

                                                                
                                                  
class ModuleSummaryIndex {
private:
                                                                         
                                                        
  GlobalValueSummaryMapTy GlobalValueMap;

                                                                               
  ModulePathStringTableTy ModulePathStringTable;

                                                                           
                  
  TypeIdSummaryMapTy TypeIdMap;

                                                                          
                                    
  std::map<GlobalValue::GUID, GlobalValue::GUID> OidGuidMap;

                                                                          
                                                                         
                      
  bool WithGlobalValueDeadStripping = false;

                                                                       
                                                                       
                                                                     
                                                                         
                        
  bool SkipModuleByDistributedBackend = false;

                                                                                
                                                                            
                                                                          
            
  bool HaveGVs;

  std::set<std::string> CfiFunctionDefs;
  std::set<std::string> CfiFunctionDecls;

                                                                    
                                                                         
  StringSaver Saver;
  BumpPtrAllocator Alloc;

                      
  friend yaml::MappingTraits<ModuleSummaryIndex>;

  GlobalValueSummaryMapTy::value_type *
  getOrInsertValuePtr(GlobalValue::GUID GUID) {
    return &*GlobalValueMap.emplace(GUID, GlobalValueSummaryInfo(HaveGVs))
                 .first;
  }

public:
                                  
  ModuleSummaryIndex(bool HaveGVs) : HaveGVs(HaveGVs), Saver(Alloc) {}

  bool haveGVs() const { return HaveGVs; }

  gvsummary_iterator begin() { return GlobalValueMap.begin(); }
  const_gvsummary_iterator begin() const { return GlobalValueMap.begin(); }
  gvsummary_iterator end() { return GlobalValueMap.end(); }
  const_gvsummary_iterator end() const { return GlobalValueMap.end(); }
  size_t size() const { return GlobalValueMap.size(); }

                                                                                
                                
  static void discoverNodes(ValueInfo V,
                            std::map<ValueInfo, bool> &FunctionHasParent) {
    if (!V.getSummaryList().size())
      return;                                                     

                                        
    auto S = FunctionHasParent.emplace(V, false);

                                                 
    if (!S.second)
      return;

    FunctionSummary *F =
        dyn_cast<FunctionSummary>(V.getSummaryList().front().get());
    assert(F != nullptr && "Expected FunctionSummary node");

    for (auto &C : F->calls()) {
                                 
      auto S = FunctionHasParent.emplace(C.first, true);

                                                
      if (!S.second && S.first->second)
        continue;

      if (S.second)
        discoverNodes(C.first, FunctionHasParent);
      else
        S.first->second = true;
    }
  }

                                 
  FunctionSummary calculateCallGraphRoot() {
                                                                             
                                                                               
                                            
    std::map<ValueInfo, bool> FunctionHasParent;

    for (auto &S : *this) {
                                
      if (!S.second.SummaryList.size() ||
          !isa<FunctionSummary>(S.second.SummaryList.front().get()))
        continue;
      discoverNodes(ValueInfo(HaveGVs, &S), FunctionHasParent);
    }

    std::vector<FunctionSummary::EdgeTy> Edges;
                                             
    for (auto &P : FunctionHasParent) {
      if (P.second)
        continue;                            
      Edges.push_back(std::make_pair(P.first, CalleeInfo{}));
    }
    if (Edges.empty()) {
                                                   
      return FunctionSummary::makeDummyFunctionSummary({});
    }
    auto CallGraphRoot = FunctionSummary::makeDummyFunctionSummary(Edges);
    return CallGraphRoot;
  }

  bool withGlobalValueDeadStripping() const {
    return WithGlobalValueDeadStripping;
  }
  void setWithGlobalValueDeadStripping() {
    WithGlobalValueDeadStripping = true;
  }

  bool skipModuleByDistributedBackend() const {
    return SkipModuleByDistributedBackend;
  }
  void setSkipModuleByDistributedBackend() {
    SkipModuleByDistributedBackend = true;
  }

  bool isGlobalValueLive(const GlobalValueSummary *GVS) const {
    return !WithGlobalValueDeadStripping || GVS->isLive();
  }
  bool isGUIDLive(GlobalValue::GUID GUID) const;

                                                                            
             
  ValueInfo getValueInfo(const GlobalValueSummaryMapTy::value_type &R) const {
    return ValueInfo(HaveGVs, &R);
  }

                                                                             
  ValueInfo getValueInfo(GlobalValue::GUID GUID) const {
    auto I = GlobalValueMap.find(GUID);
    return ValueInfo(HaveGVs, I == GlobalValueMap.end() ? nullptr : &*I);
  }

                                     
  ValueInfo getOrInsertValueInfo(GlobalValue::GUID GUID) {
    return ValueInfo(HaveGVs, getOrInsertValuePtr(GUID));
  }

                                                           
                                                                            
                      
  StringRef saveString(std::string String) { return Saver.save(String); }

                                                           
  ValueInfo getOrInsertValueInfo(GlobalValue::GUID GUID, StringRef Name) {
    assert(!HaveGVs);
    auto VP = getOrInsertValuePtr(GUID);
    VP->second.U.Name = Name;
    return ValueInfo(HaveGVs, VP);
  }

                                                                  
  ValueInfo getOrInsertValueInfo(const GlobalValue *GV) {
    assert(HaveGVs);
    auto VP = getOrInsertValuePtr(GV->getGUID());
    VP->second.U.GV = GV;
    return ValueInfo(HaveGVs, VP);
  }

                                                          
  GlobalValue::GUID getGUIDFromOriginalID(GlobalValue::GUID OriginalID) const {
    const auto I = OidGuidMap.find(OriginalID);
    return I == OidGuidMap.end() ? 0 : I->second;
  }

  std::set<std::string> &cfiFunctionDefs() { return CfiFunctionDefs; }
  const std::set<std::string> &cfiFunctionDefs() const { return CfiFunctionDefs; }

  std::set<std::string> &cfiFunctionDecls() { return CfiFunctionDecls; }
  const std::set<std::string> &cfiFunctionDecls() const { return CfiFunctionDecls; }

                                             
  void addGlobalValueSummary(const GlobalValue &GV,
                             std::unique_ptr<GlobalValueSummary> Summary) {
    addGlobalValueSummary(getOrInsertValueInfo(&GV), std::move(Summary));
  }

                                                               
  void addGlobalValueSummary(StringRef ValueName,
                             std::unique_ptr<GlobalValueSummary> Summary) {
    addGlobalValueSummary(getOrInsertValueInfo(GlobalValue::getGUID(ValueName)),
                          std::move(Summary));
  }

                                                         
  void addGlobalValueSummary(ValueInfo VI,
                             std::unique_ptr<GlobalValueSummary> Summary) {
    addOriginalName(VI.getGUID(), Summary->getOriginalName());
                                                                              
                              
    const_cast<GlobalValueSummaryMapTy::value_type *>(VI.getRef())
        ->second.SummaryList.push_back(std::move(Summary));
  }

                                                           
  void addOriginalName(GlobalValue::GUID ValueGUID,
                       GlobalValue::GUID OrigGUID) {
    if (OrigGUID == 0 || ValueGUID == OrigGUID)
      return;
    if (OidGuidMap.count(OrigGUID) && OidGuidMap[OrigGUID] != ValueGUID)
      OidGuidMap[OrigGUID] = 0;
    else
      OidGuidMap[OrigGUID] = ValueGUID;
  }

                                                                              
                
  GlobalValueSummary *findSummaryInModule(GlobalValue::GUID ValueGUID,
                                          StringRef ModuleId) const {
    auto CalleeInfo = getValueInfo(ValueGUID);
    if (!CalleeInfo) {
      return nullptr;                                         
    }
    auto Summary =
        llvh::find_if(CalleeInfo.getSummaryList(),
                      [&](const std::unique_ptr<GlobalValueSummary> &Summary) {
                        return Summary->modulePath() == ModuleId;
                      });
    if (Summary == CalleeInfo.getSummaryList().end())
      return nullptr;
    return Summary->get();
  }

                                                                          
                                       
  GlobalValueSummary *getGlobalValueSummary(const GlobalValue &GV,
                                            bool PerModuleIndex = true) const {
    assert(GV.hasName() && "Can't get GlobalValueSummary for GV with no name");
    return getGlobalValueSummary(GV.getGUID(), PerModuleIndex);
  }

                                                                           
           
                                       
  GlobalValueSummary *getGlobalValueSummary(GlobalValue::GUID ValueGUID,
                                            bool PerModuleIndex = true) const;

                                                      
  const StringMap<std::pair<uint64_t, ModuleHash>> &modulePaths() const {
    return ModulePathStringTable;
  }

                                               
  StringMap<std::pair<uint64_t, ModuleHash>> &modulePaths() {
    return ModulePathStringTable;
  }

                                                           
  uint64_t getModuleId(const StringRef ModPath) const {
    return ModulePathStringTable.lookup(ModPath).first;
  }

                                                                  
  const ModuleHash &getModuleHash(const StringRef ModPath) const {
    auto It = ModulePathStringTable.find(ModPath);
    assert(It != ModulePathStringTable.end() && "Module not registered");
    return It->second.second;
  }

                                                            
                                                                        
  static std::string getGlobalNameForLocal(StringRef Name, ModuleHash ModHash) {
    SmallString<256> NewName(Name);
    NewName += ".llvm.";
    NewName += utostr((uint64_t(ModHash[0]) << 32) |
                      ModHash[1]);                          
    return NewName.str();
  }

                                                                              
                            
  static StringRef getOriginalNameBeforePromote(StringRef Name) {
    std::pair<StringRef, StringRef> Pair = Name.split(".llvm.");
    return Pair.first;
  }

  typedef ModulePathStringTableTy::value_type ModuleInfo;

                                                                     
                                                  
  ModuleInfo *addModule(StringRef ModPath, uint64_t ModId,
                        ModuleHash Hash = ModuleHash{{0}}) {
    return &*ModulePathStringTable.insert({ModPath, {ModId, Hash}}).first;
  }

                                                               
  ModuleInfo *getModule(StringRef ModPath) {
    auto It = ModulePathStringTable.find(ModPath);
    assert(It != ModulePathStringTable.end() && "Module not registered");
    return &*It;
  }

                                                                         
                                                                               
                                 
  bool hasExportedFunctions(const Module &M) const {
    return ModulePathStringTable.count(M.getModuleIdentifier());
  }

  const TypeIdSummaryMapTy &typeIds() const { return TypeIdMap; }

                                                                  
                                                                          
                           
  TypeIdSummary &getOrInsertTypeIdSummary(StringRef TypeId) {
    auto TidIter = TypeIdMap.equal_range(GlobalValue::getGUID(TypeId));
    for (auto It = TidIter.first; It != TidIter.second; ++It)
      if (It->second.first == TypeId)
        return It->second.second;
    auto It = TypeIdMap.insert(
        {GlobalValue::getGUID(TypeId), {TypeId, TypeIdSummary()}});
    return It->second.second;
  }

                                                                             
                                                                             
  const TypeIdSummary *getTypeIdSummary(StringRef TypeId) const {
    auto TidIter = TypeIdMap.equal_range(GlobalValue::getGUID(TypeId));
    for (auto It = TidIter.first; It != TidIter.second; ++It)
      if (It->second.first == TypeId)
        return &It->second.second;
    return nullptr;
  }

                                                                   
                        
  void collectDefinedFunctionsForModule(StringRef ModulePath,
                                        GVSummaryMapTy &GVSummaryMap) const;

                                                                       
               
  void collectDefinedGVSummariesPerModule(
      StringMap<GVSummaryMapTy> &ModuleToDefinedGVSummaries) const;

                                
  void print(raw_ostream &OS, bool IsForDebug = false) const;

                                     
  void dump() const;

                                              
  void exportToDot(raw_ostream& OS) const;

                                                            
  void dumpSCCs(raw_ostream &OS);
};

                                                     
template <> struct GraphTraits<ValueInfo> {
  typedef ValueInfo NodeRef;

  static NodeRef valueInfoFromEdge(FunctionSummary::EdgeTy &P) {
    return P.first;
  }
  using ChildIteratorType =
      mapped_iterator<std::vector<FunctionSummary::EdgeTy>::iterator,
                      decltype(&valueInfoFromEdge)>;

  static NodeRef getEntryNode(ValueInfo V) { return V; }

  static ChildIteratorType child_begin(NodeRef N) {
    if (!N.getSummaryList().size())                            
      return ChildIteratorType(
          FunctionSummary::ExternalNode.CallGraphEdgeList.begin(),
          &valueInfoFromEdge);
    FunctionSummary *F =
        cast<FunctionSummary>(N.getSummaryList().front()->getBaseObject());
    return ChildIteratorType(F->CallGraphEdgeList.begin(), &valueInfoFromEdge);
  }

  static ChildIteratorType child_end(NodeRef N) {
    if (!N.getSummaryList().size())                            
      return ChildIteratorType(
          FunctionSummary::ExternalNode.CallGraphEdgeList.end(),
          &valueInfoFromEdge);
    FunctionSummary *F =
        cast<FunctionSummary>(N.getSummaryList().front()->getBaseObject());
    return ChildIteratorType(F->CallGraphEdgeList.end(), &valueInfoFromEdge);
  }
};

template <>
struct GraphTraits<ModuleSummaryIndex *> : public GraphTraits<ValueInfo> {
  static NodeRef getEntryNode(ModuleSummaryIndex *I) {
    std::unique_ptr<GlobalValueSummary> Root =
        make_unique<FunctionSummary>(I->calculateCallGraphRoot());
    GlobalValueSummaryInfo G(I->haveGVs());
    G.SummaryList.push_back(std::move(Root));
    static auto P =
        GlobalValueSummaryMapTy::value_type(GlobalValue::GUID(0), std::move(G));
    return ValueInfo(I->haveGVs(), &P);
  }
};

}                      

#endif                                
