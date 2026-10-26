//===- PassManager.h - Pass management infrastructure -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This header defines various interfaces for pass management in LLVM. There
/// is no "pass" interface in LLVM per se. Instead, an instance of any class
/// which supports a method to 'run' it over a unit of IR can be used as
/// a pass. A pass manager is generally a tool to collect a sequence of passes
/// which run over a particular IR construct, and run each of them in sequence
/// over each such construct in the containing IR construct. As there is no
/// containing IR construct for a Module, a manager for passes over modules
/// forms the base case which runs its managed passes in sequence over the
/// single module provided.
///
/// The core IR library provides managers for running passes over
/// modules and functions.
///
/// * FunctionPassManager can run over a Module, runs each pass over
///   a Function.
/// * ModulePassManager must be directly run, runs each pass over the Module.
///
/// Note that the implementations of the pass managers use concept-based
/// polymorphism as outlined in the "Value Semantics and Concept-based
/// Polymorphism" talk (or its abbreviated sibling "Inheritance Is The Base
/// Class of Evil") by Sean Parent:
/// * http://github.com/sean-parent/sean-parent.github.com/wiki/Papers-and-Presentations
/// * http://www.youtube.com/watch?v=_BpMYeUFXv8
/// * http://channel9.msdn.com/Events/GoingNative/2013/Inheritance-Is-The-Base-Class-of-Evil
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_PASSMANAGER_H
#define LLVM_IR_PASSMANAGER_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/TinyPtrVector.h"
#include "llvh/IR/Function.h"
#include "llvh/IR/Module.h"
#include "llvh/IR/PassInstrumentation.h"
#include "llvh/IR/PassManagerInternal.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/TypeName.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <iterator>
#include <list>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace llvh {

                                                                     
                                                  
   
                                                                            
                                                                            
                                                       
struct alignas(8) AnalysisKey {};

                                                                              
                                                                              
              
   
                                                                             
                                                                            
                                                                               
                                                             
struct alignas(8) AnalysisSetKey {};

                                                                       
                                                                       
                      
   
                                                                            
   
                                                                        
                                                                        
                                                                 
template <typename IRUnitT> class AllAnalysesOn {
public:
  static AnalysisSetKey *ID() { return &SetKey; }

private:
  static AnalysisSetKey SetKey;
};

template <typename IRUnitT> AnalysisSetKey AllAnalysesOn<IRUnitT>::SetKey;

extern template class AllAnalysesOn<Module>;
extern template class AllAnalysesOn<Function>;

                                                                  
   
                                                                               
                                           
   
                                                                             
                                                                             
                                                                        
                                                                               
                               
class CFGAnalyses {
public:
  static AnalysisSetKey *ID() { return &SetKey; }

private:
  static AnalysisSetKey SetKey;
};

                                                                            
         
   
                                                                             
                                                                              
                                                                            
                                                                             
                  
   
                                                                               
                                                                        
                                                                          
                                                                     
   
                                                                       
                                                                               
   
                                                                          
                                                                               
                                                                      
                                                                             
                                                
   
       
                                                 
                                                                           
                                              
                                               
                                                           
       
       
class PreservedAnalyses {
public:
                                                               
  static PreservedAnalyses none() { return PreservedAnalyses(); }

                                                                  
  static PreservedAnalyses all() {
    PreservedAnalyses PA;
    PA.PreservedIDs.insert(&AllAnalysesKey);
    return PA;
  }

                                                                        
  template <typename AnalysisSetT>
  static PreservedAnalyses allInSet() {
    PreservedAnalyses PA;
    PA.preserveSet<AnalysisSetT>();
    return PA;
  }

                                    
  template <typename AnalysisT> void preserve() { preserve(AnalysisT::ID()); }

                                                                       
                 
  void preserve(AnalysisKey *ID) {
                                                                    
    NotPreservedAnalysisIDs.erase(ID);

                                                                        
                                
    if (!areAllPreserved())
      PreservedIDs.insert(ID);
  }

                                        
  template <typename AnalysisSetT> void preserveSet() {
    preserveSet(AnalysisSetT::ID());
  }

                                                     
  void preserveSet(AnalysisSetKey *ID) {
                                                                       
    if (!areAllPreserved())
      PreservedIDs.insert(ID);
  }

                                    
     
                                                                             
                                                                         
     
                                                                        
               
  template <typename AnalysisT> void abandon() { abandon(AnalysisT::ID()); }

                                                 
     
                                                                             
                                                                         
     
                                                                        
               
  void abandon(AnalysisKey *ID) {
    PreservedIDs.erase(ID);
    NotPreservedAnalysisIDs.insert(ID);
  }

                                               
     
                                                                      
                                                                    
  void intersect(const PreservedAnalyses &Arg) {
    if (Arg.areAllPreserved())
      return;
    if (areAllPreserved()) {
      *this = Arg;
      return;
    }
                                                                            
                                                       
    for (auto ID : Arg.NotPreservedAnalysisIDs) {
      PreservedIDs.erase(ID);
      NotPreservedAnalysisIDs.insert(ID);
    }
    for (auto ID : PreservedIDs)
      if (!Arg.PreservedIDs.count(ID))
        PreservedIDs.erase(ID);
  }

                                                             
     
                                                                      
                                                                    
  void intersect(PreservedAnalyses &&Arg) {
    if (Arg.areAllPreserved())
      return;
    if (areAllPreserved()) {
      *this = std::move(Arg);
      return;
    }
                                                                            
                                                       
    for (auto ID : Arg.NotPreservedAnalysisIDs) {
      PreservedIDs.erase(ID);
      NotPreservedAnalysisIDs.insert(ID);
    }
    for (auto ID : PreservedIDs)
      if (!Arg.PreservedIDs.count(ID))
        PreservedIDs.erase(ID);
  }

                                                                             
                                        
  class PreservedAnalysisChecker {
    friend class PreservedAnalyses;

    const PreservedAnalyses &PA;
    AnalysisKey *const ID;
    const bool IsAbandoned;

                                                                           
                                                                            
                      
    PreservedAnalysisChecker(const PreservedAnalyses &PA, AnalysisKey *ID)
        : PA(PA), ID(ID), IsAbandoned(PA.NotPreservedAnalysisIDs.count(ID)) {}

  public:
                                                                           
                                                  
                                      
    bool preserved() {
      return !IsAbandoned && (PA.PreservedIDs.count(&AllAnalysesKey) ||
                              PA.PreservedIDs.count(ID));
    }

                                                                           
                                                     
                                      
    template <typename AnalysisSetT> bool preservedSet() {
      AnalysisSetKey *SetID = AnalysisSetT::ID();
      return !IsAbandoned && (PA.PreservedIDs.count(&AllAnalysesKey) ||
                              PA.PreservedIDs.count(SetID));
    }
  };

                                                                             
           
     
                                                                      
                                                                       
  template <typename AnalysisT> PreservedAnalysisChecker getChecker() const {
    return PreservedAnalysisChecker(*this, AnalysisT::ID());
  }

                                                                             
         
     
                                                                      
                                                                       
  PreservedAnalysisChecker getChecker(AnalysisKey *ID) const {
    return PreservedAnalysisChecker(*this, ID);
  }

                                                                       
     
                                                                                
                                       
  bool areAllPreserved() const {
    return NotPreservedAnalysisIDs.empty() &&
           PreservedIDs.count(&AllAnalysesKey);
  }

                                                           
     
                                                                        
  template <typename AnalysisSetT> bool allAnalysesInSetPreserved() const {
    return allAnalysesInSetPreserved(AnalysisSetT::ID());
  }

                                                           
     
                                                                        
  bool allAnalysesInSetPreserved(AnalysisSetKey *SetID) const {
    return NotPreservedAnalysisIDs.empty() &&
           (PreservedIDs.count(&AllAnalysesKey) || PreservedIDs.count(SetID));
  }

private:
                                                  
  static AnalysisSetKey AllAnalysesKey;

                                                               
  SmallPtrSet<void *, 2> PreservedIDs;

                                                   
     
                                                                          
                                                                          
                                                  
     
                                                                          
  SmallPtrSet<AnalysisKey *, 2> NotPreservedAnalysisIDs;
};

                                                 
template <typename IRUnitT, typename... ExtraArgTs> class AnalysisManager;

                                                                        
           
   
                                                             
template <typename DerivedT> struct PassInfoMixin {
                                                  
  static StringRef name() {
    static_assert(std::is_base_of<PassInfoMixin, DerivedT>::value,
                  "Must pass the derived type as the template argument!");
    StringRef Name = getTypeName<DerivedT>();
    if (Name.startswith("llvh::"))
      Name = Name.drop_front(strlen("llvh::"));
    return Name;
  }
};

                                                                              
   
                                                                         
                                            
template <typename DerivedT>
struct AnalysisInfoMixin : PassInfoMixin<DerivedT> {
                                                          
     
                                                                                
                                                                                
                       
     
                                                                              
                           
     
                                                                              
                                                                                
                                                                            
                                                                             
                                                                       
                                                                   
  static AnalysisKey *ID() {
    static_assert(std::is_base_of<AnalysisInfoMixin, DerivedT>::value,
                  "Must pass the derived type as the template argument!");
    return &DerivedT::Key;
  }
};

namespace detail {

                                                            
                                                                           
template <typename PassT, typename IRUnitT, typename AnalysisManagerT,
          typename... ArgTs, size_t... Ns>
typename PassT::Result
getAnalysisResultUnpackTuple(AnalysisManagerT &AM, IRUnitT &IR,
                             std::tuple<ArgTs...> Args,
                             llvh::index_sequence<Ns...>) {
  (void)Args;
  return AM.template getResult<PassT>(IR, std::get<Ns>(Args)...);
}

                                                                           
   
                                                                             
                                                                           
                      
template <typename PassT, typename IRUnitT, typename... AnalysisArgTs,
          typename... MainArgTs>
typename PassT::Result
getAnalysisResult(AnalysisManager<IRUnitT, AnalysisArgTs...> &AM, IRUnitT &IR,
                  std::tuple<MainArgTs...> Args) {
  return (getAnalysisResultUnpackTuple<
          PassT, IRUnitT>)(AM, IR, Args,
                           llvh::index_sequence_for<AnalysisArgTs...>{});
}

}                    

                                                                          
                            
                                                                           
          
class PassInstrumentationAnalysis;

                                                              
   
                                                                              
                                                                                
                                                                                
                                                                              
                  
   
                                                                           
                                                                           
                                                                                
                                               
template <typename IRUnitT,
          typename AnalysisManagerT = AnalysisManager<IRUnitT>,
          typename... ExtraArgTs>
class PassManager : public PassInfoMixin<
                        PassManager<IRUnitT, AnalysisManagerT, ExtraArgTs...>> {
public:
                               
     
                                                                         
  explicit PassManager(bool DebugLogging = false) : DebugLogging(DebugLogging) {}

                                                                     
                                                                           
                                                                               
                          
  PassManager(PassManager &&Arg)
      : Passes(std::move(Arg.Passes)),
        DebugLogging(std::move(Arg.DebugLogging)) {}

  PassManager &operator=(PassManager &&RHS) {
    Passes = std::move(RHS.Passes);
    DebugLogging = std::move(RHS.DebugLogging);
    return *this;
  }

                                                                      
                                        
  PreservedAnalyses run(IRUnitT &IR, AnalysisManagerT &AM,
                        ExtraArgTs... ExtraArgs) {
    PreservedAnalyses PA = PreservedAnalyses::all();

                                                                            
                                                    
                                                                           
                                                                  
    PassInstrumentation PI =
        detail::getAnalysisResult<PassInstrumentationAnalysis>(
            AM, IR, std::tuple<ExtraArgTs...>(ExtraArgs...));

    if (DebugLogging)
      dbgs() << "Starting " << getTypeName<IRUnitT>() << " pass manager run.\n";

    for (unsigned Idx = 0, Size = Passes.size(); Idx != Size; ++Idx) {
      auto *P = Passes[Idx].get();
      if (DebugLogging)
        dbgs() << "Running pass: " << P->name() << " on " << IR.getName()
               << "\n";

                                                                                
                                                                          
                
      if (!PI.runBeforePass<IRUnitT>(*P, IR))
        continue;

      PreservedAnalyses PassPA = P->run(IR, AM, ExtraArgs...);

                                                                              
                          
      PI.runAfterPass<IRUnitT>(*P, IR);

                                                                      
                              
      AM.invalidate(IR, PassPA);

                                                                           
                                             
      PA.intersect(std::move(PassPA));

                                                                             
                                                                        
                                                                              
                                                            
                                
    }

                                                                         
                                                                           
                                                                              
                                             
    PA.preserveSet<AllAnalysesOn<IRUnitT>>();

    if (DebugLogging)
      dbgs() << "Finished " << getTypeName<IRUnitT>() << " pass manager run.\n";

    return PA;
  }

  template <typename PassT> void addPass(PassT Pass) {
    using PassModelT =
        detail::PassModel<IRUnitT, PassT, PreservedAnalyses, AnalysisManagerT,
                          ExtraArgTs...>;

    Passes.emplace_back(new PassModelT(std::move(Pass)));
  }

private:
  using PassConceptT =
      detail::PassConcept<IRUnitT, AnalysisManagerT, ExtraArgTs...>;

  std::vector<std::unique_ptr<PassConceptT>> Passes;

                                                         
  bool DebugLogging;
};

extern template class PassManager<Module>;

                                                        
using ModulePassManager = PassManager<Module>;

extern template class PassManager<Function>;

                                                          
using FunctionPassManager = PassManager<Function>;

                                                                        
                                                                   
                                                                            
                                                                            
           
class PassInstrumentationAnalysis
    : public AnalysisInfoMixin<PassInstrumentationAnalysis> {
  friend AnalysisInfoMixin<PassInstrumentationAnalysis>;
  static AnalysisKey Key;

  PassInstrumentationCallbacks *Callbacks;

public:
                                                                             
                        
  PassInstrumentationAnalysis(PassInstrumentationCallbacks *Callbacks = nullptr)
      : Callbacks(Callbacks) {}

  using Result = PassInstrumentation;

  template <typename IRUnitT, typename AnalysisManagerT, typename... ExtraArgTs>
  Result run(IRUnitT &, AnalysisManagerT &, ExtraArgTs &&...) {
    return PassInstrumentation(Callbacks);
  }
};

                                                                   
            
   
                                                                              
                                   
template <typename IRUnitT, typename... ExtraArgTs> class AnalysisManager {
public:
  class Invalidator;

private:
                                                                             
  using ResultConceptT =
      detail::AnalysisResultConcept<IRUnitT, PreservedAnalyses, Invalidator>;
  using PassConceptT =
      detail::AnalysisPassConcept<IRUnitT, PreservedAnalyses, Invalidator,
                                  ExtraArgTs...>;

                                                                
     
                                                                               
                                                                             
                                                                         
              
  using AnalysisResultListT =
      std::list<std::pair<AnalysisKey *, std::unique_ptr<ResultConceptT>>>;

                                                            
  using AnalysisResultListMapT = DenseMap<IRUnitT *, AnalysisResultListT>;

                                                                   
                                                                                
                        
  using AnalysisResultMapT =
      DenseMap<std::pair<AnalysisKey *, IRUnitT *>,
               typename AnalysisResultListT::iterator>;

public:
                                                                           
     
                                                                          
                                                                               
                                                                              
                                                                             
                                                                             
                                                                            
                                            
  class Invalidator {
  public:
                                                                           
                                                              
       
                                                                              
                                                                             
                                                                              
                                                                     
       
                                                                             
                                                                               
                                                                                
                                                     
       
                                                                        
                                                          
    template <typename PassT>
    bool invalidate(IRUnitT &IR, const PreservedAnalyses &PA) {
      using ResultModelT =
          detail::AnalysisResultModel<IRUnitT, PassT, typename PassT::Result,
                                      PreservedAnalyses, Invalidator>;

      return invalidateImpl<ResultModelT>(PassT::ID(), IR, PA);
    }

                                                                               
                                                                          
                  
       
                                                                            
                                                              
    bool invalidate(AnalysisKey *ID, IRUnitT &IR, const PreservedAnalyses &PA) {
      return invalidateImpl<>(ID, IR, PA);
    }

  private:
    friend class AnalysisManager;

    template <typename ResultT = ResultConceptT>
    bool invalidateImpl(AnalysisKey *ID, IRUnitT &IR,
                        const PreservedAnalyses &PA) {
                                                                              
                             
      auto IMapI = IsResultInvalidated.find(ID);
      if (IMapI != IsResultInvalidated.end())
        return IMapI->second;

                                             
      auto RI = Results.find({ID, &IR});
      assert(RI != Results.end() &&
             "Trying to invalidate a dependent result that isn't in the "
             "manager's cache is always an error, likely due to a stale result "
             "handle!");

      auto &Result = static_cast<ResultT &>(*RI->second->second);

                                                                                
                                                                               
                                                                              
                                                  
      bool Inserted;
      std::tie(IMapI, Inserted) =
          IsResultInvalidated.insert({ID, Result.invalidate(IR, PA, *this)});
      (void)Inserted;
      assert(Inserted && "Should not have already inserted this ID, likely "
                         "indicates a dependency cycle!");
      return IMapI->second;
    }

    Invalidator(SmallDenseMap<AnalysisKey *, bool, 8> &IsResultInvalidated,
                const AnalysisResultMapT &Results)
        : IsResultInvalidated(IsResultInvalidated), Results(Results) {}

    SmallDenseMap<AnalysisKey *, bool, 8> &IsResultInvalidated;
    const AnalysisResultMapT &Results;
  };

                                          
     
                                                                         
  AnalysisManager(bool DebugLogging = false) : DebugLogging(DebugLogging) {}
  AnalysisManager(AnalysisManager &&) = default;
  AnalysisManager &operator=(AnalysisManager &&) = default;

                                                                      
  bool empty() const {
    assert(AnalysisResults.empty() == AnalysisResultLists.empty() &&
           "The storage and index of analysis results disagree on how many "
           "there are!");
    return AnalysisResults.empty();
  }

                                                                
     
                                                                                
                                                                                
                           
  void clear(IRUnitT &IR, llvh::StringRef Name) {
    if (DebugLogging)
      dbgs() << "Clearing all analysis results for: " << Name << "\n";

    auto ResultsListI = AnalysisResultLists.find(&IR);
    if (ResultsListI == AnalysisResultLists.end())
      return;
                                                               
    for (auto &IDAndResult : ResultsListI->second)
      AnalysisResults.erase({IDAndResult.first, &IR});

                                                                          
    AnalysisResultLists.erase(ResultsListI);
  }

                                                                
     
                                                                             
                                                                               
                                                                               
                                                
  void clear() {
    AnalysisResults.clear();
    AnalysisResultLists.clear();
  }

                                                             
     
                                                            
  template <typename PassT>
  typename PassT::Result &getResult(IRUnitT &IR, ExtraArgTs... ExtraArgs) {
    assert(AnalysisPasses.count(PassT::ID()) &&
           "This analysis pass was not registered prior to being queried");
    ResultConceptT &ResultConcept =
        getResultImpl(PassT::ID(), IR, ExtraArgs...);

    using ResultModelT =
        detail::AnalysisResultModel<IRUnitT, PassT, typename PassT::Result,
                                    PreservedAnalyses, Invalidator>;

    return static_cast<ResultModelT &>(ResultConcept).Result;
  }

                                                                    
     
                                          
     
                                                 
  template <typename PassT>
  typename PassT::Result *getCachedResult(IRUnitT &IR) const {
    assert(AnalysisPasses.count(PassT::ID()) &&
           "This analysis pass was not registered prior to being queried");

    ResultConceptT *ResultConcept = getCachedResultImpl(PassT::ID(), IR);
    if (!ResultConcept)
      return nullptr;

    using ResultModelT =
        detail::AnalysisResultModel<IRUnitT, PassT, typename PassT::Result,
                                    PreservedAnalyses, Invalidator>;

    return &static_cast<ResultModelT *>(ResultConcept)->Result;
  }

                                                 
     
                                                                               
                                                    
     
                                                                          
                                                                              
                                                                      
                                                                               
                                     
     
                                                                                
                                                                               
                                                                              
                                                                            
                                                                     
                 
  template <typename PassBuilderT>
  bool registerPass(PassBuilderT &&PassBuilder) {
    using PassT = decltype(PassBuilder());
    using PassModelT =
        detail::AnalysisPassModel<IRUnitT, PassT, PreservedAnalyses,
                                  Invalidator, ExtraArgTs...>;

    auto &PassPtr = AnalysisPasses[PassT::ID()];
    if (PassPtr)
                                           
      return false;

                                                                         
    PassPtr.reset(new PassModelT(PassBuilder()));
    return true;
  }

                                                           
     
                                                                                
                                
  template <typename PassT> void invalidate(IRUnitT &IR) {
    assert(AnalysisPasses.count(PassT::ID()) &&
           "This analysis pass was not registered prior to being invalidated");
    invalidateImpl(PassT::ID(), IR);
  }

                                                
     
                                                                        
                                                                              
  void invalidate(IRUnitT &IR, const PreservedAnalyses &PA) {
                                                                
    if (PA.allAnalysesInSetPreserved<AllAnalysesOn<IRUnitT>>())
      return;

    if (DebugLogging)
      dbgs() << "Invalidating all non-preserved analyses for: " << IR.getName()
             << "\n";

                                                             
                           
    SmallDenseMap<AnalysisKey *, bool, 8> IsResultInvalidated;
    Invalidator Inv(IsResultInvalidated, AnalysisResults);
    AnalysisResultListT &ResultsList = AnalysisResultLists[&IR];
    for (auto &AnalysisResultPair : ResultsList) {
                                                                            
                                                                              
                                                                            
                                            
      AnalysisKey *ID = AnalysisResultPair.first;
      auto &Result = *AnalysisResultPair.second;

      auto IMapI = IsResultInvalidated.find(ID);
      if (IMapI != IsResultInvalidated.end())
                                                               
        continue;

                                                                          
                                                                             
                                                                        
                                                                           
                  
      bool Inserted =
          IsResultInvalidated.insert({ID, Result.invalidate(IR, PA, Inv)})
              .second;
      (void)Inserted;
      assert(Inserted && "Should never have already inserted this ID, likely "
                         "indicates a cycle!");
    }

                                                                   
    if (!IsResultInvalidated.empty()) {
      for (auto I = ResultsList.begin(), E = ResultsList.end(); I != E;) {
        AnalysisKey *ID = I->first;
        if (!IsResultInvalidated.lookup(ID)) {
          ++I;
          continue;
        }

        if (DebugLogging)
          dbgs() << "Invalidating analysis: " << this->lookUpPass(ID).name()
                 << " on " << IR.getName() << "\n";

        I = ResultsList.erase(I);
        AnalysisResults.erase({ID, &IR});
      }
    }

    if (ResultsList.empty())
      AnalysisResultLists.erase(&IR);
  }

private:
                                         
  PassConceptT &lookUpPass(AnalysisKey *ID) {
    typename AnalysisPassMapT::iterator PI = AnalysisPasses.find(ID);
    assert(PI != AnalysisPasses.end() &&
           "Analysis passes must be registered prior to being queried!");
    return *PI->second;
  }

                                         
  const PassConceptT &lookUpPass(AnalysisKey *ID) const {
    typename AnalysisPassMapT::const_iterator PI = AnalysisPasses.find(ID);
    assert(PI != AnalysisPasses.end() &&
           "Analysis passes must be registered prior to being queried!");
    return *PI->second;
  }

                                                            
  ResultConceptT &getResultImpl(AnalysisKey *ID, IRUnitT &IR,
                                ExtraArgTs... ExtraArgs) {
    typename AnalysisResultMapT::iterator RI;
    bool Inserted;
    std::tie(RI, Inserted) = AnalysisResults.insert(std::make_pair(
        std::make_pair(ID, &IR), typename AnalysisResultListT::iterator()));

                                                                               
                                                                  
    if (Inserted) {
      auto &P = this->lookUpPass(ID);
      if (DebugLogging)
        dbgs() << "Running analysis: " << P.name() << " on " << IR.getName()
               << "\n";

      PassInstrumentation PI;
      if (ID != PassInstrumentationAnalysis::ID()) {
        PI = getResult<PassInstrumentationAnalysis>(IR, ExtraArgs...);
        PI.runBeforeAnalysis(P, IR);
      }

      AnalysisResultListT &ResultList = AnalysisResultLists[&IR];
      ResultList.emplace_back(ID, P.run(IR, *this, ExtraArgs...));

      PI.runAfterAnalysis(P, IR);

                                                                              
            
      RI = AnalysisResults.find({ID, &IR});
      assert(RI != AnalysisResults.end() && "we just inserted it!");

      RI->second = std::prev(ResultList.end());
    }

    return *RI->second->second;
  }

                                                  
  ResultConceptT *getCachedResultImpl(AnalysisKey *ID, IRUnitT &IR) const {
    typename AnalysisResultMapT::const_iterator RI =
        AnalysisResults.find({ID, &IR});
    return RI == AnalysisResults.end() ? nullptr : &*RI->second->second;
  }

                                        
  void invalidateImpl(AnalysisKey *ID, IRUnitT &IR) {
    typename AnalysisResultMapT::iterator RI =
        AnalysisResults.find({ID, &IR});
    if (RI == AnalysisResults.end())
      return;

    if (DebugLogging)
      dbgs() << "Invalidating analysis: " << this->lookUpPass(ID).name()
             << " on " << IR.getName() << "\n";
    AnalysisResultLists[&IR].erase(RI->second);
    AnalysisResults.erase(RI);
  }

                                                                    
  using AnalysisPassMapT =
      DenseMap<AnalysisKey *, std::unique_ptr<PassConceptT>>;

                                                          
  AnalysisPassMapT AnalysisPasses;

                                                               
     
                                                                             
                                                                   
  AnalysisResultListMapT AnalysisResultLists;

                                                                 
                      
  AnalysisResultMapT AnalysisResults;

                                                  
  bool DebugLogging;
};

extern template class AnalysisManager<Module>;

                                                        
using ModuleAnalysisManager = AnalysisManager<Module>;

extern template class AnalysisManager<Function>;

                                                          
using FunctionAnalysisManager = AnalysisManager<Function>;

                                                                  
                                                                               
                      
   
                                                                              
                                                                         
                                                                          
                                                                               
                                                                           
   
                                                                        
                                                                               
                             
   
                                                                             
                                                                       
template <typename AnalysisManagerT, typename IRUnitT, typename... ExtraArgTs>
class InnerAnalysisManagerProxy
    : public AnalysisInfoMixin<
          InnerAnalysisManagerProxy<AnalysisManagerT, IRUnitT>> {
public:
  class Result {
  public:
    explicit Result(AnalysisManagerT &InnerAM) : InnerAM(&InnerAM) {}

    Result(Result &&Arg) : InnerAM(std::move(Arg.InnerAM)) {
                                                                         
                                                                          
                        
      Arg.InnerAM = nullptr;
    }

    ~Result() {
                                                                               
      if (!InnerAM)
        return;

                                                                               
                                                                    
      InnerAM->clear();
    }

    Result &operator=(Result &&RHS) {
      InnerAM = RHS.InnerAM;
                                                                         
                                                                          
                        
      RHS.InnerAM = nullptr;
      return *this;
    }

                                          
    AnalysisManagerT &getManager() { return *InnerAM; }

                                                                  
       
                                                                                
                                                                             
                                                                               
                                                    
       
                                                                               
                                                                              
                                               
    bool invalidate(
        IRUnitT &IR, const PreservedAnalyses &PA,
        typename AnalysisManager<IRUnitT, ExtraArgTs...>::Invalidator &Inv);

  private:
    AnalysisManagerT *InnerAM;
  };

  explicit InnerAnalysisManagerProxy(AnalysisManagerT &InnerAM)
      : InnerAM(&InnerAM) {}

                                                               
     
                                                                              
                                                                            
                                                 
  Result run(IRUnitT &IR, AnalysisManager<IRUnitT, ExtraArgTs...> &AM,
             ExtraArgTs...) {
    return Result(*InnerAM);
  }

private:
  friend AnalysisInfoMixin<
      InnerAnalysisManagerProxy<AnalysisManagerT, IRUnitT>>;

  static AnalysisKey Key;

  AnalysisManagerT *InnerAM;
};

template <typename AnalysisManagerT, typename IRUnitT, typename... ExtraArgTs>
AnalysisKey
    InnerAnalysisManagerProxy<AnalysisManagerT, IRUnitT, ExtraArgTs...>::Key;

                                                              
using FunctionAnalysisManagerModuleProxy =
    InnerAnalysisManagerProxy<FunctionAnalysisManager, Module>;

                                                      
                                                
template <>
bool FunctionAnalysisManagerModuleProxy::Result::invalidate(
    Module &M, const PreservedAnalyses &PA,
    ModuleAnalysisManager::Invalidator &Inv);

                                                                            
            
extern template class InnerAnalysisManagerProxy<FunctionAnalysisManager,
                                                Module>;

                                                                  
                                                                              
                      
   
                                                                                
                                                                                
                                                                             
                                                                               
                                                              
   
                                                                              
                                                                             
                                                                      
   
                                                                               
                                                                              
                                                                              
                                                                
template <typename AnalysisManagerT, typename IRUnitT, typename... ExtraArgTs>
class OuterAnalysisManagerProxy
    : public AnalysisInfoMixin<
          OuterAnalysisManagerProxy<AnalysisManagerT, IRUnitT, ExtraArgTs...>> {
public:
                                                           
  class Result {
  public:
    explicit Result(const AnalysisManagerT &AM) : AM(&AM) {}

    const AnalysisManagerT &getManager() const { return *AM; }

                                                                            
    bool invalidate(
        IRUnitT &IRUnit, const PreservedAnalyses &PA,
        typename AnalysisManager<IRUnitT, ExtraArgTs...>::Invalidator &Inv) {
                                                                               
                                                                      
      SmallVector<AnalysisKey *, 4> DeadKeys;
      for (auto &KeyValuePair : OuterAnalysisInvalidationMap) {
        AnalysisKey *OuterID = KeyValuePair.first;
        auto &InnerIDs = KeyValuePair.second;
        InnerIDs.erase(llvh::remove_if(InnerIDs, [&](AnalysisKey *InnerID) {
          return Inv.invalidate(InnerID, IRUnit, PA); }),
                       InnerIDs.end());
        if (InnerIDs.empty())
          DeadKeys.push_back(OuterID);
      }

      for (auto OuterID : DeadKeys)
        OuterAnalysisInvalidationMap.erase(OuterID);

                                                                    
      return false;
    }

                                                                          
                                            
    template <typename OuterAnalysisT, typename InvalidatedAnalysisT>
    void registerOuterAnalysisInvalidation() {
      AnalysisKey *OuterID = OuterAnalysisT::ID();
      AnalysisKey *InvalidatedID = InvalidatedAnalysisT::ID();

      auto &InvalidatedIDList = OuterAnalysisInvalidationMap[OuterID];
                                                                        
                                                                           
                                                                         
                                                                    
      auto InvalidatedIt = std::find(InvalidatedIDList.begin(),
                                     InvalidatedIDList.end(), InvalidatedID);
      if (InvalidatedIt == InvalidatedIDList.end())
        InvalidatedIDList.push_back(InvalidatedID);
    }

                                                                             
                 
    const SmallDenseMap<AnalysisKey *, TinyPtrVector<AnalysisKey *>, 2> &
    getOuterInvalidations() const {
      return OuterAnalysisInvalidationMap;
    }

  private:
    const AnalysisManagerT *AM;

                                                                             
                                     
    SmallDenseMap<AnalysisKey *, TinyPtrVector<AnalysisKey *>, 2>
        OuterAnalysisInvalidationMap;
  };

  OuterAnalysisManagerProxy(const AnalysisManagerT &AM) : AM(&AM) {}

                                                               
                                                                        
             
  Result run(IRUnitT &, AnalysisManager<IRUnitT, ExtraArgTs...> &,
             ExtraArgTs...) {
    return Result(*AM);
  }

private:
  friend AnalysisInfoMixin<
      OuterAnalysisManagerProxy<AnalysisManagerT, IRUnitT, ExtraArgTs...>>;

  static AnalysisKey Key;

  const AnalysisManagerT *AM;
};

template <typename AnalysisManagerT, typename IRUnitT, typename... ExtraArgTs>
AnalysisKey
    OuterAnalysisManagerProxy<AnalysisManagerT, IRUnitT, ExtraArgTs...>::Key;

extern template class OuterAnalysisManagerProxy<ModuleAnalysisManager,
                                                Function>;
                                                              
using ModuleAnalysisManagerFunctionProxy =
    OuterAnalysisManagerProxy<ModuleAnalysisManager, Function>;

                                                             
   
                                                                
                                                                        
                           
   
                                                                               
                                                                               
                                                                              
                                                             
                                                                          
                           
   
                                                                              
                                                                              
                                                                         
           
                                                                          
                           
   
                                                                         
                                                                               
                                                       
template <typename FunctionPassT>
class ModuleToFunctionPassAdaptor
    : public PassInfoMixin<ModuleToFunctionPassAdaptor<FunctionPassT>> {
public:
  explicit ModuleToFunctionPassAdaptor(FunctionPassT Pass)
      : Pass(std::move(Pass)) {}

                                                                 
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    FunctionAnalysisManager &FAM =
        AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

                                                                            
                                                    
    PassInstrumentation PI = AM.getResult<PassInstrumentationAnalysis>(M);

    PreservedAnalyses PA = PreservedAnalyses::all();
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

                                                                                
                                                                          
                
      if (!PI.runBeforePass<Function>(Pass, F))
        continue;
      PreservedAnalyses PassPA = Pass.run(F, FAM);

      PI.runAfterPass(Pass, F);

                                                                           
                                                                         
                                                                           
      FAM.invalidate(F, PassPA);

                                                                        
                                                                       
      PA.intersect(std::move(PassPA));
    }

                                                                              
                                                                     
      
                                                                         
                                          
    PA.preserveSet<AllAnalysesOn<Function>>();
    PA.preserve<FunctionAnalysisManagerModuleProxy>();
    return PA;
  }

private:
  FunctionPassT Pass;
};

                                                                
                      
template <typename FunctionPassT>
ModuleToFunctionPassAdaptor<FunctionPassT>
createModuleToFunctionPassAdaptor(FunctionPassT Pass) {
  return ModuleToFunctionPassAdaptor<FunctionPassT>(std::move(Pass));
}

                                                                        
   
                                                                          
                                                                            
                                                                            
                                          
   
                                                                              
                                                                     
template <typename AnalysisT, typename IRUnitT,
          typename AnalysisManagerT = AnalysisManager<IRUnitT>,
          typename... ExtraArgTs>
struct RequireAnalysisPass
    : PassInfoMixin<RequireAnalysisPass<AnalysisT, IRUnitT, AnalysisManagerT,
                                        ExtraArgTs...>> {
                                         
     
                                                                           
                                                                         
                                                                        
                       
  PreservedAnalyses run(IRUnitT &Arg, AnalysisManagerT &AM,
                        ExtraArgTs &&... Args) {
    (void)AM.template getResult<AnalysisT>(Arg,
                                           std::forward<ExtraArgTs>(Args)...);

    return PreservedAnalyses::all();
  }
};

                                                                        
                      
template <typename AnalysisT>
struct InvalidateAnalysisPass
    : PassInfoMixin<InvalidateAnalysisPass<AnalysisT>> {
                                         
     
                                                                            
                                                                         
                                                                        
                       
  template <typename IRUnitT, typename AnalysisManagerT, typename... ExtraArgTs>
  PreservedAnalyses run(IRUnitT &Arg, AnalysisManagerT &AM, ExtraArgTs &&...) {
    auto PA = PreservedAnalyses::all();
    PA.abandon<AnalysisT>();
    return PA;
  }
};

                                                                
   
                                                                              
                                           
struct InvalidateAllAnalysesPass : PassInfoMixin<InvalidateAllAnalysesPass> {
                                         
  template <typename IRUnitT, typename AnalysisManagerT, typename... ExtraArgTs>
  PreservedAnalyses run(IRUnitT &, AnalysisManagerT &, ExtraArgTs &&...) {
    return PreservedAnalyses::none();
  }
};

                                                                         
   
                                                                             
                                                                         
template <typename PassT>
class RepeatedPass : public PassInfoMixin<RepeatedPass<PassT>> {
public:
  RepeatedPass(int Count, PassT P) : Count(Count), P(std::move(P)) {}

  template <typename IRUnitT, typename AnalysisManagerT, typename... Ts>
  PreservedAnalyses run(IRUnitT &IR, AnalysisManagerT &AM, Ts &&... Args) {

                                                                            
                                                    
                                                                           
                                                             
    PassInstrumentation PI =
        detail::getAnalysisResult<PassInstrumentationAnalysis>(
            AM, IR, std::tuple<Ts...>(Args...));

    auto PA = PreservedAnalyses::all();
    for (int i = 0; i < Count; ++i) {
                                                                                
                                                                          
                
      if (!PI.runBeforePass<IRUnitT>(P, IR))
        continue;
      PA.intersect(P.run(IR, AM, std::forward<Ts>(Args)...));
      PI.runAfterPass(P, IR);
    }
    return PA;
  }

private:
  int Count;
  PassT P;
};

template <typename PassT>
RepeatedPass<PassT> createRepeatedPass(int Count, PassT P) {
  return RepeatedPass<PassT>(Count, std::move(P));
}

}                      

#endif                         
