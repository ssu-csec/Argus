//===- PassManager internal APIs and implementation details -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This header provides internal APIs and implementation details used by the
/// pass management interfaces exposed in PassManager.h. To understand more
/// context of why these particular interfaces are needed, see that header
/// file. None of these APIs should be used elsewhere.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_PASSMANAGERINTERNAL_H
#define LLVM_IR_PASSMANAGERINTERNAL_H

#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringRef.h"
#include <memory>
#include <utility>

namespace llvh {

template <typename IRUnitT> class AllAnalysesOn;
template <typename IRUnitT, typename... ExtraArgTs> class AnalysisManager;
class PreservedAnalyses;

                                                          
namespace detail {

                                                         
                                      
template <typename IRUnitT, typename AnalysisManagerT, typename... ExtraArgTs>
struct PassConcept {
                                                                 
  virtual ~PassConcept() = default;

                                                                     
     
                                                                            
                                                                        
                                            
  virtual PreservedAnalyses run(IRUnitT &IR, AnalysisManagerT &AM,
                                ExtraArgTs... ExtraArgs) = 0;

                                                      
  virtual StringRef name() const = 0;
};

                                                             
   
                                                                               
                                                                              
                         
template <typename IRUnitT, typename PassT, typename PreservedAnalysesT,
          typename AnalysisManagerT, typename... ExtraArgTs>
struct PassModel : PassConcept<IRUnitT, AnalysisManagerT, ExtraArgTs...> {
  explicit PassModel(PassT Pass) : Pass(std::move(Pass)) {}
                                                                               
                              
  PassModel(const PassModel &Arg) : Pass(Arg.Pass) {}
  PassModel(PassModel &&Arg) : Pass(std::move(Arg.Pass)) {}

  friend void swap(PassModel &LHS, PassModel &RHS) {
    using std::swap;
    swap(LHS.Pass, RHS.Pass);
  }

  PassModel &operator=(PassModel RHS) {
    swap(*this, RHS);
    return *this;
  }

  PreservedAnalysesT run(IRUnitT &IR, AnalysisManagerT &AM,
                         ExtraArgTs... ExtraArgs) override {
    return Pass.run(IR, AM, ExtraArgs...);
  }

  StringRef name() const override { return PassT::name(); }

  PassT Pass;
};

                                           
   
                                                                            
       
template <typename IRUnitT, typename PreservedAnalysesT, typename InvalidatorT>
struct AnalysisResultConcept {
  virtual ~AnalysisResultConcept() = default;

                                                 
     
                                                                         
                                                                            
     
                                                                     
                                                                             
                                                            
     
                                                                              
                                                                        
                                                                           
                                                                             
     
                                                                  
  virtual bool invalidate(IRUnitT &IR, const PreservedAnalysesT &PA,
                          InvalidatorT &Inv) = 0;
};

                                                                    
                                  
template <typename IRUnitT, typename ResultT> class ResultHasInvalidateMethod {
  using EnabledType = char;
  struct DisabledType {
    char a, b;
  };

                                                                             
                                                                           
                                    
  template <typename T> struct Nonce { using Type = EnabledType; };
  template <typename T>
  static typename Nonce<decltype(std::declval<T>().invalidate(
      std::declval<IRUnitT &>(), std::declval<PreservedAnalyses>()))>::Type
      check(rank<2>);

                                                                      
                                                                         
                                                                       
                                                                     
  template <typename T, typename U> static DisabledType NonceFunction(T U::*);
  struct CheckerBase { int invalidate; };
  template <typename T> struct Checker : CheckerBase, T {};
  template <typename T>
  static decltype(NonceFunction(&Checker<T>::invalidate)) check(rank<1>);

                                                                        
                                              
  template <typename T>
  static EnabledType check(rank<0>);

public:
  enum { Value = sizeof(check<ResultT>(rank<2>())) == sizeof(EnabledType) };
};

                                                 
   
                                                                        
                                                                             
                                                                              
                                           
template <typename IRUnitT, typename PassT, typename ResultT,
          typename PreservedAnalysesT, typename InvalidatorT,
          bool HasInvalidateHandler =
              ResultHasInvalidateMethod<IRUnitT, ResultT>::Value>
struct AnalysisResultModel;

                                                                       
                             
template <typename IRUnitT, typename PassT, typename ResultT,
          typename PreservedAnalysesT, typename InvalidatorT>
struct AnalysisResultModel<IRUnitT, PassT, ResultT, PreservedAnalysesT,
                           InvalidatorT, false>
    : AnalysisResultConcept<IRUnitT, PreservedAnalysesT, InvalidatorT> {
  explicit AnalysisResultModel(ResultT Result) : Result(std::move(Result)) {}
                                                                               
                              
  AnalysisResultModel(const AnalysisResultModel &Arg) : Result(Arg.Result) {}
  AnalysisResultModel(AnalysisResultModel &&Arg)
      : Result(std::move(Arg.Result)) {}

  friend void swap(AnalysisResultModel &LHS, AnalysisResultModel &RHS) {
    using std::swap;
    swap(LHS.Result, RHS.Result);
  }

  AnalysisResultModel &operator=(AnalysisResultModel RHS) {
    swap(*this, RHS);
    return *this;
  }

                                                                        
    
                                                                              
                                                                               
                                        
  bool invalidate(IRUnitT &, const PreservedAnalysesT &PA,
                  InvalidatorT &) override {
    auto PAC = PA.template getChecker<PassT>();
    return !PAC.preserved() &&
           !PAC.template preservedSet<AllAnalysesOn<IRUnitT>>();
  }

  ResultT Result;
};

                                                                       
                           
template <typename IRUnitT, typename PassT, typename ResultT,
          typename PreservedAnalysesT, typename InvalidatorT>
struct AnalysisResultModel<IRUnitT, PassT, ResultT, PreservedAnalysesT,
                           InvalidatorT, true>
    : AnalysisResultConcept<IRUnitT, PreservedAnalysesT, InvalidatorT> {
  explicit AnalysisResultModel(ResultT Result) : Result(std::move(Result)) {}
                                                                               
                              
  AnalysisResultModel(const AnalysisResultModel &Arg) : Result(Arg.Result) {}
  AnalysisResultModel(AnalysisResultModel &&Arg)
      : Result(std::move(Arg.Result)) {}

  friend void swap(AnalysisResultModel &LHS, AnalysisResultModel &RHS) {
    using std::swap;
    swap(LHS.Result, RHS.Result);
  }

  AnalysisResultModel &operator=(AnalysisResultModel RHS) {
    swap(*this, RHS);
    return *this;
  }

                                                   
  bool invalidate(IRUnitT &IR, const PreservedAnalysesT &PA,
                  InvalidatorT &Inv) override {
    return Result.invalidate(IR, PA, Inv);
  }

  ResultT Result;
};

                                         
   
                                                                           
                               
template <typename IRUnitT, typename PreservedAnalysesT, typename InvalidatorT,
          typename... ExtraArgTs>
struct AnalysisPassConcept {
  virtual ~AnalysisPassConcept() = default;

                                                    
                                                                          
            
  virtual std::unique_ptr<
      AnalysisResultConcept<IRUnitT, PreservedAnalysesT, InvalidatorT>>
  run(IRUnitT &IR, AnalysisManager<IRUnitT, ExtraArgTs...> &AM,
      ExtraArgTs... ExtraArgs) = 0;

                                                      
  virtual StringRef name() const = 0;
};

                                               
   
                                                                           
                                                                               
                                                                           
template <typename IRUnitT, typename PassT, typename PreservedAnalysesT,
          typename InvalidatorT, typename... ExtraArgTs>
struct AnalysisPassModel : AnalysisPassConcept<IRUnitT, PreservedAnalysesT,
                                               InvalidatorT, ExtraArgTs...> {
  explicit AnalysisPassModel(PassT Pass) : Pass(std::move(Pass)) {}
                                                                               
                              
  AnalysisPassModel(const AnalysisPassModel &Arg) : Pass(Arg.Pass) {}
  AnalysisPassModel(AnalysisPassModel &&Arg) : Pass(std::move(Arg.Pass)) {}

  friend void swap(AnalysisPassModel &LHS, AnalysisPassModel &RHS) {
    using std::swap;
    swap(LHS.Pass, RHS.Pass);
  }

  AnalysisPassModel &operator=(AnalysisPassModel RHS) {
    swap(*this, RHS);
    return *this;
  }

                                                                     
  using ResultModelT =
      AnalysisResultModel<IRUnitT, PassT, typename PassT::Result,
                          PreservedAnalysesT, InvalidatorT>;

                                                      
     
                                                         
  std::unique_ptr<
      AnalysisResultConcept<IRUnitT, PreservedAnalysesT, InvalidatorT>>
  run(IRUnitT &IR, AnalysisManager<IRUnitT, ExtraArgTs...> &AM,
      ExtraArgTs... ExtraArgs) override {
    return llvh::make_unique<ResultModelT>(
        Pass.run(IR, AM, std::forward<ExtraArgTs>(ExtraArgs)...));
  }

                                                            
     
                                                                    
  StringRef name() const override { return PassT::name(); }

  PassT Pass;
};

}                        

}                      

#endif                                 
