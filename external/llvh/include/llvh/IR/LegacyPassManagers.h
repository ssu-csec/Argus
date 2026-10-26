//===- LegacyPassManagers.h - Legacy Pass Infrastructure --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the LLVM Pass Manager infrastructure.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_LEGACYPASSMANAGERS_H
#define LLVM_IR_LEGACYPASSMANAGERS_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/FoldingSet.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Pass.h"
#include <vector>

                                                                                
            
                                                                             
  
                                               
                                                                        
                                             
                                                                            
                                                         
  
                                                                     
                                                                                 
                                                                          
                                    
  
                                                                          
                                                                               
  
                      
  
                               
  
                                                                           
                                                                             
                                   
  
                           
  
                                                                           
                                                                               
                                                                               
                 
  
                                                                       
  
                                          
  
                                 
  
                                                                   
                                                                   
  
                                                                        
                                                                
  
                                                                            
  
                                                                     
  
                                                          
  
                                                               
  
                                                        
  
                         
  
                                                                           
                                                 
  
                                                                 
                                                       
  
                                                                       
                  
                                                                                

#include "llvh/Support/PrettyStackTrace.h"

namespace llvh {
template <typename T> class ArrayRef;
class Module;
class Pass;
class StringRef;
class Value;
class Timer;
class PMDataManager;

                              
enum PassDebuggingString {
  EXECUTION_MSG,                                 
  MODIFICATION_MSG,                                    
  FREEING_MSG,                                
  ON_BASICBLOCK_MSG,                                                    
  ON_FUNCTION_MSG,                                               
  ON_MODULE_MSG,                                           
  ON_REGION_MSG,                                     
  ON_LOOP_MSG,                                   
  ON_CG_MSG                                               
};

                                                                               
                                                                  
class PassManagerPrettyStackEntry : public PrettyStackTraceEntry {
  Pass *P;
  Value *V;
  Module *M;

public:
  explicit PassManagerPrettyStackEntry(Pass *p)
    : P(p), V(nullptr), M(nullptr) {}                               
  PassManagerPrettyStackEntry(Pass *p, Value &v)
    : P(p), V(&v), M(nullptr) {}                      
  PassManagerPrettyStackEntry(Pass *p, Module &m)
    : P(p), V(nullptr), M(&m) {}                      

                                                            
  void print(raw_ostream &OS) const override;
};

                                                                                
          
  
                                                                           
             
   
                                                                               
                                                                             
                                                                       
                     
class PMStack {
public:
  typedef std::vector<PMDataManager *>::const_reverse_iterator iterator;
  iterator begin() const { return S.rbegin(); }
  iterator end() const { return S.rend(); }

  void pop();
  PMDataManager *top() const { return S.back(); }
  void push(PMDataManager *PM);
  bool empty() const { return S.empty(); }

  void dump() const;

private:
  std::vector<PMDataManager *> S;
};

                                                                                
                    
  
                                                                            
                            
class PMTopLevelManager {
protected:
  explicit PMTopLevelManager(PMDataManager *PMDM);

  unsigned getNumContainedManagers() const {
    return (unsigned)PassManagers.size();
  }

  void initializeAllAnalysisInfo();

private:
  virtual PMDataManager *getAsPMDataManager() = 0;
  virtual PassManagerType getTopLevelPassManagerType() = 0;

public:
                                                                      
                                                                   
                                                                    
  void schedulePass(Pass *P);

                                                               
  void setLastUser(ArrayRef<Pass*> AnalysisPasses, Pass *P);

                                         
  void collectLastUses(SmallVectorImpl<Pass *> &LastUses, Pass *P);

                                                                  
                                                                
                       
  Pass *findAnalysisPass(AnalysisID AID);

                                            
  const PassInfo *findAnalysisPassInfo(AnalysisID AID) const;

                                                     
  AnalysisUsage *findAnalysisUsage(Pass *P);

  virtual ~PMTopLevelManager();

                                           
  void addImmutablePass(ImmutablePass *P);

  inline SmallVectorImpl<ImmutablePass *>& getImmutablePasses() {
    return ImmutablePasses;
  }

  void addPassManager(PMDataManager *Manager) {
    PassManagers.push_back(Manager);
  }

                                                                
                                              
  inline void addIndirectPassManager(PMDataManager *Manager) {
    IndirectPassManagers.push_back(Manager);
  }

                                                    
  void dumpPasses() const;
  void dumpArguments() const;

                         
  PMStack activeStack;

protected:
                                 
  SmallVector<PMDataManager *, 8> PassManagers;

private:
                                                                  
                          
  SmallVector<PMDataManager *, 8> IndirectPassManagers;

                                                         
                                                          
  DenseMap<Pass *, Pass *> LastUser;

                                                              
                                                          
                  
  DenseMap<Pass *, SmallPtrSet<Pass *, 8> > InversedLastUser;

                                                        
  SmallVector<ImmutablePass *, 16> ImmutablePasses;

                                      
  SmallDenseMap<AnalysisID, ImmutablePass *, 8> ImmutablePassMap;


                                                                               
                                                                               
  struct AUFoldingSetNode : public FoldingSetNode {
    AnalysisUsage AU;
    AUFoldingSetNode(const AnalysisUsage &AU) : AU(AU) {}
    void Profile(FoldingSetNodeID &ID) const {
      Profile(ID, AU);
    }
    static void Profile(FoldingSetNodeID &ID, const AnalysisUsage &AU) {
                                                                         
                                                               
      ID.AddBoolean(AU.getPreservesAll());
      auto ProfileVec = [&](const SmallVectorImpl<AnalysisID>& Vec) {
        ID.AddInteger(Vec.size());
        for(AnalysisID AID : Vec)
          ID.AddPointer(AID);
      };
      ProfileVec(AU.getRequiredSet());
      ProfileVec(AU.getRequiredTransitiveSet());
      ProfileVec(AU.getPreservedSet());
      ProfileVec(AU.getUsedSet());
    }
  };

                                                                               
                                                                           
                                                        
  FoldingSet<AUFoldingSetNode> UniqueAnalysisUsages;

                                                                               
                                           
  SpecificBumpPtrAllocator<AUFoldingSetNode> AUFoldingSetNodeAllocator;

                                                                             
                                                              
  DenseMap<Pass *, AnalysisUsage*> AnUsageMap;

                                                                           
                                                                          
                                                                            
                          
  mutable DenseMap<AnalysisID, const PassInfo *> AnalysisPassInfos;
};

                                                                                
                

                                                                       
                          
class PMDataManager {
public:
  explicit PMDataManager() : TPM(nullptr), Depth(0) {
    initializeAnalysisInfo();
  }

  virtual ~PMDataManager();

  virtual Pass *getAsPass() = 0;

                                                                            
  void recordAvailableAnalysis(Pass *P);

                                                                     
  void verifyPreservedAnalysis(Pass *P);

                                                       
  void removeNotPreservedAnalysis(Pass *P);

                                   
  void removeDeadPasses(Pass *P, StringRef Msg,
                        enum PassDebuggingString);

               
  void freePass(Pass *P, StringRef Msg,
                enum PassDebuggingString);

                                            
                                                                 
  void add(Pass *P, bool ProcessAnalysis = true);

                                                                          
                                                                       
                                    
  virtual void addLowerLevelRequiredPass(Pass *P, Pass *RequiredPass);

  virtual Pass *getOnTheFlyPass(Pass *P, AnalysisID PI, Function &F);

                                                
  void initializeAnalysisInfo() {
    AvailableAnalysis.clear();
    for (unsigned i = 0; i < PMT_Last; ++i)
      InheritedAnalysis[i] = nullptr;
  }

                                                                 
                                             
  bool preserveHigherLevelAnalysis(Pass *P);

                                                                              
                                                                               
                                                   
  void collectRequiredAndUsedAnalyses(
      SmallVectorImpl<Pass *> &UsedPasses,
      SmallVectorImpl<AnalysisID> &ReqPassNotAvailable, Pass *P);

                                                                             
                                                                    
                                                               
                               
  void initializeAnalysisImpl(Pass *P);

                                                                              
                       
  Pass *findAnalysisPass(AnalysisID AID, bool Direction);

                            
  PMTopLevelManager *getTopLevelManager() { return TPM; }
  void setTopLevelManager(PMTopLevelManager *T) { TPM = T; }

  unsigned getDepth() const { return Depth; }
  void setDepth(unsigned newDepth) { Depth = newDepth; }

                                      
  void dumpLastUses(Pass *P, unsigned Offset) const;
  void dumpPassArguments() const;
  void dumpPassInfo(Pass *P, enum PassDebuggingString S1,
                    enum PassDebuggingString S2, StringRef Msg);
  void dumpRequiredSet(const Pass *P) const;
  void dumpPreservedSet(const Pass *P) const;
  void dumpUsedSet(const Pass *P) const;

  unsigned getNumContainedPasses() const {
    return (unsigned)PassVector.size();
  }

  virtual PassManagerType getPassManagerType() const {
    assert ( 0 && "Invalid use of getPassManagerType");
    return PMT_Unknown;
  }

  DenseMap<AnalysisID, Pass*> *getAvailableAnalysis() {
    return &AvailableAnalysis;
  }

                                                                 
  void populateInheritedAnalysis(PMStack &PMS) {
    unsigned Index = 0;
    for (PMStack::iterator I = PMS.begin(), E = PMS.end();
         I != E; ++I)
      InheritedAnalysis[Index++] = (*I)->getAvailableAnalysis();
  }

                                                                            
                            
                                                
  unsigned initSizeRemarkInfo(
      Module &M,
      StringMap<std::pair<unsigned, unsigned>> &FunctionToInstrCount);

                                                                               
              
                                                                          
                                                                   
     
                                                                           
                                                                                
                                                                          
                   
  void emitInstrCountChangedRemark(
      Pass *P, Module &M, int64_t Delta, unsigned CountBefore,
      StringMap<std::pair<unsigned, unsigned>> &FunctionToInstrCount,
      Function *F = nullptr);

protected:
                       
  PMTopLevelManager *TPM;

                                                        
  SmallVector<Pass *, 16> PassVector;

                                                               
                                                                   
                                       
  DenseMap<AnalysisID, Pass *> *InheritedAnalysis[PMT_Last];

                                                                             
                             
  bool isPassDebuggingExecutionsOrMore() const;

private:
  void dumpAnalysisUsage(StringRef Msg, const Pass *P,
                         const AnalysisUsage::VectorType &Set) const;

                                                                         
                                                                     
                                                                             
                      
  DenseMap<AnalysisID, Pass*> AvailableAnalysis;

                                                                    
                  
  SmallVector<Pass *, 16> HigherLevelAnalysis;

  unsigned Depth;
};

                                                                                
                
  
                                                            
                                                                             
                                                                          
             
class FPPassManager : public ModulePass, public PMDataManager {
public:
  static char ID;
  explicit FPPassManager()
  : ModulePass(ID), PMDataManager() { }

                                                                             
                                                                            
  bool runOnFunction(Function &F);
  bool runOnModule(Module &M) override;

                                                                      
  void cleanup();

                                                                         
                          
     
  using ModulePass::doInitialization;

                                                                             
     
  bool doInitialization(Module &M) override;

                                                                     
                        
     
  using ModulePass::doFinalization;

                                                                         
     
  bool doFinalization(Module &M) override;

  PMDataManager *getAsPMDataManager() override { return this; }
  Pass *getAsPass() override { return this; }

                                                                
  void getAnalysisUsage(AnalysisUsage &Info) const override {
    Info.setPreservesAll();
  }

                                         
  void dumpPassStructure(unsigned Offset) override;

  StringRef getPassName() const override { return "Function Pass Manager"; }

  FunctionPass *getContainedPass(unsigned N) {
    assert ( N < PassVector.size() && "Pass number out of range!");
    FunctionPass *FP = static_cast<FunctionPass *>(PassVector[N]);
    return FP;
  }

  PassManagerType getPassManagerType() const override {
    return PMT_FunctionPassManager;
  }
};

}

#endif
