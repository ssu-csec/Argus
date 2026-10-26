//===- llvm/BasicBlock.h - Represent a basic block in the VM ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the BasicBlock class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_BASICBLOCK_H
#define LLVM_IR_BASICBLOCK_H

#include "llvh-c/Types.h"
#include "llvh/ADT/Twine.h"
#include "llvh/ADT/ilist.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/ADT/iterator.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Instruction.h"
#include "llvh/IR/SymbolTableListTraits.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/Compiler.h"
#include <cassert>
#include <cstddef>
#include <iterator>

namespace llvh {

class CallInst;
class Function;
class LandingPadInst;
class LLVMContext;
class Module;
class PHINode;
class TerminatorInst;
class ValueSymbolTable;

                                   
   
                                                                           
                                                                                
                                                                           
                                                                               
                                                  
   
                                                                    
                                                                 
                                                                          
                                                                               
                                                                               
                                                                            
                      
class BasicBlock final : public Value,                                      
                         public ilist_node_with_parent<BasicBlock, Function> {
public:
  using InstListType = SymbolTableList<Instruction>;

private:
  friend class BlockAddress;
  friend class SymbolTableListTraits<BasicBlock>;

  InstListType InstList;
  Function *Parent;

  void setParent(Function *parent);

                  
     
                                                                              
                                                                              
                                       
  explicit BasicBlock(LLVMContext &C, const Twine &Name = "",
                      Function *Parent = nullptr,
                      BasicBlock *InsertBefore = nullptr);

public:
  BasicBlock(const BasicBlock &) = delete;
  BasicBlock &operator=(const BasicBlock &) = delete;
  ~BasicBlock();

                                                      
  LLVMContext &getContext() const;

                              
  using iterator = InstListType::iterator;
  using const_iterator = InstListType::const_iterator;
  using reverse_iterator = InstListType::reverse_iterator;
  using const_reverse_iterator = InstListType::const_reverse_iterator;

                               
     
                                                                            
                                                                           
                                       
  static BasicBlock *Create(LLVMContext &Context, const Twine &Name = "",
                            Function *Parent = nullptr,
                            BasicBlock *InsertBefore = nullptr) {
    return new BasicBlock(Context, Name, Parent, InsertBefore);
  }

                                                   
  const Function *getParent() const { return Parent; }
        Function *getParent()       { return Parent; }

                                                                           
                                                     
     
                                                                           
  const Module *getModule() const;
  Module *getModule() {
    return const_cast<Module *>(
                            static_cast<const BasicBlock *>(this)->getModule());
  }

                                                                            
                                      
  const TerminatorInst *getTerminator() const LLVM_READONLY;
  TerminatorInst *getTerminator() {
    return const_cast<TerminatorInst *>(
                        static_cast<const BasicBlock *>(this)->getTerminator());
  }

                                                                         
                                                                              
                                                  
  const CallInst *getTerminatingDeoptimizeCall() const;
  CallInst *getTerminatingDeoptimizeCall() {
    return const_cast<CallInst *>(
         static_cast<const BasicBlock *>(this)->getTerminatingDeoptimizeCall());
  }

                                                                             
                                                                        
                              
  const CallInst *getTerminatingMustTailCall() const;
  CallInst *getTerminatingMustTailCall() {
    return const_cast<CallInst *>(
           static_cast<const BasicBlock *>(this)->getTerminatingMustTailCall());
  }

                                                                            
                          
     
                                                                               
                                                                           
                                                                      
  const Instruction* getFirstNonPHI() const;
  Instruction* getFirstNonPHI() {
    return const_cast<Instruction *>(
                       static_cast<const BasicBlock *>(this)->getFirstNonPHI());
  }

                                                                            
                                   
  const Instruction* getFirstNonPHIOrDbg() const;
  Instruction* getFirstNonPHIOrDbg() {
    return const_cast<Instruction *>(
                  static_cast<const BasicBlock *>(this)->getFirstNonPHIOrDbg());
  }

                                                                            
                                                          
  const Instruction* getFirstNonPHIOrDbgOrLifetime() const;
  Instruction* getFirstNonPHIOrDbgOrLifetime() {
    return const_cast<Instruction *>(
        static_cast<const BasicBlock *>(this)->getFirstNonPHIOrDbgOrLifetime());
  }

                                                                        
                                                   
     
                                                                   
  const_iterator getFirstInsertionPt() const;
  iterator getFirstInsertionPt() {
    return static_cast<const BasicBlock *>(this)
                                          ->getFirstInsertionPt().getNonConst();
  }

                                                                                
                             
  iterator_range<filter_iterator<BasicBlock::const_iterator,
                                 std::function<bool(const Instruction &)>>>
  instructionsWithoutDebug() const;

                                                                               
                         
  iterator_range<filter_iterator<BasicBlock::iterator,
                                 std::function<bool(Instruction &)>>>
  instructionsWithoutDebug();

                                                                       
  void removeFromParent();

                                                               
     
                                                                       
  SymbolTableList<BasicBlock>::iterator eraseFromParent();

                                                                          
                                                                     
  void moveBefore(BasicBlock *MovePos);

                                                                     
                                                                 
  void moveAfter(BasicBlock *MovePos);

                                                  
     
                                                                            
                                                                              
     
                                        
  void insertInto(Function *Parent, BasicBlock *InsertBefore = nullptr);

                                                                         
                                             
  const BasicBlock *getSinglePredecessor() const;
  BasicBlock *getSinglePredecessor() {
    return const_cast<BasicBlock *>(
                 static_cast<const BasicBlock *>(this)->getSinglePredecessor());
  }

                                                                         
                                             
     
                                                                         
                                                                             
                                                                        
  const BasicBlock *getUniquePredecessor() const;
  BasicBlock *getUniquePredecessor() {
    return const_cast<BasicBlock *>(
                 static_cast<const BasicBlock *>(this)->getUniquePredecessor());
  }

                                                                      
                                      
     
                                                             
  const BasicBlock *getSingleSuccessor() const;
  BasicBlock *getSingleSuccessor() {
    return const_cast<BasicBlock *>(
                   static_cast<const BasicBlock *>(this)->getSingleSuccessor());
  }

                                                                      
                                      
     
                                                             
  const BasicBlock *getUniqueSuccessor() const;
  BasicBlock *getUniqueSuccessor() {
    return const_cast<BasicBlock *>(
                   static_cast<const BasicBlock *>(this)->getUniqueSuccessor());
  }

                                                                                
                                  
     
  inline iterator                begin()       { return InstList.begin(); }
  inline const_iterator          begin() const { return InstList.begin(); }
  inline iterator                end  ()       { return InstList.end();   }
  inline const_iterator          end  () const { return InstList.end();   }

  inline reverse_iterator        rbegin()       { return InstList.rbegin(); }
  inline const_reverse_iterator  rbegin() const { return InstList.rbegin(); }
  inline reverse_iterator        rend  ()       { return InstList.rend();   }
  inline const_reverse_iterator  rend  () const { return InstList.rend();   }

  inline size_t                   size() const { return InstList.size();  }
  inline bool                    empty() const { return InstList.empty(); }
  inline const Instruction      &front() const { return InstList.front(); }
  inline       Instruction      &front()       { return InstList.front(); }
  inline const Instruction       &back() const { return InstList.back();  }
  inline       Instruction       &back()       { return InstList.back();  }

                                                             
  template <typename PHINodeT = PHINode, typename BBIteratorT = iterator>
  class phi_iterator_impl
      : public iterator_facade_base<phi_iterator_impl<PHINodeT, BBIteratorT>,
                                    std::forward_iterator_tag, PHINodeT> {
    friend BasicBlock;

    PHINodeT *PN;

    phi_iterator_impl(PHINodeT *PN) : PN(PN) {}

  public:
                                                                            
                         
    phi_iterator_impl() = default;

                                                           
    template <typename PHINodeU, typename BBIteratorU>
    phi_iterator_impl(const phi_iterator_impl<PHINodeU, BBIteratorU> &Arg)
        : PN(Arg.PN) {}

    bool operator==(const phi_iterator_impl &Arg) const { return PN == Arg.PN; }

    PHINodeT &operator*() const { return *PN; }

    using phi_iterator_impl::iterator_facade_base::operator++;
    phi_iterator_impl &operator++() {
      assert(PN && "Cannot increment the end iterator!");
      PN = dyn_cast<PHINodeT>(std::next(BBIteratorT(PN)));
      return *this;
    }
  };
  using phi_iterator = phi_iterator_impl<>;
  using const_phi_iterator =
      phi_iterator_impl<const PHINode, BasicBlock::const_iterator>;

                                                                     
     
                                                                              
  iterator_range<const_phi_iterator> phis() const {
    return const_cast<BasicBlock *>(this)->phis();
  }
  iterator_range<phi_iterator> phis();

                                                       
     
                                                                            
                                        
  const InstListType &getInstList() const { return InstList; }
        InstListType &getInstList()       { return InstList; }

                                                            
  static InstListType BasicBlock::*getSublistAccess(Instruction*) {
    return &BasicBlock::InstList;
  }

                                                          
  ValueSymbolTable *getValueSymbolTable();

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == Value::BasicBlockVal;
  }

                                                                           
                                      
     
                                                                                
                                                                             
                                                                             
                                                                          
                             
  void dropAllReferences();

                                                                             
               
     
                                                                               
                                                                            
                                                                        
  void removePredecessor(BasicBlock *Pred, bool DontDeleteUselessPHIs = false);

  bool canSplitPredecessors() const;

                                                                               
     
                                                                              
                                                                                
                                                                             
                                                                             
                                                       
     
                                                                        
                                                                               
                                                                                
                       
     
                                                                            
                                                                               
  BasicBlock *splitBasicBlock(iterator I, const Twine &BBName = "");
  BasicBlock *splitBasicBlock(Instruction *I, const Twine &BBName = "") {
    return splitBasicBlock(I->getIterator(), BBName);
  }

                                                                       
                                            
  bool hasAddressTaken() const { return getSubclassDataFromValue() != 0; }

                                                                             
                                    
  void replaceSuccessorsPhiUsesWith(BasicBlock *New);

                                                                     
  bool isEHPad() const { return getFirstNonPHI()->isEHPad(); }

                                                       
     
                                                                              
                                                 
  bool isLandingPad() const;

                                                                        
  const LandingPadInst *getLandingPadInst() const;
  LandingPadInst *getLandingPadInst() {
    return const_cast<LandingPadInst *>(
                    static_cast<const BasicBlock *>(this)->getLandingPadInst());
  }

                                                                       
  bool isLegalToHoistInto() const;

  Optional<uint64_t> getIrrLoopHeaderWeight() const;

private:
                                                                     
                                            
     
                                                                              
                              
  void AdjustBlockAddressRefCount(int Amt) {
    setValueSubclassData(getSubclassDataFromValue()+Amt);
    assert((int)(signed char)getSubclassDataFromValue() >= 0 &&
           "Refcount wrap-around");
  }

                                                                            
                                                            
  void setValueSubclassData(unsigned short D) {
    Value::setValueSubclassData(D);
  }
};

                                                                
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(BasicBlock, LLVMBasicBlockRef)

                                                                               
                                                         
BasicBlock::iterator skipDebugIntrinsics(BasicBlock::iterator It);

}                      

#endif                        
