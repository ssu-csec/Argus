//===- InstVisitor.h - Instruction visitor templates ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#ifndef LLVM_IR_INSTVISITOR_H
#define LLVM_IR_INSTVISITOR_H

#include "llvh/IR/CallSite.h"
#include "llvh/IR/Function.h"
#include "llvh/IR/Instructions.h"
#include "llvh/IR/IntrinsicInst.h"
#include "llvh/IR/Intrinsics.h"
#include "llvh/IR/Module.h"
#include "llvh/Support/ErrorHandling.h"

namespace llvh {

                                                                               
               
  
#define HANDLE_INST(NUM, OPCODE, CLASS)   class CLASS;
#include "llvh/IR/Instruction.def"

#define DELEGATE(CLASS_TO_VISIT) \
  return static_cast<SubClass*>(this)-> \
               visit##CLASS_TO_VISIT(static_cast<CLASS_TO_VISIT&>(I))


                                       
   
                                                                            
                                                                           
                                                       
   
                                                                        
                                                                           
                                                                           
                                                                       
   
                                                                   
                           
   
                                                                              
                                        
        
                                                                         
                      
                                         
   
                                                        
       
   
                                            
                              
                           
                              
   
                                                                             
                                                                               
   
                                                                        
                                                                      
                                                                       
                                                       
   
                                                                             
                                                                               
                                                  
   
                                                                        
                                                                              
                                                                         
           
template<typename SubClass, typename RetTy=void>
class InstVisitor {
                                                                                
                                                                              
                                 
    

public:
                                                                           
  template<class Iterator>
  void visit(Iterator Start, Iterator End) {
    while (Start != End)
      static_cast<SubClass*>(this)->visit(*Start++);
  }

                                                      
    
  void visit(Module &M) {
    static_cast<SubClass*>(this)->visitModule(M);
    visit(M.begin(), M.end());
  }
  void visit(Function &F) {
    static_cast<SubClass*>(this)->visitFunction(F);
    visit(F.begin(), F.end());
  }
  void visit(BasicBlock &BB) {
    static_cast<SubClass*>(this)->visitBasicBlock(BB);
    visit(BB.begin(), BB.end());
  }

                                                                            
  void visit(Module       *M)  { visit(*M); }
  void visit(Function     *F)  { visit(*F); }
  void visit(BasicBlock   *BB) { visit(*BB); }
  RetTy visit(Instruction *I)  { return visit(*I); }

                                                     
    
  RetTy visit(Instruction &I) {
    static_assert(std::is_base_of<InstVisitor, SubClass>::value,
                  "Must pass the derived type to this template!");

    switch (I.getOpcode()) {
    default: llvm_unreachable("Unknown instruction type encountered!");
                                                                     
#define HANDLE_INST(NUM, OPCODE, CLASS) \
    case Instruction::OPCODE: return \
           static_cast<SubClass*>(this)-> \
                      visit##OPCODE(static_cast<CLASS&>(I));
#include "llvh/IR/Instruction.def"
    }
  }

                                                                                
                                                                              
                                                                            
                                                                              
                                                                            
                                                              
    

                                                                                
                                                           
    
  void visitModule    (Module &M) {}
  void visitFunction  (Function &F) {}
  void visitBasicBlock(BasicBlock &BB) {}

                                                                            
                                                                        
                                                                                
                              
    
                                                                         
                                                                             
                                                                               
                                                
#define HANDLE_INST(NUM, OPCODE, CLASS) \
    RetTy visit##OPCODE(CLASS &I) { \
      if (NUM == Instruction::Call) \
        return delegateCallInst(I); \
      else \
        DELEGATE(CLASS); \
    }
#include "llvh/IR/Instruction.def"

                                                                        
                                                                        
    
  RetTy visitReturnInst(ReturnInst &I)            { DELEGATE(TerminatorInst);}
  RetTy visitBranchInst(BranchInst &I)            { DELEGATE(TerminatorInst);}
  RetTy visitSwitchInst(SwitchInst &I)            { DELEGATE(TerminatorInst);}
  RetTy visitIndirectBrInst(IndirectBrInst &I)    { DELEGATE(TerminatorInst);}
  RetTy visitResumeInst(ResumeInst &I)            { DELEGATE(TerminatorInst);}
  RetTy visitUnreachableInst(UnreachableInst &I)  { DELEGATE(TerminatorInst);}
  RetTy visitCleanupReturnInst(CleanupReturnInst &I) { DELEGATE(TerminatorInst);}
  RetTy visitCatchReturnInst(CatchReturnInst &I)  { DELEGATE(TerminatorInst); }
  RetTy visitCatchSwitchInst(CatchSwitchInst &I)  { DELEGATE(TerminatorInst);}
  RetTy visitICmpInst(ICmpInst &I)                { DELEGATE(CmpInst);}
  RetTy visitFCmpInst(FCmpInst &I)                { DELEGATE(CmpInst);}
  RetTy visitAllocaInst(AllocaInst &I)            { DELEGATE(UnaryInstruction);}
  RetTy visitLoadInst(LoadInst     &I)            { DELEGATE(UnaryInstruction);}
  RetTy visitStoreInst(StoreInst   &I)            { DELEGATE(Instruction);}
  RetTy visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) { DELEGATE(Instruction);}
  RetTy visitAtomicRMWInst(AtomicRMWInst &I)      { DELEGATE(Instruction);}
  RetTy visitFenceInst(FenceInst   &I)            { DELEGATE(Instruction);}
  RetTy visitGetElementPtrInst(GetElementPtrInst &I){ DELEGATE(Instruction);}
  RetTy visitPHINode(PHINode       &I)            { DELEGATE(Instruction);}
  RetTy visitTruncInst(TruncInst &I)              { DELEGATE(CastInst);}
  RetTy visitZExtInst(ZExtInst &I)                { DELEGATE(CastInst);}
  RetTy visitSExtInst(SExtInst &I)                { DELEGATE(CastInst);}
  RetTy visitFPTruncInst(FPTruncInst &I)          { DELEGATE(CastInst);}
  RetTy visitFPExtInst(FPExtInst &I)              { DELEGATE(CastInst);}
  RetTy visitFPToUIInst(FPToUIInst &I)            { DELEGATE(CastInst);}
  RetTy visitFPToSIInst(FPToSIInst &I)            { DELEGATE(CastInst);}
  RetTy visitUIToFPInst(UIToFPInst &I)            { DELEGATE(CastInst);}
  RetTy visitSIToFPInst(SIToFPInst &I)            { DELEGATE(CastInst);}
  RetTy visitPtrToIntInst(PtrToIntInst &I)        { DELEGATE(CastInst);}
  RetTy visitIntToPtrInst(IntToPtrInst &I)        { DELEGATE(CastInst);}
  RetTy visitBitCastInst(BitCastInst &I)          { DELEGATE(CastInst);}
  RetTy visitAddrSpaceCastInst(AddrSpaceCastInst &I) { DELEGATE(CastInst);}
  RetTy visitSelectInst(SelectInst &I)            { DELEGATE(Instruction);}
  RetTy visitVAArgInst(VAArgInst   &I)            { DELEGATE(UnaryInstruction);}
  RetTy visitExtractElementInst(ExtractElementInst &I) { DELEGATE(Instruction);}
  RetTy visitInsertElementInst(InsertElementInst &I) { DELEGATE(Instruction);}
  RetTy visitShuffleVectorInst(ShuffleVectorInst &I) { DELEGATE(Instruction);}
  RetTy visitExtractValueInst(ExtractValueInst &I){ DELEGATE(UnaryInstruction);}
  RetTy visitInsertValueInst(InsertValueInst &I)  { DELEGATE(Instruction); }
  RetTy visitLandingPadInst(LandingPadInst &I)    { DELEGATE(Instruction); }
  RetTy visitFuncletPadInst(FuncletPadInst &I) { DELEGATE(Instruction); }
  RetTy visitCleanupPadInst(CleanupPadInst &I) { DELEGATE(FuncletPadInst); }
  RetTy visitCatchPadInst(CatchPadInst &I)     { DELEGATE(FuncletPadInst); }

                                                       
  RetTy visitDbgDeclareInst(DbgDeclareInst &I)    { DELEGATE(DbgVariableIntrinsic);}
  RetTy visitDbgValueInst(DbgValueInst &I)        { DELEGATE(DbgVariableIntrinsic);}
  RetTy visitDbgVariableIntrinsic(DbgVariableIntrinsic &I)
                                                  { DELEGATE(DbgInfoIntrinsic);}
  RetTy visitDbgLabelInst(DbgLabelInst &I)        { DELEGATE(DbgInfoIntrinsic);}
  RetTy visitDbgInfoIntrinsic(DbgInfoIntrinsic &I){ DELEGATE(IntrinsicInst); }
  RetTy visitMemSetInst(MemSetInst &I)            { DELEGATE(MemIntrinsic); }
  RetTy visitMemCpyInst(MemCpyInst &I)            { DELEGATE(MemTransferInst); }
  RetTy visitMemMoveInst(MemMoveInst &I)          { DELEGATE(MemTransferInst); }
  RetTy visitMemTransferInst(MemTransferInst &I)  { DELEGATE(MemIntrinsic); }
  RetTy visitMemIntrinsic(MemIntrinsic &I)        { DELEGATE(IntrinsicInst); }
  RetTy visitVAStartInst(VAStartInst &I)          { DELEGATE(IntrinsicInst); }
  RetTy visitVAEndInst(VAEndInst &I)              { DELEGATE(IntrinsicInst); }
  RetTy visitVACopyInst(VACopyInst &I)            { DELEGATE(IntrinsicInst); }
  RetTy visitIntrinsicInst(IntrinsicInst &I)      { DELEGATE(CallInst); }

                                                                          
                                
  RetTy visitCallInst(CallInst &I) {
    return static_cast<SubClass*>(this)->visitCallSite(&I);
  }
  RetTy visitInvokeInst(InvokeInst &I) {
    return static_cast<SubClass*>(this)->visitCallSite(&I);
  }

                                                                     
                                                                            
                       
    
  RetTy visitCastInst(CastInst &I)                { DELEGATE(UnaryInstruction);}
  RetTy visitBinaryOperator(BinaryOperator &I)    { DELEGATE(Instruction);}
  RetTy visitCmpInst(CmpInst &I)                  { DELEGATE(Instruction);}
  RetTy visitTerminatorInst(TerminatorInst &I)    { DELEGATE(Instruction);}
  RetTy visitUnaryInstruction(UnaryInstruction &I){ DELEGATE(Instruction);}

                                                                          
                                                                                
                                 
  RetTy visitCallSite(CallSite CS) {
    assert(CS);
    Instruction &I = *CS.getInstruction();
    if (CS.isCall())
      DELEGATE(Instruction);

    assert(CS.isInvoke());
    DELEGATE(TerminatorInst);
  }

                                                                         
                                                                               
                                        
    
                                                                               
    
  void visitInstruction(Instruction &I) {}                                  

private:
                                                                       
  RetTy delegateCallInst(CallInst &I) {
    if (const Function *F = I.getCalledFunction()) {
      switch (F->getIntrinsicID()) {
      default:                     DELEGATE(IntrinsicInst);
      case Intrinsic::dbg_declare: DELEGATE(DbgDeclareInst);
      case Intrinsic::dbg_value:   DELEGATE(DbgValueInst);
      case Intrinsic::dbg_label:   DELEGATE(DbgLabelInst);
      case Intrinsic::memcpy:      DELEGATE(MemCpyInst);
      case Intrinsic::memmove:     DELEGATE(MemMoveInst);
      case Intrinsic::memset:      DELEGATE(MemSetInst);
      case Intrinsic::vastart:     DELEGATE(VAStartInst);
      case Intrinsic::vaend:       DELEGATE(VAEndInst);
      case Intrinsic::vacopy:      DELEGATE(VACopyInst);
      case Intrinsic::not_intrinsic: break;
      }
    }
    DELEGATE(CallInst);
  }

                                                                              
                                                                    
  RetTy delegateCallInst(Instruction &I) {
    llvm_unreachable("delegateCallInst called for non-CallInst");
  }
};

#undef DELEGATE

}                      

#endif
