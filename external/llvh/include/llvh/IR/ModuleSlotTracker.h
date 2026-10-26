//===-- llvm/IR/ModuleSlotTracker.h -----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_MODULESLOTTRACKER_H
#define LLVM_IR_MODULESLOTTRACKER_H

#include <memory>

namespace llvh {

class Module;
class Function;
class SlotTracker;
class Value;

                                                      
   
                                                                            
                                                                             
                         
   
                                                                        
                                                                    
class ModuleSlotTracker {
                                 
  std::unique_ptr<SlotTracker> MachineStorage;
  bool ShouldCreateStorage = false;
  bool ShouldInitializeAllMetadata = false;

  const Module *M = nullptr;
  const Function *F = nullptr;
  SlotTracker *Machine = nullptr;

public:
                                        
  ModuleSlotTracker(SlotTracker &Machine, const Module *M,
                    const Function *F = nullptr);

                                             
     
                                                                              
                                                             
                                                                              
                                                                              
                   
  explicit ModuleSlotTracker(const Module *M,
                             bool ShouldInitializeAllMetadata = true);

                                     
  ~ModuleSlotTracker();

                                    
  SlotTracker *getMachine();

  const Module *getModule() const { return M; }
  const Function *getCurrentFunction() const { return F; }

                                     
     
                                                                              
                                                 
  void incorporateFunction(const Function &F);

                                                          
     
                                                                                
                  
                                                                  
  int getLocalSlot(const Value *V);
};

}                      

#endif
