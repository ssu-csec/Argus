/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_INTERPRETER_H
#define HERMES_VM_INTERPRETER_H
#include <cstdint>

#include "hermes/VM/Runtime.h"

class CodeBlock;

namespace hermes {
namespace vm {
                                                                               
                                                                        
            
class Interpreter {
 public:
                                                                       
                                                                                
  static CallResult<PseudoHandle<JSGenerator>> createGenerator_RJS(
      Runtime &runtime,
      RuntimeModule *runtimeModule,
      unsigned funcIndex,
      Handle<Environment> envHandle,
      NativeArgs args);

                                                             
                                                                              
                   
  static void saveGenerator(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      const Inst *resumeIP);

                                                  
                                                                          
                                                                               
                               
  static CallResult<Handle<Arguments>> reifyArgumentsSlowPath(
      Runtime &runtime,
      Handle<Callable> curFunction,
      bool strictMode);

                                                                       
     
                                                                             
                                                                               
                                                                           
           
                                 
                            
                               
                                                                              
                                                                           
                    
                                                                           
                         
                                                                             
          
                                                                       
                                       
                                                                          
                                                                          
                                           
  static CallResult<PseudoHandle<>> getArgumentsPropByValSlowPath_RJS(
      Runtime &runtime,
      PinnedHermesValue *lazyReg,
      PinnedHermesValue *valueReg,
      Handle<Callable> curFunction,
      bool strictMode);

                                                                               
                                                                           
                                                       
                                                                               
                           
                                                                   
                                                           
  static CallResult<PseudoHandle<>> handleCallSlowPath(
      Runtime &runtime,
      PinnedHermesValue *callTarget);

                                                                             
                     
                                                                            
                   
                                                                           
                                                             
  static PseudoHandle<>
  tryGetPrimitiveOwnPropertyById(Runtime &runtime, Handle<> base, SymbolID id);

                                                                          
  static CallResult<PseudoHandle<>>
  getByIdTransient_RJS(Runtime &runtime, Handle<> base, SymbolID id);

                                                                            
                                                           
                                                   
  static PseudoHandle<>
  getByValTransientFast(Runtime &runtime, Handle<> base, Handle<> nameHandle);

                                                                
  static CallResult<PseudoHandle<>>
  getByValTransient_RJS(Runtime &runtime, Handle<> base, Handle<> name);

                                                                          
  static ExecutionStatus putByIdTransient_RJS(
      Runtime &runtime,
      Handle<> base,
      SymbolID id,
      Handle<> value,
      bool strictMode);

                                                                
  static ExecutionStatus putByValTransient_RJS(
      Runtime &runtime,
      Handle<> base,
      Handle<> name,
      Handle<> value,
      bool strictMode);

                                                                              
                                                                              
                                                                       
                                                                               
                                                                               
                                                                             
                                                                              
                                                
  template <bool SingleStep, bool EnableCrashTrace>
  LLVM_ATTRIBUTE_NOINLINE static CallResult<HermesValue> interpretFunction(
      Runtime &runtime,
      InterpreterState &state);

                                                                     
                                                                        
                                                                        
                                                                        
                                                                           
  static CallResult<PseudoHandle<>> createObjectFromBuffer(
      Runtime &runtime,
      CodeBlock *curCodeBlock,
      unsigned numLiterals,
      unsigned keyBufferIndex,
      unsigned valBufferIndex);

                                                                   
                                                                        
                                                                 
                                                                           
  static CallResult<PseudoHandle<>> createArrayFromBuffer(
      Runtime &runtime,
      CodeBlock *curCodeBlock,
      unsigned numElements,
      unsigned numLiterals,
      unsigned bufferIndex);

                                                                         
                                                                       
               
  static ExecutionStatus declareGlobalVarImpl(
      Runtime &runtime,
      CodeBlock *curCodeBlock,
      const Inst *ip);

                                                            
                           
                                                                           
                                                          
  static ExecutionStatus throwIfHasRestrictedGlobalPropertyImpl(
      Runtime &runtime,
      CodeBlock *curCodeBlock,
      const Inst *ip);

#ifdef HERMES_ENABLE_DEBUGGER
                                                                        
                                                                            
                                                                                
                                                                              
                                                                               
                                                                          
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  static inline ExecutionStatus runDebuggerUpdatingState(
      Debugger::RunReason reason,
      Runtime &runtime,
      CodeBlock *&codeBlock,
      const Inst *&ip,
      PinnedHermesValue *&frameRegs) {
                                                                                
                                                                            
                                                                
    if (runtime.debugger_.isDebugging())
      return ExecutionStatus::RETURNED;
    uint32_t offset = codeBlock->getOffsetOf(ip);
    InterpreterState state(codeBlock, offset);
    ExecutionStatus status = runtime.debugger_.runDebugger(reason, state);
    codeBlock = state.codeBlock;
    ip = state.codeBlock->getOffsetPtr(state.offset);
    frameRegs = &runtime.currentFrame_.getFirstLocalRef();
    return status;
  }
#endif

                                                                               
                                                        

                                            
                                                                  
                                                                              
  static ExecutionStatus caseDirectEval(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      const inst::Inst *ip);

  static ExecutionStatus casePutOwnByVal(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      const inst::Inst *ip);

  static ExecutionStatus casePutOwnGetterSetterByVal(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      const inst::Inst *ip);

  static ExecutionStatus caseIteratorBegin(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      const inst::Inst *ip);
  static ExecutionStatus caseIteratorNext(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      const inst::Inst *ip);

  static ExecutionStatus caseGetPNameList(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      const Inst *ip);

                                                                              
                                                                              
                                                                             
          
  static ExecutionStatus implCallBuiltin(
      Runtime &runtime,
      PinnedHermesValue *frameRegs,
      CodeBlock *curCodeBlock,
      uint32_t op3);
};

#ifndef NDEBUG
                                                                           
                                                    
struct DumpHermesValue {
  const HermesValue hv;
  DumpHermesValue(HermesValue hv) : hv(hv) {}
};

llvh::raw_ostream &operator<<(llvh::raw_ostream &OS, DumpHermesValue dhv);

                                           
void dumpCallArguments(
    llvh::raw_ostream &OS,
    Runtime &runtime,
    StackFramePtr calleeFrame);

#endif

}                
}                    

#endif
