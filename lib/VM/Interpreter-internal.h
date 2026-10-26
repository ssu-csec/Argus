/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_INTERPRETER_INTERNAL_H
#define HERMES_VM_INTERPRETER_INTERNAL_H

#include "hermes/VM/Interpreter.h"

                                            
#if !defined(__arm__) || !defined(__clang__) || \
    !defined(HERMESVM_ALLOW_INLINE_ASM)
#define REG(index) frameRegs[index]
#else
                                                                         
                                           
#define REG(index)                                                           \
  (*({                                                                       \
    PinnedHermesValue *addr;                                                 \
    static_assert(sizeof(PinnedHermesValue) == 8, "asm depends on HV size"); \
    static_assert(sizeof(index) <= 4, "index must fit in a register");       \
    asm("add.w   %0, %1, %2, lsl #3"                                         \
        : "=r"(addr)                                                         \
        : "r"(frameRegs), "r"(index));                                       \
    addr;                                                                    \
  }))
#endif
#define O1REG(name) REG(ip->i##name.op1)
#define O2REG(name) REG(ip->i##name.op2)
#define O3REG(name) REG(ip->i##name.op3)
#define O4REG(name) REG(ip->i##name.op4)
#define O5REG(name) REG(ip->i##name.op5)
#define O6REG(name) REG(ip->i##name.op6)

                                                   
#define FRAME StackFramePtr(frameRegs - StackFrameLayout::FirstLocal)

                                                                            
                 
#define DEFAULT_PROP_OP_FLAGS(strictMode) \
  (strictMode ? PropOpFlags().plusThrowOnError() : PropOpFlags())

                                                              
                                                         
#define ID(stringID) \
  (curCodeBlock->getRuntimeModule()->getSymbolIDMustExist(stringID))

                                      
#define IPADD(val) ((const Inst *)((const uint8_t *)ip + (val)))

                                   
#define CUROFFSET ((const uint8_t *)ip - (const uint8_t *)curCodeBlock->begin())

                                                                              
       
#define NEXTINST(name) ((const Inst *)(&ip->i##name + 1))

namespace hermes {
namespace vm {

                                           
double doDiv(double x, double y) LLVM_NO_SANITIZE("float-divide-by-zero");
inline double doDiv(double x, double y) {
                                                                         
                                                                        
                                                                         
                                             
  return x / y;
}

inline double doMod(double x, double y) {
                                                                         
                                                                              
                                                                          
                                                                
                                                                              
                                                                               
                                
  return std::fmod(x, y);
}

                                             
inline double doMul(double x, double y) {
  return x * y;
}

                                                  
inline double doSub(double x, double y) {
  return x - y;
}

inline int32_t doBitAnd(int32_t x, int32_t y) {
  return x & y;
}

inline int32_t doBitOr(int32_t x, int32_t y) {
  return x | y;
}

inline int32_t doBitXor(int32_t x, int32_t y) {
  return x ^ y;
}

inline int32_t doLShift(uint32_t x, uint32_t y) {
  return x << y;
}

inline int32_t doRShift(int32_t x, uint32_t y) {
  return x >> y;
}

inline uint32_t doURshift(uint32_t x, uint32_t y) {
  return x >> y;
}

inline double doInc(double d) {
  return d + 1;
}

inline double doDec(double d) {
  return d - 1;
}

template <auto Oper>
CallResult<HermesValue>
doOperSlowPath(Runtime &runtime, Handle<> lhs, Handle<> rhs);

template <auto Oper>
CallResult<HermesValue>
doBitOperSlowPath(Runtime &runtime, Handle<> lhs, Handle<> rhs);

template <auto Oper>
CallResult<HermesValue>
doShiftOperSlowPath(Runtime &runtime, Handle<> lhs, Handle<> rhs);

template <auto Oper>
CallResult<HermesValue> doIncDecOperSlowPath(Runtime &runtime, Handle<> src);

CallResult<HermesValue> doBitNotSlowPath(Runtime &runtime, Handle<> src);

CallResult<HermesValue> doNegateSlowPath(Runtime &runtime, Handle<> src);

}                
}                    
#endif                                    
