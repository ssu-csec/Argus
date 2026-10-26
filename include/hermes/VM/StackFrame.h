/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_STACKFRAME_H
#define HERMES_VM_STACKFRAME_H

#include "hermes/BCGen/HBC/StackFrameLayout.h"
#include "hermes/Support/Compiler.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/NativeArgs.h"

#include <iterator>
#include <type_traits>

namespace llvh {
class raw_ostream;
}

namespace hermes {
namespace inst {
struct Inst;
}
namespace vm {

class CodeBlock;

using hbc::StackFrameLayout;
using inst::Inst;

                                                                             
                                                                            
                                                                   
                                               
template <bool isConst>
class StackFramePtrT {
  using QualifiedHV = typename std::
      conditional<isConst, const PinnedHermesValue, PinnedHermesValue>::type;
  using QualifiedCB =
      typename std::conditional<isConst, const CodeBlock, CodeBlock>::type;

  QualifiedHV *frame_;

 public:
                                                  
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  explicit StackFramePtrT() : frame_(nullptr) {}
                                                                          
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  explicit StackFramePtrT(QualifiedHV *frame) : frame_(frame) {}

                                          
  template <
      bool isOtherConst,
      typename = typename std::enable_if<!isOtherConst && isConst>::type>
  StackFramePtrT(const StackFramePtrT<isOtherConst> &other)
      : frame_(other.ptr()){};

                                                    
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  explicit operator bool() const {
    return frame_;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE
  bool operator==(StackFramePtrT o) const {
    return frame_ == o.frame_;
  }
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  bool operator!=(StackFramePtrT o) const {
    return frame_ != o.frame_;
  }

                                                                               
                     
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  StackFramePtrT *operator->() {
    return this;
  }
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  const StackFramePtrT *operator->() const {
    return this;
  }

                                                                               
                                                           
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  QualifiedHV *ptr() const {
    return frame_;
  }

#define _HERMESVM_DEFINE_STACKFRAME_REF(name) \
  LLVM_ATTRIBUTE_ALWAYS_INLINE                \
  QualifiedHV &get##name##Ref() const {       \
    return frame_[StackFrameLayout::name];    \
  }

                                                                       
  _HERMESVM_DEFINE_STACKFRAME_REF(FirstLocal)
  _HERMESVM_DEFINE_STACKFRAME_REF(Scratch)
  _HERMESVM_DEFINE_STACKFRAME_REF(PreviousFrame)
  _HERMESVM_DEFINE_STACKFRAME_REF(SavedIP)
  _HERMESVM_DEFINE_STACKFRAME_REF(SavedCodeBlock)
  _HERMESVM_DEFINE_STACKFRAME_REF(ArgCount)
  _HERMESVM_DEFINE_STACKFRAME_REF(NewTarget)
  _HERMESVM_DEFINE_STACKFRAME_REF(CalleeClosureOrCB)
  _HERMESVM_DEFINE_STACKFRAME_REF(ThisArg)
  _HERMESVM_DEFINE_STACKFRAME_REF(FirstArg)

#undef _HERMESVM_DEFINE_STACKFRAME_REF

                                                                          
            
  QualifiedHV *getPreviousFramePointer() const {
    return getPreviousFrameRef().template getNativePointer<PinnedHermesValue>();
  }

                                       
  StackFramePtrT<isConst> getPreviousFrame() const {
    return StackFramePtrT<isConst>{getPreviousFramePointer()};
  }

                                                                               
                                                      
  const Inst *getSavedIP() const {
    return getSavedIPRef().template getNativePointer<const Inst>();
  }

                                                                              
                                                              
  QualifiedCB *getSavedCodeBlock() const {
    return getSavedCodeBlockRef().template getNativePointer<CodeBlock>();
  }

                                                                               
                
  uint32_t getArgCount() const {
    return getArgCountRef().getNativeUInt32();
  }

                                                                               
                                                                            
                       
  void setArgCount(uint32_t argCount) const {
    getArgCountRef() = HermesValue::encodeNativeUInt32(argCount);
  }

                                                                              
                                                                      
                  
  inline Callable *getCalleeClosureUnsafe() const;

                                                                         
                                                                      
                  
  inline Handle<Callable> getCalleeClosureHandleUnsafe() const;

                                                                             
                                                                              
                     
  QualifiedCB *getCalleeCodeBlock(Runtime &runtime) const;

                                                                    
  bool isConstructorCall() const {
    return !getNewTargetRef().isUndefined();
  }

                                                                  
  ArgIteratorT<isConst> argsBegin() const {
    return ArgIteratorT<isConst>(&getThisArgRef());
  }

                                                                             
                                                                             
                                                        
  QualifiedHV &getArgRef(int32_t n) const {
    assert(n >= -1 && n < (int64_t)getArgCount() && "invalid argument index");
    return argsBegin()[n];
  }

                                                                             
                    
  QualifiedHV &getArgRefUnsafe(int32_t n) const {
    return argsBegin()[n];
  }

                                                      
                                                                            
                                                                               
                                                                         
                                        
                                                                           
                                  
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  static StackFramePtrT<false> initFrame(
      PinnedHermesValue *stackPointer,
      StackFramePtrT previousFrame,
      const Inst *savedIP,
      const CodeBlock *savedCodeBlock,
      uint32_t argCount,
      HermesValue calleeClosureOrCB,
      HermesValue newTarget) {
    stackPointer[StackFrameLayout::PreviousFrame] =
        HermesValue::encodeNativePointer(previousFrame.ptr());
    stackPointer[StackFrameLayout::SavedIP] =
        HermesValue::encodeNativePointer(savedIP);
    stackPointer[StackFrameLayout::SavedCodeBlock] =
        HermesValue::encodeNativePointer(savedCodeBlock);
    stackPointer[StackFrameLayout::ArgCount] =
        HermesValue::encodeNativeUInt32(argCount);
    stackPointer[StackFrameLayout::NewTarget] = newTarget;
    stackPointer[StackFrameLayout::CalleeClosureOrCB] = calleeClosureOrCB;

    return StackFramePtrT<false>{stackPointer};
  }

                                                      
  LLVM_ATTRIBUTE_ALWAYS_INLINE
  static StackFramePtrT<false> initFrame(
      PinnedHermesValue *stackPointer,
      StackFramePtrT previousFrame,
      const Inst *savedIP,
      const CodeBlock *savedCodeBlock,
      uint32_t argCount,
      Callable *calleeClosure,
      bool construct) {
    return initFrame(
        stackPointer,
        previousFrame,
        savedIP,
        savedCodeBlock,
        argCount,
        HermesValue::encodeObjectValue(calleeClosure),
        construct ? HermesValue::encodeObjectValue(calleeClosure)
                  : HermesValue::encodeUndefinedValue());
  }

                                                                        
            
  NativeArgs getNativeArgs() const {
    return NativeArgs{argsBegin(), getArgCount(), &getNewTargetRef()};
  }
};

using StackFramePtr = StackFramePtrT<false>;
using ConstStackFramePtr = StackFramePtrT<true>;

                                                             
                                                                          
                                                                  
void dumpStackFrame(
    ConstStackFramePtr frame,
    llvh::raw_ostream &OS,
    const PinnedHermesValue *next = nullptr);

                                                      
void dumpStackFrame(ConstStackFramePtr frame);
                                                                            
                                                
void dumpStackFrame(StackFramePtr frame);

static_assert(
    std::is_trivially_copyable<StackFramePtr>::value,
    "StackFramePtr must be trivially copyable");
static_assert(
    std::is_trivially_copyable<ConstStackFramePtr>::value,
    "ConstStackFramePtr must be trivially copyable");

                                                                         
          
template <bool isConst>
class StackFrameIteratorT {
  using QualifiedHV = typename std::
      conditional<isConst, const PinnedHermesValue, PinnedHermesValue>::type;

  StackFramePtrT<isConst> frame_;

 public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = StackFramePtrT<isConst>;
  using difference_type = int32_t;
  using pointer = StackFramePtrT<isConst>;
  using reference = StackFramePtrT<isConst>;

                                                                              
                                                        
  StackFrameIteratorT() : frame_() {}

  StackFrameIteratorT(QualifiedHV *frame) : frame_(frame) {}

  StackFrameIteratorT(StackFramePtrT<isConst> frame) : frame_(frame) {}

                                          
  template <
      bool isOtherConst,
      typename = typename std::enable_if<!isOtherConst && isConst>::type>
  StackFrameIteratorT(const StackFrameIteratorT<isOtherConst> &other)
      : frame_(other.operator->()){};

                                                                   
  explicit operator bool() const {
    return frame_;
  }

  bool operator==(StackFrameIteratorT o) const {
    return frame_ == o.frame_;
  }
  bool operator!=(StackFrameIteratorT o) const {
    return frame_ != o.frame_;
  }

  StackFrameIteratorT &operator++() {
    frame_ = frame_.getPreviousFrame();
    return *this;
  }
  StackFrameIteratorT operator++(int) {
    auto res = *this;
    frame_ = frame_.getPreviousFrame();
    return res;
  }

  StackFramePtrT<isConst> operator->() const {
    return frame_;
  }
  StackFramePtrT<isConst> operator*() const {
    return frame_;
  }
};

using StackFrameIterator = StackFrameIteratorT<false>;
using ConstStackFrameIterator = StackFrameIteratorT<true>;

static_assert(
    std::is_trivially_copyable<StackFrameIterator>::value,
    "StackFrameIterator must be trivially copyable");
static_assert(
    std::is_trivially_copyable<ConstStackFrameIterator>::value,
    "ConstStackFrameIterator must be trivially copyable");

}                
}                    

#endif                          
