/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_CALLABLE_H
#define HERMES_VM_CALLABLE_H

#include "hermes/VM/ArrayStorage.h"
#include "hermes/VM/Domain.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/NativeArgs.h"
#include "hermes/VM/Runtime-inline.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                              
class Environment final
    : public VariableSizeRuntimeCell,
      private llvh::TrailingObjects<Environment, GCHermesValue> {
  friend TrailingObjects;
  friend void EnvironmentBuildMeta(const GCCell *cell, Metadata::Builder &mb);

                                                                       
                                 
  GCPointer<Environment> parentEnvironment_{};

                                           
  AtomicIfConcurrentGC<uint32_t> size_;

 public:
  static const VTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::EnvironmentKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::EnvironmentKind;
  }

                               
  static HermesValue create(
      Runtime &runtime,
      Handle<Environment> parentEnvironment,
      uint32_t size) {
    auto *cell = runtime.makeAVariable<Environment>(
        allocationSize(size), runtime, parentEnvironment, size);
    return HermesValue::encodeObjectValue(cell);
  }

                                                                               
                                 
  Environment *getParentEnvironment(Runtime &runtime) const {
    return parentEnvironment_.get(runtime);
  }

                                                                  
  uint32_t getSize() const {
    return size_.load(std::memory_order_relaxed);
  }

  GCHermesValue &slot(uint32_t index) {
    assert(index < getSize() && "invalid Environment slot index");
    return getSlots()[index];
  }

                                                                         
  static uint32_t allocationSize(uint32_t size) {
    return totalSizeToAlloc<GCHermesValue>(size);
  }

 public:
                                                                                
                                   
                                                           
  Environment(
      Runtime &runtime,
      Handle<Environment> parentEnvironment,
      uint32_t size)
      : parentEnvironment_(runtime, parentEnvironment.get(), runtime.getHeap()),
        size_(size) {
                                           
    GCHermesValue::uninitialized_fill(
        getSlots(),
        getSlots() + size,
        HermesValue::encodeUndefinedValue(),
        runtime.getHeap());
  }

 private:
                                                    
  GCHermesValue *getSlots() {
    return getTrailingObjects<GCHermesValue>();
  }
  const GCHermesValue *getSlots() const {
    return getTrailingObjects<GCHermesValue>();
  }
};

struct CallableVTable : public ObjectVTable {
                                                                           
                                                                         
                                          
  CallResult<PseudoHandle<JSObject>> (*newObject)(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<JSObject> parentHandle);

                                                            
  CallResult<PseudoHandle<>> (
      *call)(Handle<Callable> selfHandle, Runtime &runtime);
};

                                                                            
                                                                               
                                                                    
                          
class Callable : public JSObject {
  using Super = JSObject;
  friend void CallableBuildMeta(const GCCell *cell, Metadata::Builder &mb);

                                                                     
  GCPointer<Environment> environment_{};

 public:
  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::CallableKind_first,
        CellKind::CallableKind_last);
  }

  const CallableVTable *getVT() const {
    return static_cast<const CallableVTable *>(GCCell::getVT());
  }

                                                            
  Environment *getEnvironment(Runtime &runtime) const {
    return environment_.get(runtime);
  }

  enum class WritablePrototype : uint8_t { No = 0, Yes = 1 };

                                                                             
                                                       
                                                                           
                                          
                                                              
                                                                             
                                                                            
                             
                                                        
                                 
                                                           
                                                                
                                                                             
                                            
                                                                       
                                                            
  static ExecutionStatus defineNameLengthAndPrototype(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      SymbolID name,
      unsigned paramCount,
      Handle<JSObject> prototypeObjectHandle,
      WritablePrototype writablePrototype,
      bool strictMode);

                                                                         
                                                                     
  static CallResult<PseudoHandle<>> executeCall0(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<> thisArgHandle,
      bool construct = false);

                                                                         
                                                                     
  static CallResult<PseudoHandle<>> executeCall1(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<> thisArgHandle,
      HermesValue param1,
      bool construct = false);

                                                                          
                                                                     
  static CallResult<PseudoHandle<>> executeCall2(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<> thisArgHandle,
      HermesValue param1,
      HermesValue param2,
      bool construct = false);

                                                                            
                                                                     
  static CallResult<PseudoHandle<>> executeCall3(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<> thisArgHandle,
      HermesValue param1,
      HermesValue param2,
      HermesValue param3,
      bool construct = false);

                                                                           
                                                                     
  static CallResult<PseudoHandle<>> executeCall4(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<> thisArgHandle,
      HermesValue param1,
      HermesValue param2,
      HermesValue param3,
      HermesValue param4,
      bool construct = false);

                                                                
                                                                      
                                  
  static CallResult<PseudoHandle<>> executeCall(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<> newTarget,
      Handle<> thisArgument,
      Handle<JSObject> arrayLike);

                                      
  static CallResult<PseudoHandle<JSObject>> newObject(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<JSObject> parentHandle) {
    return selfHandle->getVT()->newObject(selfHandle, runtime, parentHandle);
  }

                                 
  static CallResult<PseudoHandle<>> call(
      Handle<Callable> selfHandle,
      Runtime &runtime) {
                                                                      
                                                                               
            
    runtime.potentiallyMoveHeap();
    return selfHandle->getVT()->call(selfHandle, runtime);
  }

                                                                              
                                                                              
                                                        
  static CallResult<PseudoHandle<>>
  construct(Handle<Callable> selfHandle, Runtime &runtime, Handle<> thisVal) {
    auto result = call(selfHandle, runtime);
    if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return (*result)->isObject()
        ? std::move(result)
        : CallResult<PseudoHandle<>>{PseudoHandle<>(thisVal)};
  }

                                                                        
                                                    
                                                                            
  static CallResult<PseudoHandle<>> executeConstruct0(
      Handle<Callable> selfHandle,
      Runtime &runtime);

                                                                        
                                                    
                                                                            
                                                          
  static CallResult<PseudoHandle<>> executeConstruct1(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<> param1);

                                                                             
                                                                               
                         
                                      
  static CallResult<double> extractOwnLengthProperty_RJS(
      Handle<Callable> selfHandle,
      Runtime &runtime);

                                                                        
                                                
  static void defineLazyProperties(Handle<Callable> fn, Runtime &runtime);

                                                             
                                                                     
                                           
                                                            
                                                    
                                                                     
  static CallResult<PseudoHandle<>> createThisForConstruct_RJS(
      Handle<Callable> selfHandle,
      Runtime &runtime);

                                                                           
                                                                   
  static CallResult<PseudoHandle<>> prepareThisForConstruct_RJS(
      Handle<Callable> selfHandle, Runtime &runtime, Handle<Callable> newTarget);

 protected:
  Callable(
      Runtime &runtime,
      JSObject *parent,
      HiddenClass *clazz,
      Handle<Environment> env)
      : JSObject(runtime, parent, clazz),
        environment_(runtime, *env, runtime.getHeap()) {}
  Callable(Runtime &runtime, JSObject *parent, HiddenClass *clazz)
      : JSObject(runtime, parent, clazz), environment_() {}

#ifdef HERMES_MEMORY_INSTRUMENTATION
  static std::string _snapshotNameImpl(GCCell *cell, GC &gc);
#endif

                                                                             
                               
  static CallResult<PseudoHandle<JSObject>> _newObjectImpl(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<JSObject> parentHandle);
};

                                                                            
                                           
class BoundFunction final : public Callable {
  friend void BoundFunctionBuildMeta(const GCCell *cell, Metadata::Builder &mb);

                                  
  GCPointer<Callable> target_;

                                
  GCPointer<ArrayStorage> argStorage_;

 public:
  using Super = Callable;
  static const CallableVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::BoundFunctionKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::BoundFunctionKind;
  }

                                  
  Callable *getTarget(Runtime &runtime) const {
    return target_.get(runtime);
  }

                                                                          
                                        
                                                                               
                                              
                                                            
  static CallResult<HermesValue> create(
      Runtime &runtime,
      Handle<Callable> target,
      unsigned argCountWithThis,
      ConstArgIterator argsWithThis);

                                                                              
                                                                          
                                                             
                                                                             
                    
  static CallResult<PseudoHandle<>>
  _boundCall(BoundFunction *self, const Inst *ip, Runtime &runtime);

                                                                           
               
  static ExecutionStatus initializeLengthAndName_RJS(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<Callable> target,
      unsigned argCount);

                                                                  
  unsigned getArgCountWithThis(Runtime &runtime) const {
    return argStorage_.getNonNull(runtime)->size();
  }

 public:
  BoundFunction(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<Callable> target,
      Handle<ArrayStorage> argStorage)
      : Callable(runtime, *parent, *clazz),
        target_(runtime, *target, runtime.getHeap()),
        argStorage_(runtime, *argStorage, runtime.getHeap()) {}

 private:
                                                                             
                                       
  GCHermesValue *getArgsWithThis(Runtime &runtime) {
    return argStorage_.getNonNull(runtime)->begin();
  }

                                                                   
  static CallResult<PseudoHandle<JSObject>> _newObjectImpl_RJS(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<JSObject> parentHandle);

                                                            
  static CallResult<PseudoHandle<>> _callImpl(
      Handle<Callable> selfHandle,
      Runtime &runtime);
};

                                 
typedef CallResult<HermesValue> (
    *NativeFunctionPtr)(void *context, Runtime &runtime, NativeArgs args);

                                                                         
                                         
class NativeFunction : public Callable {
 protected:
                                                  
  void *const context_;
                                 
  const NativeFunctionPtr functionPtr_;

#ifdef HERMESVM_PROFILER_NATIVECALL
                                             
  uint32_t callCount_{0};
                                  
  uint64_t callDuration_{0};
#endif

 public:
  using Super = Callable;
  static const CallableVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::NativeFunctionKind;
  }
  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::NativeFunctionKind_first,
        CellKind::NativeFunctionKind_last);
  }

  void *getContext() const {
    return context_;
  }

  NativeFunctionPtr getFunctionPtr() const {
    return functionPtr_;
  }

#ifdef HERMESVM_PROFILER_NATIVECALL
  uint32_t getCallCount() const {
    return callCount_;
  }
  uint32_t getCallDuration() const {
    return callDuration_;
  }
#else
  uint32_t getCallCount() const {
    return 0;
  }
  uint32_t getCallDuration() const {
    return 0;
  }
#endif

                                                                              
                                                                          
             
  static CallResult<PseudoHandle<>> _nativeCall(
      NativeFunction *self,
      Runtime &runtime) {
    ScopedNativeDepthTracker depthTracker{runtime};
    if (LLVM_UNLIKELY(depthTracker.overflowed())) {
      return runtime.raiseStackOverflow(
          Runtime::StackOverflowKind::NativeStack);
    }

    auto newFrame = runtime.setCurrentFrameToTopOfStack();
    runtime.saveCallerIPInStackFrame();
                                                          
    if (LLVM_UNLIKELY(!runtime.checkAndAllocStack(
            StackFrameLayout::CalleeExtraRegistersAtStart,
            HermesValue::encodeUndefinedValue()))) {
                                                       
      runtime.restoreStackAndPreviousFrame(newFrame);
      return runtime.raiseStackOverflow(
          Runtime::StackOverflowKind::JSRegisterStack);
    }

#ifdef HERMESVM_PROFILER_NATIVECALL
    auto t1 = HERMESVM_RDTSC();
#endif

    auto res =
        self->functionPtr_(self->context_, runtime, newFrame.getNativeArgs());

#ifdef HERMESVM_PROFILER_NATIVECALL
    self->callDuration_ = HERMESVM_RDTSC() - t1;
    ++self->callCount_;
#endif
    runtime.restoreStackAndPreviousFrame(newFrame);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return createPseudoHandle(*res);
  }

                                           
                                                         
                                                             
                                            
                                                    
                                                               
                                                                          
                                                                     
                                
  static Handle<NativeFunction> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle,
      void *context,
      NativeFunctionPtr functionPtr,
      SymbolID name,
      unsigned paramCount,
      Handle<JSObject> prototypeObjectHandle,
      unsigned additionalSlotCount = 0);

                                           
                                                         
                                                   
                                                             
                                            
                                                    
                                                               
                                                                          
                                                                     
                                
  static Handle<NativeFunction> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle,
      Handle<Environment> parentEnvHandle,
      void *context,
      NativeFunctionPtr functionPtr,
      SymbolID name,
      unsigned paramCount,
      Handle<JSObject> prototypeObjectHandle,
      unsigned additionalSlotCount = 0);

                                           
                                          
                                                         
                                                             
                                            
                                                    
                                                               
                                                                     
                                
  static Handle<NativeFunction> createWithoutPrototype(
      Runtime &runtime,
      Handle<JSObject> parentHandle,
      void *context,
      NativeFunctionPtr functionPtr,
      SymbolID name,
      unsigned paramCount,
      unsigned additionalSlotCount = 0) {
    return create(
        runtime,
        parentHandle,
        context,
        functionPtr,
        name,
        paramCount,
        runtime.makeNullHandle<JSObject>(),
        additionalSlotCount);
  }

                                          
                                                   
                                         
                                                             
                                            
                                                    
                                                               
                                                                     
                                
  static Handle<NativeFunction> createWithoutPrototype(
      Runtime &runtime,
      void *context,
      NativeFunctionPtr functionPtr,
      SymbolID name,
      unsigned paramCount,
      unsigned additionalSlotCount = 0) {
    return createWithoutPrototype(
        runtime,
        Handle<JSObject>::vmcast(&runtime.functionPrototype),
        context,
        functionPtr,
        name,
        paramCount,
        additionalSlotCount);
  }

                                              
                                                                         
                        
  static SmallHermesValue getAdditionalSlotValue(
      NativeFunction *self,
      Runtime &runtime,
      unsigned index) {
    return JSObject::getInternalProperty(
        self, runtime, numOverlapSlots<NativeFunction>() + index);
  }

                                          
                                                                         
                        
  static void setAdditionalSlotValue(
      NativeFunction *self,
      Runtime &runtime,
      unsigned index,
      SmallHermesValue value) {
    JSObject::setInternalProperty(
        self, runtime, numOverlapSlots<NativeFunction>() + index, value);
  }

 public:
  NativeFunction(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      void *context,
      NativeFunctionPtr functionPtr)
      : Callable(runtime, *parent, *clazz),
        context_(context),
        functionPtr_(functionPtr) {}
  NativeFunction(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<Environment> environment,
      void *context,
      NativeFunctionPtr functionPtr)
      : Callable(runtime, *parent, *clazz, environment),
        context_(context),
        functionPtr_(functionPtr) {}

 protected:
#ifdef HERMES_MEMORY_INSTRUMENTATION
  static std::string _snapshotNameImpl(GCCell *cell, GC &gc);
#endif

                                                                   
  static CallResult<PseudoHandle<>> _callImpl(
      Handle<Callable> selfHandle,
      Runtime &runtime);

                                                                          
                          
                                                                         
                                                        
  static CallResult<PseudoHandle<JSObject>>
  _newObjectImpl(Handle<Callable>, Runtime &runtime, Handle<JSObject>);
};

                                                                              
           
class NativeConstructor final : public NativeFunction {
 public:
                                                                              
                                
                                                                                
                                              
                                                                          
  using CreatorFunction = CallResult<PseudoHandle<JSObject>>(
      Runtime &,
      Handle<JSObject> proto,
      void *context);

                                                                      
                               
                                                                      
                                                  
  template <class NativeClass>
  static CallResult<PseudoHandle<JSObject>>
  creatorFunction(Runtime &runtime, Handle<JSObject> prototype, void *context);

  static const CallableVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::NativeConstructorKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::NativeConstructorKind;
  }

                                              
                                                                               
                                                                                
                                                                            
                                            
                                                               
                                                                              
                               
                                                                        
                 
  static PseudoHandle<NativeConstructor> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle,
      void *context,
      NativeFunctionPtr functionPtr,
      unsigned paramCount,
      CreatorFunction *creator,
      CellKind targetKind) {
    auto *cell = runtime.makeAFixed<NativeConstructor>(
        runtime,
        parentHandle,
        runtime.getHiddenClassForPrototype(
            *parentHandle, numOverlapSlots<NativeConstructor>()),
        context,
        functionPtr,
        creator,
        targetKind);
    return JSObjectInit::initToPseudoHandle(runtime, cell);
  }

                                              
                                                         
                                                   
                                                             
                                            
  static PseudoHandle<NativeConstructor> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle,
      Handle<Environment> parentEnvHandle,
      void *context,
      NativeFunctionPtr functionPtr,
      CreatorFunction *creator,
      CellKind targetKind) {
    auto *cell = runtime.makeAFixed<NativeConstructor>(
        runtime,
        parentHandle,
        runtime.getHiddenClassForPrototype(
            *parentHandle, numOverlapSlots<NativeConstructor>()),
        parentEnvHandle,
        context,
        functionPtr,
        creator,
        targetKind);
    return JSObjectInit::initToPseudoHandle(runtime, cell);
  }

 private:
#ifndef NDEBUG
                                                             
  const CellKind targetKind_;
#endif

                                                               
                                                                         
  CreatorFunction *const creator_;

 public:
  NativeConstructor(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      void *context,
      NativeFunctionPtr functionPtr,
      CreatorFunction *creator,
      CellKind targetKind)
      : NativeFunction(runtime, parent, clazz, context, functionPtr),
#ifndef NDEBUG
        targetKind_(targetKind),
#endif
        creator_(creator) {
  }

  NativeConstructor(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<Environment> parentEnvHandle,
      void *context,
      NativeFunctionPtr functionPtr,
      CreatorFunction *creator,
      CellKind targetKind)
      : NativeFunction(
            runtime,
            parent,
            clazz,
            parentEnvHandle,
            context,
            functionPtr),
#ifndef NDEBUG
        targetKind_(targetKind),
#endif
        creator_(creator) {
  }

 private:
                                                                            
                                                    
  static CallResult<PseudoHandle<JSObject>> _newObjectImpl(
      Handle<Callable> selfHandle,
      Runtime &runtime,
      Handle<JSObject> parentHandle) {
    auto nativeConsHandle = Handle<NativeConstructor>::vmcast(selfHandle);
    return nativeConsHandle->creator_(
        runtime, parentHandle, nativeConsHandle->getContext());
  }

#ifndef NDEBUG
                                                                            
                          
  static CallResult<PseudoHandle<>> _callImpl(
      Handle<Callable> selfHandle,
      Runtime &runtime);
#endif
};

                                                      
class JSFunction : public Callable {
  using Super = Callable;
  friend void JSFunctionBuildMeta(const GCCell *cell, Metadata::Builder &mb);

                                       
  XorPtr<CodeBlock, XorPtrKeyID::JSFunctionCodeBlock> codeBlock_;

  static constexpr auto kHasFinalizer = HasFinalizer::No;

                                                
  GCPointer<Domain> domain_;

 public:
  JSFunction(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<Environment> environment,
      CodeBlock *codeBlock)
      : Callable(runtime, *parent, *clazz, environment),
        codeBlock_(runtime, codeBlock),
        domain_(runtime, *domain, runtime.getHeap()) {
    assert(
        !vt.finalize_ == (kHasFinalizer != HasFinalizer::Yes) &&
        "kHasFinalizer invalid value");
  }

 public:
  static const CallableVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSFunctionKind;
  }
  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::CodeBlockFunctionKind_first,
        CellKind::CodeBlockFunctionKind_last);
  }

                                                                        
  static PseudoHandle<JSFunction> create(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parentHandle,
      Handle<Environment> envHandle,
      CodeBlock *codeBlock);

                                                                            
                                                                              
  static PseudoHandle<JSFunction> create(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parentHandle) {
    return create(
        runtime,
        domain,
        parentHandle,
        Runtime::makeNullHandle<Environment>(),
        runtime.getEmptyCodeBlock());
  }

                                                                            
                                                                              
  static PseudoHandle<JSFunction> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle) {
    return create(
        runtime, runtime.makeHandle(Domain::create(runtime)), parentHandle);
  }

                                                          
  CodeBlock *getCodeBlock(Runtime &runtime) const {
    return codeBlock_.get(runtime);
  }

  RuntimeModule *getRuntimeModule(Runtime &runtime) const {
    return getCodeBlock(runtime)->getRuntimeModule();
  }

                                                              
                                                    
                                                            
  void addLocationToSnapshot(
      HeapSnapshot &snap,
      HeapSnapshot::NodeID id,
      GC &gc) const;

 protected:
                                                                       
  static CallResult<PseudoHandle<>> _callImpl(
      Handle<Callable> selfHandle,
      Runtime &runtime);

#ifdef HERMES_MEMORY_INSTRUMENTATION
  static std::string _snapshotNameImpl(GCCell *cell, GC &gc);
  static void
  _snapshotAddLocationsImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif
};

                                                                              
                                                                       
               
class JSAsyncFunction final : public JSFunction {
  using Super = JSFunction;

  static constexpr auto kHasFinalizer = HasFinalizer::No;

 public:
  static const CallableVTable vt;

                             
  static PseudoHandle<JSAsyncFunction> create(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parentHandle,
      Handle<Environment> envHandle,
      CodeBlock *codeBlock);

                                                                       
                                                                              
               
  static PseudoHandle<JSAsyncFunction> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle) {
    return create(
        runtime,
        runtime.makeHandle(Domain::create(runtime)),
        parentHandle,
        runtime.makeNullHandle<Environment>(),
        runtime.getEmptyCodeBlock());
  }

  static constexpr CellKind getCellKind() {
    return CellKind::JSAsyncFunctionKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSAsyncFunctionKind;
  }

  JSAsyncFunction(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<Environment> environment,
      CodeBlock *codeBlock)
      : Super(runtime, domain, parent, clazz, environment, codeBlock) {
    assert(
        !vt.finalize_ == (kHasFinalizer != HasFinalizer::Yes) &&
        "kHasFinalizer invalid value");
  }
};

                                                                         
                                                                       
               
class JSGeneratorFunction final : public JSFunction {
  using Super = JSFunction;

  static constexpr auto kHasFinalizer = HasFinalizer::No;

 public:
  static const CallableVTable vt;

                                 
  static PseudoHandle<JSGeneratorFunction> create(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parentHandle,
      Handle<Environment> envHandle,
      CodeBlock *codeBlock);

                                                                           
                                                                              
               
  static PseudoHandle<JSGeneratorFunction> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle) {
    return create(
        runtime,
        runtime.makeHandle(Domain::create(runtime)),
        parentHandle,
        runtime.makeNullHandle<Environment>(),
        runtime.getEmptyCodeBlock());
  }

  static constexpr CellKind getCellKind() {
    return CellKind::JSGeneratorFunctionKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSGeneratorFunctionKind;
  }

 public:
  JSGeneratorFunction(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<Environment> environment,
      CodeBlock *codeBlock)
      : Super(runtime, domain, parent, clazz, environment, codeBlock) {
    assert(
        !vt.finalize_ == (kHasFinalizer != HasFinalizer::Yes) &&
        "kHasFinalizer invalid value");
  }
};

                                                                          
                                                                       
                      
                                                                        
                                                                       
                                             
                                                                           
                                                            
                                                              
                        
                                                                 
                                                         
                                                                 
                                                               
                                                                          
                                              
                                                                             
                                                              
class GeneratorInnerFunction final : public JSFunction {
  using Super = JSFunction;
  friend void GeneratorInnerFunctionBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

  static constexpr auto kHasFinalizer = HasFinalizer::No;

 public:
  static const CallableVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::GeneratorInnerFunctionKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::GeneratorInnerFunctionKind;
  }

                                   
                   
  enum class State {
    SuspendedStart,
    SuspendedYield,
    Executing,
    Completed,
  };

                                                                       
  enum class Action {
    Next,
    Throw,
    Return,
  };

  static CallResult<Handle<GeneratorInnerFunction>> create(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parentHandle,
      Handle<Environment> envHandle,
      CodeBlock *codeBlock,
      NativeArgs args);

                                                                          
                                                                                
                                                                           
                                                                             
                                                                       
               
  static CallResult<PseudoHandle<>> callInnerFunction(
      Handle<GeneratorInnerFunction> selfHandle,
      Runtime &runtime,
      Handle<> arg,
      Action action);

                                                                             
                               
  static CallResult<PseudoHandle<>> _callImpl(
      Handle<Callable> selfHandle,
      Runtime &runtime) {
    return runtime.raiseTypeError(
        "Generator inner functions may not be called directly by user code");
  }

  void setState(State state) {
    assert(
        state_ != State::Completed && "Cannot leave completed generator state");
    state_ = state;
  }

  State getState() const {
    return state_;
  }

  void setAction(Action action) {
    action_ = action;
  }

  Action getAction() const {
    return action_;
  }

                                                             
                                                                            
  void clearResult(Runtime &runtime) {
    result_.setNonPtr(SmallHermesValue::encodeEmptyValue(), runtime.getHeap());
  }

  SmallHermesValue getResult() const {
    return result_;
  }

  bool isDelegated() const {
    return isDelegated_;
  }

  void setIsDelegated(bool isDelegated) {
    isDelegated_ = isDelegated;
  }

                                                                    
                           
  void restoreStack(Runtime &runtime);

                                                                                
                                                     
  void saveStack(Runtime &runtime);

  void setNextIP(Runtime &runtime, const Inst *ip) {
    nextIPOffset_ = getCodeBlock(runtime)->getOffsetOf(ip);
  }

  const Inst *getNextIP(Runtime &runtime) const {
    return getCodeBlock(runtime)->getOffsetPtr(nextIPOffset_);
  }

 public:
  GeneratorInnerFunction(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<Environment> environment,
      CodeBlock *codeBlock,
      uint32_t argCount)
      : JSFunction(runtime, domain, parent, clazz, environment, codeBlock),
        argCount_(argCount) {
    assert(
        !vt.finalize_ == (kHasFinalizer != HasFinalizer::Yes) &&
        "kHasFinalizer invalid value");
  }

 private:
                                         
  State state_{State::SuspendedStart};

                                                                              
                
                                                      
  uint32_t argCount_;

                                                                                
                                                                      
                                                                             
  GCPointer<ArrayStorage> savedContext_{nullptr};

                                                                          
                                                         
  GCSmallHermesValue result_{};

                                                                        
                                                     
                                                                  
  uint32_t nextIPOffset_{0};

                                                                           
  Action action_;

                                                                             
                                                           
  bool isDelegated_{false};

 private:
                                                                       
                                         
                                                                                
  static uint32_t getContextSize(CodeBlock *codeBlock, uint32_t argCount) {
                                                                               
                                    
    const uint32_t frameSize = codeBlock->getFrameSize() +
        StackFrameLayout::CalleeExtraRegistersAtStart;

                                                 
               
                         
                    
    return 1 + argCount + frameSize;
  }

                                                                      
  uint32_t getFrameOffsetInContext() const {
                                   
    return 1 + argCount_;
  }

                                                                  
  uint32_t getFrameSizeInContext(Runtime &runtime) const {
    uint32_t frameOffset = getFrameOffsetInContext();
    return savedContext_.getNonNull(runtime)->size() - frameOffset;
  }
};

}                
}                    
#pragma GCC diagnostic pop

#endif                        
