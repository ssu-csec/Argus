/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_HANDLEROOTOWNER_H
#define HERMES_VM_HANDLEROOTOWNER_H

#include "hermes/VM/Casting.h"
#include "hermes/VM/GCDecl.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/HermesValueTraits.h"
#include "hermes/VM/SymbolID.h"

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                        
class GCScope;
class HandleBase;
template <typename T>
class Handle;
template <typename T>
class MutableHandle;

#ifndef HERMESVM_DEBUG_MAX_GCSCOPE_HANDLES
                                                                                
                                                                            
                                                             
#define HERMESVM_DEBUG_MAX_GCSCOPE_HANDLES 48
#endif

                                                                       
                                                
                                               

                                           
#if defined(NDEBUG) && defined(HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES)
#undef HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES
#endif

                                                                        
                                                       
                                                                    
class HandleRootOwner {
 public:
                                                                             
                                                                    
                        
                                                                         
                                                                          
                                                                          
  virtual ~HandleRootOwner() = default;

                                              
  Handle<HermesValue> makeHandle(HermesValue value);

                                                             
  template <class T>
  Handle<T> makeHandle(T *p);

                                                                      
  template <class T>
  Handle<T> makeHandle(HermesValue value);

                                                        
  Handle<SymbolID> makeHandle(SymbolID value);

                                                                          
  template <class T>
  Handle<T> makeHandle(PseudoHandle<T> &&pseudo);

                                                                             
                                                   
  template <class T>
  Handle<T> makeHandle(PseudoHandle<HermesValue> &&pseudo);

                                                     
  MutableHandle<HermesValue> makeMutableHandle(HermesValue value);
                                                                    
  template <class T>
  MutableHandle<T> makeMutableHandle(T *p);

                                                                            
                                                         
  template <class T>
  static Handle<T> makeNullHandle();

                                                                        
  static Handle<HermesValue> getUndefinedValue();

                                                                   
  static Handle<HermesValue> getNullValue();

                                                                    
  static Handle<HermesValue> getEmptyValue();

                                                                    
  static Handle<HermesValue> getBoolValue(bool b);

                                                                
  static Handle<HermesValue> getZeroValue();

                                                                
  static Handle<HermesValue> getOneValue();

                                                                 
  static Handle<HermesValue> getNegOneValue();

 protected:
                                                                
  static const PinnedHermesValue nullPointer_;
                                                           
  static const PinnedHermesValue undefinedValue_;
                                                      
  static const PinnedHermesValue nullValue_;
                                                       
  static const PinnedHermesValue emptyValue_;
                                                      
  static const PinnedHermesValue trueValue_;
  static const PinnedHermesValue falseValue_;
                                                   
  static const PinnedHermesValue zeroValue_;
                                                   
  static const PinnedHermesValue oneValue_;
                                                    
  static const PinnedHermesValue negOneValue_;

  void markGCScopes(RootAcceptor &acceptor);

                                     
  GCScope *getTopGCScope();

 private:
  friend class GCScope;
  friend class GCScopeMarkerRAII;
  friend class HandleBase;

                            
  GCScope *topGCScope_{};

#ifndef NDEBUG
                                                                          
  uint32_t noHandleLevel_{0};

  friend class NoHandleScope;
#endif

                                                                               
                                  
  static PinnedHermesValue *newPinnedHermesValue(
      GCScope *inScope,
      HermesValue value);

                                                                              
                                  
  PinnedHermesValue *newPinnedHermesValue(HermesValue value);
};

                                                                  
                                                                          
                                                                         
class GCScopeDebugBase {
  friend class HandleBase;

#ifndef NDEBUG
                                                                              
  int numActiveHandles_{0};
#endif

 public:
  ~GCScopeDebugBase() {
    assert(numActiveHandles_ == 0 && "Destroying GCScope with active handles");
  }
};

#ifdef HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES

                                                                           
                                                                         
class GCScopeHandleTracker {
  using CountMapT = llvh::DenseMap<unsigned, std::pair<unsigned, const char *>>;
  using NameMapT = llvh::DenseMap<const char *, unsigned>;

                                                                          
                
  CountMapT countMap_;

                                                                             
  NameMapT nameMap_;

 public:
                                        
  ~GCScopeHandleTracker();

                                                           
  void record(const char *name, unsigned count) {
    auto &byCountValue = countMap_[count];
    ++byCountValue.first;

    if (name) {
      if (!byCountValue.second)
        byCountValue.second = name;

      unsigned &byNameEntry = nameMap_[name];
      if (count > byNameEntry)
        byNameEntry = count;
    }
  }
};

                                                                    
                                                    
extern GCScopeHandleTracker gcScopeHandleTracker;

#endif                                        

                                                                        
                                                                       
                                                                          
                                                             
                                                                              
                                                                          
                                 
class GCScope : public GCScopeDebugBase {
  friend class HandleRootOwner;

                                                            
  static constexpr size_t CHUNK_SIZE = 16;

                                                           
  HandleRootOwner &runtime_;

#ifndef NDEBUG
                                                                               
  unsigned const handlesLimit_;
                                            
  unsigned numAllocatedHandles_{0};
#endif

#ifdef HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES
                                           
  const char *name_;

                                                                              
                                             
  unsigned maxAllocatedHandles_{0};
#endif

                                      
  GCScope *const prevScope_;

                                                                         
  alignas(PinnedHermesValue) char inlineStorage_
      [sizeof(PinnedHermesValue) * CHUNK_SIZE];

                                                                            
           
  llvh::SmallVector<PinnedHermesValue *, 4> chunks_;

                                                       
  PinnedHermesValue *next_ = (PinnedHermesValue *)inlineStorage_;
                                                                             
  PinnedHermesValue *curChunkEnd_ =
      (PinnedHermesValue *)inlineStorage_ + CHUNK_SIZE;

                                              
  unsigned curChunkIndex_{0};

  GCScope(const GCScope &) = delete;
  void operator=(const GCScope &) = delete;

 public:
                                                                          
                                                                                
             
                                                                            
                                                        
                                                                             
                                                                           
                                                                               
                                                                          
                       
  explicit GCScope(
      HandleRootOwner &runtime,
      const char *name = nullptr,
      unsigned handlesLimit = HERMESVM_DEBUG_MAX_GCSCOPE_HANDLES)
      : runtime_(runtime),
#ifndef NDEBUG
        handlesLimit_(handlesLimit),
#endif
#ifdef HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES
        name_(name),
#endif
        prevScope_(runtime.topGCScope_),
        chunks_({(PinnedHermesValue *)inlineStorage_}) {
    runtime.topGCScope_ = this;
  }

  ~GCScope();

                                             
  GCScope *getParentScope() {
    return prevScope_;
  }

                                                                          
                                     
  static constexpr size_t getChunkSize() {
    return CHUNK_SIZE;
  }

                                                       
  bool isEmpty() const {
    return curChunkIndex_ == 0 &&
        next_ == (const PinnedHermesValue *)inlineStorage_;
  }

#ifndef NDEBUG
                                                
  LLVM_ATTRIBUTE_ALWAYS_INLINE size_t getHandleCountDbg() const {
    return numAllocatedHandles_;
  }

  LLVM_ATTRIBUTE_ALWAYS_INLINE void setHandleCountDbg(unsigned count) {
    numAllocatedHandles_ = count;
  }
#else
  LLVM_ATTRIBUTE_ALWAYS_INLINE size_t getHandleCountDbg() const {
    return curChunkIndex_ * CHUNK_SIZE + (next_ - chunks_[curChunkIndex_]);
  }
  LLVM_ATTRIBUTE_ALWAYS_INLINE void setHandleCountDbg(unsigned          ) {}
#endif

                                                                           
                                                                               
                                      
                                                                              
                                                                                
                                                                           
                      
  class Marker {
    friend class GCScope;
    PinnedHermesValue *const next;
    unsigned const curChunkIndex;

    Marker(PinnedHermesValue *next, unsigned int curChunkIndex)
        : next(next), curChunkIndex(curChunkIndex) {}

   public:
    bool operator==(Marker other) const {
      return next == other.next && curChunkIndex == other.curChunkIndex;
    }
  };

                                                                             
                                                                               
                                                  
  Marker createMarker() const {
    return Marker(next_, curChunkIndex_);
  }

                                                                         
                                                                              
  void flushToMarker(Marker marker) {
    assert(
        marker.curChunkIndex <= curChunkIndex_ &&
        "trying to reset to a higher chunk");
    assert(
        (marker.curChunkIndex < curChunkIndex_ || marker.next <= next_) &&
        "trying to reset to a higher next pointer");
    PinnedHermesValue *const chunkStart = chunks_[marker.curChunkIndex];
    PinnedHermesValue *const chunkEnd = chunkStart + CHUNK_SIZE;
                                                                                
    invalidateFreedHandleValues(marker.curChunkIndex, marker.next);
    curChunkIndex_ = marker.curChunkIndex;
    curChunkEnd_ = chunkEnd;
                                                                               
                                                                              
                                                                               
                        
    assert(
        marker.next >= chunkStart && marker.next <= curChunkEnd_ &&
        "savedNext is not within the current chunk");
    next_ = marker.next;

    setHandleCountDbg(
        curChunkIndex_ * CHUNK_SIZE + (next_ - chunks_[curChunkIndex_]));
  }

                                                          
                                                                                
  void flushToSmallCount(unsigned numHandlesToPreserve) {
    assert(
        numHandlesToPreserve <= CHUNK_SIZE && "numHandles exceeds CHUNK_SIZE");
    assert(
        numHandlesToPreserve <= getHandleCountDbg() &&
        "numHandles exceeds the actual number of handles");

    auto *chunk = (PinnedHermesValue *)inlineStorage_;
                                                                                
    invalidateFreedHandleValues(0, chunk + numHandlesToPreserve);
    next_ = chunk + numHandlesToPreserve;
    curChunkEnd_ = chunk + CHUNK_SIZE;
    curChunkIndex_ = 0;

    setHandleCountDbg(numHandlesToPreserve);
  }

                                                                             
                                                        
  void clearAllHandles() {
    flushToSmallCount(0);
  }

 private:
                                                                        
                                                                               
                                                 
  void invalidateFreedHandleValues(
      unsigned chunkStart,
      PinnedHermesValue *valueStart)
#ifdef HERMES_SLOW_DEBUG
      ;
#else
  {
  }
#endif

                                                                               
                                           
  PinnedHermesValue *newPinnedHermesValue(HermesValue value) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(NDEBUG)
                                                      
    (void)handlesLimit_;                                  
#else
    assert(
        getHandleCountDbg() < handlesLimit_ &&
        "Too many handles allocated in GCScope");
#endif
    assert(runtime_.noHandleLevel_ == 0 && "No handles allowed right now.");

    setHandleCountDbg(getHandleCountDbg() + 1);
#ifdef HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES
    if (numAllocatedHandles_ > maxAllocatedHandles_)
      maxAllocatedHandles_ = numAllocatedHandles_;
#endif

                                                                 
    if (LLVM_LIKELY(next_ < curChunkEnd_)) {
                                                                        
      return new (next_++) PinnedHermesValue(value);
    }

                                        
    return _newChunkAndPHV(value);
  }

                                                                       
                                                                    
  PinnedHermesValue *_newChunkAndPHV(HermesValue value);

                                     
  void mark(RootAcceptor &acceptor);
};

                                                                               
                                       
                                                                              
                                                                                
                                                                               
                                                                           
              
class GCScopeMarkerRAII {
  GCScope *const gcScope_;
  GCScope::Marker const marker_;

  GCScopeMarkerRAII(const GCScopeMarkerRAII &) = delete;
  void operator=(const GCScopeMarkerRAII &) = delete;

 public:
                                                     
  explicit GCScopeMarkerRAII(HandleRootOwner &runtime)
      : gcScope_(runtime.getTopGCScope()), marker_(gcScope_->createMarker()) {}
                                                    
  explicit GCScopeMarkerRAII(GCScope &gcScope)
      : gcScope_(&gcScope), marker_(gcScope_->createMarker()) {}
                                                        
  explicit GCScopeMarkerRAII(GCScope &gcScope, const GCScope::Marker &marker)
      : gcScope_(&gcScope), marker_(marker) {}

                                             
  void flush() {
    gcScope_->flushToMarker(marker_);
  }

  ~GCScopeMarkerRAII() {
    flush();
  }
};

}                
}                    

#pragma GCC diagnostic pop
#endif
