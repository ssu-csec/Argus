//===- ValueHandle.h - Value Smart Pointer classes --------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the ValueHandle class and its sub-classes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_VALUEHANDLE_H
#define LLVM_IR_VALUEHANDLE_H

#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/ADT/PointerIntPair.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include <cassert>

namespace llvh {

                                                   
   
                                                                               
                                                                           
                      
class ValueHandleBase {
  friend class Value;

protected:
                                                           
     
                                                                                
                                                        
  enum HandleBaseKind { Assert, Callback, Weak, WeakTracking };

  ValueHandleBase(const ValueHandleBase &RHS)
      : ValueHandleBase(RHS.PrevPair.getInt(), RHS) {}

  ValueHandleBase(HandleBaseKind Kind, const ValueHandleBase &RHS)
      : PrevPair(nullptr, Kind), Val(RHS.getValPtr()) {
    if (isValid(getValPtr()))
      AddToExistingUseList(RHS.getPrevPtr());
  }

private:
  PointerIntPair<ValueHandleBase**, 2, HandleBaseKind> PrevPair;
  ValueHandleBase *Next = nullptr;
  Value *Val = nullptr;

  void setValPtr(Value *V) { Val = V; }

public:
  explicit ValueHandleBase(HandleBaseKind Kind)
      : PrevPair(nullptr, Kind) {}
  ValueHandleBase(HandleBaseKind Kind, Value *V)
      : PrevPair(nullptr, Kind), Val(V) {
    if (isValid(getValPtr()))
      AddToUseList();
  }

  ~ValueHandleBase() {
    if (isValid(getValPtr()))
      RemoveFromUseList();
  }

  Value *operator=(Value *RHS) {
    if (getValPtr() == RHS)
      return RHS;
    if (isValid(getValPtr()))
      RemoveFromUseList();
    setValPtr(RHS);
    if (isValid(getValPtr()))
      AddToUseList();
    return RHS;
  }

  Value *operator=(const ValueHandleBase &RHS) {
    if (getValPtr() == RHS.getValPtr())
      return RHS.getValPtr();
    if (isValid(getValPtr()))
      RemoveFromUseList();
    setValPtr(RHS.getValPtr());
    if (isValid(getValPtr()))
      AddToExistingUseList(RHS.getPrevPtr());
    return getValPtr();
  }

  Value *operator->() const { return getValPtr(); }
  Value &operator*() const { return *getValPtr(); }

protected:
  Value *getValPtr() const { return Val; }

  static bool isValid(Value *V) {
    return V &&
           V != DenseMapInfo<Value *>::getEmptyKey() &&
           V != DenseMapInfo<Value *>::getTombstoneKey();
  }

                                                        
  void RemoveFromUseList();

                                                                 
     
                                                                          
                               
  void clearValPtr() { setValPtr(nullptr); }

public:
                               
  static void ValueIsDeleted(Value *V);
  static void ValueIsRAUWd(Value *Old, Value *New);

private:
                                     
  ValueHandleBase **getPrevPtr() const { return PrevPair.getPointer(); }
  HandleBaseKind getKind() const { return PrevPair.getInt(); }
  void setPrevPtr(ValueHandleBase **Ptr) { PrevPair.setPointer(Ptr); }

                                                 
     
                                                                              
                            
  void AddToExistingUseList(ValueHandleBase **List);

                                                      
  void AddToExistingUseListAfter(ValueHandleBase *Node);

                                                 
  void AddToUseList();
};

                                             
   
                                                                   
                                 
class WeakVH : public ValueHandleBase {
public:
  WeakVH() : ValueHandleBase(Weak) {}
  WeakVH(Value *P) : ValueHandleBase(Weak, P) {}
  WeakVH(const WeakVH &RHS)
      : ValueHandleBase(Weak, RHS) {}

  WeakVH &operator=(const WeakVH &RHS) = default;

  Value *operator=(Value *RHS) {
    return ValueHandleBase::operator=(RHS);
  }
  Value *operator=(const ValueHandleBase &RHS) {
    return ValueHandleBase::operator=(RHS);
  }

  operator Value*() const {
    return getValPtr();
  }
};

                                                             
                      
template <> struct simplify_type<WeakVH> {
  using SimpleType = Value *;

  static SimpleType getSimplifiedValue(WeakVH &WVH) { return WVH; }
};
template <> struct simplify_type<const WeakVH> {
  using SimpleType = Value *;

  static SimpleType getSimplifiedValue(const WeakVH &WVH) { return WVH; }
};

                                                                
   
                                                                           
                                                                              
                                                                              
                                                                               
             
class WeakTrackingVH : public ValueHandleBase {
public:
  WeakTrackingVH() : ValueHandleBase(WeakTracking) {}
  WeakTrackingVH(Value *P) : ValueHandleBase(WeakTracking, P) {}
  WeakTrackingVH(const WeakTrackingVH &RHS)
      : ValueHandleBase(WeakTracking, RHS) {}

  WeakTrackingVH &operator=(const WeakTrackingVH &RHS) = default;

  Value *operator=(Value *RHS) {
    return ValueHandleBase::operator=(RHS);
  }
  Value *operator=(const ValueHandleBase &RHS) {
    return ValueHandleBase::operator=(RHS);
  }

  operator Value*() const {
    return getValPtr();
  }

  bool pointsToAliveValue() const {
    return ValueHandleBase::isValid(getValPtr());
  }
};

                                                                     
                      
template <> struct simplify_type<WeakTrackingVH> {
  using SimpleType = Value *;

  static SimpleType getSimplifiedValue(WeakTrackingVH &WVH) { return WVH; }
};
template <> struct simplify_type<const WeakTrackingVH> {
  using SimpleType = Value *;

  static SimpleType getSimplifiedValue(const WeakTrackingVH &WVH) {
    return WVH;
  }
};

                                                      
   
                                                                              
                                                                         
                                                                             
                                                                               
                                                                            
                                                                              
                                                                         
                  
   
                                                                        
                                                                     
                                                                                
                                                        
template <typename ValueTy>
class AssertingVH
#ifndef NDEBUG
  : public ValueHandleBase
#endif
  {
  friend struct DenseMapInfo<AssertingVH<ValueTy>>;

#ifndef NDEBUG
  Value *getRawValPtr() const { return ValueHandleBase::getValPtr(); }
  void setRawValPtr(Value *P) { ValueHandleBase::operator=(P); }
#else
  Value *ThePtr;
  Value *getRawValPtr() const { return ThePtr; }
  void setRawValPtr(Value *P) { ThePtr = P; }
#endif
                                                               
  static Value *GetAsValue(Value *V) { return V; }
  static Value *GetAsValue(const Value *V) { return const_cast<Value*>(V); }

  ValueTy *getValPtr() const { return static_cast<ValueTy *>(getRawValPtr()); }
  void setValPtr(ValueTy *P) { setRawValPtr(GetAsValue(P)); }

public:
#ifndef NDEBUG
  AssertingVH() : ValueHandleBase(Assert) {}
  AssertingVH(ValueTy *P) : ValueHandleBase(Assert, GetAsValue(P)) {}
  AssertingVH(const AssertingVH &RHS) : ValueHandleBase(Assert, RHS) {}
#else
  AssertingVH() : ThePtr(nullptr) {}
  AssertingVH(ValueTy *P) : ThePtr(GetAsValue(P)) {}
#endif

  operator ValueTy*() const {
    return getValPtr();
  }

  ValueTy *operator=(ValueTy *RHS) {
    setValPtr(RHS);
    return getValPtr();
  }
  ValueTy *operator=(const AssertingVH<ValueTy> &RHS) {
    setValPtr(RHS.getValPtr());
    return getValPtr();
  }

  ValueTy *operator->() const { return getValPtr(); }
  ValueTy &operator*() const { return *getValPtr(); }
};

                                                                           
template<typename T>
struct DenseMapInfo<AssertingVH<T>> {
  static inline AssertingVH<T> getEmptyKey() {
    AssertingVH<T> Res;
    Res.setRawValPtr(DenseMapInfo<Value *>::getEmptyKey());
    return Res;
  }

  static inline AssertingVH<T> getTombstoneKey() {
    AssertingVH<T> Res;
    Res.setRawValPtr(DenseMapInfo<Value *>::getTombstoneKey());
    return Res;
  }

  static unsigned getHashValue(const AssertingVH<T> &Val) {
    return DenseMapInfo<Value *>::getHashValue(Val.getRawValPtr());
  }

  static bool isEqual(const AssertingVH<T> &LHS, const AssertingVH<T> &RHS) {
    return DenseMapInfo<Value *>::isEqual(LHS.getRawValPtr(),
                                          RHS.getRawValPtr());
  }
};

template <typename T>
struct isPodLike<AssertingVH<T>> {
#ifdef NDEBUG
  static const bool value = true;
#else
  static const bool value = false;
#endif
};

                                                 
   
                                                                               
                                                                              
                                                                          
   
                                                                            
                                                         
   
                                                                           
                                                                           
                                                                             
                           
   
                                                                                
                                      
template <typename ValueTy> class TrackingVH {
  WeakTrackingVH InnerHandle;

public:
  ValueTy *getValPtr() const {
    assert(InnerHandle.pointsToAliveValue() &&
           "TrackingVH must be non-null and valid on dereference!");

                                                                              
                                                                              
                                                                               
                                                                             
    assert(isa<ValueTy>(InnerHandle) &&
           "Tracked Value was replaced by one with an invalid type!");
    return cast<ValueTy>(InnerHandle);
  }

  void setValPtr(ValueTy *P) {
                                                                              
                   
    InnerHandle = GetAsValue(P);
  }

                                                                 
                   
  static Value *GetAsValue(Value *V) { return V; }
  static Value *GetAsValue(const Value *V) { return const_cast<Value*>(V); }

public:
  TrackingVH() = default;
  TrackingVH(ValueTy *P) { setValPtr(P); }

  operator ValueTy*() const {
    return getValPtr();
  }

  ValueTy *operator=(ValueTy *RHS) {
    setValPtr(RHS);
    return getValPtr();
  }

  ValueTy *operator->() const { return getValPtr(); }
  ValueTy &operator*() const { return *getValPtr(); }
};

                                                        
   
                                                                              
                                                                          
                                                                              
                                                                             
                                                                                
class CallbackVH : public ValueHandleBase {
  virtual void anchor();
protected:
  ~CallbackVH() = default;
  CallbackVH(const CallbackVH &) = default;
  CallbackVH &operator=(const CallbackVH &) = default;

  void setValPtr(Value *P) {
    ValueHandleBase::operator=(P);
  }

public:
  CallbackVH() : ValueHandleBase(Callback) {}
  CallbackVH(Value *P) : ValueHandleBase(Callback, P) {}

  operator Value*() const {
    return getValPtr();
  }

                                     
     
                                                                         
                                                                           
                                                                                
          
                                                                           
                                 
     
                                                                           
                                   
  virtual void deleted() { setValPtr(nullptr); }

                              
     
                                                                             
                                                                              
          
                                                                   
                                                                         
  virtual void allUsesReplacedWith(Value *) {}
};

                                                             
   
                                                                           
                                                                               
                                                                         
                                                                             
         
   
                                                                              
                                                                            
                                                                             
                                                                               
                                                 
   
                                                                       
                                                                    
                                                                               
                                                        
template <typename ValueTy>
class PoisoningVH
#ifndef NDEBUG
    final : public CallbackVH
#endif
{
  friend struct DenseMapInfo<PoisoningVH<ValueTy>>;

                                                               
  static Value *GetAsValue(Value *V) { return V; }
  static Value *GetAsValue(const Value *V) { return const_cast<Value *>(V); }

#ifndef NDEBUG
                                                           
     
                                                                           
                                                                         
                                                                              
                
  bool Poisoned = false;

  Value *getRawValPtr() const { return ValueHandleBase::getValPtr(); }
  void setRawValPtr(Value *P) { ValueHandleBase::operator=(P); }

                                              
  void deleted() override {
    assert(!Poisoned && "Tried to delete an already poisoned handle!");
    Poisoned = true;
    RemoveFromUseList();
  }

                                          
  void allUsesReplacedWith(Value *) override {
    assert(!Poisoned && "Tried to RAUW an already poisoned handle!");
    Poisoned = true;
    RemoveFromUseList();
  }
#else          
  Value *ThePtr = nullptr;

  Value *getRawValPtr() const { return ThePtr; }
  void setRawValPtr(Value *P) { ThePtr = P; }
#endif

  ValueTy *getValPtr() const {
    assert(!Poisoned && "Accessed a poisoned value handle!");
    return static_cast<ValueTy *>(getRawValPtr());
  }
  void setValPtr(ValueTy *P) { setRawValPtr(GetAsValue(P)); }

public:
  PoisoningVH() = default;
#ifndef NDEBUG
  PoisoningVH(ValueTy *P) : CallbackVH(GetAsValue(P)) {}
  PoisoningVH(const PoisoningVH &RHS)
      : CallbackVH(RHS), Poisoned(RHS.Poisoned) {}

  ~PoisoningVH() {
    if (Poisoned)
      clearValPtr();
  }

  PoisoningVH &operator=(const PoisoningVH &RHS) {
    if (Poisoned)
      clearValPtr();
    CallbackVH::operator=(RHS);
    Poisoned = RHS.Poisoned;
    return *this;
  }
#else
  PoisoningVH(ValueTy *P) : ThePtr(GetAsValue(P)) {}
#endif

  operator ValueTy *() const { return getValPtr(); }

  ValueTy *operator->() const { return getValPtr(); }
  ValueTy &operator*() const { return *getValPtr(); }
};

                                                                           
template <typename T> struct DenseMapInfo<PoisoningVH<T>> {
  static inline PoisoningVH<T> getEmptyKey() {
    PoisoningVH<T> Res;
    Res.setRawValPtr(DenseMapInfo<Value *>::getEmptyKey());
    return Res;
  }

  static inline PoisoningVH<T> getTombstoneKey() {
    PoisoningVH<T> Res;
    Res.setRawValPtr(DenseMapInfo<Value *>::getTombstoneKey());
    return Res;
  }

  static unsigned getHashValue(const PoisoningVH<T> &Val) {
    return DenseMapInfo<Value *>::getHashValue(Val.getRawValPtr());
  }

  static bool isEqual(const PoisoningVH<T> &LHS, const PoisoningVH<T> &RHS) {
    return DenseMapInfo<Value *>::isEqual(LHS.getRawValPtr(),
                                          RHS.getRawValPtr());
  }
};

template <typename T> struct isPodLike<PoisoningVH<T>> {
#ifdef NDEBUG
  static const bool value = true;
#else
  static const bool value = false;
#endif
};

}                      

#endif                         
