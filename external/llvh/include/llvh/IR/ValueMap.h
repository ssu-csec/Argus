//===- ValueMap.h - Safe map from Values to data ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the ValueMap class.  ValueMap maps Value* or any subclass
// to an arbitrary other type.  It provides the DenseMap interface but updates
// itself to remain safe when keys are RAUWed or deleted.  By default, when a
// key is RAUWed from V1 to V2, the old mapping V1->target is removed, and a new
// mapping V2->target is added.  If V2 already existed, its old target is
// overwritten.  When a key is deleted, its mapping is removed.
//
// You can override a ValueMap's Config parameter to control exactly what
// happens on RAUW and destruction and to get called back on each event.  It's
// legal to call back into the ValueMap from a Config's callbacks.  Config
// parameters should inherit from ValueMapConfig<KeyT> to get default
// implementations of all the methods ValueMap uses.  See ValueMapConfig for
// documentation of the functions you can override.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_VALUEMAP_H
#define LLVM_IR_VALUEMAP_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/Optional.h"
#include "llvh/IR/TrackingMDRef.h"
#include "llvh/IR/ValueHandle.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/Mutex.h"
#include "llvh/Support/UniqueLock.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <utility>

namespace llvh {

template<typename KeyT, typename ValueT, typename Config>
class ValueMapCallbackVH;
template<typename DenseMapT, typename KeyT>
class ValueMapIterator;
template<typename DenseMapT, typename KeyT>
class ValueMapConstIterator;

                                                                       
                                                                                
                                                 
template<typename KeyT, typename MutexT = sys::Mutex>
struct ValueMapConfig {
  using mutex_type = MutexT;

                                                                               
                                                                   
  enum { FollowRAUW = true };

                                                                             
                                                                             
                                                                        
                               
  struct ExtraData {};

  template<typename ExtraDataT>
  static void onRAUW(const ExtraDataT &         , KeyT        , KeyT        ) {}
  template<typename ExtraDataT>
  static void onDelete(const ExtraDataT &        , KeyT        ) {}

                                                                            
                                                                                
                                                                              
                         
  template<typename ExtraDataT>
  static mutex_type *getMutex(const ExtraDataT &        ) { return nullptr; }
};

                         
template<typename KeyT, typename ValueT, typename Config =ValueMapConfig<KeyT>>
class ValueMap {
  friend class ValueMapCallbackVH<KeyT, ValueT, Config>;

  using ValueMapCVH = ValueMapCallbackVH<KeyT, ValueT, Config>;
  using MapT = DenseMap<ValueMapCVH, ValueT, DenseMapInfo<ValueMapCVH>>;
  using MDMapT = DenseMap<const Metadata *, TrackingMDRef>;
  using ExtraData = typename Config::ExtraData;

  MapT Map;
  Optional<MDMapT> MDMap;
  ExtraData Data;
  bool MayMapMetadata = true;

public:
  using key_type = KeyT;
  using mapped_type = ValueT;
  using value_type = std::pair<KeyT, ValueT>;
  using size_type = unsigned;

  explicit ValueMap(unsigned NumInitBuckets = 64)
      : Map(NumInitBuckets), Data() {}
  explicit ValueMap(const ExtraData &Data, unsigned NumInitBuckets = 64)
      : Map(NumInitBuckets), Data(Data) {}
                                                                            
           
  ValueMap(const ValueMap &) = delete;
  ValueMap(ValueMap &&) = delete;
  ValueMap &operator=(const ValueMap &) = delete;
  ValueMap &operator=(ValueMap &&) = delete;

  bool hasMD() const { return bool(MDMap); }
  MDMapT &MD() {
    if (!MDMap)
      MDMap.emplace();
    return *MDMap;
  }
  Optional<MDMapT> &getMDMap() { return MDMap; }

  bool mayMapMetadata() const { return MayMapMetadata; }
  void enableMapMetadata() { MayMapMetadata = true; }
  void disableMapMetadata() { MayMapMetadata = false; }

                                                  
  Optional<Metadata *> getMappedMD(const Metadata *MD) const {
    if (!MDMap)
      return None;
    auto Where = MDMap->find(MD);
    if (Where == MDMap->end())
      return None;
    return Where->second.get();
  }

  using iterator = ValueMapIterator<MapT, KeyT>;
  using const_iterator = ValueMapConstIterator<MapT, KeyT>;

  inline iterator begin() { return iterator(Map.begin()); }
  inline iterator end() { return iterator(Map.end()); }
  inline const_iterator begin() const { return const_iterator(Map.begin()); }
  inline const_iterator end() const { return const_iterator(Map.end()); }

  bool empty() const { return Map.empty(); }
  size_type size() const { return Map.size(); }

                                                                        
  void resize(size_t Size) { Map.resize(Size); }

  void clear() {
    Map.clear();
    MDMap.reset();
  }

                                                               
  size_type count(const KeyT &Val) const {
    return Map.find_as(Val) == Map.end() ? 0 : 1;
  }

  iterator find(const KeyT &Val) {
    return iterator(Map.find_as(Val));
  }
  const_iterator find(const KeyT &Val) const {
    return const_iterator(Map.find_as(Val));
  }

                                                                   
                                                
  ValueT lookup(const KeyT &Val) const {
    typename MapT::const_iterator I = Map.find_as(Val);
    return I != Map.end() ? I->second : ValueT();
  }

                                                                             
                                                                              
           
  std::pair<iterator, bool> insert(const std::pair<KeyT, ValueT> &KV) {
    auto MapResult = Map.insert(std::make_pair(Wrap(KV.first), KV.second));
    return std::make_pair(iterator(MapResult.first), MapResult.second);
  }

  std::pair<iterator, bool> insert(std::pair<KeyT, ValueT> &&KV) {
    auto MapResult =
        Map.insert(std::make_pair(Wrap(KV.first), std::move(KV.second)));
    return std::make_pair(iterator(MapResult.first), MapResult.second);
  }

                                        
  template<typename InputIt>
  void insert(InputIt I, InputIt E) {
    for (; I != E; ++I)
      insert(*I);
  }

  bool erase(const KeyT &Val) {
    typename MapT::iterator I = Map.find_as(Val);
    if (I == Map.end())
      return false;

    Map.erase(I);
    return true;
  }
  void erase(iterator I) {
    return Map.erase(I.base());
  }

  value_type& FindAndConstruct(const KeyT &Key) {
    return Map.FindAndConstruct(Wrap(Key));
  }

  ValueT &operator[](const KeyT &Key) {
    return Map[Wrap(Key)];
  }

                                                                             
                                                                             
                             
  bool isPointerIntoBucketsArray(const void *Ptr) const {
    return Map.isPointerIntoBucketsArray(Ptr);
  }

                                                                              
                                                                          
                                                                       
  const void *getPointerIntoBucketsArray() const {
    return Map.getPointerIntoBucketsArray();
  }

private:
                                                               
                                                                         
                                                                         
  ValueMapCVH Wrap(KeyT key) const {
                                                                              
                                                                               
                                                                              
                     
    return ValueMapCVH(key, const_cast<ValueMap*>(this));
  }
};

                                                                         
                                                                           
template <typename KeyT, typename ValueT, typename Config>
class ValueMapCallbackVH final : public CallbackVH {
  friend class ValueMap<KeyT, ValueT, Config>;
  friend struct DenseMapInfo<ValueMapCallbackVH>;

  using ValueMapT = ValueMap<KeyT, ValueT, Config>;
  using KeySansPointerT = typename std::remove_pointer<KeyT>::type;

  ValueMapT *Map;

  ValueMapCallbackVH(KeyT Key, ValueMapT *Map)
      : CallbackVH(const_cast<Value*>(static_cast<const Value*>(Key))),
        Map(Map) {}

                                                                      
  ValueMapCallbackVH(Value *V) : CallbackVH(V), Map(nullptr) {}

public:
  KeyT Unwrap() const { return cast_or_null<KeySansPointerT>(getValPtr()); }

  void deleted() override {
                                                                       
    ValueMapCallbackVH Copy(*this);
    typename Config::mutex_type *M = Config::getMutex(Copy.Map->Data);
    unique_lock<typename Config::mutex_type> Guard;
    if (M)
      Guard = unique_lock<typename Config::mutex_type>(*M);
    Config::onDelete(Copy.Map->Data, Copy.Unwrap());                       
    Copy.Map->Map.erase(Copy);                               
  }

  void allUsesReplacedWith(Value *new_key) override {
    assert(isa<KeySansPointerT>(new_key) &&
           "Invalid RAUW on key of ValueMap<>");
                                                                       
    ValueMapCallbackVH Copy(*this);
    typename Config::mutex_type *M = Config::getMutex(Copy.Map->Data);
    unique_lock<typename Config::mutex_type> Guard;
    if (M)
      Guard = unique_lock<typename Config::mutex_type>(*M);

    KeyT typed_new_key = cast<KeySansPointerT>(new_key);
                         
    Config::onRAUW(Copy.Map->Data, Copy.Unwrap(), typed_new_key);
    if (Config::FollowRAUW) {
      typename ValueMapT::MapT::iterator I = Copy.Map->Map.find(Copy);
                                                                      
                                 
      if (I != Copy.Map->Map.end()) {
        ValueT Target(std::move(I->second));
        Copy.Map->Map.erase(I);                               
        Copy.Map->insert(std::make_pair(typed_new_key, std::move(Target)));
      }
    }
  }
};

template<typename KeyT, typename ValueT, typename Config>
struct DenseMapInfo<ValueMapCallbackVH<KeyT, ValueT, Config>> {
  using VH = ValueMapCallbackVH<KeyT, ValueT, Config>;

  static inline VH getEmptyKey() {
    return VH(DenseMapInfo<Value *>::getEmptyKey());
  }

  static inline VH getTombstoneKey() {
    return VH(DenseMapInfo<Value *>::getTombstoneKey());
  }

  static unsigned getHashValue(const VH &Val) {
    return DenseMapInfo<KeyT>::getHashValue(Val.Unwrap());
  }

  static unsigned getHashValue(const KeyT &Val) {
    return DenseMapInfo<KeyT>::getHashValue(Val);
  }

  static bool isEqual(const VH &LHS, const VH &RHS) {
    return LHS == RHS;
  }

  static bool isEqual(const KeyT &LHS, const VH &RHS) {
    return LHS == RHS.getValPtr();
  }
};

template <typename DenseMapT, typename KeyT> class ValueMapIterator {
  using BaseT = typename DenseMapT::iterator;
  using ValueT = typename DenseMapT::mapped_type;

  BaseT I;

public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = std::pair<KeyT, typename DenseMapT::mapped_type>;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

  ValueMapIterator() : I() {}
  ValueMapIterator(BaseT I) : I(I) {}

  BaseT base() const { return I; }

  struct ValueTypeProxy {
    const KeyT first;
    ValueT& second;

    ValueTypeProxy *operator->() { return this; }

    operator std::pair<KeyT, ValueT>() const {
      return std::make_pair(first, second);
    }
  };

  ValueTypeProxy operator*() const {
    ValueTypeProxy Result = {I->first.Unwrap(), I->second};
    return Result;
  }

  ValueTypeProxy operator->() const {
    return operator*();
  }

  bool operator==(const ValueMapIterator &RHS) const {
    return I == RHS.I;
  }
  bool operator!=(const ValueMapIterator &RHS) const {
    return I != RHS.I;
  }

  inline ValueMapIterator& operator++() {                 
    ++I;
    return *this;
  }
  ValueMapIterator operator++(int) {                  
    ValueMapIterator tmp = *this; ++*this; return tmp;
  }
};

template <typename DenseMapT, typename KeyT> class ValueMapConstIterator {
  using BaseT = typename DenseMapT::const_iterator;
  using ValueT = typename DenseMapT::mapped_type;

  BaseT I;

public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = std::pair<KeyT, typename DenseMapT::mapped_type>;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

  ValueMapConstIterator() : I() {}
  ValueMapConstIterator(BaseT I) : I(I) {}
  ValueMapConstIterator(ValueMapIterator<DenseMapT, KeyT> Other)
    : I(Other.base()) {}

  BaseT base() const { return I; }

  struct ValueTypeProxy {
    const KeyT first;
    const ValueT& second;
    ValueTypeProxy *operator->() { return this; }
    operator std::pair<KeyT, ValueT>() const {
      return std::make_pair(first, second);
    }
  };

  ValueTypeProxy operator*() const {
    ValueTypeProxy Result = {I->first.Unwrap(), I->second};
    return Result;
  }

  ValueTypeProxy operator->() const {
    return operator*();
  }

  bool operator==(const ValueMapConstIterator &RHS) const {
    return I == RHS.I;
  }
  bool operator!=(const ValueMapConstIterator &RHS) const {
    return I != RHS.I;
  }

  inline ValueMapConstIterator& operator++() {                 
    ++I;
    return *this;
  }
  ValueMapConstIterator operator++(int) {                  
    ValueMapConstIterator tmp = *this; ++*this; return tmp;
  }
};

}                      

#endif                      
