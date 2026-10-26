/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
#ifndef HERMES_VM_WEAKVALUEMAP_H
#define HERMES_VM_WEAKVALUEMAP_H

#include "hermes/VM/HandleRootOwner.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/WeakRef.h"

#include "llvh/ADT/DenseMap.h"

namespace hermes {
namespace vm {

                                                                               
                                                         
                                                                            
                                          
template <class KeyT, class ValueT>
class WeakValueMap {
                                                                     
                                                                                
                                                        
  using DenseMapT = llvh::SmallDenseMap<KeyT, WeakRef<ValueT>, 8>;
  using InternalIterator = typename DenseMapT::iterator;

 public:
  using key_type = typename DenseMapT::mapped_type;
  using mapped_type = typename DenseMapT::mapped_type;
  using value_type = typename DenseMapT::value_type;
  using size_type = typename DenseMapT::size_type;

  WeakValueMap() : map_() {}
  ~WeakValueMap() {
    for (auto &[k, v] : map_)
      v.releaseSlot();
  }

  WeakValueMap(const WeakValueMap &) = delete;
  WeakValueMap &operator=(const WeakValueMap &) = delete;

                                                          
                                                                               
                                                                          
                                                                          
            
  bool isKnownEmpty() const {
    return map_.empty();
  }

                                                                              
  template <typename CallbackFunction>
  void forEachEntry(const CallbackFunction &callback) const {
    for (auto it = map_.begin(), e = map_.end(); it != e; ++it) {
      callback(it->first, it->second);
    }
  }

                                                                            
  bool containsKey(const KeyT &key) {
    return internalFind(key) != map_.end();
  }

                                                                         
  ValueT *lookup(Runtime &runtime, const KeyT &key) {
    auto it = internalFind(key);
    if (it == map_.end())
      return nullptr;
    return it->second.get(runtime);
  }

                                                                         
  bool erase(const KeyT &key, GC &gc) {
    auto it = internalFind(key);
    if (it == map_.end())
      return false;
    it->second.releaseSlot();
    map_.erase(it);
    recalcPruneLimit();
    return true;
  }

                                                                      
                                                                                
  bool insertNew(Runtime &runtime, const KeyT &key, Handle<ValueT> value) {
    auto [it, inserted] = map_.try_emplace(key, runtime, value);
    if (!inserted) {
                                                                               
      if (it->second.isValid()) {
        return false;
      }
                                                            
      it->second.releaseSlot();
      it->second = WeakRef<ValueT>(runtime, value);
    }
    pruneInvalid(runtime.getHeap());
    return true;
  }

  size_t getMemorySize() const {
    return map_.getMemorySize();
  }

 private:
  DenseMapT map_;

  static constexpr size_type kMinPruneLimit = 5;

                                                                             
  size_type pruneLimit_{kMinPruneLimit};

                                                                            
                                                                               
                      
                                                               
  InternalIterator internalFind(const KeyT &key) {
    auto it = map_.find(key);
                 
    if (it == map_.end())
      return it;

                                                                          
    if (!it->second.isValid()) {
      return map_.end();
    }

    return it;
  }

                                                                           
                                                                     
  void pruneInvalid(GC &gc) {
    if (map_.size() <= pruneLimit_)
      return;

    for (auto it = map_.begin(), e = map_.end(); it != e; ++it) {
      if (!it->second.isValid()) {
        it->second.releaseSlot();
                                                                    
                                                                             
                                                          
                                 
        map_.erase(it);
      }
    }

    recalcPruneLimit();
  }

                                                                         
  void recalcPruneLimit() {
    pruneLimit_ = std::max(map_.size() * 2 + 1, toRValue(kMinPruneLimit));
  }
};

}                
}                    

#endif                            
