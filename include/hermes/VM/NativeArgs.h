/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_NATIVEARGS_H
#define HERMES_VM_NATIVEARGS_H

#include "hermes/VM/Handle.h"
#include "hermes/VM/HandleRootOwner.h"

namespace hermes {
namespace vm {

template <bool isConst>
using ArgIteratorT = std::reverse_iterator<typename std::conditional<
    isConst,
    const PinnedHermesValue *,
    PinnedHermesValue *>::type>;
using ArgIterator = ArgIteratorT<false>;
using ConstArgIterator = ArgIteratorT<true>;

                                                                           
                              
class NativeArgs final {
                                                                               
                       
  const ConstArgIterator firstArg_;
                                                          
  unsigned const argCount_;
                                          
  const PinnedHermesValue *const newTarget_;

                                                             
                                                                     
                                                                         
  NativeArgs(
      ConstArgIterator firstArg,
      unsigned argCount,
      const PinnedHermesValue *newTarget)
      : firstArg_(firstArg), argCount_(argCount), newTarget_(newTarget) {}

  template <bool isConst>
  friend class StackFramePtrT;

 public:
                                                                         
                                                                            
                         
  const PinnedHermesValue &getNewTarget() const {
    return *newTarget_;
  }

                                                                         
                                                                            
                         
  Handle<> getNewTargetHandle() const {
    return Handle<>(newTarget_);
  }

                                              
  bool isFunctionCall() const {
    return newTarget_->isUndefined();
  }
                                                       
  bool isConstructorCall() const {
    return !isFunctionCall();
  }

                                                                               
  unsigned getArgCount() const {
    return argCount_;
  }

                                                         
  const PinnedHermesValue &getThisArg() const {
    return begin()[-1];
  }

                                                          
  Handle<> getThisHandle() const {
    return Handle<>(&getThisArg());
  }

                                                                           
                                             
  template <class T>
  Handle<T> dyncastThis() const {
    return vmisa<T>(getThisArg()) ? Handle<T>::vmcast(&getThisArg())
                                  : HandleRootOwner::makeNullHandle<T>();
  }

                                                                         
  template <class T>
  Handle<T> vmcastThis() const {
    return Handle<T>::vmcast(&getThisArg());
  }

                                                                            
                                                                  
  HermesValue getArg(unsigned index) const {
    return index < argCount_ ? static_cast<HermesValue>(begin()[index])
                             : HermesValue::encodeUndefinedValue();
  }

                                                                           
                                                                      
                             
  Handle<> getArgHandle(unsigned index) const {
    return index < argCount_ ? Handle<>(&begin()[index])
                             : HandleRootOwner::getUndefinedValue();
  }

                                                                               
                                                                         
                                            
                                                                           
  template <class T>
  Handle<T> dyncastArg(unsigned index) const {
    return index < argCount_ && vmisa<T>(begin()[index])
        ? Handle<T>::vmcast(&begin()[index])
        : HandleRootOwner::makeNullHandle<T>();
  }

                                                                         
                                                                           
                                                                             
                                                                             
                
           
                                   
                          
                                                  
                                   
                                   
              
  class handle_iterator {
    friend class NativeArgs;

    ConstArgIterator arg_;

    explicit handle_iterator(ConstArgIterator arg) : arg_(arg) {}

   public:
    using iterator_category = std::random_access_iterator_tag;
    using value_type = Handle<>;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    handle_iterator(const handle_iterator &) = default;
    handle_iterator &operator=(const handle_iterator &) = default;

    bool operator!=(const handle_iterator &o) const {
      return arg_ != o.arg_;
    }
    bool operator==(const handle_iterator &o) const {
      return arg_ == o.arg_;
    }

    Handle<> operator*() const {
      return Handle<>(&*arg_);
    }
    Handle<> operator[](difference_type o) const {
      return Handle<>(&*(arg_ + o));
    }
    const HermesValue *operator->() const {
      return &*arg_;
    }

    handle_iterator &operator++() {
      ++arg_;
      return *this;
    }
    handle_iterator &operator--() {
      --arg_;
      return *this;
    }
    handle_iterator operator++(int) {
      auto res = *this;
      ++arg_;
      return res;
    }
    handle_iterator operator--(int) {
      auto res = *this;
      --arg_;
      return res;
    }
    handle_iterator &operator+=(difference_type o) {
      arg_ += o;
      return *this;
    }
    handle_iterator &operator-=(difference_type o) {
      arg_ -= o;
      return *this;
    }

    handle_iterator operator+(difference_type o) const {
      return handle_iterator(arg_ + o);
    }
    handle_iterator operator-(difference_type o) const {
      return handle_iterator(arg_ - o);
    }
    difference_type operator-(const handle_iterator x) const {
      return arg_ - x.arg_;
    }
  };

                                                                             
                                 
           
                                             
              
         
              
  llvh::iterator_range<handle_iterator> handles() const {
    return llvh::make_range(handle_iterator(begin()), handle_iterator(end()));
  };

  ConstArgIterator begin() const {
    return firstArg_;
  }
  ConstArgIterator end() const {
    return begin() + argCount_;
  }
};

}                
}                    

#endif                          
