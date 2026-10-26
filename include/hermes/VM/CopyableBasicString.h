/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_COPYABLEBASICSTRING_H
#define HERMES_VM_COPYABLEBASICSTRING_H

                                                                                
                                                                                
                                                                           
                                                                         
                                                                                

#include <cassert>
#include <string>

namespace hermes {
namespace vm {

                                                                    
                                                   
                                                                        
                                                                        
                                                                     
                                                                 
                                                                 
                                                              
                                                           
#if !_ITERATOR_DEBUG_LEVEL && !defined(HERMESVM_API_TRACE_ANDROID_REPLAY)

                                                                         
                                                                               
                                                                               
                                                                             
                                                                               
                      
static constexpr size_t COPYABLE_BASIC_STRING_MIN_LENGTH = 128;

                                                                              
                                                                        
                                                                           
                                                                           
                                                                     
   
                                                                                
                                                                             
                                                                                
                                                                        
   
                                                                      
                                                                             
                                                                         
                                 
template <typename T>
using CopyableBasicString = std::basic_string<T>;

#else

                                                                         
                                                                              
                                                                              
                                        
                                                                             
                                                                               
                      
static constexpr size_t COPYABLE_BASIC_STRING_MIN_LENGTH =
    sizeof(std::u16string) * 2;

                                                                              
                                                                        
                                                                           
                                                                           
                                                                     
   
                                                                                
                                                                             
                                                                                
                                                                        
   
                                                                      
                                                                             
                                                                         
                                 
   
                                                                             
                                                            
template <typename T>
class CopyableBasicString {
 public:
  using value_type = T;

  CopyableBasicString(const CopyableBasicString &) = delete;
  void operator=(const CopyableBasicString &) = delete;

  explicit CopyableBasicString() : str_(new std::basic_string<T>()) {}
  explicit CopyableBasicString(size_t count, char ch)
      : str_(new std::basic_string<T>(count, ch)) {}

  explicit CopyableBasicString(std::basic_string<T> &&o)
      : str_(new std::basic_string<T>(std::move(o))) {}

  CopyableBasicString(CopyableBasicString<T> &&o) : str_(o.str_) {
    o.str_ = nullptr;
  }

  ~CopyableBasicString() {
    delete str_;
  }

  size_t size() const {
    return get().size();
  }
  size_t capacity() const {
    return get().capacity();
  }

  void reserve(size_t new_cap) {
    get().reserve();
  }

  const T *data() const {
    return get().data();
  }

  template <class InputIt>
  CopyableBasicString<T> &append(InputIt first, InputIt last) {
    get().append(first, last);
    return *this;
  }

  T &operator[](size_t index) {
    return get()[index];
  }
  const T &operator[](size_t index) const {
    return get()[index];
  }

 private:
                                                                         
  std::basic_string<T> &get() {
    assert(str_ && "accessing moved from string");
    return *str_;
  }
                                                                         
  const std::basic_string<T> &get() const {
    assert(str_ && "accessing moved from string");
    return *const_cast<const std::basic_string<T> *>(str_);
  }

 private:
                                                                      
                                                
                                                                           
                                                                     
                                                                   
  std::basic_string<T> *str_;
};

#endif

}                
}                    

#endif                                   
