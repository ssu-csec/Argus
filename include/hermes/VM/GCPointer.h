/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_GCPOINTER_H
#define HERMES_VM_GCPOINTER_H

#include "hermes/Support/Compiler.h"
#include "hermes/VM/Casting.h"
#include "hermes/VM/CompressedPointer.h"
#include "hermes/VM/GCDecl.h"

#include <cassert>
#include <cstddef>
#include <type_traits>

namespace hermes {
namespace vm {

class GCPointerBase : public CompressedPointer {
 protected:
  explicit GCPointerBase(std::nullptr_t) : CompressedPointer(nullptr) {}

  template <typename NeedsBarriers>
  inline GCPointerBase(PointerBase &base, GCCell *ptr, GC &gc, NeedsBarriers);

 public:
                                                                      
                                                                      
               
  class NoBarriers : public std::false_type {};
  class YesBarriers : public std::true_type {};

                                                                
                                             
                                  
                                        
  inline void set(PointerBase &base, GCCell *ptr, GC &gc);
  inline void set(PointerBase &base, CompressedPointer ptr, GC &gc);
  inline void setNonNull(PointerBase &base, GCCell *ptr, GC &gc);

                                                                           
                         
  inline void setNull(GC &gc);
};

                                                                               
                                                                   
template <typename T>
class GCPointer : public GCPointerBase {
 public:
                                                           
  GCPointer() : GCPointerBase(nullptr) {}
                                                                     
  GCPointer(std::nullptr_t) : GCPointerBase(nullptr) {}

                                                                                
                                                                   
                                                                              
                                     
  template <typename NeedsBarriers>
  GCPointer(PointerBase &base, T *ptr, GC &gc, NeedsBarriers needsBarriers)
      : GCPointerBase(base, ptr, gc, needsBarriers) {}

                                                         
                                                                     
                                           
  inline GCPointer(PointerBase &base, T *ptr, GC &gc)
      : GCPointer<T>(base, ptr, gc, YesBarriers()) {}

                                                                
  GCPointer(const GCPointerBase &) = delete;
  GCPointer &operator=(const GCPointerBase &) = delete;
  GCPointer(const GCPointer<T> &) = delete;
  GCPointer &operator=(const GCPointer<T> &) = delete;

                                
                                                                               
  T *get(PointerBase &base) const {
    return vmcast_or_null<T>(GCPointerBase::get(base));
  }
  T *getNonNull(PointerBase &base) const {
    return vmcast<T>(GCPointerBase::getNonNull(base));
  }

                                           
                                  
                                             
                                        
  void set(PointerBase &base, T *ptr, GC &gc) {
    GCPointerBase::set(base, ptr, gc);
  }
  void setNonNull(PointerBase &base, T *ptr, GC &gc) {
    GCPointerBase::setNonNull(base, ptr, gc);
  }

                                                                  
  void set(PointerBase &base, const GCPointer<T> &ptr, GC &gc) {
    GCPointerBase::set(base, ptr, gc);
  }
};

}                
}                    

#endif                         
