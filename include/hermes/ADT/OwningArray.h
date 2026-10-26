/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_ADT_OWNINGARRAY_H
#define HERMES_ADT_OWNINGARRAY_H

#include "llvh/ADT/ArrayRef.h"

namespace hermes {

                                                                     
                                                                         
                                              
template <typename T>
class OwningArray : public llvh::OwningArrayRef<T> {
 public:
  using llvh::OwningArrayRef<T>::OwningArrayRef;
                                                            
  OwningArray() = default;
                                                                             
                                                      
  OwningArray(OwningArray &&Other) {
    *this = std::move(Other);
  }
  OwningArray &operator=(OwningArray &&Other) {
    llvh::OwningArrayRef<T>::operator=(std::move(Other));
    return *this;
  }
};

}                    

#endif
