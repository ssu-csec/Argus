/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_CASTING_H
#define HERMES_VM_CASTING_H

#include "hermes/VM/GCCell.h"
#include "hermes/VM/HermesValue.h"

#include "llvh/Support/Casting.h"

#include <cassert>

namespace hermes {
namespace vm {

                 
                                                                     
                                    
      

                                                                          
                                       
template <class ToType>
ToType *vmcast(GCCell *cell) {
  return llvh::cast<ToType>(cell);
}

                            
template <class ToType>
const ToType *vmcast(const GCCell *cell) {
  return llvh::cast<ToType>(cell);
}

                                                                            
                                       
template <class ToType>
ToType *vmcast(HermesValue val) {
  assert(val.isPointer() && "vmcast with non-pointer");
  return vmcast<ToType>(static_cast<GCCell *>(val.getPointer()));
}

                                                           
template <class ToType>
ToType *vmcast_or_null(GCCell *cell) {
#ifndef NDEBUG
  return llvh::cast_or_null<ToType>(cell);
#else
                                                           
  return static_cast<ToType *>(cell);
#endif
}

                                                           
template <class ToType>
ToType *vmcast_or_null(HermesValue val) {
  assert(val.isPointer() && "vmcast with non-pointer");
  return vmcast_or_null<ToType>(static_cast<GCCell *>(val.getPointer()));
}

                                                                              
                                        
template <class ToType>
ToType *dyn_vmcast(GCCell *cell) {
  return llvh::dyn_cast<ToType>(cell);
}

                                
template <class ToType>
const ToType *dyn_vmcast(const GCCell *cell) {
  return llvh::dyn_cast<ToType>(cell);
}

                                                                                
                                                
template <class ToType>
ToType *dyn_vmcast(HermesValue val) {
  return val.isPointer()
      ? dyn_vmcast<ToType>(static_cast<GCCell *>(val.getPointer()))
      : nullptr;
}

                                                               
template <class ToType>
ToType *dyn_vmcast_or_null(GCCell *cell) {
  return llvh::dyn_cast_or_null<ToType>(cell);
}

                                                               
template <class ToType>
ToType *dyn_vmcast_or_null(HermesValue val) {
  return val.isPointer()
      ? dyn_vmcast_or_null<ToType>(static_cast<GCCell *>(val.getPointer()))
      : nullptr;
}

                                                      
template <class ToType>
bool vmisa(HermesValue val) {
  return val.isPointer() &&
      llvh::isa<ToType>(static_cast<GCCell *>(val.getPointer()));
}

                                                                  
template <class ToType>
bool vmisa(GCCell *cell) {
  return llvh::isa<ToType>(cell);
}

                           
template <class ToType>
bool vmisa(const GCCell *cell) {
  return llvh::isa<ToType>(cell);
}

      

}                
}                    

#endif                       
