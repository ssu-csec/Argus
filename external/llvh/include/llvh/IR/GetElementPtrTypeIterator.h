//===- GetElementPtrTypeIterator.h ------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements an iterator for walking through the types indexed by
// getelementptr instructions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_GETELEMENTPTRTYPEITERATOR_H
#define LLVM_IR_GETELEMENTPTRTYPEITERATOR_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/PointerUnion.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/Operator.h"
#include "llvh/IR/User.h"
#include "llvh/Support/Casting.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>

namespace llvh {

  template <typename ItTy = User::const_op_iterator>
  class generic_gep_type_iterator {

    ItTy OpIt;
    PointerUnion<StructType *, Type *> CurTy;

    generic_gep_type_iterator() = default;

  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = Type *;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    static generic_gep_type_iterator begin(Type *Ty, ItTy It) {
      generic_gep_type_iterator I;
      I.CurTy = Ty;
      I.OpIt = It;
      return I;
    }

    bool operator==(const generic_gep_type_iterator& x) const {
      return OpIt == x.OpIt;
    }

    bool operator!=(const generic_gep_type_iterator& x) const {
      return !operator==(x);
    }

                                                                         
                                                                        
                                                                            
                       
    Type *getIndexedType() const {
      if (auto *T = CurTy.dyn_cast<Type *>())
        return T;
      return CurTy.get<StructType *>()->getTypeAtIndex(getOperand());
    }

    Value *getOperand() const { return const_cast<Value *>(&**OpIt); }

    generic_gep_type_iterator& operator++() {                  
      Type *Ty = getIndexedType();
      if (auto *STy = dyn_cast<SequentialType>(Ty)) {
        CurTy = STy->getElementType();
        NumElements = STy->getNumElements();
      } else
        CurTy = dyn_cast<StructType>(Ty);
      ++OpIt;
      return *this;
    }

    generic_gep_type_iterator operator++(int) {                 
      generic_gep_type_iterator tmp = *this; ++*this; return tmp;
    }

                                                                                
                                                                             
                                                                               
                                                                               
                                                                       
                                                                           
                                                   
      
                                                                          
                                                                             
                                                                           
                                                                                
                                                                                
            

    bool isStruct() const { return CurTy.is<StructType *>(); }
    bool isSequential() const { return CurTy.is<Type *>(); }

    StructType *getStructType() const { return CurTy.get<StructType *>(); }

    StructType *getStructTypeOrNull() const {
      return CurTy.dyn_cast<StructType *>();
    }

    bool isBoundedSequential() const {
      return isSequential() && NumElements != Unbounded;
    }

    uint64_t getSequentialNumElements() const {
      assert(isBoundedSequential());
      return NumElements;
    }
  };

  using gep_type_iterator = generic_gep_type_iterator<>;

  inline gep_type_iterator gep_type_begin(const User *GEP) {
    auto *GEPOp = cast<GEPOperator>(GEP);
    return gep_type_iterator::begin(
        GEPOp->getSourceElementType(),
        GEP->op_begin() + 1);
  }

  inline gep_type_iterator gep_type_end(const User *GEP) {
    return gep_type_iterator::end(GEP->op_end());
  }

  inline gep_type_iterator gep_type_begin(const User &GEP) {
    auto &GEPOp = cast<GEPOperator>(GEP);
    return gep_type_iterator::begin(
        GEPOp.getSourceElementType(),
        GEP.op_begin() + 1);
  }

  inline gep_type_iterator gep_type_end(const User &GEP) {
    return gep_type_iterator::end(GEP.op_end());
  }

  template<typename T>
  inline generic_gep_type_iterator<const T *>
  gep_type_begin(Type *Op0, ArrayRef<T> A) {
    return generic_gep_type_iterator<const T *>::begin(Op0, A.begin());
  }

  template<typename T>
  inline generic_gep_type_iterator<const T *>
  gep_type_end(Type *        , ArrayRef<T> A) {
    return generic_gep_type_iterator<const T *>::end(A.end());
  }

}                      

#endif                                       
