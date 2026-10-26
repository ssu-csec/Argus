//===- ArrayRef.h - Array Reference Wrapper ---------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_ARRAYREF_H
#define LLVM_ADT_ARRAYREF_H

#include "llvh/ADT/Hashing.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/Support/Compiler.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <type_traits>
#include <vector>

namespace llvh {

                                                                               
                                                                             
                                                                        
     
                                                                               
                                                                            
                                                                              
                                
     
                                                                          
            
  template<typename T>
  class LLVM_NODISCARD ArrayRef {
  public:
    using iterator = const T *;
    using const_iterator = const T *;
    using size_type = size_t;
    using reverse_iterator = std::reverse_iterator<iterator>;

  private:
                                                      
    const T *Data = nullptr;

                               
    size_type Length = 0;

  public:
                          
          

                                    
                 ArrayRef() = default;

                                              
                 ArrayRef(NoneType) {}

                                                    
                 ArrayRef(const T &OneElt)
      : Data(&OneElt), Length(1) {}

                                                        
                 ArrayRef(const T *data, size_t length)
      : Data(data), Length(length) {}

                                           
    ArrayRef(const T *begin, const T *end)
      : Data(begin), Length(end - begin) {}

                                                                               
                                                                    
                                   
    template<typename U>
                 ArrayRef(const SmallVectorTemplateCommon<T, U> &Vec)
      : Data(Vec.data()), Length(Vec.size()) {
    }

                                                 
    template<typename A>
                 ArrayRef(const std::vector<T, A> &Vec)
      : Data(Vec.data()), Length(Vec.size()) {}

                                               
    template <size_t N>
                 constexpr ArrayRef(const std::array<T, N> &Arr)
        : Data(Arr.data()), Length(N) {}

                                             
    template <size_t N>
                 constexpr ArrayRef(const T (&Arr)[N]) : Data(Arr), Length(N) {}

                                                           
                 ArrayRef(const std::initializer_list<T> &Vec)
    : Data(Vec.begin() == Vec.end() ? (T*)nullptr : Vec.begin()),
      Length(Vec.size()) {}

                                                                              
                                                                
    template <typename U>
    ArrayRef(
        const ArrayRef<U *> &A,
        typename std::enable_if<
           std::is_convertible<U *const *, T const *>::value>::type * = nullptr)
      : Data(A.data()), Length(A.size()) {}

                                                                       
                                                                              
                                               
    template<typename U, typename DummyT>
                 ArrayRef(
      const SmallVectorTemplateCommon<U *, DummyT> &Vec,
      typename std::enable_if<
          std::is_convertible<U *const *, T const *>::value>::type * = nullptr)
      : Data(Vec.data()), Length(Vec.size()) {
    }

                                                                              
                                                                 
    template<typename U, typename A>
    ArrayRef(const std::vector<U *, A> &Vec,
             typename std::enable_if<
                 std::is_convertible<U *const *, T const *>::value>::type* = 0)
      : Data(Vec.data()), Length(Vec.size()) {}

          
                               
          

    iterator begin() const { return Data; }
    iterator end() const { return Data + Length; }

    reverse_iterator rbegin() const { return reverse_iterator(end()); }
    reverse_iterator rend() const { return reverse_iterator(begin()); }

                                            
    bool empty() const { return Length == 0; }

    const T *data() const { return Data; }

                                  
    size_t size() const { return Length; }

                                      
    const T &front() const {
      assert(!empty());
      return Data[0];
    }

                                    
    const T &back() const {
      assert(!empty());
      return Data[Length-1];
    }

                                                                      
    template <typename Allocator> ArrayRef<T> copy(Allocator &A) {
      T *Buff = A.template Allocate<T>(Length);
      std::uninitialized_copy(begin(), end(), Buff);
      return ArrayRef<T>(Buff, Length);
    }

                                                 
    bool equals(ArrayRef RHS) const {
      if (Length != RHS.Length)
        return false;
      return std::equal(begin(), end(), RHS.begin());
    }

                                                                            
                              
    ArrayRef<T> slice(size_t N, size_t M) const {
      assert(N+M <= size() && "Invalid specifier");
      return ArrayRef<T>(data()+N, M);
    }

                                                              
    ArrayRef<T> slice(size_t N) const { return slice(N, size() - N); }

                                                  
    ArrayRef<T> drop_front(size_t N = 1) const {
      assert(size() >= N && "Dropping more elements than exist");
      return slice(N, size() - N);
    }

                                                 
    ArrayRef<T> drop_back(size_t N = 1) const {
      assert(size() >= N && "Dropping more elements than exist");
      return slice(0, size() - N);
    }

                                                                       
                                
    template <class PredicateT> ArrayRef<T> drop_while(PredicateT Pred) const {
      return ArrayRef<T>(find_if_not(*this, Pred), end());
    }

                                                                       
                                    
    template <class PredicateT> ArrayRef<T> drop_until(PredicateT Pred) const {
      return ArrayRef<T>(find_if(*this, Pred), end());
    }

                                                                 
    ArrayRef<T> take_front(size_t N = 1) const {
      if (N >= size())
        return *this;
      return drop_back(size() - N);
    }

                                                                
    ArrayRef<T> take_back(size_t N = 1) const {
      if (N >= size())
        return *this;
      return drop_front(size() - N);
    }

                                                                        
                  
    template <class PredicateT> ArrayRef<T> take_while(PredicateT Pred) const {
      return ArrayRef<T>(begin(), find_if_not(*this, Pred));
    }

                                                                        
                        
    template <class PredicateT> ArrayRef<T> take_until(PredicateT Pred) const {
      return ArrayRef<T>(begin(), find_if(*this, Pred));
    }

          
                                
          
    const T &operator[](size_t Index) const {
      assert(Index < Length && "Invalid index!");
      return Data[Index];
    }

                                                        
       
                                                                         
                                                         
    template <typename U>
    typename std::enable_if<std::is_same<U, T>::value, ArrayRef<T>>::type &
    operator=(U &&Temporary) = delete;

                                                        
       
                                                                         
                                                         
    template <typename U>
    typename std::enable_if<std::is_same<U, T>::value, ArrayRef<T>>::type &
    operator=(std::initializer_list<U>) = delete;

          
                                  
          
    std::vector<T> vec() const {
      return std::vector<T>(Data, Data+Length);
    }

          
                                  
          
    operator std::vector<T>() const {
      return std::vector<T>(Data, Data+Length);
    }

          
  };

                                                                            
                                                                               
                                                                            
                   
     
                                                                               
                                                                            
                                                                             
                                              
     
                                                                          
            
  template<typename T>
  class LLVM_NODISCARD MutableArrayRef : public ArrayRef<T> {
  public:
    using iterator = T *;
    using reverse_iterator = std::reverse_iterator<iterator>;

                                           
                 MutableArrayRef() = default;

                                                     
                 MutableArrayRef(NoneType) : ArrayRef<T>() {}

                                                           
                 MutableArrayRef(T &OneElt) : ArrayRef<T>(OneElt) {}

                                                               
                 MutableArrayRef(T *data, size_t length)
      : ArrayRef<T>(data, length) {}

                                                  
    MutableArrayRef(T *begin, T *end) : ArrayRef<T>(begin, end) {}

                                                        
                 MutableArrayRef(SmallVectorImpl<T> &Vec)
    : ArrayRef<T>(Vec) {}

                                                       
                 MutableArrayRef(std::vector<T> &Vec)
    : ArrayRef<T>(Vec) {}

                                               
    template <size_t N>
                 constexpr MutableArrayRef(std::array<T, N> &Arr)
        : ArrayRef<T>(Arr) {}

                                                    
    template <size_t N>
                 constexpr MutableArrayRef(T (&Arr)[N]) : ArrayRef<T>(Arr) {}

    T *data() const { return const_cast<T*>(ArrayRef<T>::data()); }

    iterator begin() const { return data(); }
    iterator end() const { return data() + this->size(); }

    reverse_iterator rbegin() const { return reverse_iterator(end()); }
    reverse_iterator rend() const { return reverse_iterator(begin()); }

                                      
    T &front() const {
      assert(!this->empty());
      return data()[0];
    }

                                    
    T &back() const {
      assert(!this->empty());
      return data()[this->size()-1];
    }

                                                                            
                              
    MutableArrayRef<T> slice(size_t N, size_t M) const {
      assert(N + M <= this->size() && "Invalid specifier");
      return MutableArrayRef<T>(this->data() + N, M);
    }

                                                              
    MutableArrayRef<T> slice(size_t N) const {
      return slice(N, this->size() - N);
    }

                                                  
    MutableArrayRef<T> drop_front(size_t N = 1) const {
      assert(this->size() >= N && "Dropping more elements than exist");
      return slice(N, this->size() - N);
    }

    MutableArrayRef<T> drop_back(size_t N = 1) const {
      assert(this->size() >= N && "Dropping more elements than exist");
      return slice(0, this->size() - N);
    }

                                                                       
                                
    template <class PredicateT>
    MutableArrayRef<T> drop_while(PredicateT Pred) const {
      return MutableArrayRef<T>(find_if_not(*this, Pred), end());
    }

                                                                       
                                    
    template <class PredicateT>
    MutableArrayRef<T> drop_until(PredicateT Pred) const {
      return MutableArrayRef<T>(find_if(*this, Pred), end());
    }

                                                                 
    MutableArrayRef<T> take_front(size_t N = 1) const {
      if (N >= this->size())
        return *this;
      return drop_back(this->size() - N);
    }

                                                                
    MutableArrayRef<T> take_back(size_t N = 1) const {
      if (N >= this->size())
        return *this;
      return drop_front(this->size() - N);
    }

                                                                        
                  
    template <class PredicateT>
    MutableArrayRef<T> take_while(PredicateT Pred) const {
      return MutableArrayRef<T>(begin(), find_if_not(*this, Pred));
    }

                                                                        
                        
    template <class PredicateT>
    MutableArrayRef<T> take_until(PredicateT Pred) const {
      return MutableArrayRef<T>(begin(), find_if(*this, Pred));
    }

          
                                
          
    T &operator[](size_t Index) const {
      assert(Index < this->size() && "Invalid index!");
      return data()[Index];
    }
  };

                                                    
  template <typename T> class OwningArrayRef : public MutableArrayRef<T> {
  public:
    OwningArrayRef() = default;
    OwningArrayRef(size_t Size) : MutableArrayRef<T>(new T[Size], Size) {}

    OwningArrayRef(ArrayRef<T> Data)
        : MutableArrayRef<T>(new T[Data.size()], Data.size()) {
      std::copy(Data.begin(), Data.end(), this->begin());
    }

    OwningArrayRef(OwningArrayRef &&Other) { *this = Other; }

    OwningArrayRef &operator=(OwningArrayRef &&Other) {
      delete[] this->data();
      this->MutableArrayRef<T>::operator=(Other);
      Other.MutableArrayRef<T>::operator=(MutableArrayRef<T>());
      return *this;
    }

    ~OwningArrayRef() { delete[] this->data(); }
  };

                                             
        

                                                  
  template<typename T>
  ArrayRef<T> makeArrayRef(const T &OneElt) {
    return OneElt;
  }

                                                      
  template<typename T>
  ArrayRef<T> makeArrayRef(const T *data, size_t length) {
    return ArrayRef<T>(data, length);
  }

                                         
  template<typename T>
  ArrayRef<T> makeArrayRef(const T *begin, const T *end) {
    return ArrayRef<T>(begin, end);
  }

                                               
  template <typename T>
  ArrayRef<T> makeArrayRef(const SmallVectorImpl<T> &Vec) {
    return Vec;
  }

                                               
  template <typename T, unsigned N>
  ArrayRef<T> makeArrayRef(const SmallVector<T, N> &Vec) {
    return Vec;
  }

                                               
  template<typename T>
  ArrayRef<T> makeArrayRef(const std::vector<T> &Vec) {
    return Vec;
  }

                                                            
  template <typename T> ArrayRef<T> makeArrayRef(const ArrayRef<T> &Vec) {
    return Vec;
  }

                                                    
  template <typename T> ArrayRef<T> &makeArrayRef(ArrayRef<T> &Vec) {
    return Vec;
  }

                                           
  template<typename T, size_t N>
  ArrayRef<T> makeArrayRef(const T (&Arr)[N]) {
    return ArrayRef<T>(Arr);
  }

                                                        
  template<typename T>
  MutableArrayRef<T> makeMutableArrayRef(T &OneElt) {
    return OneElt;
  }

                                                            
  template<typename T>
  MutableArrayRef<T> makeMutableArrayRef(T *data, size_t length) {
    return MutableArrayRef<T>(data, length);
  }

        
                                         
        

  template<typename T>
  inline bool operator==(ArrayRef<T> LHS, ArrayRef<T> RHS) {
    return LHS.equals(RHS);
  }

  template<typename T>
  inline bool operator!=(ArrayRef<T> LHS, ArrayRef<T> RHS) {
    return !(LHS == RHS);
  }

        

                                              
  template <typename T> struct isPodLike;
  template <typename T> struct isPodLike<ArrayRef<T>> {
    static const bool value = true;
  };

  template <typename T> hash_code hash_value(ArrayRef<T> S) {
    return hash_combine_range(S.begin(), S.end());
  }

}                      

#endif                       
