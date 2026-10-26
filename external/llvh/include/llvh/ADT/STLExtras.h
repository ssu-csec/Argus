//===- llvm/ADT/STLExtras.h - Useful STL related functions ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains some templates that are useful if you are working with the
// STL at all.
//
// No library is required when using these functions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_STLEXTRAS_H
#define LLVM_ADT_STLEXTRAS_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/iterator.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/Config/abi-breaking.h"
#include "llvh/Support/ErrorHandling.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>

#ifdef EXPENSIVE_CHECKS
#include <random>                    
#endif

namespace llvh {

                                                                          
                                                              
template <typename T, T> struct SameType;

namespace detail {

template <typename RangeT>
using IterOfRange = decltype(std::begin(std::declval<RangeT &>()));

template <typename RangeT>
using ValueOfRange = typename std::remove_reference<decltype(
    *std::begin(std::declval<RangeT &>()))>::type;

}                        

                                                                                
                                       
                                                                                

template <typename T>
struct negation : std::integral_constant<bool, !bool(T::value)> {};

template <typename...> struct conjunction : std::true_type {};
template <typename B1> struct conjunction<B1> : B1 {};
template <typename B1, typename... Bn>
struct conjunction<B1, Bn...>
    : std::conditional<bool(B1::value), conjunction<Bn...>, B1>::type {};

                                                                                
                                      
                                                                                

template <class Ty> struct identity {
  using argument_type = Ty;

  Ty &operator()(Ty &self) const {
    return self;
  }
  const Ty &operator()(const Ty &self) const {
    return self;
  }
};

template <class Ty> struct less_ptr {
  bool operator()(const Ty* left, const Ty* right) const {
    return *left < *right;
  }
};

template <class Ty> struct greater_ptr {
  bool operator()(const Ty* left, const Ty* right) const {
    return *right < *left;
  }
};

                                                                           
                                                                         
                                           
   
                                                                               
                   
template<typename Fn> class function_ref;

template<typename Ret, typename ...Params>
class function_ref<Ret(Params...)> {
  Ret (*callback)(intptr_t callable, Params ...params) = nullptr;
  intptr_t callable;

  template<typename Callable>
  static Ret callback_fn(intptr_t callable, Params ...params) {
    return (*reinterpret_cast<Callable*>(callable))(
        std::forward<Params>(params)...);
  }

public:
  function_ref() = default;
  function_ref(std::nullptr_t) {}

  template <typename Callable>
  function_ref(Callable &&callable,
               typename std::enable_if<
                   !std::is_same<typename std::remove_reference<Callable>::type,
                                 function_ref>::value>::type * = nullptr)
      : callback(callback_fn<typename std::remove_reference<Callable>::type>),
        callable(reinterpret_cast<intptr_t>(&callable)) {}

  Ret operator()(Params ...params) const {
    return callback(callable, std::forward<Params>(params)...);
  }

  operator bool() const { return callback; }
};

                                                                         
                                              
  
                                                     
template <class T>
inline void deleter(T *Ptr) {
  delete Ptr;
}

                                                                                
                                    
                                                                                

namespace adl_detail {

using std::begin;

template <typename ContainerTy>
auto adl_begin(ContainerTy &&container)
    -> decltype(begin(std::forward<ContainerTy>(container))) {
  return begin(std::forward<ContainerTy>(container));
}

using std::end;

template <typename ContainerTy>
auto adl_end(ContainerTy &&container)
    -> decltype(end(std::forward<ContainerTy>(container))) {
  return end(std::forward<ContainerTy>(container));
}

using std::swap;

template <typename T>
void adl_swap(T &&lhs, T &&rhs) noexcept(noexcept(swap(std::declval<T>(),
                                                       std::declval<T>()))) {
  swap(std::forward<T>(lhs), std::forward<T>(rhs));
}

}                            

template <typename ContainerTy>
auto adl_begin(ContainerTy &&container)
    -> decltype(adl_detail::adl_begin(std::forward<ContainerTy>(container))) {
  return adl_detail::adl_begin(std::forward<ContainerTy>(container));
}

template <typename ContainerTy>
auto adl_end(ContainerTy &&container)
    -> decltype(adl_detail::adl_end(std::forward<ContainerTy>(container))) {
  return adl_detail::adl_end(std::forward<ContainerTy>(container));
}

template <typename T>
void adl_swap(T &&lhs, T &&rhs) noexcept(
    noexcept(adl_detail::adl_swap(std::declval<T>(), std::declval<T>()))) {
  adl_detail::adl_swap(std::forward<T>(lhs), std::forward<T>(rhs));
}

                                                                                
                                                            

template <typename ItTy, typename FuncTy,
          typename FuncReturnTy =
            decltype(std::declval<FuncTy>()(*std::declval<ItTy>()))>
class mapped_iterator
    : public iterator_adaptor_base<
             mapped_iterator<ItTy, FuncTy>, ItTy,
             typename std::iterator_traits<ItTy>::iterator_category,
             typename std::remove_reference<FuncReturnTy>::type> {
public:
  mapped_iterator(ItTy U, FuncTy F)
    : mapped_iterator::iterator_adaptor_base(std::move(U)), F(std::move(F)) {}

  ItTy getCurrent() { return this->I; }

  FuncReturnTy operator*() { return F(*this->I); }

private:
  FuncTy F;
};

                                                                                
                                            
template <class ItTy, class FuncTy>
inline mapped_iterator<ItTy, FuncTy> map_iterator(ItTy I, FuncTy F) {
  return mapped_iterator<ItTy, FuncTy>(std::move(I), std::move(F));
}

                                                               
template <typename Ty> class has_rbegin_impl {
  using yes = char[1];
  using no = char[2];

  template <typename Inner>
  static yes& test(Inner *I, decltype(I->rbegin()) * = nullptr);

  template <typename>
  static no& test(...);

public:
  static const bool value = sizeof(test<Ty>(nullptr)) == sizeof(yes);
};

                                                                      
template <typename Ty>
struct has_rbegin : has_rbegin_impl<typename std::remove_reference<Ty>::type> {
};

                                                                                
                                                                              
template <typename ContainerTy>
auto reverse(ContainerTy &&C,
             typename std::enable_if<has_rbegin<ContainerTy>::value>::type * =
                 nullptr) -> decltype(make_range(C.rbegin(), C.rend())) {
  return make_range(C.rbegin(), C.rend());
}

                                                                     
template <typename IteratorTy>
std::reverse_iterator<IteratorTy> make_reverse_iterator(IteratorTy It) {
  return std::reverse_iterator<IteratorTy>(It);
}

                                                                                
                                                                       
                                            
template <typename ContainerTy>
auto reverse(
    ContainerTy &&C,
    typename std::enable_if<!has_rbegin<ContainerTy>::value>::type * = nullptr)
    -> decltype(make_range(llvh::make_reverse_iterator(std::end(C)),
                           llvh::make_reverse_iterator(std::begin(C)))) {
  return make_range(llvh::make_reverse_iterator(std::end(C)),
                    llvh::make_reverse_iterator(std::begin(C)));
}

                                                                           
   
                                                                                
                                                                      
                                                                             
                                    
   
         
                               
                                                                      
                             
            
   
                                                                        
                                                                               
                                                            
template <typename WrappedIteratorT, typename PredicateT, typename IterTag>
class filter_iterator_base
    : public iterator_adaptor_base<
          filter_iterator_base<WrappedIteratorT, PredicateT, IterTag>,
          WrappedIteratorT,
          typename std::common_type<
              IterTag, typename std::iterator_traits<
                           WrappedIteratorT>::iterator_category>::type> {
  using BaseT = iterator_adaptor_base<
      filter_iterator_base<WrappedIteratorT, PredicateT, IterTag>,
      WrappedIteratorT,
      typename std::common_type<
          IterTag, typename std::iterator_traits<
                       WrappedIteratorT>::iterator_category>::type>;

protected:
  WrappedIteratorT End;
  PredicateT Pred;

  void findNextValid() {
    while (this->I != End && !Pred(*this->I))
      BaseT::operator++();
  }

                                                                           
                                                                               
                                                            
  filter_iterator_base(WrappedIteratorT Begin, WrappedIteratorT End,
                       PredicateT Pred)
      : BaseT(Begin), End(End), Pred(Pred) {
    findNextValid();
  }

public:
  using BaseT::operator++;

  filter_iterator_base &operator++() {
    BaseT::operator++();
    findNextValid();
    return *this;
  }
};

                                                                      
template <typename WrappedIteratorT, typename PredicateT,
          typename IterTag = std::forward_iterator_tag>
class filter_iterator_impl
    : public filter_iterator_base<WrappedIteratorT, PredicateT, IterTag> {
  using BaseT = filter_iterator_base<WrappedIteratorT, PredicateT, IterTag>;

public:
  filter_iterator_impl(WrappedIteratorT Begin, WrappedIteratorT End,
                       PredicateT Pred)
      : BaseT(Begin, End, Pred) {}
};

                                                                       
template <typename WrappedIteratorT, typename PredicateT>
class filter_iterator_impl<WrappedIteratorT, PredicateT,
                           std::bidirectional_iterator_tag>
    : public filter_iterator_base<WrappedIteratorT, PredicateT,
                                  std::bidirectional_iterator_tag> {
  using BaseT = filter_iterator_base<WrappedIteratorT, PredicateT,
                                     std::bidirectional_iterator_tag>;
  void findPrevValid() {
    while (!this->Pred(*this->I))
      BaseT::operator--();
  }

public:
  using BaseT::operator--;

  filter_iterator_impl(WrappedIteratorT Begin, WrappedIteratorT End,
                       PredicateT Pred)
      : BaseT(Begin, End, Pred) {}

  filter_iterator_impl &operator--() {
    BaseT::operator--();
    findPrevValid();
    return *this;
  }
};

namespace detail {

template <bool is_bidirectional> struct fwd_or_bidi_tag_impl {
  using type = std::forward_iterator_tag;
};

template <> struct fwd_or_bidi_tag_impl<true> {
  using type = std::bidirectional_iterator_tag;
};

                                                                             
                                                                       
                                         
template <typename IterT> struct fwd_or_bidi_tag {
  using type = typename fwd_or_bidi_tag_impl<std::is_base_of<
      std::bidirectional_iterator_tag,
      typename std::iterator_traits<IterT>::iterator_category>::value>::type;
};

}                    

                                                           
                                                                      
template <typename WrappedIteratorT, typename PredicateT>
using filter_iterator = filter_iterator_impl<
    WrappedIteratorT, PredicateT,
    typename detail::fwd_or_bidi_tag<WrappedIteratorT>::type>;

                                                                        
                                           
   
                                                                           
                                                                                
                                                                               
                                                     
template <typename RangeT, typename PredicateT>
iterator_range<filter_iterator<detail::IterOfRange<RangeT>, PredicateT>>
make_filter_range(RangeT &&Range, PredicateT Pred) {
  using FilterIteratorT =
      filter_iterator<detail::IterOfRange<RangeT>, PredicateT>;
  return make_range(
      FilterIteratorT(std::begin(std::forward<RangeT>(Range)),
                      std::end(std::forward<RangeT>(Range)), Pred),
      FilterIteratorT(std::end(std::forward<RangeT>(Range)),
                      std::end(std::forward<RangeT>(Range)), Pred));
}

                                                                             
                
   
                                                                                
                                                                              
               
   
                                                                          
                                                                   
   
                                                                      
                                                
                                                                               
                            
   
                                                                           
                                           
template <typename WrappedIteratorT>
class early_inc_iterator_impl
    : public iterator_adaptor_base<early_inc_iterator_impl<WrappedIteratorT>,
                                   WrappedIteratorT, std::input_iterator_tag> {
  using BaseT =
      iterator_adaptor_base<early_inc_iterator_impl<WrappedIteratorT>,
                            WrappedIteratorT, std::input_iterator_tag>;

  using PointerT = typename std::iterator_traits<WrappedIteratorT>::pointer;

protected:
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
  bool IsEarlyIncremented = false;
#endif

public:
  early_inc_iterator_impl(WrappedIteratorT I) : BaseT(I) {}

  using BaseT::operator*;
  typename BaseT::reference operator*() {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    assert(!IsEarlyIncremented && "Cannot dereference twice!");
    IsEarlyIncremented = true;
#endif
    return *(this->I)++;
  }

  using BaseT::operator++;
  early_inc_iterator_impl &operator++() {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    assert(IsEarlyIncremented && "Cannot increment before dereferencing!");
    IsEarlyIncremented = false;
#endif
    return *this;
  }

  using BaseT::operator==;
  bool operator==(const early_inc_iterator_impl &RHS) const {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    assert(!IsEarlyIncremented && "Cannot compare after dereferencing!");
#endif
    return BaseT::operator==(RHS);
  }
};

                                                                              
                                       
   
                                                                       
                                                                                
                                                                                
                                            
   
                                                                             
                                                                              
                                                                                
            
template <typename RangeT>
iterator_range<early_inc_iterator_impl<detail::IterOfRange<RangeT>>>
make_early_inc_range(RangeT &&Range) {
  using EarlyIncIteratorT =
      early_inc_iterator_impl<detail::IterOfRange<RangeT>>;
  return make_range(EarlyIncIteratorT(std::begin(std::forward<RangeT>(Range))),
                    EarlyIncIteratorT(std::end(std::forward<RangeT>(Range))));
}

                                                          
template <typename R, typename UnaryPredicate>
bool all_of(R &&range, UnaryPredicate P);

template <size_t... I> struct index_sequence;

template <class... Ts> struct index_sequence_for;

namespace detail {

using std::declval;

                                                                         
                                                                        
template<typename... Iters> struct ZipTupleType {
  using type = std::tuple<decltype(*declval<Iters>())...>;
};

template <typename ZipType, typename... Iters>
using zip_traits = iterator_facade_base<
    ZipType, typename std::common_type<std::bidirectional_iterator_tag,
                                       typename std::iterator_traits<
                                           Iters>::iterator_category...>::type,
                                               
    typename ZipTupleType<Iters...>::type,
    typename std::iterator_traits<typename std::tuple_element<
        0, std::tuple<Iters...>>::type>::difference_type,
                                                                           
                                                                           
                                                                              
                
    typename ZipTupleType<Iters...>::type *,
    typename ZipTupleType<Iters...>::type>;

template <typename ZipType, typename... Iters>
struct zip_common : public zip_traits<ZipType, Iters...> {
  using Base = zip_traits<ZipType, Iters...>;
  using value_type = typename Base::value_type;

  std::tuple<Iters...> iterators;

protected:
  template <size_t... Ns> value_type deref(index_sequence<Ns...>) const {
    return value_type(*std::get<Ns>(iterators)...);
  }

  template <size_t... Ns>
  decltype(iterators) tup_inc(index_sequence<Ns...>) const {
    return std::tuple<Iters...>(std::next(std::get<Ns>(iterators))...);
  }

  template <size_t... Ns>
  decltype(iterators) tup_dec(index_sequence<Ns...>) const {
    return std::tuple<Iters...>(std::prev(std::get<Ns>(iterators))...);
  }

public:
  zip_common(Iters &&... ts) : iterators(std::forward<Iters>(ts)...) {}

  value_type operator*() { return deref(index_sequence_for<Iters...>{}); }

  const value_type operator*() const {
    return deref(index_sequence_for<Iters...>{});
  }

  ZipType &operator++() {
    iterators = tup_inc(index_sequence_for<Iters...>{});
    return *reinterpret_cast<ZipType *>(this);
  }

  ZipType &operator--() {
    static_assert(Base::IsBidirectional,
                  "All inner iterators must be at least bidirectional.");
    iterators = tup_dec(index_sequence_for<Iters...>{});
    return *reinterpret_cast<ZipType *>(this);
  }
};

template <typename... Iters>
struct zip_first : public zip_common<zip_first<Iters...>, Iters...> {
  using Base = zip_common<zip_first<Iters...>, Iters...>;

  bool operator==(const zip_first<Iters...> &other) const {
    return std::get<0>(this->iterators) == std::get<0>(other.iterators);
  }

  zip_first(Iters &&... ts) : Base(std::forward<Iters>(ts)...) {}
};

template <typename... Iters>
class zip_shortest : public zip_common<zip_shortest<Iters...>, Iters...> {
  template <size_t... Ns>
  bool test(const zip_shortest<Iters...> &other, index_sequence<Ns...>) const {
    return all_of(std::initializer_list<bool>{std::get<Ns>(this->iterators) !=
                                              std::get<Ns>(other.iterators)...},
                  identity<bool>{});
  }

public:
  using Base = zip_common<zip_shortest<Iters...>, Iters...>;

  zip_shortest(Iters &&... ts) : Base(std::forward<Iters>(ts)...) {}

  bool operator==(const zip_shortest<Iters...> &other) const {
    return !test(other, index_sequence_for<Iters...>{});
  }
};

template <template <typename...> class ItType, typename... Args> class zippy {
public:
  using iterator = ItType<decltype(std::begin(std::declval<Args>()))...>;
  using iterator_category = typename iterator::iterator_category;
  using value_type = typename iterator::value_type;
  using difference_type = typename iterator::difference_type;
  using pointer = typename iterator::pointer;
  using reference = typename iterator::reference;

private:
  std::tuple<Args...> ts;

  template <size_t... Ns> iterator begin_impl(index_sequence<Ns...>) const {
    return iterator(std::begin(std::get<Ns>(ts))...);
  }
  template <size_t... Ns> iterator end_impl(index_sequence<Ns...>) const {
    return iterator(std::end(std::get<Ns>(ts))...);
  }

public:
  zippy(Args &&... ts_) : ts(std::forward<Args>(ts_)...) {}

  iterator begin() const { return begin_impl(index_sequence_for<Args...>{}); }
  iterator end() const { return end_impl(index_sequence_for<Args...>{}); }
};

}                        

                                                  
template <typename T, typename U, typename... Args>
detail::zippy<detail::zip_shortest, T, U, Args...> zip(T &&t, U &&u,
                                                       Args &&... args) {
  return detail::zippy<detail::zip_shortest, T, U, Args...>(
      std::forward<T>(t), std::forward<U>(u), std::forward<Args>(args)...);
}

                                                                                
                    
template <typename T, typename U, typename... Args>
detail::zippy<detail::zip_first, T, U, Args...> zip_first(T &&t, U &&u,
                                                          Args &&... args) {
  return detail::zippy<detail::zip_first, T, U, Args...>(
      std::forward<T>(t), std::forward<U>(u), std::forward<Args>(args)...);
}

                                                          
   
                                                                             
                                                                      
                                                                             
                                                                   
                                                      
   
                                                                         
                                                           
template <typename ValueT, typename... IterTs>
class concat_iterator
    : public iterator_facade_base<concat_iterator<ValueT, IterTs...>,
                                  std::forward_iterator_tag, ValueT> {
  using BaseT = typename concat_iterator::iterator_facade_base;

                                                                       
                                   
     
                                                                               
                                                                          
                                                              
  std::tuple<IterTs...> Begins;
  std::tuple<IterTs...> Ends;

                                                
     
                                                                             
                                                  
  template <size_t Index> bool incrementHelper() {
    auto &Begin = std::get<Index>(Begins);
    auto &End = std::get<Index>(Ends);
    if (Begin == End)
      return false;

    ++Begin;
    return true;
  }

                                            
     
                                                                
  template <size_t... Ns> void increment(index_sequence<Ns...>) {
                                                                            
    bool (concat_iterator::*IncrementHelperFns[])() = {
        &concat_iterator::incrementHelper<Ns>...};

                                                                          
    for (auto &IncrementHelperFn : IncrementHelperFns)
      if ((this->*IncrementHelperFn)())
        return;

    llvm_unreachable("Attempted to increment an end concat iterator!");
  }

                                                                      
                                                                        
                
  template <size_t Index> ValueT *getHelper() const {
    auto &Begin = std::get<Index>(Begins);
    auto &End = std::get<Index>(Ends);
    if (Begin == End)
      return nullptr;

    return &*Begin;
  }

                                                                               
                
     
                                                                
  template <size_t... Ns> ValueT &get(index_sequence<Ns...>) const {
                                                                      
    ValueT *(concat_iterator::*GetHelperFns[])() const = {
        &concat_iterator::getHelper<Ns>...};

                                                           
    for (auto &GetHelperFn : GetHelperFns)
      if (ValueT *P = (this->*GetHelperFn)())
        return *P;

    llvm_unreachable("Attempted to get a pointer from an end concat iterator!");
  }

public:
                                                      
     
                                                                      
                
  template <typename... RangeTs>
  explicit concat_iterator(RangeTs &&... Ranges)
      : Begins(std::begin(Ranges)...), Ends(std::end(Ranges)...) {}

  using BaseT::operator++;

  concat_iterator &operator++() {
    increment(index_sequence_for<IterTs...>());
    return *this;
  }

  ValueT &operator*() const { return get(index_sequence_for<IterTs...>()); }

  bool operator==(const concat_iterator &RHS) const {
    return Begins == RHS.Begins && Ends == RHS.Ends;
  }
};

namespace detail {

                                                                            
   
                                                                            
                                                                            
                    
template <typename ValueT, typename... RangeTs> class concat_range {
public:
  using iterator =
      concat_iterator<ValueT,
                      decltype(std::begin(std::declval<RangeTs &>()))...>;

private:
  std::tuple<RangeTs...> Ranges;

  template <size_t... Ns> iterator begin_impl(index_sequence<Ns...>) {
    return iterator(std::get<Ns>(Ranges)...);
  }
  template <size_t... Ns> iterator end_impl(index_sequence<Ns...>) {
    return iterator(make_range(std::end(std::get<Ns>(Ranges)),
                               std::end(std::get<Ns>(Ranges)))...);
  }

public:
  concat_range(RangeTs &&... Ranges)
      : Ranges(std::forward<RangeTs>(Ranges)...) {}

  iterator begin() { return begin_impl(index_sequence_for<RangeTs...>{}); }
  iterator end() { return end_impl(index_sequence_for<RangeTs...>{}); }
};

}                        

                                                 
   
                                                        
template <typename ValueT, typename... RangeTs>
detail::concat_range<ValueT, RangeTs...> concat(RangeTs &&... Ranges) {
  static_assert(sizeof...(RangeTs) > 1,
                "Need more than one range to concatenate!");
  return detail::concat_range<ValueT, RangeTs...>(
      std::forward<RangeTs>(Ranges)...);
}

                                                                                
                                   
                                                                                

                                                                       
                                                                
struct less_first {
  template <typename T> bool operator()(const T &lhs, const T &rhs) const {
    return lhs.first < rhs.first;
  }
};

                                                                        
                                                                 
struct less_second {
  template <typename T> bool operator()(const T &lhs, const T &rhs) const {
    return lhs.second < rhs.second;
  }
};

                                                                               
                
template<typename FuncTy>
struct on_first {
  FuncTy func;

  template <typename T>
  auto operator()(const T &lhs, const T &rhs) const
      -> decltype(func(lhs.first, rhs.first)) {
    return func(lhs.first, rhs.first);
  }
};

                                                        

                                                   
template <class T, T... I> struct integer_sequence {
  using value_type = T;

  static constexpr size_t size() { return sizeof...(I); }
};

                                                       
template <size_t... I>
struct index_sequence : integer_sequence<std::size_t, I...> {};

template <std::size_t N, std::size_t... I>
struct build_index_impl : build_index_impl<N - 1, N - 1, I...> {};
template <std::size_t... I>
struct build_index_impl<0, I...> : index_sequence<I...> {};

                                                                 
template <class... Ts>
struct index_sequence_for : build_index_impl<sizeof...(Ts)> {};

                                                                         
                        
template <int N> struct rank : rank<N - 1> {};
template <> struct rank<0> {};

                                                                       
                               
template <typename T, typename... Ts> struct is_one_of {
  static const bool value = false;
};

template <typename T, typename U, typename... Ts>
struct is_one_of<T, U, Ts...> {
  static const bool value =
      std::is_same<T, U>::value || is_one_of<T, Ts...>::value;
};

                                                                    
                                          
template <typename T, typename... Ts> struct are_base_of {
  static const bool value = true;
};

template <typename T, typename U, typename... Ts>
struct are_base_of<T, U, Ts...> {
  static const bool value =
      std::is_base_of<T, U>::value && are_base_of<T, Ts...>::value;
};

                                                                                
                                 
                                                                                

                                
template <class T, std::size_t N>
constexpr inline size_t array_lengthof(T (&)[N]) {
  return N;
}

                                          
template<typename T>
inline int array_pod_sort_comparator(const void *P1, const void *P2) {
  if (std::less<T>()(*reinterpret_cast<const T*>(P1),
                     *reinterpret_cast<const T*>(P2)))
    return -1;
  if (std::less<T>()(*reinterpret_cast<const T*>(P2),
                     *reinterpret_cast<const T*>(P1)))
    return 1;
  return 0;
}

                                                                               
                                  
template<typename T>
inline int (*get_array_pod_sort_comparator(const T &))
             (const void*, const void*) {
  return array_pod_sort_comparator<T>;
}

                                                                         
                                                                               
                                                                            
                                                                           
                                                                             
                                                                             
             
   
                                                                         
                                                                              
                             
   
                                                                          
                         
template<class IteratorTy>
inline void array_pod_sort(IteratorTy Start, IteratorTy End) {
                                                                         
                                     
  auto NElts = End - Start;
  if (NElts <= 1) return;
#ifdef EXPENSIVE_CHECKS
  std::mt19937 Generator(std::random_device{}());
  std::shuffle(Start, End, Generator);
#endif
  qsort(&*Start, NElts, sizeof(*Start), get_array_pod_sort_comparator(*Start));
}

template <class IteratorTy>
inline void array_pod_sort(
    IteratorTy Start, IteratorTy End,
    int (*Compare)(
        const typename std::iterator_traits<IteratorTy>::value_type *,
        const typename std::iterator_traits<IteratorTy>::value_type *)) {
                                                                         
                                     
  auto NElts = End - Start;
  if (NElts <= 1) return;
#ifdef EXPENSIVE_CHECKS
  std::mt19937 Generator(std::random_device{}());
  std::shuffle(Start, End, Generator);
#endif
  qsort(&*Start, NElts, sizeof(*Start),
        reinterpret_cast<int (*)(const void *, const void *)>(Compare));
}

                                                                          
                                                        
template <typename IteratorTy>
inline void sort(IteratorTy Start, IteratorTy End) {
#ifdef EXPENSIVE_CHECKS
  std::mt19937 Generator(std::random_device{}());
  std::shuffle(Start, End, Generator);
#endif
  std::sort(Start, End);
}

template <typename Container> inline void sort(Container &&C) {
  llvh::sort(adl_begin(C), adl_end(C));
}

template <typename IteratorTy, typename Compare>
inline void sort(IteratorTy Start, IteratorTy End, Compare Comp) {
#ifdef EXPENSIVE_CHECKS
  std::mt19937 Generator(std::random_device{}());
  std::shuffle(Start, End, Generator);
#endif
  std::sort(Start, End, Comp);
}

template <typename Container, typename Compare>
inline void sort(Container &&C, Compare Comp) {
  llvh::sort(adl_begin(C), adl_end(C), Comp);
}

                                                                                
                                     
                                                                                

                                                                         
              
template<typename Container>
void DeleteContainerPointers(Container &C) {
  for (auto V : C)
    delete V;
  C.clear();
}

                                                                              
                                                              
template<typename Container>
void DeleteContainerSeconds(Container &C) {
  for (auto &V : C)
    delete V.second;
  C.clear();
}

                                                                            
                                                     
template <typename R>
auto size(R &&Range, typename std::enable_if<
                         std::is_same<typename std::iterator_traits<decltype(
                                          Range.begin())>::iterator_category,
                                      std::random_access_iterator_tag>::value,
                         void>::type * = nullptr)
    -> decltype(std::distance(Range.begin(), Range.end())) {
  return std::distance(Range.begin(), Range.end());
}

                                                                            
                              
template <typename R, typename UnaryPredicate>
UnaryPredicate for_each(R &&Range, UnaryPredicate P) {
  return std::for_each(adl_begin(Range), adl_end(Range), P);
}

                                                                               
                         
template <typename R, typename UnaryPredicate>
bool all_of(R &&Range, UnaryPredicate P) {
  return std::all_of(adl_begin(Range), adl_end(Range), P);
}

                                                                               
                         
template <typename R, typename UnaryPredicate>
bool any_of(R &&Range, UnaryPredicate P) {
  return std::any_of(adl_begin(Range), adl_end(Range), P);
}

                                                                                
                         
template <typename R, typename UnaryPredicate>
bool none_of(R &&Range, UnaryPredicate P) {
  return std::none_of(adl_begin(Range), adl_end(Range), P);
}

                                                                             
                         
template <typename R, typename T>
auto find(R &&Range, const T &Val) -> decltype(adl_begin(Range)) {
  return std::find(adl_begin(Range), adl_end(Range), Val);
}

                                                                                
                         
template <typename R, typename UnaryPredicate>
auto find_if(R &&Range, UnaryPredicate P) -> decltype(adl_begin(Range)) {
  return std::find_if(adl_begin(Range), adl_end(Range), P);
}

template <typename R, typename UnaryPredicate>
auto find_if_not(R &&Range, UnaryPredicate P) -> decltype(adl_begin(Range)) {
  return std::find_if_not(adl_begin(Range), adl_end(Range), P);
}

                                                                             
                              
template <typename R, typename UnaryPredicate>
auto remove_if(R &&Range, UnaryPredicate P) -> decltype(adl_begin(Range)) {
  return std::remove_if(adl_begin(Range), adl_end(Range), P);
}

                                                                           
                              
template <typename R, typename OutputIt, typename UnaryPredicate>
OutputIt copy_if(R &&Range, OutputIt Out, UnaryPredicate P) {
  return std::copy_if(adl_begin(Range), adl_end(Range), Out, P);
}

template <typename R, typename OutputIt>
OutputIt copy(R &&Range, OutputIt Out) {
  return std::copy(adl_begin(Range), adl_end(Range), Out);
}

                                                                    
                   
template <typename R, typename E>
bool is_contained(R &&Range, const E &Element) {
  return std::find(adl_begin(Range), adl_end(Range), Element) != adl_end(Range);
}

                                                                              
                                                  
template <typename R, typename E>
auto count(R &&Range, const E &Element) ->
    typename std::iterator_traits<decltype(adl_begin(Range))>::difference_type {
  return std::count(adl_begin(Range), adl_end(Range), Element);
}

                                                                         
                                                           
template <typename R, typename UnaryPredicate>
auto count_if(R &&Range, UnaryPredicate P) ->
    typename std::iterator_traits<decltype(adl_begin(Range))>::difference_type {
  return std::count_if(adl_begin(Range), adl_end(Range), P);
}

                                                                             
                               
template <typename R, typename OutputIt, typename UnaryPredicate>
OutputIt transform(R &&Range, OutputIt d_first, UnaryPredicate P) {
  return std::transform(adl_begin(Range), adl_end(Range), d_first, P);
}

                                                                             
                              
template <typename R, typename UnaryPredicate>
auto partition(R &&Range, UnaryPredicate P) -> decltype(adl_begin(Range)) {
  return std::partition(adl_begin(Range), adl_end(Range), P);
}

                                                                               
                              
template <typename R, typename ForwardIt>
auto lower_bound(R &&Range, ForwardIt I) -> decltype(adl_begin(Range)) {
  return std::lower_bound(adl_begin(Range), adl_end(Range), I);
}

template <typename R, typename ForwardIt, typename Compare>
auto lower_bound(R &&Range, ForwardIt I, Compare C)
    -> decltype(adl_begin(Range)) {
  return std::lower_bound(adl_begin(Range), adl_end(Range), I, C);
}

                                                                               
                              
template <typename R, typename ForwardIt>
auto upper_bound(R &&Range, ForwardIt I) -> decltype(adl_begin(Range)) {
  return std::upper_bound(adl_begin(Range), adl_end(Range), I);
}

template <typename R, typename ForwardIt, typename Compare>
auto upper_bound(R &&Range, ForwardIt I, Compare C)
    -> decltype(adl_begin(Range)) {
  return std::upper_bound(adl_begin(Range), adl_end(Range), I, C);
}
                                                                
                            
template <typename R>
bool is_splat(R &&Range) {
  size_t range_size = size(Range);
  return range_size != 0 && (range_size == 1 ||
         std::equal(adl_begin(Range) + 1, adl_end(Range), adl_begin(Range)));
}

                                                                  
                                                                          
                                                               
template <unsigned Size, typename R>
SmallVector<typename std::remove_const<detail::ValueOfRange<R>>::type, Size>
to_vector(R &&Range) {
  return {adl_begin(Range), adl_end(Range)};
}

                                                                          
                                      
   
                                           
   
                                                                            
                  
template <typename Container, typename UnaryPredicate>
void erase_if(Container &C, UnaryPredicate P) {
  C.erase(remove_if(C, P), C.end());
}

                                                                                
                                  
                                                                                

                                            

                                                            
                                                 
   
            
   
                                    
                                                         
template <class T, class... Args>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type
make_unique(Args &&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

                                                             
                                                   
   
                                   
   
            
   
                                                                                
template <class T>
typename std::enable_if<std::is_array<T>::value && std::extent<T>::value == 0,
                        std::unique_ptr<T>>::type
make_unique(size_t n) {
  return std::unique_ptr<T>(new typename std::remove_extent<T>::type[n]());
}

                                                                               
template <class T, class... Args>
typename std::enable_if<std::extent<T>::value != 0>::type
make_unique(Args &&...) = delete;

struct FreeDeleter {
  void operator()(void* v) {
    ::free(v);
  }
};

template<typename First, typename Second>
struct pair_hash {
  size_t operator()(const std::pair<First, Second> &P) const {
    return std::hash<First>()(P.first) * 31 + std::hash<Second>()(P.second);
  }
};

                                                          
struct less {
  template <typename A, typename B> bool operator()(A &&a, B &&b) const {
    return std::forward<A>(a) < std::forward<B>(b);
  }
};

                                                           
struct equal {
  template <typename A, typename B> bool operator()(A &&a, B &&b) const {
    return std::forward<A>(a) == std::forward<B>(b);
  }
};

                                                                              
             
template <typename T> struct deref {
  T func;

                                                                      
                                                                       
                 
  template <typename A, typename B>
  auto operator()(A &lhs, B &rhs) const -> decltype(func(*lhs, *rhs)) {
    assert(lhs);
    assert(rhs);
    return func(*lhs, *rhs);
  }
};

namespace detail {

template <typename R> class enumerator_iter;

template <typename R> struct result_pair {
  friend class enumerator_iter<R>;

  result_pair() = default;
  result_pair(std::size_t Index, IterOfRange<R> Iter)
      : Index(Index), Iter(Iter) {}

  result_pair<R> &operator=(const result_pair<R> &Other) {
    Index = Other.Index;
    Iter = Other.Iter;
    return *this;
  }

  std::size_t index() const { return Index; }
  const ValueOfRange<R> &value() const { return *Iter; }
  ValueOfRange<R> &value() { return *Iter; }

private:
  std::size_t Index = std::numeric_limits<std::size_t>::max();
  IterOfRange<R> Iter;
};

template <typename R>
class enumerator_iter
    : public iterator_facade_base<
          enumerator_iter<R>, std::forward_iterator_tag, result_pair<R>,
          typename std::iterator_traits<IterOfRange<R>>::difference_type,
          typename std::iterator_traits<IterOfRange<R>>::pointer,
          typename std::iterator_traits<IterOfRange<R>>::reference> {
  using result_type = result_pair<R>;

public:
  explicit enumerator_iter(IterOfRange<R> EndIter)
      : Result(std::numeric_limits<size_t>::max(), EndIter) {}

  enumerator_iter(std::size_t Index, IterOfRange<R> Iter)
      : Result(Index, Iter) {}

  result_type &operator*() { return Result; }
  const result_type &operator*() const { return Result; }

  enumerator_iter<R> &operator++() {
    assert(Result.Index != std::numeric_limits<size_t>::max());
    ++Result.Iter;
    ++Result.Index;
    return *this;
  }

  bool operator==(const enumerator_iter<R> &RHS) const {
                                                                            
                                                                             
                                                                  
    return Result.Iter == RHS.Result.Iter;
  }

  enumerator_iter<R> &operator=(const enumerator_iter<R> &Other) {
    Result = Other.Result;
    return *this;
  }

private:
  result_type Result;
};

template <typename R> class enumerator {
public:
  explicit enumerator(R &&Range) : TheRange(std::forward<R>(Range)) {}

  enumerator_iter<R> begin() {
    return enumerator_iter<R>(0, std::begin(TheRange));
  }

  enumerator_iter<R> end() {
    return enumerator_iter<R>(std::end(TheRange));
  }

private:
  R TheRange;
};

}                        

                                                                             
                                                                          
                                                   
   
                                                   
                                     
                                                     
     
   
           
                
                
                
                
   
template <typename R> detail::enumerator<R> enumerate(R &&TheRange) {
  return detail::enumerator<R>(std::forward<R>(TheRange));
}

namespace detail {

template <typename F, typename Tuple, std::size_t... I>
auto apply_tuple_impl(F &&f, Tuple &&t, index_sequence<I...>)
    -> decltype(std::forward<F>(f)(std::get<I>(std::forward<Tuple>(t))...)) {
  return std::forward<F>(f)(std::get<I>(std::forward<Tuple>(t))...);
}

}                        

                                                                     
                                                                   
                      
template <typename F, typename Tuple>
auto apply_tuple(F &&f, Tuple &&t) -> decltype(detail::apply_tuple_impl(
    std::forward<F>(f), std::forward<Tuple>(t),
    build_index_impl<
        std::tuple_size<typename std::decay<Tuple>::type>::value>{})) {
  using Indices = build_index_impl<
      std::tuple_size<typename std::decay<Tuple>::type>::value>;

  return detail::apply_tuple_impl(std::forward<F>(f), std::forward<Tuple>(t),
                                  Indices{});
}

}                      

#endif                        
