//===-- llvm/Support/MathExtras.h - Useful math functions -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains some functions that are useful for math stuff.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_MATHEXTRAS_H
#define LLVM_SUPPORT_MATHEXTRAS_H

#include "llvh/Support/Compiler.h"
#include "llvh/Support/SwapByteOrder.h"
#include <algorithm>
#include <cassert>
#include <climits>
#include <cstring>
#include <limits>
#include <type_traits>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

#ifdef __ANDROID_NDK__
#include <android/api-level.h>
#endif

#ifdef _MSC_VER
                                                                         
                                          
                      
extern "C" {
unsigned char _BitScanForward(unsigned long *_Index, unsigned long _Mask);
unsigned char _BitScanForward64(unsigned long *_Index, unsigned __int64 _Mask);
unsigned char _BitScanReverse(unsigned long *_Index, unsigned long _Mask);
unsigned char _BitScanReverse64(unsigned long *_Index, unsigned __int64 _Mask);
}
#endif

namespace llvh {
                                                   
enum ZeroBehavior {
                                      
  ZB_Undefined,
                                                    
  ZB_Max,
                                                     
  ZB_Width
};

namespace detail {
template <typename T, std::size_t SizeOfT> struct TrailingZerosCounter {
  static std::size_t count(T Val, ZeroBehavior) {
    if (!Val)
      return std::numeric_limits<T>::digits;
    if (Val & 0x1)
      return 0;

                        
    std::size_t ZeroBits = 0;
    T Shift = std::numeric_limits<T>::digits >> 1;
    T Mask = std::numeric_limits<T>::max() >> Shift;
    while (Shift) {
      if ((Val & Mask) == 0) {
        Val >>= Shift;
        ZeroBits |= Shift;
      }
      Shift >>= 1;
      Mask >>= Shift;
    }
    return ZeroBits;
  }
};

#if __GNUC__ >= 4 || defined(_MSC_VER)
template <typename T> struct TrailingZerosCounter<T, 4> {
  static std::size_t count(T Val, ZeroBehavior ZB) {
    if (ZB != ZB_Undefined && Val == 0)
      return 32;

#if __has_builtin(__builtin_ctz) || LLVM_GNUC_PREREQ(4, 0, 0)
    return __builtin_ctz(Val);
#elif defined(_MSC_VER)
    unsigned long Index;
    _BitScanForward(&Index, Val);
    return Index;
#endif
  }
};

#if !defined(_MSC_VER) || defined(_M_X64)
template <typename T> struct TrailingZerosCounter<T, 8> {
  static std::size_t count(T Val, ZeroBehavior ZB) {
    if (ZB != ZB_Undefined && Val == 0)
      return 64;

#if __has_builtin(__builtin_ctzll) || LLVM_GNUC_PREREQ(4, 0, 0)
    return __builtin_ctzll(Val);
#elif defined(_MSC_VER)
    unsigned long Index;
    _BitScanForward64(&Index, Val);
    return Index;
#endif
  }
};
#endif
#endif
}                    

                                                                  
                              
   
                                             
   
                                                                               
                      
template <typename T>
std::size_t countTrailingZeros(T Val, ZeroBehavior ZB = ZB_Width) {
  static_assert(std::numeric_limits<T>::is_integer &&
                    !std::numeric_limits<T>::is_signed,
                "Only unsigned integral types are allowed.");
  return llvh::detail::TrailingZerosCounter<T, sizeof(T)>::count(Val, ZB);
}

namespace detail {
template <typename T, std::size_t SizeOfT> struct LeadingZerosCounter {
  static std::size_t count(T Val, ZeroBehavior) {
    if (!Val)
      return std::numeric_limits<T>::digits;

                        
    std::size_t ZeroBits = 0;
    for (T Shift = std::numeric_limits<T>::digits >> 1; Shift; Shift >>= 1) {
      T Tmp = Val >> Shift;
      if (Tmp)
        Val = Tmp;
      else
        ZeroBits |= Shift;
    }
    return ZeroBits;
  }
};

#if __GNUC__ >= 4 || defined(_MSC_VER)
template <typename T> struct LeadingZerosCounter<T, 4> {
  static std::size_t count(T Val, ZeroBehavior ZB) {
    if (ZB != ZB_Undefined && Val == 0)
      return 32;

#if __has_builtin(__builtin_clz) || LLVM_GNUC_PREREQ(4, 0, 0)
    return __builtin_clz(Val);
#elif defined(_MSC_VER)
    unsigned long Index;
    _BitScanReverse(&Index, Val);
    return Index ^ 31;
#endif
  }
};

#if !defined(_MSC_VER) || defined(_M_X64)
template <typename T> struct LeadingZerosCounter<T, 8> {
  static std::size_t count(T Val, ZeroBehavior ZB) {
    if (ZB != ZB_Undefined && Val == 0)
      return 64;

#if __has_builtin(__builtin_clzll) || LLVM_GNUC_PREREQ(4, 0, 0)
    return __builtin_clzll(Val);
#elif defined(_MSC_VER)
    unsigned long Index;
    _BitScanReverse64(&Index, Val);
    return Index ^ 63;
#endif
  }
};
#endif
#endif
}                    

                                                                  
                              
   
                                             
   
                                                                               
                      
template <typename T>
std::size_t countLeadingZeros(T Val, ZeroBehavior ZB = ZB_Width) {
  static_assert(std::numeric_limits<T>::is_integer &&
                    !std::numeric_limits<T>::is_signed,
                "Only unsigned integral types are allowed.");
  return llvh::detail::LeadingZerosCounter<T, sizeof(T)>::count(Val, ZB);
}

                                                              
                      
   
                                             
   
                                                                             
                      
template <typename T> T findFirstSet(T Val, ZeroBehavior ZB = ZB_Max) {
  if (ZB == ZB_Max && Val == 0)
    return std::numeric_limits<T>::max();

  return countTrailingZeros(Val, ZB_Undefined);
}

                                                                       
                                                    
template <typename T> T maskTrailingOnes(unsigned N) {
  static_assert(std::is_unsigned<T>::value, "Invalid type!");
  const unsigned Bits = CHAR_BIT * sizeof(T);
  assert(N <= Bits && "Invalid bit index");
  return N == 0 ? 0 : (T(-1) >> (Bits - N));
}

                                                                      
                                                    
template <typename T> T maskLeadingOnes(unsigned N) {
  return ~maskTrailingOnes<T>(CHAR_BIT * sizeof(T) - N);
}

                                                                       
                                                    
template <typename T> T maskTrailingZeros(unsigned N) {
  return maskLeadingOnes<T>(CHAR_BIT * sizeof(T) - N);
}

                                                                      
                                                    
template <typename T> T maskLeadingZeros(unsigned N) {
  return maskTrailingOnes<T>(CHAR_BIT * sizeof(T) - N);
}

                                                             
                      
   
                                             
   
                                                                             
                      
template <typename T> T findLastSet(T Val, ZeroBehavior ZB = ZB_Max) {
  if (ZB == ZB_Max && Val == 0)
    return std::numeric_limits<T>::max();

                                                                             
                                           
  return countLeadingZeros(Val, ZB_Undefined) ^
         (std::numeric_limits<T>::digits - 1);
}

                                                     
   
                                                                       
static const unsigned char BitReverseTable256[256] = {
#define R2(n) n, n + 2 * 64, n + 1 * 64, n + 3 * 64
#define R4(n) R2(n), R2(n + 2 * 16), R2(n + 1 * 16), R2(n + 3 * 16)
#define R6(n) R4(n), R4(n + 2 * 4), R4(n + 1 * 4), R4(n + 3 * 4)
  R6(0), R6(2), R6(1), R6(3)
#undef R2
#undef R4
#undef R6
};

                               
template <typename T>
T reverseBits(T Val) {
  unsigned char in[sizeof(Val)];
  unsigned char out[sizeof(Val)];
  std::memcpy(in, &Val, sizeof(Val));
  for (unsigned i = 0; i < sizeof(Val); ++i)
    out[(sizeof(Val) - i) - 1] = BitReverseTable256[in[i]];
  std::memcpy(&Val, out, sizeof(Val));
  return Val;
}

                                                                              
                                                                            
             

                                              
constexpr inline uint32_t Hi_32(uint64_t Value) {
  return static_cast<uint32_t>(Value >> 32);
}

                                             
constexpr inline uint32_t Lo_32(uint64_t Value) {
  return static_cast<uint32_t>(Value);
}

                                                                    
constexpr inline uint64_t Make_64(uint32_t High, uint32_t Low) {
  return ((uint64_t)High << 32) | (uint64_t)Low;
}

                                                       
template <unsigned N> constexpr inline bool isInt(int64_t x) {
  return N >= 64 || (-(INT64_C(1)<<(N-1)) <= x && x < (INT64_C(1)<<(N-1)));
}
                                                                
template <> constexpr inline bool isInt<8>(int64_t x) {
  return static_cast<int8_t>(x) == x;
}
template <> constexpr inline bool isInt<16>(int64_t x) {
  return static_cast<int16_t>(x) == x;
}
template <> constexpr inline bool isInt<32>(int64_t x) {
  return static_cast<int32_t>(x) == x;
}

                                                                    
template <unsigned N, unsigned S>
constexpr inline bool isShiftedInt(int64_t x) {
  static_assert(
      N > 0, "isShiftedInt<0> doesn't make sense (refers to a 0-bit number.");
  static_assert(N + S <= 64, "isShiftedInt<N, S> with N + S > 64 is too wide.");
  return isInt<N + S>(x) && (x % (UINT64_C(1) << S) == 0);
}

                                                                
   
                                                          
   
                                               
   
                                                                             
                         
template <unsigned N>
constexpr inline typename std::enable_if<(N < 64), bool>::type
isUInt(uint64_t X) {
  static_assert(N > 0, "isUInt<0> doesn't make sense");
  return X < (UINT64_C(1) << (N));
}
template <unsigned N>
constexpr inline typename std::enable_if<N >= 64, bool>::type
isUInt(uint64_t X) {
  return true;
}

                                                                
template <> constexpr inline bool isUInt<8>(uint64_t x) {
  return static_cast<uint8_t>(x) == x;
}
template <> constexpr inline bool isUInt<16>(uint64_t x) {
  return static_cast<uint16_t>(x) == x;
}
template <> constexpr inline bool isUInt<32>(uint64_t x) {
  return static_cast<uint32_t>(x) == x;
}

                                                                      
template <unsigned N, unsigned S>
constexpr inline bool isShiftedUInt(uint64_t x) {
  static_assert(
      N > 0, "isShiftedUInt<0> doesn't make sense (refers to a 0-bit number)");
  static_assert(N + S <= 64,
                "isShiftedUInt<N, S> with N + S > 64 is too wide.");
                                                                           
                                      
  return isUInt<N + S>(x) && (x % (UINT64_C(1) << S) == 0);
}

                                                        
inline uint64_t maxUIntN(uint64_t N) {
  assert(N > 0 && N <= 64 && "integer width out of range");

                                                            
                             
                                                                            
            
  return UINT64_MAX >> (64 - N);
}

                                                      
inline int64_t minIntN(int64_t N) {
  assert(N > 0 && N <= 64 && "integer width out of range");

  return -(UINT64_C(1)<<(N-1));
}

                                                      
inline int64_t maxIntN(int64_t N) {
  assert(N > 0 && N <= 64 && "integer width out of range");

                                                                              
                                              
  return (UINT64_C(1) << (N - 1)) - 1;
}

                                                                          
inline bool isUIntN(unsigned N, uint64_t x) {
  return N >= 64 || x <= maxUIntN(N);
}

                                                                        
inline bool isIntN(unsigned N, int64_t x) {
  return N >= 64 || (minIntN(N) <= x && x <= maxIntN(N));
}

                                                                               
                                                                   
                                       
constexpr inline bool isMask_32(uint32_t Value) {
  return Value && ((Value + 1) & Value) == 0;
}

                                                                               
                                                                   
constexpr inline bool isMask_64(uint64_t Value) {
  return Value && ((Value + 1) & Value) == 0;
}

                                                                              
                                                                               
constexpr inline bool isShiftedMask_32(uint32_t Value) {
  return Value && isMask_32((Value - 1) | Value);
}

                                                                              
                                    
constexpr inline bool isShiftedMask_64(uint64_t Value) {
  return Value && isMask_64((Value - 1) | Value);
}

                                                      
                                                            
constexpr inline bool isPowerOf2_32(uint32_t Value) {
  return Value && !(Value & (Value - 1));
}

                                                                       
constexpr inline bool isPowerOf2_64(uint64_t Value) {
  return Value && !(Value & (Value - 1));
}

                                                                
inline uint16_t ByteSwap_16(uint16_t Value) {
  return sys::SwapByteOrder_16(Value);
}

                                                                
inline uint32_t ByteSwap_32(uint32_t Value) {
  return sys::SwapByteOrder_32(Value);
}

                                                                
inline uint64_t ByteSwap_64(uint64_t Value) {
  return sys::SwapByteOrder_64(Value);
}

                                                                       
             
   
                                          
                                             
   
                                                                     
                                     
template <typename T>
std::size_t countLeadingOnes(T Value, ZeroBehavior ZB = ZB_Width) {
  static_assert(std::numeric_limits<T>::is_integer &&
                    !std::numeric_limits<T>::is_signed,
                "Only unsigned integral types are allowed.");
  return countLeadingZeros<T>(~Value, ZB);
}

                                                                        
             
   
                                           
                                             
   
                                                                     
                                     
template <typename T>
std::size_t countTrailingOnes(T Value, ZeroBehavior ZB = ZB_Width) {
  static_assert(std::numeric_limits<T>::is_integer &&
                    !std::numeric_limits<T>::is_signed,
                "Only unsigned integral types are allowed.");
  return countTrailingZeros<T>(~Value, ZB);
}

namespace detail {
template <typename T, std::size_t SizeOfT> struct PopulationCounter {
  static unsigned count(T Value) {
                                           
    static_assert(SizeOfT <= 4, "Not implemented!");
#if __GNUC__ >= 4
    return __builtin_popcount(Value);
#else
    uint32_t v = Value;
    v = v - ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    return ((v + (v >> 4) & 0xF0F0F0F) * 0x1010101) >> 24;
#endif
  }
};

template <typename T> struct PopulationCounter<T, 8> {
  static unsigned count(T Value) {
#if __GNUC__ >= 4
    return __builtin_popcountll(Value);
#else
    uint64_t v = Value;
    v = v - ((v >> 1) & 0x5555555555555555ULL);
    v = (v & 0x3333333333333333ULL) + ((v >> 2) & 0x3333333333333333ULL);
    v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return unsigned((uint64_t)(v * 0x0101010101010101ULL) >> 56);
#endif
  }
};
}                    

                                            
                                       
                                  
template <typename T>
inline unsigned countPopulation(T Value) {
  static_assert(std::numeric_limits<T>::is_integer &&
                    !std::numeric_limits<T>::is_signed,
                "Only unsigned integral types are allowed.");
  return detail::PopulationCounter<T, sizeof(T)>::count(Value);
}

                                                 
inline double Log2(double Value) {
#if defined(__ANDROID_API__) && __ANDROID_API__ < 18
  return __builtin_log(Value) / __builtin_log(2.0);
#else
  return log2(Value);
#endif
}

                                                                                
                     
                                                                            
inline unsigned Log2_32(uint32_t Value) {
  return 31 - countLeadingZeros(Value);
}

                                                                                
                     
inline unsigned Log2_64(uint64_t Value) {
  return 63 - countLeadingZeros(Value);
}

                                                                               
                     
                                                                         
inline unsigned Log2_32_Ceil(uint32_t Value) {
  return 32 - countLeadingZeros(Value - 1);
}

                                                                               
                     
inline unsigned Log2_64_Ceil(uint64_t Value) {
  return 64 - countLeadingZeros(Value - 1);
}

                                                                              
inline uint64_t GreatestCommonDivisor64(uint64_t A, uint64_t B) {
  while (B) {
    uint64_t T = B;
    B = A % B;
    A = T;
  }
  return A;
}

                                                                               
inline double BitsToDouble(uint64_t Bits) {
  double D;
  static_assert(sizeof(uint64_t) == sizeof(double), "Unexpected type sizes");
  memcpy(&D, &Bits, sizeof(Bits));
  return D;
}

                                                                              
inline float BitsToFloat(uint32_t Bits) {
  float F;
  static_assert(sizeof(uint32_t) == sizeof(float), "Unexpected type sizes");
  memcpy(&F, &Bits, sizeof(Bits));
  return F;
}

                                                                               
                                                                            
                                                                         
inline uint64_t DoubleToBits(double Double) {
  uint64_t Bits;
  static_assert(sizeof(uint64_t) == sizeof(double), "Unexpected type sizes");
  memcpy(&Bits, &Double, sizeof(Double));
  return Bits;
}

                                                                              
                                                                           
                                                                         
inline uint32_t FloatToBits(float Float) {
  uint32_t Bits;
  static_assert(sizeof(uint32_t) == sizeof(float), "Unexpected type sizes");
  memcpy(&Bits, &Float, sizeof(Float));
  return Bits;
}

                                                                               
                                                 
constexpr inline uint64_t MinAlign(uint64_t A, uint64_t B) {
                                                      
    
                                                                            
                       
                                  
  return (A | B) & (1 + ~(A | B));
}

                                                      
   
                                                                  
                                                  
inline uintptr_t alignAddr(const void *Addr, size_t Alignment) {
  assert(Alignment && isPowerOf2_64((uint64_t)Alignment) &&
         "Alignment is not a power of two!");

  assert((uintptr_t)Addr + Alignment - 1 >= (uintptr_t)Addr);

  return (((uintptr_t)Addr + Alignment - 1) & ~(uintptr_t)(Alignment - 1));
}

                                                                        
                       
inline size_t alignmentAdjustment(const void *Ptr, size_t Alignment) {
  return alignAddr(Ptr, Alignment) - (uintptr_t)Ptr;
}

                                                                               
                             
inline uint64_t NextPowerOf2(uint64_t A) {
  A |= (A >> 1);
  A |= (A >> 2);
  A |= (A >> 4);
  A |= (A >> 8);
  A |= (A >> 16);
  A |= (A >> 32);
  return A + 1;
}

                                                                            
                                                                            
inline uint64_t PowerOf2Floor(uint64_t A) {
  if (!A) return 0;
  return 1ull << (63 - countLeadingZeros(A, ZB_Undefined));
}

                                                                               
                                                                           
inline uint64_t PowerOf2Ceil(uint64_t A) {
  if (!A)
    return 0;
  return NextPowerOf2(A - 1);
}

                                                                         
                                                                      
   
                                                                        
                                                                  
                                                                        
                                                              
   
             
         
                       
                         
                          
                             
   
                          
                            
                             
                                 
            
inline uint64_t alignTo(uint64_t Value, uint64_t Align, uint64_t Skew = 0) {
  assert(Align != 0u && "Align can't be 0.");
  Skew %= Align;
  return (Value + Align - 1 - Skew) / Align * Align + Skew;
}

                                                                         
                                                                      
template <uint64_t Align> constexpr inline uint64_t alignTo(uint64_t Value) {
  static_assert(Align != 0u, "Align must be non-zero");
  return (Value + Align - 1) / Align * Align;
}

                                                      
inline uint64_t divideCeil(uint64_t Numerator, uint64_t Denominator) {
  return alignTo(Numerator, Denominator) / Denominator;
}

                                                                    
               
   
                                                                     
template <uint64_t Align>
struct AlignTo {
  static_assert(Align != 0u, "Align must be non-zero");
  template <uint64_t Value>
  struct from_value {
    static const uint64_t value = (Value + Align - 1) / Align * Align;
  };
};

                                                                      
                                                   
inline uint64_t alignDown(uint64_t Value, uint64_t Align, uint64_t Skew = 0) {
  assert(Align != 0u && "Align can't be 0.");
  Skew %= Align;
  return (Value - Skew) / Align * Align + Skew;
}

                                                                           
                                                                        
             
inline uint64_t OffsetToAlignment(uint64_t Value, uint64_t Align) {
  return alignTo(Value, Align) - Value;
}

                                                                         
                         
template <unsigned B> constexpr inline int32_t SignExtend32(uint32_t X) {
  static_assert(B > 0, "Bit width can't be 0.");
  static_assert(B <= 32, "Bit width out of range.");
  return int32_t(X << (32 - B)) >> (32 - B);
}

                                                                         
                        
inline int32_t SignExtend32(uint32_t X, unsigned B) {
  assert(B > 0 && "Bit width can't be 0.");
  assert(B <= 32 && "Bit width out of range.");
  return int32_t(X << (32 - B)) >> (32 - B);
}

                                                                         
                        
template <unsigned B> constexpr inline int64_t SignExtend64(uint64_t x) {
  static_assert(B > 0, "Bit width can't be 0.");
  static_assert(B <= 64, "Bit width out of range.");
  return int64_t(x << (64 - B)) >> (64 - B);
}

                                                                         
                        
inline int64_t SignExtend64(uint64_t X, unsigned B) {
  assert(B > 0 && "Bit width can't be 0.");
  assert(B <= 64 && "Bit width out of range.");
  return int64_t(X << (64 - B)) >> (64 - B);
}

                                                                              
                        
template <typename T>
typename std::enable_if<std::is_unsigned<T>::value, T>::type
AbsoluteDifference(T X, T Y) {
  return std::max(X, Y) - std::min(X, Y);
}

                                                                           
                                                                                
                                                                        
template <typename T>
typename std::enable_if<std::is_unsigned<T>::value, T>::type
SaturatingAdd(T X, T Y, bool *ResultOverflowed = nullptr) {
  bool Dummy;
  bool &Overflowed = ResultOverflowed ? *ResultOverflowed : Dummy;
                            
  T Z = X + Y;
  Overflowed = (Z < X || Z < Y);
  if (Overflowed)
    return std::numeric_limits<T>::max();
  else
    return Z;
}

                                                                                
                                                                                
                                                                        
template <typename T>
typename std::enable_if<std::is_unsigned<T>::value, T>::type
SaturatingMultiply(T X, T Y, bool *ResultOverflowed = nullptr) {
  bool Dummy;
  bool &Overflowed = ResultOverflowed ? *ResultOverflowed : Dummy;

                                                                             
                                                                           
                                                                           
                           

  Overflowed = false;

                                                
                                                              
                                                      
  int Log2Z = Log2_64(X) + Log2_64(Y);
  const T Max = std::numeric_limits<T>::max();
  int Log2Max = Log2_64(Max);
  if (Log2Z < Log2Max) {
    return X * Y;
  }
  if (Log2Z > Log2Max) {
    Overflowed = true;
    return Max;
  }

                                                           
                                                          
                        
  T Z = (X >> 1) * Y;
  if (Z & ~(Max >> 1)) {
    Overflowed = true;
    return Max;
  }
  Z <<= 1;
  if (X & 1)
    return SaturatingAdd(Z, Y, ResultOverflowed);

  return Z;
}

                                                                               
                                                                            
                                                                         
                                          
template <typename T>
typename std::enable_if<std::is_unsigned<T>::value, T>::type
SaturatingMultiplyAdd(T X, T Y, T A, bool *ResultOverflowed = nullptr) {
  bool Dummy;
  bool &Overflowed = ResultOverflowed ? *ResultOverflowed : Dummy;

  T Product = SaturatingMultiply(X, Y, &Overflowed);
  if (Overflowed)
    return Product;

  return SaturatingAdd(A, Product, &Overflowed);
}

                                                                       
extern const float huge_valf;
}                      
#pragma GCC diagnostic pop
#endif
