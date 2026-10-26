//===- llvm/ADT/APFloat.h - Arbitrary Precision Floating Point ---*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// \brief
/// This file declares a class to represent arbitrary precision floating point
/// values and provide a variety of arithmetic operations on them.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_APFLOAT_H
#define LLVM_ADT_APFLOAT_H

#include "llvh/ADT/APInt.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/Support/ErrorHandling.h"
#include <memory>

#define APFLOAT_DISPATCH_ON_SEMANTICS(METHOD_CALL)                             \
  do {                                                                         \
    if (usesLayout<IEEEFloat>(getSemantics()))                                 \
      return U.IEEE.METHOD_CALL;                                               \
    if (usesLayout<DoubleAPFloat>(getSemantics()))                             \
      return U.Double.METHOD_CALL;                                             \
    llvm_unreachable("Unexpected semantics");                                  \
  } while (false)

namespace llvh {

struct fltSemantics;
class APSInt;
class StringRef;
class APFloat;
class raw_ostream;

template <typename T> class SmallVectorImpl;

                                                                                
              
   
                                                                 
enum lostFraction {                              
  lfExactlyZero,             
  lfLessThanHalf,                              
  lfExactlyHalf,             
  lfMoreThanHalf                               
};

                                                                     
                                           
   
                                                                             
                                                                                
                                                                        
   
                                                                              
                                                                                
                                                                         
                                                                  
                                                                        
                        
   
                                                                             
                                                                                
                                                              
                                                                          
                                                                        
   
                                                                       
                                                                            
                                                                            
                                                                               
           
   
                                                                                
                                                                             
                                                                                
                                                                                
                                                                            
                                                                          
   
                                                                           
                                                                     
   
                                                                        
                                                                           
                                                                              
                                                                       
                                                                            
                                                                            
                                                                                
         
   
                                                                               
                                   
   
                                                            
   
                                                                              
                                                                             
                                                                                
                                                                     
                                                                          
                                                                              
                                                                      
                                                                              
                                                                               
                                                                             
                                                                               
                                                                                
                                                                         
   
                                                                            
                                                                                
                                                                                
      
   
        
        
   
                                                      
   
                                        
   
                                                                  
   
                                                                         
                                    
   
                                                               
   

                                                                         
                                                                            
           
struct APFloatBase {
  typedef APInt::WordType integerPart;
  static const unsigned integerPartWidth = APInt::APINT_BITS_PER_WORD;

                                                                            
  typedef signed short ExponentType;

                                     
        

  static const fltSemantics &IEEEhalf() LLVM_READNONE;
  static const fltSemantics &IEEEsingle() LLVM_READNONE;
  static const fltSemantics &IEEEdouble() LLVM_READNONE;
  static const fltSemantics &IEEEquad() LLVM_READNONE;
  static const fltSemantics &PPCDoubleDouble() LLVM_READNONE;
  static const fltSemantics &x87DoubleExtended() LLVM_READNONE;

                                                                               
                    
  static const fltSemantics &Bogus() LLVM_READNONE;

        

                                                          
  enum cmpResult {
    cmpLessThan,
    cmpEqual,
    cmpGreaterThan,
    cmpUnordered
  };

                                                   
  enum roundingMode {
    rmNearestTiesToEven,
    rmTowardPositive,
    rmTowardNegative,
    rmTowardZero,
    rmNearestTiesToAway
  };

                                              
     
                                                                         
  enum opStatus {
    opOK = 0x00,
    opInvalidOp = 0x01,
    opDivByZero = 0x02,
    opOverflow = 0x04,
    opUnderflow = 0x08,
    opInexact = 0x10
  };

                                                
  enum fltCategory {
    fcInfinity,
    fcNaN,
    fcNormal,
    fcZero
  };

                                                                  
  enum uninitializedTag {
    uninitialized
  };

                                            
  enum IlogbErrorKinds {
    IEK_Zero = INT_MIN + 1,
    IEK_NaN = INT_MIN,
    IEK_Inf = INT_MAX
  };

  static unsigned int semanticsPrecision(const fltSemantics &);
  static ExponentType semanticsMinExponent(const fltSemantics &);
  static ExponentType semanticsMaxExponent(const fltSemantics &);
  static unsigned int semanticsSizeInBits(const fltSemantics &);

                                                                          
                
  static unsigned getSizeInBits(const fltSemantics &Sem);
};

namespace detail {

class IEEEFloat final : public APFloatBase {
public:
                        
        

  IEEEFloat(const fltSemantics &);                            
  IEEEFloat(const fltSemantics &, integerPart);
  IEEEFloat(const fltSemantics &, uninitializedTag);
  IEEEFloat(const fltSemantics &, const APInt &);
  explicit IEEEFloat(double d);
  explicit IEEEFloat(float f);
  IEEEFloat(const IEEEFloat &);
  IEEEFloat(IEEEFloat &&);
  ~IEEEFloat();

        

                                                     
  bool needsCleanup() const { return partCount() > 1; }

                                      
        

        

                      
        

  opStatus add(const IEEEFloat &, roundingMode);
  opStatus subtract(const IEEEFloat &, roundingMode);
  opStatus multiply(const IEEEFloat &, roundingMode);
  opStatus divide(const IEEEFloat &, roundingMode);
                     
  opStatus remainder(const IEEEFloat &);
                           
  opStatus mod(const IEEEFloat &);
  opStatus fusedMultiplyAdd(const IEEEFloat &, const IEEEFloat &, roundingMode);
  opStatus roundToIntegral(roundingMode);
                                       
  opStatus next(bool nextDown);

        

                            
        

  void changeSign();

        

                       
        

  opStatus convert(const fltSemantics &, roundingMode, bool *);
  opStatus convertToInteger(MutableArrayRef<integerPart>, unsigned int, bool,
                            roundingMode, bool *) const;
  opStatus convertFromAPInt(const APInt &, bool, roundingMode);
  opStatus convertFromSignExtendedInteger(const integerPart *, unsigned int,
                                          bool, roundingMode);
  opStatus convertFromZeroExtendedInteger(const integerPart *, unsigned int,
                                          bool, roundingMode);
  opStatus convertFromString(StringRef, roundingMode);
  APInt bitcastToAPInt() const;
  double convertToDouble() const;
  float convertToFloat() const;

        

                                                                              
                                                                              
                         
  bool operator==(const IEEEFloat &) const = delete;

                                                                      
                        
  cmpResult compare(const IEEEFloat &) const;

                                                                   
  bool bitwiseIsEqual(const IEEEFloat &) const;

                                                                                
                                                                          
                                                                             
  unsigned int convertToHexString(char *dst, unsigned int hexDigits,
                                  bool upperCase, roundingMode) const;

                                               
        

                                                                             
               
     
                                             
  bool isNegative() const { return sign; }

                                                                                  
     
                                                                              
                                                                            
  bool isNormal() const { return !isDenormal() && isFiniteNonZero(); }

                                                                          
             
     
                                                       
  bool isFinite() const { return !isNaN() && !isInfinity(); }

                                                                  
  bool isZero() const { return category == fcZero; }

                                                                         
               
  bool isDenormal() const;

                                                                                
  bool isInfinity() const { return category == fcInfinity; }

                                                                        
  bool isNaN() const { return category == fcNaN; }

                                                               
  bool isSignaling() const;

        

                          
        

  fltCategory getCategory() const { return category; }
  const fltSemantics &getSemantics() const { return *semantics; }
  bool isNonZero() const { return category != fcZero; }
  bool isFiniteNonZero() const { return isFinite() && !isZero(); }
  bool isPosZero() const { return isZero() && !isNegative(); }
  bool isNegZero() const { return isZero() && isNegative(); }

                                                                               
                                         
  bool isSmallest() const;

                                                                            
                                         
  bool isLargest() const;

                                                                 
  bool isInteger() const;

        

  IEEEFloat &operator=(const IEEEFloat &);
  IEEEFloat &operator=(IEEEFloat &&);

                                                           
     
                                                                             
                                                                          
                                                                             
                                                                    
                                                                           
                                                                       
                                  
  friend hash_code hash_value(const IEEEFloat &Arg);

                                                
     
                                                            
                                                                  
                                                         
                                                    
                                                           
                                
                                                            
                                                            
                                                             
     
                                                                         
                                                                          
                                                                    
                                                                           
                                                
     
                                                      
                                                      
                                                      
                                                        
                                                        
                                                       
                                                       
                                                        
  void toString(SmallVectorImpl<char> &Str, unsigned FormatPrecision = 0,
                unsigned FormatMaxPadding = 3, bool TruncateZero = true) const;

                                                                            
                  
  bool getExactInverse(APFloat *inv) const;

                                                                         
     
                                                                              
                                                                   
     
                         
                          
                         
     
  friend int ilogb(const IEEEFloat &Arg);

                                                
  friend IEEEFloat scalbn(IEEEFloat X, int Exp, roundingMode);

  friend IEEEFloat frexp(const IEEEFloat &X, int &Exp, roundingMode);

                                  
        

  void makeLargest(bool Neg = false);
  void makeSmallest(bool Neg = false);
  void makeNaN(bool SNaN = false, bool Neg = false,
               const APInt *fill = nullptr);
  void makeInf(bool Neg = false);
  void makeZero(bool Neg = false);
  void makeQuiet();

                                                                               
                
     
                                                              
  void makeSmallestNormalized(bool Negative = false);

        

  cmpResult compareAbsoluteValue(const IEEEFloat &) const;

private:
                          
        

  integerPart *significandParts();
  const integerPart *significandParts() const;
  unsigned int partCount() const;

        

                                   
        

  integerPart addSignificand(const IEEEFloat &);
  integerPart subtractSignificand(const IEEEFloat &, integerPart);
  lostFraction addOrSubtractSignificand(const IEEEFloat &, bool subtract);
  lostFraction multiplySignificand(const IEEEFloat &, const IEEEFloat *);
  lostFraction divideSignificand(const IEEEFloat &);
  void incrementSignificand();
  void initialize(const fltSemantics *);
  void shiftSignificandLeft(unsigned int);
  lostFraction shiftSignificandRight(unsigned int);
  unsigned int significandLSB() const;
  unsigned int significandMSB() const;
  void zeroSignificand();
                                                                            
  bool isSignificandAllOnes() const;
                                                                             
  bool isSignificandAllZeros() const;

        

                                         
        

  opStatus addOrSubtractSpecials(const IEEEFloat &, bool subtract);
  opStatus divideSpecials(const IEEEFloat &);
  opStatus multiplySpecials(const IEEEFloat &);
  opStatus modSpecials(const IEEEFloat &);

        

                      
        

  bool convertFromStringSpecials(StringRef str);
  opStatus normalize(roundingMode, lostFraction);
  opStatus addOrSubtract(const IEEEFloat &, roundingMode, bool subtract);
  opStatus handleOverflow(roundingMode);
  bool roundAwayFromZero(roundingMode, lostFraction, unsigned int) const;
  opStatus convertToSignExtendedInteger(MutableArrayRef<integerPart>,
                                        unsigned int, bool, roundingMode,
                                        bool *) const;
  opStatus convertFromUnsignedParts(const integerPart *, unsigned int,
                                    roundingMode);
  opStatus convertFromHexadecimalString(StringRef, roundingMode);
  opStatus convertFromDecimalString(StringRef, roundingMode);
  char *convertNormalToHexString(char *, unsigned int, bool,
                                 roundingMode) const;
  opStatus roundSignificandWithExponent(const integerPart *, unsigned int, int,
                                        roundingMode);

        

  APInt convertHalfAPFloatToAPInt() const;
  APInt convertFloatAPFloatToAPInt() const;
  APInt convertDoubleAPFloatToAPInt() const;
  APInt convertQuadrupleAPFloatToAPInt() const;
  APInt convertF80LongDoubleAPFloatToAPInt() const;
  APInt convertPPCDoubleDoubleAPFloatToAPInt() const;
  void initFromAPInt(const fltSemantics *Sem, const APInt &api);
  void initFromHalfAPInt(const APInt &api);
  void initFromFloatAPInt(const APInt &api);
  void initFromDoubleAPInt(const APInt &api);
  void initFromQuadrupleAPInt(const APInt &api);
  void initFromF80LongDoubleAPInt(const APInt &api);
  void initFromPPCDoubleDoubleAPInt(const APInt &api);

  void assign(const IEEEFloat &);
  void copySignificand(const IEEEFloat &);
  void freeSignificand();

                                               
                                          
  const fltSemantics *semantics;

                                                     
     
                                                                               
  union Significand {
    integerPart part;
    integerPart *parts;
  } significand;

                                                
  ExponentType exponent;

                                                 
     
                                                                             
                                                                   
  fltCategory category : 3;

                             
  unsigned int sign : 1;
};

hash_code hash_value(const IEEEFloat &Arg);
int ilogb(const IEEEFloat &Arg);
IEEEFloat scalbn(IEEEFloat X, int Exp, IEEEFloat::roundingMode);
IEEEFloat frexp(const IEEEFloat &Val, int &Exp, IEEEFloat::roundingMode RM);

                                                                    
                                                                          
                                                                       
                                                     
class DoubleAPFloat final : public APFloatBase {
                                              
  const fltSemantics *Semantics;
  std::unique_ptr<APFloat[]> Floats;

  opStatus addImpl(const APFloat &a, const APFloat &aa, const APFloat &c,
                   const APFloat &cc, roundingMode RM);

  opStatus addWithSpecial(const DoubleAPFloat &LHS, const DoubleAPFloat &RHS,
                          DoubleAPFloat &Out, roundingMode RM);

public:
  DoubleAPFloat(const fltSemantics &S);
  DoubleAPFloat(const fltSemantics &S, uninitializedTag);
  DoubleAPFloat(const fltSemantics &S, integerPart);
  DoubleAPFloat(const fltSemantics &S, const APInt &I);
  DoubleAPFloat(const fltSemantics &S, APFloat &&First, APFloat &&Second);
  DoubleAPFloat(const DoubleAPFloat &RHS);
  DoubleAPFloat(DoubleAPFloat &&RHS);

  DoubleAPFloat &operator=(const DoubleAPFloat &RHS);

  DoubleAPFloat &operator=(DoubleAPFloat &&RHS) {
    if (this != &RHS) {
      this->~DoubleAPFloat();
      new (this) DoubleAPFloat(std::move(RHS));
    }
    return *this;
  }

  bool needsCleanup() const { return Floats != nullptr; }

  APFloat &getFirst() { return Floats[0]; }
  const APFloat &getFirst() const { return Floats[0]; }
  APFloat &getSecond() { return Floats[1]; }
  const APFloat &getSecond() const { return Floats[1]; }

  opStatus add(const DoubleAPFloat &RHS, roundingMode RM);
  opStatus subtract(const DoubleAPFloat &RHS, roundingMode RM);
  opStatus multiply(const DoubleAPFloat &RHS, roundingMode RM);
  opStatus divide(const DoubleAPFloat &RHS, roundingMode RM);
  opStatus remainder(const DoubleAPFloat &RHS);
  opStatus mod(const DoubleAPFloat &RHS);
  opStatus fusedMultiplyAdd(const DoubleAPFloat &Multiplicand,
                            const DoubleAPFloat &Addend, roundingMode RM);
  opStatus roundToIntegral(roundingMode RM);
  void changeSign();
  cmpResult compareAbsoluteValue(const DoubleAPFloat &RHS) const;

  fltCategory getCategory() const;
  bool isNegative() const;

  void makeInf(bool Neg);
  void makeZero(bool Neg);
  void makeLargest(bool Neg);
  void makeSmallest(bool Neg);
  void makeSmallestNormalized(bool Neg);
  void makeNaN(bool SNaN, bool Neg, const APInt *fill);

  cmpResult compare(const DoubleAPFloat &RHS) const;
  bool bitwiseIsEqual(const DoubleAPFloat &RHS) const;
  APInt bitcastToAPInt() const;
  opStatus convertFromString(StringRef, roundingMode);
  opStatus next(bool nextDown);

  opStatus convertToInteger(MutableArrayRef<integerPart> Input,
                            unsigned int Width, bool IsSigned, roundingMode RM,
                            bool *IsExact) const;
  opStatus convertFromAPInt(const APInt &Input, bool IsSigned, roundingMode RM);
  opStatus convertFromSignExtendedInteger(const integerPart *Input,
                                          unsigned int InputSize, bool IsSigned,
                                          roundingMode RM);
  opStatus convertFromZeroExtendedInteger(const integerPart *Input,
                                          unsigned int InputSize, bool IsSigned,
                                          roundingMode RM);
  unsigned int convertToHexString(char *DST, unsigned int HexDigits,
                                  bool UpperCase, roundingMode RM) const;

  bool isDenormal() const;
  bool isSmallest() const;
  bool isLargest() const;
  bool isInteger() const;

  void toString(SmallVectorImpl<char> &Str, unsigned FormatPrecision,
                unsigned FormatMaxPadding, bool TruncateZero = true) const;

  bool getExactInverse(APFloat *inv) const;

  friend int ilogb(const DoubleAPFloat &Arg);
  friend DoubleAPFloat scalbn(DoubleAPFloat X, int Exp, roundingMode);
  friend DoubleAPFloat frexp(const DoubleAPFloat &X, int &Exp, roundingMode);
  friend hash_code hash_value(const DoubleAPFloat &Arg);
};

hash_code hash_value(const DoubleAPFloat &Arg);

}                        

                                                                              
                     
class APFloat : public APFloatBase {
  typedef detail::IEEEFloat IEEEFloat;
  typedef detail::DoubleAPFloat DoubleAPFloat;

  static_assert(std::is_standard_layout<IEEEFloat>::value, "");

  union Storage {
    const fltSemantics *semantics;
    IEEEFloat IEEE;
    DoubleAPFloat Double;

    explicit Storage(IEEEFloat F, const fltSemantics &S);
    explicit Storage(DoubleAPFloat F, const fltSemantics &S)
        : Double(std::move(F)) {
      assert(&S == &PPCDoubleDouble());
    }

    template <typename... ArgTypes>
    Storage(const fltSemantics &Semantics, ArgTypes &&... Args) {
      if (usesLayout<IEEEFloat>(Semantics)) {
        new (&IEEE) IEEEFloat(Semantics, std::forward<ArgTypes>(Args)...);
        return;
      }
      if (usesLayout<DoubleAPFloat>(Semantics)) {
        new (&Double) DoubleAPFloat(Semantics, std::forward<ArgTypes>(Args)...);
        return;
      }
      llvm_unreachable("Unexpected semantics");
    }

    ~Storage() {
      if (usesLayout<IEEEFloat>(*semantics)) {
        IEEE.~IEEEFloat();
        return;
      }
      if (usesLayout<DoubleAPFloat>(*semantics)) {
        Double.~DoubleAPFloat();
        return;
      }
      llvm_unreachable("Unexpected semantics");
    }

    Storage(const Storage &RHS) {
      if (usesLayout<IEEEFloat>(*RHS.semantics)) {
        new (this) IEEEFloat(RHS.IEEE);
        return;
      }
      if (usesLayout<DoubleAPFloat>(*RHS.semantics)) {
        new (this) DoubleAPFloat(RHS.Double);
        return;
      }
      llvm_unreachable("Unexpected semantics");
    }

    Storage(Storage &&RHS) {
      if (usesLayout<IEEEFloat>(*RHS.semantics)) {
        new (this) IEEEFloat(std::move(RHS.IEEE));
        return;
      }
      if (usesLayout<DoubleAPFloat>(*RHS.semantics)) {
        new (this) DoubleAPFloat(std::move(RHS.Double));
        return;
      }
      llvm_unreachable("Unexpected semantics");
    }

    Storage &operator=(const Storage &RHS) {
      if (usesLayout<IEEEFloat>(*semantics) &&
          usesLayout<IEEEFloat>(*RHS.semantics)) {
        IEEE = RHS.IEEE;
      } else if (usesLayout<DoubleAPFloat>(*semantics) &&
                 usesLayout<DoubleAPFloat>(*RHS.semantics)) {
        Double = RHS.Double;
      } else if (this != &RHS) {
        this->~Storage();
        new (this) Storage(RHS);
      }
      return *this;
    }

    Storage &operator=(Storage &&RHS) {
      if (usesLayout<IEEEFloat>(*semantics) &&
          usesLayout<IEEEFloat>(*RHS.semantics)) {
        IEEE = std::move(RHS.IEEE);
      } else if (usesLayout<DoubleAPFloat>(*semantics) &&
                 usesLayout<DoubleAPFloat>(*RHS.semantics)) {
        Double = std::move(RHS.Double);
      } else if (this != &RHS) {
        this->~Storage();
        new (this) Storage(std::move(RHS));
      }
      return *this;
    }
  } U;

  template <typename T> static bool usesLayout(const fltSemantics &Semantics) {
    static_assert(std::is_same<T, IEEEFloat>::value ||
                  std::is_same<T, DoubleAPFloat>::value, "");
    if (std::is_same<T, DoubleAPFloat>::value) {
      return &Semantics == &PPCDoubleDouble();
    }
    return &Semantics != &PPCDoubleDouble();
  }

  IEEEFloat &getIEEE() {
    if (usesLayout<IEEEFloat>(*U.semantics))
      return U.IEEE;
    if (usesLayout<DoubleAPFloat>(*U.semantics))
      return U.Double.getFirst().U.IEEE;
    llvm_unreachable("Unexpected semantics");
  }

  const IEEEFloat &getIEEE() const {
    if (usesLayout<IEEEFloat>(*U.semantics))
      return U.IEEE;
    if (usesLayout<DoubleAPFloat>(*U.semantics))
      return U.Double.getFirst().U.IEEE;
    llvm_unreachable("Unexpected semantics");
  }

  void makeZero(bool Neg) { APFLOAT_DISPATCH_ON_SEMANTICS(makeZero(Neg)); }

  void makeInf(bool Neg) { APFLOAT_DISPATCH_ON_SEMANTICS(makeInf(Neg)); }

  void makeNaN(bool SNaN, bool Neg, const APInt *fill) {
    APFLOAT_DISPATCH_ON_SEMANTICS(makeNaN(SNaN, Neg, fill));
  }

  void makeLargest(bool Neg) {
    APFLOAT_DISPATCH_ON_SEMANTICS(makeLargest(Neg));
  }

  void makeSmallest(bool Neg) {
    APFLOAT_DISPATCH_ON_SEMANTICS(makeSmallest(Neg));
  }

  void makeSmallestNormalized(bool Neg) {
    APFLOAT_DISPATCH_ON_SEMANTICS(makeSmallestNormalized(Neg));
  }

                                                                             
                                                                         
                                                  
  APFloat() : U(IEEEdouble()) {
    llvm_unreachable("This is a workaround for old clang.");
  }

  explicit APFloat(IEEEFloat F, const fltSemantics &S) : U(std::move(F), S) {}
  explicit APFloat(DoubleAPFloat F, const fltSemantics &S)
      : U(std::move(F), S) {}

  cmpResult compareAbsoluteValue(const APFloat &RHS) const {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only compare APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.compareAbsoluteValue(RHS.U.IEEE);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.compareAbsoluteValue(RHS.U.Double);
    llvm_unreachable("Unexpected semantics");
  }

public:
  APFloat(const fltSemantics &Semantics) : U(Semantics) {}
  APFloat(const fltSemantics &Semantics, StringRef S);
  APFloat(const fltSemantics &Semantics, integerPart I) : U(Semantics, I) {}
                                                                         
  APFloat(const fltSemantics &Semantics, uninitializedTag)
      : U(Semantics, uninitialized) {}
  APFloat(const fltSemantics &Semantics, const APInt &I) : U(Semantics, I) {}
  explicit APFloat(double d) : U(IEEEFloat(d), IEEEdouble()) {}
  explicit APFloat(float f) : U(IEEEFloat(f), IEEEsingle()) {}
  APFloat(const APFloat &RHS) = default;
  APFloat(APFloat &&RHS) = default;

  ~APFloat() = default;

  bool needsCleanup() const { APFLOAT_DISPATCH_ON_SEMANTICS(needsCleanup()); }

                                             
     
                                                             
  static APFloat getZero(const fltSemantics &Sem, bool Negative = false) {
    APFloat Val(Sem, uninitialized);
    Val.makeZero(Negative);
    return Val;
  }

                                                 
     
                                                             
  static APFloat getInf(const fltSemantics &Sem, bool Negative = false) {
    APFloat Val(Sem, uninitialized);
    Val.makeInf(Negative);
    return Val;
  }

                             
     
                                                                      
                                                                        
                                                    
  static APFloat getNaN(const fltSemantics &Sem, bool Negative = false,
                        unsigned type = 0) {
    if (type) {
      APInt fill(64, type);
      return getQNaN(Sem, Negative, &fill);
    } else {
      return getQNaN(Sem, Negative, nullptr);
    }
  }

                              
  static APFloat getQNaN(const fltSemantics &Sem, bool Negative = false,
                         const APInt *payload = nullptr) {
    APFloat Val(Sem, uninitialized);
    Val.makeNaN(false, Negative, payload);
    return Val;
  }

                              
  static APFloat getSNaN(const fltSemantics &Sem, bool Negative = false,
                         const APInt *payload = nullptr) {
    APFloat Val(Sem, uninitialized);
    Val.makeNaN(true, Negative, payload);
    return Val;
  }

                                                               
     
                                                              
  static APFloat getLargest(const fltSemantics &Sem, bool Negative = false) {
    APFloat Val(Sem, uninitialized);
    Val.makeLargest(Negative);
    return Val;
  }

                                                                               
                                                                        
     
                                                              
  static APFloat getSmallest(const fltSemantics &Sem, bool Negative = false) {
    APFloat Val(Sem, uninitialized);
    Val.makeSmallest(Negative);
    return Val;
  }

                                                                               
                
     
                                                              
  static APFloat getSmallestNormalized(const fltSemantics &Sem,
                                       bool Negative = false) {
    APFloat Val(Sem, uninitialized);
    Val.makeSmallestNormalized(Negative);
    return Val;
  }

                                                                   
     
                                         
                                                                      
  static APFloat getAllOnesValue(unsigned BitWidth, bool isIEEE = false);

                                                                              
                       
  void Profile(FoldingSetNodeID &NID) const;

  opStatus add(const APFloat &RHS, roundingMode RM) {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only call on two APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.add(RHS.U.IEEE, RM);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.add(RHS.U.Double, RM);
    llvm_unreachable("Unexpected semantics");
  }
  opStatus subtract(const APFloat &RHS, roundingMode RM) {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only call on two APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.subtract(RHS.U.IEEE, RM);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.subtract(RHS.U.Double, RM);
    llvm_unreachable("Unexpected semantics");
  }
  opStatus multiply(const APFloat &RHS, roundingMode RM) {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only call on two APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.multiply(RHS.U.IEEE, RM);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.multiply(RHS.U.Double, RM);
    llvm_unreachable("Unexpected semantics");
  }
  opStatus divide(const APFloat &RHS, roundingMode RM) {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only call on two APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.divide(RHS.U.IEEE, RM);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.divide(RHS.U.Double, RM);
    llvm_unreachable("Unexpected semantics");
  }
  opStatus remainder(const APFloat &RHS) {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only call on two APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.remainder(RHS.U.IEEE);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.remainder(RHS.U.Double);
    llvm_unreachable("Unexpected semantics");
  }
  opStatus mod(const APFloat &RHS) {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only call on two APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.mod(RHS.U.IEEE);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.mod(RHS.U.Double);
    llvm_unreachable("Unexpected semantics");
  }
  opStatus fusedMultiplyAdd(const APFloat &Multiplicand, const APFloat &Addend,
                            roundingMode RM) {
    assert(&getSemantics() == &Multiplicand.getSemantics() &&
           "Should only call on APFloats with the same semantics");
    assert(&getSemantics() == &Addend.getSemantics() &&
           "Should only call on APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.fusedMultiplyAdd(Multiplicand.U.IEEE, Addend.U.IEEE, RM);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.fusedMultiplyAdd(Multiplicand.U.Double, Addend.U.Double,
                                       RM);
    llvm_unreachable("Unexpected semantics");
  }
  opStatus roundToIntegral(roundingMode RM) {
    APFLOAT_DISPATCH_ON_SEMANTICS(roundToIntegral(RM));
  }

                                                                 
                  
  opStatus next(bool nextDown) {
    APFLOAT_DISPATCH_ON_SEMANTICS(next(nextDown));
  }

                                                          
                        
  APFloat operator+(const APFloat &RHS) const {
    APFloat Result(*this);
    (void)Result.add(RHS, rmNearestTiesToEven);
    return Result;
  }

                                                               
                        
  APFloat operator-(const APFloat &RHS) const {
    APFloat Result(*this);
    (void)Result.subtract(RHS, rmNearestTiesToEven);
    return Result;
  }

                                                               
                        
  APFloat operator*(const APFloat &RHS) const {
    APFloat Result(*this);
    (void)Result.multiply(RHS, rmNearestTiesToEven);
    return Result;
  }

                                                                                
                        
  APFloat operator/(const APFloat &RHS) const {
    APFloat Result(*this);
    (void)Result.divide(RHS, rmNearestTiesToEven);
    return Result;
  }

  void changeSign() { APFLOAT_DISPATCH_ON_SEMANTICS(changeSign()); }
  void clearSign() {
    if (isNegative())
      changeSign();
  }
  void copySign(const APFloat &RHS) {
    if (isNegative() != RHS.isNegative())
      changeSign();
  }

                                                                         
                                     
  static APFloat copySign(APFloat Value, const APFloat &Sign) {
    Value.copySign(Sign);
    return Value;
  }

  opStatus convert(const fltSemantics &ToSemantics, roundingMode RM,
                   bool *losesInfo);
  opStatus convertToInteger(MutableArrayRef<integerPart> Input,
                            unsigned int Width, bool IsSigned, roundingMode RM,
                            bool *IsExact) const {
    APFLOAT_DISPATCH_ON_SEMANTICS(
        convertToInteger(Input, Width, IsSigned, RM, IsExact));
  }
  opStatus convertToInteger(APSInt &Result, roundingMode RM,
                            bool *IsExact) const;
  opStatus convertFromAPInt(const APInt &Input, bool IsSigned,
                            roundingMode RM) {
    APFLOAT_DISPATCH_ON_SEMANTICS(convertFromAPInt(Input, IsSigned, RM));
  }
  opStatus convertFromSignExtendedInteger(const integerPart *Input,
                                          unsigned int InputSize, bool IsSigned,
                                          roundingMode RM) {
    APFLOAT_DISPATCH_ON_SEMANTICS(
        convertFromSignExtendedInteger(Input, InputSize, IsSigned, RM));
  }
  opStatus convertFromZeroExtendedInteger(const integerPart *Input,
                                          unsigned int InputSize, bool IsSigned,
                                          roundingMode RM) {
    APFLOAT_DISPATCH_ON_SEMANTICS(
        convertFromZeroExtendedInteger(Input, InputSize, IsSigned, RM));
  }
  opStatus convertFromString(StringRef, roundingMode);
  APInt bitcastToAPInt() const {
    APFLOAT_DISPATCH_ON_SEMANTICS(bitcastToAPInt());
  }
  double convertToDouble() const { return getIEEE().convertToDouble(); }
  float convertToFloat() const { return getIEEE().convertToFloat(); }

  bool operator==(const APFloat &) const = delete;

  cmpResult compare(const APFloat &RHS) const {
    assert(&getSemantics() == &RHS.getSemantics() &&
           "Should only compare APFloats with the same semantics");
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.compare(RHS.U.IEEE);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.compare(RHS.U.Double);
    llvm_unreachable("Unexpected semantics");
  }

  bool bitwiseIsEqual(const APFloat &RHS) const {
    if (&getSemantics() != &RHS.getSemantics())
      return false;
    if (usesLayout<IEEEFloat>(getSemantics()))
      return U.IEEE.bitwiseIsEqual(RHS.U.IEEE);
    if (usesLayout<DoubleAPFloat>(getSemantics()))
      return U.Double.bitwiseIsEqual(RHS.U.Double);
    llvm_unreachable("Unexpected semantics");
  }

                                                              
                                                                               
                                                                               
                                
     
                                                                             
                                                                         
                                                         
  bool isExactlyValue(double V) const {
    bool ignored;
    APFloat Tmp(V);
    Tmp.convert(getSemantics(), APFloat::rmNearestTiesToEven, &ignored);
    return bitwiseIsEqual(Tmp);
  }

  unsigned int convertToHexString(char *DST, unsigned int HexDigits,
                                  bool UpperCase, roundingMode RM) const {
    APFLOAT_DISPATCH_ON_SEMANTICS(
        convertToHexString(DST, HexDigits, UpperCase, RM));
  }

  bool isZero() const { return getCategory() == fcZero; }
  bool isInfinity() const { return getCategory() == fcInfinity; }
  bool isNaN() const { return getCategory() == fcNaN; }

  bool isNegative() const { return getIEEE().isNegative(); }
  bool isDenormal() const { APFLOAT_DISPATCH_ON_SEMANTICS(isDenormal()); }
  bool isSignaling() const { return getIEEE().isSignaling(); }

  bool isNormal() const { return !isDenormal() && isFiniteNonZero(); }
  bool isFinite() const { return !isNaN() && !isInfinity(); }

  fltCategory getCategory() const { return getIEEE().getCategory(); }
  const fltSemantics &getSemantics() const { return *U.semantics; }
  bool isNonZero() const { return !isZero(); }
  bool isFiniteNonZero() const { return isFinite() && !isZero(); }
  bool isPosZero() const { return isZero() && !isNegative(); }
  bool isNegZero() const { return isZero() && isNegative(); }
  bool isSmallest() const { APFLOAT_DISPATCH_ON_SEMANTICS(isSmallest()); }
  bool isLargest() const { APFLOAT_DISPATCH_ON_SEMANTICS(isLargest()); }
  bool isInteger() const { APFLOAT_DISPATCH_ON_SEMANTICS(isInteger()); }

  APFloat &operator=(const APFloat &RHS) = default;
  APFloat &operator=(APFloat &&RHS) = default;

  void toString(SmallVectorImpl<char> &Str, unsigned FormatPrecision = 0,
                unsigned FormatMaxPadding = 3, bool TruncateZero = true) const {
    APFLOAT_DISPATCH_ON_SEMANTICS(
        toString(Str, FormatPrecision, FormatMaxPadding, TruncateZero));
  }

  void print(raw_ostream &) const;
  void dump() const;

  bool getExactInverse(APFloat *inv) const {
    APFLOAT_DISPATCH_ON_SEMANTICS(getExactInverse(inv));
  }

  friend hash_code hash_value(const APFloat &Arg);
  friend int ilogb(const APFloat &Arg) { return ilogb(Arg.getIEEE()); }
  friend APFloat scalbn(APFloat X, int Exp, roundingMode RM);
  friend APFloat frexp(const APFloat &X, int &Exp, roundingMode RM);
  friend IEEEFloat;
  friend DoubleAPFloat;
};

                                  
   
                                                                                
                 
hash_code hash_value(const APFloat &Arg);
inline APFloat scalbn(APFloat X, int Exp, APFloat::roundingMode RM) {
  if (APFloat::usesLayout<detail::IEEEFloat>(X.getSemantics()))
    return APFloat(scalbn(X.U.IEEE, Exp, RM), X.getSemantics());
  if (APFloat::usesLayout<detail::DoubleAPFloat>(X.getSemantics()))
    return APFloat(scalbn(X.U.Double, Exp, RM), X.getSemantics());
  llvm_unreachable("Unexpected semantics");
}

                                              
   
                                                                               
                                                              
inline APFloat frexp(const APFloat &X, int &Exp, APFloat::roundingMode RM) {
  if (APFloat::usesLayout<detail::IEEEFloat>(X.getSemantics()))
    return APFloat(frexp(X.U.IEEE, Exp, RM), X.getSemantics());
  if (APFloat::usesLayout<detail::DoubleAPFloat>(X.getSemantics()))
    return APFloat(frexp(X.U.Double, Exp, RM), X.getSemantics());
  llvm_unreachable("Unexpected semantics");
}
                                               
inline APFloat abs(APFloat X) {
  X.clearSign();
  return X;
}

                                              
inline APFloat neg(APFloat X) {
  X.changeSign();
  return X;
}

                                                                               
                                                                              
LLVM_READONLY
inline APFloat minnum(const APFloat &A, const APFloat &B) {
  if (A.isNaN())
    return B;
  if (B.isNaN())
    return A;
  return (B.compare(A) == APFloat::cmpLessThan) ? B : A;
}

                                                                              
                                                                              
LLVM_READONLY
inline APFloat maxnum(const APFloat &A, const APFloat &B) {
  if (A.isNaN())
    return B;
  if (B.isNaN())
    return A;
  return (A.compare(B) == APFloat::cmpLessThan) ? B : A;
}

}                  

#undef APFLOAT_DISPATCH_ON_SEMANTICS
#endif                      
