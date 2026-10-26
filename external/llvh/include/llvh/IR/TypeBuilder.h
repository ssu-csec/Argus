//===---- llvm/TypeBuilder.h - Builder for LLVM types -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the TypeBuilder class, which is used as a convenient way to
// create LLVM types with a consistent and simplified interface.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_TYPEBUILDER_H
#define LLVM_IR_TYPEBUILDER_H

#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/LLVMContext.h"
#include <climits>

namespace llvh {

                                                                  
                                                                     
                                                                
                                                                     
                                                                    
                                                                  
                                                                     
                                                                   
                                                                     
                                                                
                                                                      
                                   
   
               
   
                     
                
                 
                                                         
        
                                           
   
            
   
                      
                                                                           
                                                                            
                                                                              
          
   
               
   
                      
                                                                   
             
                                                      
                                                                     
                                  
                                 
                                                              
                                                               
                                                                
                     
         
   
                                                                     
                                                                     
                                        
                     
                  
                  
                     
          
       
                          
   
            
   
                                                                                
                                                                        
                                                   
template<typename T, bool cross_compilable> class TypeBuilder {};

                                                                      
                                    
namespace types {
                                                         
template<uint32_t num_bits> class i {};

                                                           
class ieee_float {};
class ieee_double {};
class x86_fp80 {};
class fp128 {};
class ppc_fp128 {};
           
class x86_mmx {};
}                    

                                             
template<typename T, bool cross> class TypeBuilder<const T, cross>
  : public TypeBuilder<T, cross> {};
template<typename T, bool cross> class TypeBuilder<volatile T, cross>
  : public TypeBuilder<T, cross> {};
template<typename T, bool cross> class TypeBuilder<const volatile T, cross>
  : public TypeBuilder<T, cross> {};

           
template<typename T, bool cross> class TypeBuilder<T*, cross> {
public:
  static PointerType *get(LLVMContext &Context) {
    return PointerType::getUnqual(TypeBuilder<T,cross>::get(Context));
  }
};

                                      
template<typename T, bool cross> class TypeBuilder<T&, cross> {};

         
template<typename T, size_t N, bool cross> class TypeBuilder<T[N], cross> {
public:
  static ArrayType *get(LLVMContext &Context) {
    return ArrayType::get(TypeBuilder<T, cross>::get(Context), N);
  }
};
                                                                        
template<typename T, bool cross> class TypeBuilder<T[], cross> {
public:
  static ArrayType *get(LLVMContext &Context) {
    return ArrayType::get(TypeBuilder<T, cross>::get(Context), 0);
  }
};

                                                              
  
                                                                           
                                                                              
                     
  
                                              
  
                         
                               
                         
  
                                                                               
                                                                             
                                                                               
                                            
  
                         
                               
                        
  
                                                           
#define DEFINE_INTEGRAL_TYPEBUILDER(T) \
template<> class TypeBuilder<T, false> { \
public: \
  static IntegerType *get(LLVMContext &Context) { \
    return IntegerType::get(Context, sizeof(T) * CHAR_BIT); \
  } \
}; \
template<> class TypeBuilder<T, true> { \
                                                                 \
                                    \
}
DEFINE_INTEGRAL_TYPEBUILDER(char);
DEFINE_INTEGRAL_TYPEBUILDER(signed char);
DEFINE_INTEGRAL_TYPEBUILDER(unsigned char);
DEFINE_INTEGRAL_TYPEBUILDER(short);
DEFINE_INTEGRAL_TYPEBUILDER(unsigned short);
DEFINE_INTEGRAL_TYPEBUILDER(int);
DEFINE_INTEGRAL_TYPEBUILDER(unsigned int);
DEFINE_INTEGRAL_TYPEBUILDER(long);
DEFINE_INTEGRAL_TYPEBUILDER(unsigned long);
#ifdef _MSC_VER
DEFINE_INTEGRAL_TYPEBUILDER(__int64);
DEFINE_INTEGRAL_TYPEBUILDER(unsigned __int64);
#else               
DEFINE_INTEGRAL_TYPEBUILDER(long long);
DEFINE_INTEGRAL_TYPEBUILDER(unsigned long long);
#endif               
#undef DEFINE_INTEGRAL_TYPEBUILDER

template<uint32_t num_bits, bool cross>
class TypeBuilder<types::i<num_bits>, cross> {
public:
  static IntegerType *get(LLVMContext &C) {
    return IntegerType::get(C, num_bits);
  }
};

template<> class TypeBuilder<float, false> {
public:
  static Type *get(LLVMContext& C) {
    return Type::getFloatTy(C);
  }
};
template<> class TypeBuilder<float, true> {};

template<> class TypeBuilder<double, false> {
public:
  static Type *get(LLVMContext& C) {
    return Type::getDoubleTy(C);
  }
};
template<> class TypeBuilder<double, true> {};

template<bool cross> class TypeBuilder<types::ieee_float, cross> {
public:
  static Type *get(LLVMContext& C) { return Type::getFloatTy(C); }
};
template<bool cross> class TypeBuilder<types::ieee_double, cross> {
public:
  static Type *get(LLVMContext& C) { return Type::getDoubleTy(C); }
};
template<bool cross> class TypeBuilder<types::x86_fp80, cross> {
public:
  static Type *get(LLVMContext& C) { return Type::getX86_FP80Ty(C); }
};
template<bool cross> class TypeBuilder<types::fp128, cross> {
public:
  static Type *get(LLVMContext& C) { return Type::getFP128Ty(C); }
};
template<bool cross> class TypeBuilder<types::ppc_fp128, cross> {
public:
  static Type *get(LLVMContext& C) { return Type::getPPC_FP128Ty(C); }
};
template<bool cross> class TypeBuilder<types::x86_mmx, cross> {
public:
  static Type *get(LLVMContext& C) { return Type::getX86_MMXTy(C); }
};

template<bool cross> class TypeBuilder<void, cross> {
public:
  static Type *get(LLVMContext &C) {
    return Type::getVoidTy(C);
  }
};

                                                                                
                       
template<> class TypeBuilder<void*, false>
  : public TypeBuilder<types::i<8>*, false> {};
template<> class TypeBuilder<const void*, false>
  : public TypeBuilder<types::i<8>*, false> {};
template<> class TypeBuilder<volatile void*, false>
  : public TypeBuilder<types::i<8>*, false> {};
template<> class TypeBuilder<const volatile void*, false>
  : public TypeBuilder<types::i<8>*, false> {};

template<typename R, bool cross> class TypeBuilder<R(), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    return FunctionType::get(TypeBuilder<R, cross>::get(Context), false);
  }
};
template<typename R, typename A1, bool cross> class TypeBuilder<R(A1), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                             params, false);
  }
};
template<typename R, typename A1, typename A2, bool cross>
class TypeBuilder<R(A1, A2), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                             params, false);
  }
};
template<typename R, typename A1, typename A2, typename A3, bool cross>
class TypeBuilder<R(A1, A2, A3), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
      TypeBuilder<A3, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                             params, false);
  }
};

template<typename R, typename A1, typename A2, typename A3, typename A4,
         bool cross>
class TypeBuilder<R(A1, A2, A3, A4), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
      TypeBuilder<A3, cross>::get(Context),
      TypeBuilder<A4, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                             params, false);
  }
};

template<typename R, typename A1, typename A2, typename A3, typename A4,
         typename A5, bool cross>
class TypeBuilder<R(A1, A2, A3, A4, A5), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
      TypeBuilder<A3, cross>::get(Context),
      TypeBuilder<A4, cross>::get(Context),
      TypeBuilder<A5, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                             params, false);
  }
};

template<typename R, bool cross> class TypeBuilder<R(...), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    return FunctionType::get(TypeBuilder<R, cross>::get(Context), true);
  }
};
template<typename R, typename A1, bool cross>
class TypeBuilder<R(A1, ...), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context), params, true);
  }
};
template<typename R, typename A1, typename A2, bool cross>
class TypeBuilder<R(A1, A2, ...), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                                   params, true);
  }
};
template<typename R, typename A1, typename A2, typename A3, bool cross>
class TypeBuilder<R(A1, A2, A3, ...), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
      TypeBuilder<A3, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                                   params, true);
  }
};

template<typename R, typename A1, typename A2, typename A3, typename A4,
         bool cross>
class TypeBuilder<R(A1, A2, A3, A4, ...), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
      TypeBuilder<A3, cross>::get(Context),
      TypeBuilder<A4, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                             params, true);
  }
};

template<typename R, typename A1, typename A2, typename A3, typename A4,
         typename A5, bool cross>
class TypeBuilder<R(A1, A2, A3, A4, A5, ...), cross> {
public:
  static FunctionType *get(LLVMContext &Context) {
    Type *params[] = {
      TypeBuilder<A1, cross>::get(Context),
      TypeBuilder<A2, cross>::get(Context),
      TypeBuilder<A3, cross>::get(Context),
      TypeBuilder<A4, cross>::get(Context),
      TypeBuilder<A5, cross>::get(Context),
    };
    return FunctionType::get(TypeBuilder<R, cross>::get(Context),
                                   params, true);
  }
};

}                   

#endif
