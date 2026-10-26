//===- llvm/Use.h - Definition of the Use class -----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This defines the Use class.  The Use class represents the operand of an
/// instruction or some other User instance which refers to a Value.  The Use
/// class keeps the "use list" of the referenced value up to date.
///
/// Pointer tagging is used to efficiently find the User corresponding to a Use
/// without having to store a User pointer in every Use. A User is preceded in
/// memory by all the Uses corresponding to its operands, and the low bits of
/// one of the fields (Prev) of the Use class are used to encode offsets to be
/// able to find that User given a pointer to any Use. For details, see:
///
///   http://www.llvm.org/docs/ProgrammersManual.html#UserLayout
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_USE_H
#define LLVM_IR_USE_H

#include "llvh-c/Types.h"
#include "llvh/ADT/PointerIntPair.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/Compiler.h"

namespace llvh {

template <typename> struct simplify_type;
class User;
class Value;

                                                                       
   
                                                                            
                                                                               
                                                                           
                                                                      
   
                                                                             
                                                                      
                                         
   
                                                                              
   
                                                                               
                                                                            
                                                                              
                    
class Use {
public:
  Use(const Use &U) = delete;

                                                 
                                                            
  void swap(Use &RHS);

                                                                           
                                                                       
  struct UserRefPointerTraits {
    static inline void *getAsVoidPointer(User *P) { return P; }

    static inline User *getFromVoidPointer(void *P) {
      return (User *)P;
    }

    enum { NumLowBitsAvailable = 1 };
  };

                                                                                
                                                          
  using UserRef = PointerIntPair<User *, 1, unsigned, UserRefPointerTraits>;

                                                                            
                                                                        
  struct PrevPointerTraits {
    static inline void *getAsVoidPointer(Use **P) { return P; }

    static inline Use **getFromVoidPointer(void *P) {
      return (Use **)P;
    }

    enum { NumLowBitsAvailable = 2 };
  };

private:
                                 
  ~Use() {
    if (Val)
      removeFromList();
  }

  enum PrevPtrTag { zeroDigitTag, oneDigitTag, stopTag, fullStopTag };

                 
  Use(PrevPtrTag tag) { Prev.setInt(tag); }

public:
  friend class Value;

  operator Value *() const { return Val; }
  Value *get() const { return Val; }

                                              
     
                                                                   
                  
  User *getUser() const LLVM_READONLY;

  inline void set(Value *Val);

  inline Value *operator=(Value *RHS);
  inline const Use &operator=(const Use &RHS);

  Value *operator->() { return Val; }
  const Value *operator->() const { return Val; }

  Use *getNext() const { return Next; }

                                                   
  unsigned getOperandNo() const;

                                                          
     
                                                                               
                        
  static Use *initTags(Use *Start, Use *Stop);

                                                          
                     
  static void zap(Use *Start, const Use *Stop, bool del = false);

private:
  const Use *getImpliedUser() const LLVM_READONLY;

  Value *Val = nullptr;
  Use *Next;
  PointerIntPair<Use **, 2, PrevPtrTag, PrevPointerTraits> Prev;

  void setPrev(Use **NewPrev) { Prev.setPointer(NewPrev); }

  void addToList(Use **List) {
    Next = *List;
    if (Next)
      Next->setPrev(&Next);
    setPrev(List);
    *List = this;
  }

  void removeFromList() {
    Use **StrippedPrev = Prev.getPointer();
    *StrippedPrev = Next;
    if (Next)
      Next->setPrev(StrippedPrev);
  }
};

                                                           
                      
template <> struct simplify_type<Use> {
  using SimpleType = Value *;

  static SimpleType getSimplifiedValue(Use &Val) { return Val.get(); }
};
template <> struct simplify_type<const Use> {
  using SimpleType =           Value *;

  static SimpleType getSimplifiedValue(const Use &Val) { return Val.get(); }
};

                                                                
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(Use, LLVMUseRef)

}                      

#endif                 
