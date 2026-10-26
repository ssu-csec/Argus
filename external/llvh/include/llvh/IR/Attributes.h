//===- llvm/Attributes.h - Container for Attributes -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// \file
/// This file contains the simple types necessary to represent the
/// attributes associated with functions and their calls.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_ATTRIBUTES_H
#define LLVM_IR_ATTRIBUTES_H

#include "llvh-c/Types.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/FoldingSet.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/Config/llvm-config.h"
#include "llvh/Support/PointerLikeTypeTraits.h"
#include <bitset>
#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace llvh {

class AttrBuilder;
class AttributeImpl;
class AttributeListImpl;
class AttributeSetNode;
template<typename T> struct DenseMapInfo;
class Function;
class LLVMContext;
class Type;

                                                                                
          
                                                                        
                                                                    
                                                                                
                                         
class Attribute {
public:
                                                                       
                                                           
     
                                                                             
                                                                               
                              
     
                                                                         
                                                                               
                                         
     
                                                                             
                                               
                                                                             
                                                      
                                                                  

  enum AttrKind {
                          
    None,                                                  
    #define GET_ATTR_ENUM
    #include "llvh/IR/Attributes.inc"
    EndAttrKinds                                               
  };

private:
  AttributeImpl *pImpl = nullptr;

  Attribute(AttributeImpl *A) : pImpl(A) {}

public:
  Attribute() = default;

                                                                                
                           
                                                                                

                                           
  static Attribute get(LLVMContext &Context, AttrKind Kind, uint64_t Val = 0);
  static Attribute get(LLVMContext &Context, StringRef Kind,
                       StringRef Val = StringRef());

                                                                
                    
  static Attribute getWithAlignment(LLVMContext &Context, uint64_t Align);
  static Attribute getWithStackAlignment(LLVMContext &Context, uint64_t Align);
  static Attribute getWithDereferenceableBytes(LLVMContext &Context,
                                              uint64_t Bytes);
  static Attribute getWithDereferenceableOrNullBytes(LLVMContext &Context,
                                                     uint64_t Bytes);
  static Attribute getWithAllocSizeArgs(LLVMContext &Context,
                                        unsigned ElemSizeArg,
                                        const Optional<unsigned> &NumElemsArg);

                                                                                
                        
                                                                                

                                                                  
  bool isEnumAttribute() const;

                                                           
  bool isIntAttribute() const;

                                                                 
                
  bool isStringAttribute() const;

                                              
  bool hasAttribute(AttrKind Val) const;

                                                               
  bool hasAttribute(StringRef Val) const;

                                                                        
                                                                
  Attribute::AttrKind getKindAsEnum() const;

                                                                        
                                        
  uint64_t getValueAsInt() const;

                                                                
                                         
  StringRef getKindAsString() const;

                                                                 
                                         
  StringRef getValueAsString() const;

                                                                     
            
  unsigned getAlignment() const;

                                                                 
                      
  unsigned getStackAlignment() const;

                                                          
                                
  uint64_t getDereferenceableBytes() const;

                                                                  
                                        
  uint64_t getDereferenceableOrNullBytes() const;

                                                                             
                    
  std::pair<unsigned, Optional<unsigned>> getAllocSizeArgs() const;

                                                                         
                                                                            
  std::string getAsString(bool InAttrGrp = false) const;

                                          
  bool operator==(Attribute A) const { return pImpl == A.pImpl; }
  bool operator!=(Attribute A) const { return pImpl != A.pImpl; }

                                                                 
  bool operator<(Attribute A) const;

  void Profile(FoldingSetNodeID &ID) const {
    ID.AddPointer(pImpl);
  }

                                                                   
  void *getRawPointer() const {
    return pImpl;
  }

                                                                   
  static Attribute fromRawPointer(void *RawPtr) {
    return Attribute(reinterpret_cast<AttributeImpl*>(RawPtr));
  }
};

                                        
inline LLVMAttributeRef wrap(Attribute Attr) {
  return reinterpret_cast<LLVMAttributeRef>(Attr.getRawPointer());
}

                                        
inline Attribute unwrap(LLVMAttributeRef Attr) {
  return Attribute::fromRawPointer(Attr);
}

                                                                                
          
                                                                         
                                                                             
                                                                                
                                                                           
class AttributeSet {
  friend AttributeListImpl;
  template <typename Ty> friend struct DenseMapInfo;

                                                                            
                                                                    
                                    

                                     
  AttributeSetNode *SetNode = nullptr;

private:
  explicit AttributeSet(AttributeSetNode *ASN) : SetNode(ASN) {}

public:
                                                      
  AttributeSet() = default;
  AttributeSet(const AttributeSet &) = default;
  ~AttributeSet() = default;

  static AttributeSet get(LLVMContext &C, const AttrBuilder &B);
  static AttributeSet get(LLVMContext &C, ArrayRef<Attribute> Attrs);

  bool operator==(const AttributeSet &O) const { return SetNode == O.SetNode; }
  bool operator!=(const AttributeSet &O) const { return !(*this == O); }

                                                                             
                
  AttributeSet addAttribute(LLVMContext &C, Attribute::AttrKind Kind) const;

                                                                                
                    
  AttributeSet addAttribute(LLVMContext &C, StringRef Kind,
                            StringRef Value = StringRef()) const;

                                                                              
                         
  AttributeSet addAttributes(LLVMContext &C, AttributeSet AS) const;

                                                                             
                                   
  AttributeSet removeAttribute(LLVMContext &C, Attribute::AttrKind Kind) const;

                                                                             
                                   
  AttributeSet removeAttribute(LLVMContext &C, StringRef Kind) const;

                                                                              
                                   
  AttributeSet removeAttributes(LLVMContext &C,
                                const AttrBuilder &AttrsToRemove) const;

                                                  
  unsigned getNumAttributes() const;

                                                   
  bool hasAttributes() const { return SetNode != nullptr; }

                                                      
  bool hasAttribute(Attribute::AttrKind Kind) const;

                                                      
  bool hasAttribute(StringRef Kind) const;

                                  
  Attribute getAttribute(Attribute::AttrKind Kind) const;

                                                   
  Attribute getAttribute(StringRef Kind) const;

  unsigned getAlignment() const;
  unsigned getStackAlignment() const;
  uint64_t getDereferenceableBytes() const;
  uint64_t getDereferenceableOrNullBytes() const;
  std::pair<unsigned, Optional<unsigned>> getAllocSizeArgs() const;
  std::string getAsString(bool InAttrGrp = false) const;

  using iterator = const Attribute *;

  iterator begin() const;
  iterator end() const;
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
  void dump() const;
#endif
};

                                                                                
          
                                          
template <> struct DenseMapInfo<AttributeSet> {
  static AttributeSet getEmptyKey() {
    auto Val = static_cast<uintptr_t>(-1);
    Val <<= PointerLikeTypeTraits<void *>::NumLowBitsAvailable;
    return AttributeSet(reinterpret_cast<AttributeSetNode *>(Val));
  }

  static AttributeSet getTombstoneKey() {
    auto Val = static_cast<uintptr_t>(-2);
    Val <<= PointerLikeTypeTraits<void *>::NumLowBitsAvailable;
    return AttributeSet(reinterpret_cast<AttributeSetNode *>(Val));
  }

  static unsigned getHashValue(AttributeSet AS) {
    return (unsigned((uintptr_t)AS.SetNode) >> 4) ^
           (unsigned((uintptr_t)AS.SetNode) >> 9);
  }

  static bool isEqual(AttributeSet LHS, AttributeSet RHS) { return LHS == RHS; }
};

                                                                                
          
                                                                         
                                                                                
                                                                  
                                                                
                                                                                
                                         
class AttributeList {
public:
  enum AttrIndex : unsigned {
    ReturnIndex = 0U,
    FunctionIndex = ~0U,
    FirstArgIndex = 1,
  };

private:
  friend class AttrBuilder;
  friend class AttributeListImpl;
  friend class AttributeSet;
  friend class AttributeSetNode;
  template <typename Ty> friend struct DenseMapInfo;

                                                                        
                                
  AttributeListImpl *pImpl = nullptr;

public:
                                                                  
  static AttributeList get(LLVMContext &C,
                           ArrayRef<std::pair<unsigned, Attribute>> Attrs);
  static AttributeList get(LLVMContext &C,
                           ArrayRef<std::pair<unsigned, AttributeSet>> Attrs);

                                                                     
                                             
  static AttributeList get(LLVMContext &C, AttributeSet FnAttrs,
                           AttributeSet RetAttrs,
                           ArrayRef<AttributeSet> ArgAttrs);

private:
  explicit AttributeList(AttributeListImpl *LI) : pImpl(LI) {}

  static AttributeList getImpl(LLVMContext &C, ArrayRef<AttributeSet> AttrSets);

public:
  AttributeList() = default;

                                                                                
                                            
                                                                                

                                                                  
  static AttributeList get(LLVMContext &C, ArrayRef<AttributeList> Attrs);
  static AttributeList get(LLVMContext &C, unsigned Index,
                           ArrayRef<Attribute::AttrKind> Kinds);
  static AttributeList get(LLVMContext &C, unsigned Index,
                           ArrayRef<StringRef> Kind);
  static AttributeList get(LLVMContext &C, unsigned Index,
                           const AttrBuilder &B);

                                                               
                                                               
  AttributeList addAttribute(LLVMContext &C, unsigned Index,
                             Attribute::AttrKind Kind) const;

                                                               
                                                               
  AttributeList addAttribute(LLVMContext &C, unsigned Index, StringRef Kind,
                             StringRef Value = StringRef()) const;

                                                               
                                                               
  AttributeList addAttribute(LLVMContext &C, unsigned Index, Attribute A) const;

                                                             
                                                               
  AttributeList addAttributes(LLVMContext &C, unsigned Index,
                              const AttrBuilder &B) const;

                                                                       
                                    
  AttributeList addParamAttribute(LLVMContext &C, unsigned ArgNo,
                                  Attribute::AttrKind Kind) const {
    return addAttribute(C, ArgNo + FirstArgIndex, Kind);
  }

                                                                       
                                    
  AttributeList addParamAttribute(LLVMContext &C, unsigned ArgNo,
                                  StringRef Kind,
                                  StringRef Value = StringRef()) const {
    return addAttribute(C, ArgNo + FirstArgIndex, Kind, Value);
  }

                                                                                
                                                     
  AttributeList addParamAttribute(LLVMContext &C, ArrayRef<unsigned> ArgNos,
                                  Attribute A) const;

                                                                       
                                    
  AttributeList addParamAttributes(LLVMContext &C, unsigned ArgNo,
                                   const AttrBuilder &B) const {
    return addAttributes(C, ArgNo + FirstArgIndex, B);
  }

                                                                     
                                                                               
  AttributeList removeAttribute(LLVMContext &C, unsigned Index,
                                Attribute::AttrKind Kind) const;

                                                                     
                                                                               
  AttributeList removeAttribute(LLVMContext &C, unsigned Index,
                                StringRef Kind) const;

                                                                      
                                                                               
  AttributeList removeAttributes(LLVMContext &C, unsigned Index,
                                 const AttrBuilder &AttrsToRemove) const;

                                                            
                                                                               
  AttributeList removeAttributes(LLVMContext &C, unsigned Index) const;

                                                                         
                                                                               
  AttributeList removeParamAttribute(LLVMContext &C, unsigned ArgNo,
                                     Attribute::AttrKind Kind) const {
    return removeAttribute(C, ArgNo + FirstArgIndex, Kind);
  }

                                                                         
                                                                               
  AttributeList removeParamAttribute(LLVMContext &C, unsigned ArgNo,
                                     StringRef Kind) const {
    return removeAttribute(C, ArgNo + FirstArgIndex, Kind);
  }

                                                                         
                                                                               
  AttributeList removeParamAttributes(LLVMContext &C, unsigned ArgNo,
                                      const AttrBuilder &AttrsToRemove) const {
    return removeAttributes(C, ArgNo + FirstArgIndex, AttrsToRemove);
  }

                                                                
                                                                               
  AttributeList removeParamAttributes(LLVMContext &C, unsigned ArgNo) const {
    return removeAttributes(C, ArgNo + FirstArgIndex);
  }

                                                                                
                                                                      
  AttributeList addDereferenceableAttr(LLVMContext &C, unsigned Index,
                                       uint64_t Bytes) const;

                                                                                
                                                                          
  AttributeList addDereferenceableParamAttr(LLVMContext &C, unsigned ArgNo,
                                            uint64_t Bytes) const {
    return addDereferenceableAttr(C, ArgNo + FirstArgIndex, Bytes);
  }

                                                                       
                                                                                
  AttributeList addDereferenceableOrNullAttr(LLVMContext &C, unsigned Index,
                                             uint64_t Bytes) const;

                                                                       
                                                                         
                
  AttributeList addDereferenceableOrNullParamAttr(LLVMContext &C,
                                                  unsigned ArgNo,
                                                  uint64_t Bytes) const {
    return addDereferenceableOrNullAttr(C, ArgNo + FirstArgIndex, Bytes);
  }

                                                                          
                                                               
  AttributeList addAllocSizeAttr(LLVMContext &C, unsigned Index,
                                 unsigned ElemSizeArg,
                                 const Optional<unsigned> &NumElemsArg);

                                                                              
                                                               
  AttributeList addAllocSizeParamAttr(LLVMContext &C, unsigned ArgNo,
                                      unsigned ElemSizeArg,
                                      const Optional<unsigned> &NumElemsArg) {
    return addAllocSizeAttr(C, ArgNo + FirstArgIndex, ElemSizeArg, NumElemsArg);
  }

                                                                                
                            
                                                                                

                                
  LLVMContext &getContext() const;

                                                          
  AttributeSet getAttributes(unsigned Index) const;

                                                                         
               
  AttributeSet getParamAttributes(unsigned ArgNo) const;

                                                    
  AttributeSet getRetAttributes() const;

                                           
  AttributeSet getFnAttributes() const;

                                                             
  bool hasAttribute(unsigned Index, Attribute::AttrKind Kind) const;

                                                             
  bool hasAttribute(unsigned Index, StringRef Kind) const;

                                                         
  bool hasAttributes(unsigned Index) const;

                                                                
  bool hasParamAttr(unsigned ArgNo, Attribute::AttrKind Kind) const {
    return hasAttribute(ArgNo + FirstArgIndex, Kind);
  }

                                                                
  bool hasParamAttr(unsigned ArgNo, StringRef Kind) const {
    return hasAttribute(ArgNo + FirstArgIndex, Kind);
  }

                                                             
  bool hasParamAttrs(unsigned ArgNo) const {
    return hasAttributes(ArgNo + FirstArgIndex);
  }

                                                                        
                    
  bool hasFnAttribute(Attribute::AttrKind Kind) const;

                                                                        
                    
  bool hasFnAttribute(StringRef Kind) const;

                                                              
  bool hasParamAttribute(unsigned ArgNo, Attribute::AttrKind Kind) const;

                                                                    
                                                                           
                                                              
  bool hasAttrSomewhere(Attribute::AttrKind Kind,
                        unsigned *Index = nullptr) const;

                                                                 
  Attribute getAttribute(unsigned Index, Attribute::AttrKind Kind) const;

                                                                 
  Attribute getAttribute(unsigned Index, StringRef Kind) const;

                                                               
  Attribute getParamAttr(unsigned ArgNo, Attribute::AttrKind Kind) const {
    return getAttribute(ArgNo + FirstArgIndex, Kind);
  }

                                                                 
  Attribute getParamAttr(unsigned ArgNo, StringRef Kind) const {
    return getAttribute(ArgNo + FirstArgIndex, Kind);
  }

                                               
  unsigned getRetAlignment() const;

                                                                
  unsigned getParamAlignment(unsigned ArgNo) const;

                              
  unsigned getStackAlignment(unsigned Index) const;

                                                                   
  uint64_t getDereferenceableBytes(unsigned Index) const;

                                                                        
          
  uint64_t getParamDereferenceableBytes(unsigned ArgNo) const {
    return getDereferenceableBytes(ArgNo + FirstArgIndex);
  }

                                                                 
               
  uint64_t getDereferenceableOrNullBytes(unsigned Index) const;

                                                                 
                         
  uint64_t getParamDereferenceableOrNullBytes(unsigned ArgNo) const {
    return getDereferenceableOrNullBytes(ArgNo + FirstArgIndex);
  }

                                                                    
  std::pair<unsigned, Optional<unsigned>>
  getAllocSizeArgs(unsigned Index) const;

                                                     
  std::string getAsString(unsigned Index, bool InAttrGrp = false) const;

                                                                                
                                
                                                                                

  using iterator = const AttributeSet *;

  iterator begin() const;
  iterator end() const;

  unsigned getNumAttrSets() const;

                                                            
  unsigned index_begin() const { return AttributeList::FunctionIndex; }
  unsigned index_end() const { return getNumAttrSets() - 1; }

                                                  
  bool operator==(const AttributeList &RHS) const { return pImpl == RHS.pImpl; }
  bool operator!=(const AttributeList &RHS) const { return pImpl != RHS.pImpl; }

                                                                        
  void *getRawPointer() const {
    return pImpl;
  }

                                             
  bool isEmpty() const { return pImpl == nullptr; }

  void dump() const;
};

                                                                                
          
                                           
template <> struct DenseMapInfo<AttributeList> {
  static AttributeList getEmptyKey() {
    auto Val = static_cast<uintptr_t>(-1);
    Val <<= PointerLikeTypeTraits<void*>::NumLowBitsAvailable;
    return AttributeList(reinterpret_cast<AttributeListImpl *>(Val));
  }

  static AttributeList getTombstoneKey() {
    auto Val = static_cast<uintptr_t>(-2);
    Val <<= PointerLikeTypeTraits<void*>::NumLowBitsAvailable;
    return AttributeList(reinterpret_cast<AttributeListImpl *>(Val));
  }

  static unsigned getHashValue(AttributeList AS) {
    return (unsigned((uintptr_t)AS.pImpl) >> 4) ^
           (unsigned((uintptr_t)AS.pImpl) >> 9);
  }

  static bool isEqual(AttributeList LHS, AttributeList RHS) {
    return LHS == RHS;
  }
};

                                                                                
          
                                                                       
                                                                              
                                                                          
                                          
class AttrBuilder {
  std::bitset<Attribute::EndAttrKinds> Attrs;
  std::map<std::string, std::string> TargetDepAttrs;
  uint64_t Alignment = 0;
  uint64_t StackAlignment = 0;
  uint64_t DerefBytes = 0;
  uint64_t DerefOrNullBytes = 0;
  uint64_t AllocSizeArgs = 0;

public:
  AttrBuilder() = default;

  AttrBuilder(const Attribute &A) {
    addAttribute(A);
  }

  AttrBuilder(AttributeList AS, unsigned Idx);
  AttrBuilder(AttributeSet AS);

  void clear();

                                      
  AttrBuilder &addAttribute(Attribute::AttrKind Val);

                                              
  AttrBuilder &addAttribute(Attribute A);

                                                        
  AttrBuilder &addAttribute(StringRef A, StringRef V = StringRef());

                                           
  AttrBuilder &removeAttribute(Attribute::AttrKind Val);

                                             
  AttrBuilder &removeAttributes(AttributeList A, uint64_t WithoutIndex);

                                                           
  AttrBuilder &removeAttribute(StringRef A);

                                          
  AttrBuilder &merge(const AttrBuilder &B);

                                             
  AttrBuilder &remove(const AttrBuilder &B);

                                                                
                        
  bool overlaps(const AttrBuilder &B) const;

                                                             
  bool contains(Attribute::AttrKind A) const {
    assert((unsigned)A < Attribute::EndAttrKinds && "Attribute out of range!");
    return Attrs[A];
  }

                                                                   
                
  bool contains(StringRef A) const;

                                                         
  bool hasAttributes() const;

                                                                
                          
  bool hasAttributes(AttributeList A, uint64_t Index) const;

                                                            
  bool hasAlignmentAttr() const;

                                                     
  uint64_t getAlignment() const { return Alignment; }

                                                           
  uint64_t getStackAlignment() const { return StackAlignment; }

                                                          
                                                                    
  uint64_t getDereferenceableBytes() const { return DerefBytes; }

                                                                  
                                                                            
  uint64_t getDereferenceableOrNullBytes() const { return DerefOrNullBytes; }

                                                                            
                                            
  std::pair<unsigned, Optional<unsigned>> getAllocSizeArgs() const;

                                                                       
                                        
  AttrBuilder &addAlignmentAttr(unsigned Align);

                                                                         
                                            
  AttrBuilder &addStackAlignmentAttr(unsigned Align);

                                                                       
                              
  AttrBuilder &addDereferenceableAttr(uint64_t Bytes);

                                                                     
                                        
  AttrBuilder &addDereferenceableOrNullAttr(uint64_t Bytes);

                                                                              
  AttrBuilder &addAllocSizeAttr(unsigned ElemSizeArg,
                                const Optional<unsigned> &NumElemsArg);

                                                                      
                              
  AttrBuilder &addAllocSizeAttrFromRawRepr(uint64_t RawAllocSizeRepr);

                                                               
                 
  bool empty() const { return Attrs.none(); }

                                               
  using td_type = std::pair<std::string, std::string>;
  using td_iterator = std::map<std::string, std::string>::iterator;
  using td_const_iterator = std::map<std::string, std::string>::const_iterator;
  using td_range = iterator_range<td_iterator>;
  using td_const_range = iterator_range<td_const_iterator>;

  td_iterator td_begin() { return TargetDepAttrs.begin(); }
  td_iterator td_end() { return TargetDepAttrs.end(); }

  td_const_iterator td_begin() const { return TargetDepAttrs.begin(); }
  td_const_iterator td_end() const { return TargetDepAttrs.end(); }

  td_range td_attrs() { return td_range(td_begin(), td_end()); }

  td_const_range td_attrs() const {
    return td_const_range(td_begin(), td_end());
  }

  bool td_empty() const { return TargetDepAttrs.empty(); }

  bool operator==(const AttrBuilder &B);
  bool operator!=(const AttrBuilder &B) {
    return !(*this == B);
  }
};

namespace AttributeFuncs {

                                                 
AttrBuilder typeIncompatible(Type *Ty);

                                                                                
                                     
bool areInlineCompatible(const Function &Caller, const Function &Callee);

                                           
void mergeAttributesForInlining(Function &Caller, const Function &Callee);

}                                

}                      

#endif                        
