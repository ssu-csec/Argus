//===- llvm/IR/Metadata.h - Metadata definitions ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// @file
/// This file contains the declarations for metadata subclasses.
/// They represent the different flavors of metadata that live in LLVM.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_METADATA_H
#define LLVM_IR_METADATA_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/PointerUnion.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Constant.h"
#include "llvh/IR/LLVMContext.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace llvh {

class Module;
class ModuleSlotTracker;
class raw_ostream;
class Type;

enum LLVMConstants : uint32_t {
  DEBUG_METADATA_VERSION = 3                                      
};

                                   
   
                                                     
class Metadata {
  friend class ReplaceableMetadataImpl;

           
  const unsigned char SubclassID;

protected:
                             
  enum StorageType { Uniqued, Distinct, Temporary };

                                                                
  unsigned char Storage : 7;
                                               

  unsigned char ImplicitCode : 1;

  unsigned short SubclassData16 = 0;
  unsigned SubclassData32 = 0;

public:
  enum MetadataKind {
#define HANDLE_METADATA_LEAF(CLASS) CLASS##Kind,
#include "llvh/IR/Metadata.def"
  };

protected:
  Metadata(unsigned ID, StorageType Storage)
      : SubclassID(ID), Storage(Storage), ImplicitCode(false) {
    static_assert(sizeof(*this) == 8, "Metadata fields poorly packed");
  }

  ~Metadata() = default;

                                                           
     
                                                                              
                                                         
  void handleChangedOperand(void *, Metadata *) {
    llvm_unreachable("Unimplemented in Metadata subclass");
  }

public:
  unsigned getMetadataID() const { return SubclassID; }

                         
     
                                                                       
                                                   
     
                                                                               
                                                          
     
        
  void dump() const;
  void dump(const Module *M) const;
        

            
     
                                   
     
                                                                       
                                                   
        
  void print(raw_ostream &OS, const Module *M = nullptr,
             bool IsForDebug = false) const;
  void print(raw_ostream &OS, ModuleSlotTracker &MST, const Module *M = nullptr,
             bool IsForDebug = false) const;
        

                       
     
                                  
     
                                                                       
                                                   
        
  void printAsOperand(raw_ostream &OS, const Module *M = nullptr) const;
  void printAsOperand(raw_ostream &OS, ModuleSlotTracker &MST,
                      const Module *M = nullptr) const;
        
};

                                                                
DEFINE_ISA_CONVERSION_FUNCTIONS(Metadata, LLVMMetadataRef)

                                           
inline Metadata **unwrap(LLVMMetadataRef *MDs) {
  return reinterpret_cast<Metadata**>(MDs);
}

#define HANDLE_METADATA(CLASS) class CLASS;
#include "llvh/IR/Metadata.def"

                                                                      
                                                   
#define HANDLE_METADATA_LEAF(CLASS)                                            \
  template <> struct isa_impl<CLASS, Metadata> {                               \
    static inline bool doit(const Metadata &MD) {                              \
      return MD.getMetadataID() == Metadata::CLASS##Kind;                      \
    }                                                                          \
  };
#include "llvh/IR/Metadata.def"

inline raw_ostream &operator<<(raw_ostream &OS, const Metadata &MD) {
  MD.print(OS);
  return OS;
}

                                            
   
                                                                            
                                                                
   
                                                                          
                                 
class MetadataAsValue : public Value {
  friend class ReplaceableMetadataImpl;
  friend class LLVMContextImpl;

  Metadata *MD;

  MetadataAsValue(Type *Ty, Metadata *MD);

                                             
  void dropUse() { MD = nullptr; }

public:
  ~MetadataAsValue();

  static MetadataAsValue *get(LLVMContext &Context, Metadata *MD);
  static MetadataAsValue *getIfExists(LLVMContext &Context, Metadata *MD);

  Metadata *getMetadata() const { return MD; }

  static bool classof(const Value *V) {
    return V->getValueID() == MetadataAsValueVal;
  }

private:
  void handleChangedMetadata(Metadata *MD);
  void track();
  void untrack();
};

                                                                   
   
                                                                           
         
   
                                                                          
                                     
class MetadataTracking {
public:
                                      
     
                                                                               
                                                                             
                                               
     
                                                          
     
                                                      
  static bool track(Metadata *&MD) {
    return track(&MD, *MD, static_cast<Metadata *>(nullptr));
  }

                                                      
     
                                                                               
                                                                          
                 
  static bool track(void *Ref, Metadata &MD, Metadata &Owner) {
    return track(Ref, MD, &Owner);
  }

                                                             
     
                                                                               
                                                                          
                 
  static bool track(void *Ref, Metadata &MD, MetadataAsValue &Owner) {
    return track(Ref, MD, &Owner);
  }

                                            
     
                                       
  static void untrack(Metadata *&MD) { untrack(&MD, *MD); }
  static void untrack(void *Ref, Metadata &MD);

                                                  
     
                                                                          
                                                     
     
                                                           
     
                                                      
  static bool retrack(Metadata *&MD, Metadata *&New) {
    return retrack(&MD, *MD, &New);
  }
  static bool retrack(void *Ref, Metadata &MD, void *New);

                                            
  static bool isReplaceable(const Metadata &MD);

  using OwnerTy = PointerUnion<MetadataAsValue *, Metadata *>;

private:
                                                 
     
                                      
  static bool track(void *Ref, Metadata &MD, OwnerTy Owner);
};

                                                                
   
                                                                        
                                                                                
                       
class ReplaceableMetadataImpl {
  friend class MetadataTracking;

public:
  using OwnerTy = MetadataTracking::OwnerTy;

private:
  LLVMContext &Context;
  uint64_t NextIndex = 0;
  SmallDenseMap<void *, std::pair<OwnerTy, uint64_t>, 4> UseMap;

public:
  ReplaceableMetadataImpl(LLVMContext &Context) : Context(Context) {}

  ~ReplaceableMetadataImpl() {
    assert(UseMap.empty() && "Cannot destroy in-use replaceable metadata");
  }

  LLVMContext &getContext() const { return Context; }

                                       
     
                                                                       
  void replaceAllUsesWith(Metadata *MD);

                               
     
                                                                    
                                                                             
                  
  void resolveAllUses(bool ResolveUsers = true);

private:
  void addRef(void *Ref, OwnerTy Owner);
  void dropRef(void *Ref);
  void moveRef(void *Ref, void *New, const Metadata &MD);

                                          
     
                                                                              
                                              
  static ReplaceableMetadataImpl *getOrCreate(Metadata &MD);

                                           
  static ReplaceableMetadataImpl *getIfExists(Metadata &MD);

                                                
     
                                                             
  static bool isReplaceable(const Metadata &MD);
};

                                            
   
                                                                        
                                   
   
                                                                               
                                                                          
                                
class ValueAsMetadata : public Metadata, ReplaceableMetadataImpl {
  friend class ReplaceableMetadataImpl;
  friend class LLVMContextImpl;

  Value *V;

                                                
  void dropUsers() {
    ReplaceableMetadataImpl::resolveAllUses(                   false);
  }

protected:
  ValueAsMetadata(unsigned ID, Value *V)
      : Metadata(ID, Uniqued), ReplaceableMetadataImpl(V->getContext()), V(V) {
    assert(V && "Expected valid value");
  }

  ~ValueAsMetadata() = default;

public:
  static ValueAsMetadata *get(Value *V);

  static ConstantAsMetadata *getConstant(Value *C) {
    return cast<ConstantAsMetadata>(get(C));
  }

  static LocalAsMetadata *getLocal(Value *Local) {
    return cast<LocalAsMetadata>(get(Local));
  }

  static ValueAsMetadata *getIfExists(Value *V);

  static ConstantAsMetadata *getConstantIfExists(Value *C) {
    return cast_or_null<ConstantAsMetadata>(getIfExists(C));
  }

  static LocalAsMetadata *getLocalIfExists(Value *Local) {
    return cast_or_null<LocalAsMetadata>(getIfExists(Local));
  }

  Value *getValue() const { return V; }
  Type *getType() const { return V->getType(); }
  LLVMContext &getContext() const { return V->getContext(); }

  static void handleDeletion(Value *V);
  static void handleRAUW(Value *From, Value *To);

protected:
                                                             
     
                                                                              
                                                                          
                                   
  void replaceAllUsesWith(Metadata *MD) {
    ReplaceableMetadataImpl::replaceAllUsesWith(MD);
  }

public:
  static bool classof(const Metadata *MD) {
    return MD->getMetadataID() == LocalAsMetadataKind ||
           MD->getMetadataID() == ConstantAsMetadataKind;
  }
};

class ConstantAsMetadata : public ValueAsMetadata {
  friend class ValueAsMetadata;

  ConstantAsMetadata(Constant *C)
      : ValueAsMetadata(ConstantAsMetadataKind, C) {}

public:
  static ConstantAsMetadata *get(Constant *C) {
    return ValueAsMetadata::getConstant(C);
  }

  static ConstantAsMetadata *getIfExists(Constant *C) {
    return ValueAsMetadata::getConstantIfExists(C);
  }

  Constant *getValue() const {
    return cast<Constant>(ValueAsMetadata::getValue());
  }

  static bool classof(const Metadata *MD) {
    return MD->getMetadataID() == ConstantAsMetadataKind;
  }
};

class LocalAsMetadata : public ValueAsMetadata {
  friend class ValueAsMetadata;

  LocalAsMetadata(Value *Local)
      : ValueAsMetadata(LocalAsMetadataKind, Local) {
    assert(!isa<Constant>(Local) && "Expected local value");
  }

public:
  static LocalAsMetadata *get(Value *Local) {
    return ValueAsMetadata::getLocal(Local);
  }

  static LocalAsMetadata *getIfExists(Value *Local) {
    return ValueAsMetadata::getLocalIfExists(Local);
  }

  static bool classof(const Metadata *MD) {
    return MD->getMetadataID() == LocalAsMetadataKind;
  }
};

                                                            
   
                                                                              
                 
   
                                                                          
                                                                               
   
         
                        
                                                           
            
   
                                                                              
                                                                              
                                                                             
                                                                        
                                         
   
                                                                             
                                                                               
                                                                               
   
         
                        
                                                     
            
   
                                                                              
                                                                              
                                                                            
                                                                          
                                               
   
         
                        
                                                                       
            
   
                                                
   
                                          
                                           
                                                   
                                               
                                                       
   
                                                             
namespace mdconst {

namespace detail {

template <class T> T &make();
template <class T, class Result> struct HasDereference {
  using Yes = char[1];
  using No = char[2];
  template <size_t N> struct SFINAE {};

  template <class U, class V>
  static Yes &hasDereference(SFINAE<sizeof(static_cast<V>(*make<U>()))> * = 0);
  template <class U, class V> static No &hasDereference(...);

  static const bool value =
      sizeof(hasDereference<T, Result>(nullptr)) == sizeof(Yes);
};
template <class V, class M> struct IsValidPointer {
  static const bool value = std::is_base_of<Constant, V>::value &&
                            HasDereference<M, const Metadata &>::value;
};
template <class V, class M> struct IsValidReference {
  static const bool value = std::is_base_of<Constant, V>::value &&
                            std::is_convertible<M, const Metadata &>::value;
};

}                        

                                       
   
                                                                             
              
template <class X, class Y>
inline typename std::enable_if<detail::IsValidPointer<X, Y>::value, bool>::type
hasa(Y &&MD) {
  assert(MD && "Null pointer sent into hasa");
  if (auto *V = dyn_cast<ConstantAsMetadata>(MD))
    return isa<X>(V->getValue());
  return false;
}
template <class X, class Y>
inline
    typename std::enable_if<detail::IsValidReference<X, Y &>::value, bool>::type
    hasa(Y &MD) {
  return hasa(&MD);
}

                                  
   
                                                                               
template <class X, class Y>
inline typename std::enable_if<detail::IsValidPointer<X, Y>::value, X *>::type
extract(Y &&MD) {
  return cast<X>(cast<ConstantAsMetadata>(MD)->getValue());
}
template <class X, class Y>
inline
    typename std::enable_if<detail::IsValidReference<X, Y &>::value, X *>::type
    extract(Y &MD) {
  return extract(&MD);
}

                                                 
   
                                                                           
                                          
template <class X, class Y>
inline typename std::enable_if<detail::IsValidPointer<X, Y>::value, X *>::type
extract_or_null(Y &&MD) {
  if (auto *V = cast_or_null<ConstantAsMetadata>(MD))
    return cast<X>(V->getValue());
  return nullptr;
}

                                          
   
                                                                               
                                                                            
                                                   
template <class X, class Y>
inline typename std::enable_if<detail::IsValidPointer<X, Y>::value, X *>::type
dyn_extract(Y &&MD) {
  if (auto *V = dyn_cast<ConstantAsMetadata>(MD))
    return dyn_cast<X>(V->getValue());
  return nullptr;
}

                                                         
   
                                                                               
                                                                            
                                                                              
template <class X, class Y>
inline typename std::enable_if<detail::IsValidPointer<X, Y>::value, X *>::type
dyn_extract_or_null(Y &&MD) {
  if (auto *V = dyn_cast_or_null<ConstantAsMetadata>(MD))
    return dyn_cast<X>(V->getValue());
  return nullptr;
}

}                         

                                                                                
                            
   
                                                                       
                               
class MDString : public Metadata {
  friend class StringMapEntry<MDString>;

  StringMapEntry<MDString> *Entry = nullptr;

  MDString() : Metadata(MDStringKind, Uniqued) {}

public:
  MDString(const MDString &) = delete;
  MDString &operator=(MDString &&) = delete;
  MDString &operator=(const MDString &) = delete;

  static MDString *get(LLVMContext &Context, StringRef Str);
  static MDString *get(LLVMContext &Context, const char *Str) {
    return get(Context, Str ? StringRef(Str) : StringRef());
  }

  StringRef getString() const;

  unsigned getLength() const { return (unsigned)getString().size(); }

  using iterator = StringRef::iterator;

                                              
  iterator begin() const { return getString().begin(); }

                                                     
  iterator end() const { return getString().end(); }

  const unsigned char *bytes_begin() const { return getString().bytes_begin(); }
  const unsigned char *bytes_end() const { return getString().bytes_end(); }

                                                                       
  static bool classof(const Metadata *MD) {
    return MD->getMetadataID() == MDStringKind;
  }
};

                                                                  
                                                            
struct AAMDNodes {
  explicit AAMDNodes(MDNode *T = nullptr, MDNode *S = nullptr,
                     MDNode *N = nullptr)
      : TBAA(T), Scope(S), NoAlias(N) {}

  bool operator==(const AAMDNodes &A) const {
    return TBAA == A.TBAA && Scope == A.Scope && NoAlias == A.NoAlias;
  }

  bool operator!=(const AAMDNodes &A) const { return !(*this == A); }

  explicit operator bool() const { return TBAA || Scope || NoAlias; }

                                            
  MDNode *TBAA;

                                                                
  MDNode *Scope;

                                           
  MDNode *NoAlias;

                                                                 
                                                                          
                                                                      
                                                               
                                             
  AAMDNodes intersect(const AAMDNodes &Other) {
    AAMDNodes Result;
    Result.TBAA = Other.TBAA == TBAA ? TBAA : nullptr;
    Result.Scope = Other.Scope == Scope ? Scope : nullptr;
    Result.NoAlias = Other.NoAlias == NoAlias ? NoAlias : nullptr;
    return Result;
  }
};

                                         
template<>
struct DenseMapInfo<AAMDNodes> {
  static inline AAMDNodes getEmptyKey() {
    return AAMDNodes(DenseMapInfo<MDNode *>::getEmptyKey(),
                     nullptr, nullptr);
  }

  static inline AAMDNodes getTombstoneKey() {
    return AAMDNodes(DenseMapInfo<MDNode *>::getTombstoneKey(),
                     nullptr, nullptr);
  }

  static unsigned getHashValue(const AAMDNodes &Val) {
    return DenseMapInfo<MDNode *>::getHashValue(Val.TBAA) ^
           DenseMapInfo<MDNode *>::getHashValue(Val.Scope) ^
           DenseMapInfo<MDNode *>::getHashValue(Val.NoAlias);
  }

  static bool isEqual(const AAMDNodes &LHS, const AAMDNodes &RHS) {
    return LHS == RHS;
  }
};

                                                  
   
                                                                             
                                                                               
                     
   
                                             
class MDOperand {
  Metadata *MD = nullptr;

public:
  MDOperand() = default;
  MDOperand(MDOperand &&) = delete;
  MDOperand(const MDOperand &) = delete;
  MDOperand &operator=(MDOperand &&) = delete;
  MDOperand &operator=(const MDOperand &) = delete;
  ~MDOperand() { untrack(); }

  Metadata *get() const { return MD; }
  operator Metadata *() const { return get(); }
  Metadata *operator->() const { return get(); }
  Metadata &operator*() const { return *get(); }

  void reset() {
    untrack();
    MD = nullptr;
  }
  void reset(Metadata *MD, Metadata *Owner) {
    untrack();
    this->MD = MD;
    track(Owner);
  }

private:
  void track(Metadata *Owner) {
    if (MD) {
      if (Owner)
        MetadataTracking::track(this, *MD, *Owner);
      else
        MetadataTracking::track(MD);
    }
  }

  void untrack() {
    assert(static_cast<void *>(this) == &MD && "Expected same address");
    if (MD)
      MetadataTracking::untrack(MD);
  }
};

template <> struct simplify_type<MDOperand> {
  using SimpleType = Metadata *;

  static SimpleType getSimplifiedValue(MDOperand &MD) { return MD.get(); }
};

template <> struct simplify_type<const MDOperand> {
  using SimpleType = Metadata *;

  static SimpleType getSimplifiedValue(const MDOperand &MD) { return MD.get(); }
};

                                                       
   
                                                                              
                                                                            
class ContextAndReplaceableUses {
  PointerUnion<LLVMContext *, ReplaceableMetadataImpl *> Ptr;

public:
  ContextAndReplaceableUses(LLVMContext &Context) : Ptr(&Context) {}
  ContextAndReplaceableUses(
      std::unique_ptr<ReplaceableMetadataImpl> ReplaceableUses)
      : Ptr(ReplaceableUses.release()) {
    assert(getReplaceableUses() && "Expected non-null replaceable uses");
  }
  ContextAndReplaceableUses() = delete;
  ContextAndReplaceableUses(ContextAndReplaceableUses &&) = delete;
  ContextAndReplaceableUses(const ContextAndReplaceableUses &) = delete;
  ContextAndReplaceableUses &operator=(ContextAndReplaceableUses &&) = delete;
  ContextAndReplaceableUses &
  operator=(const ContextAndReplaceableUses &) = delete;
  ~ContextAndReplaceableUses() { delete getReplaceableUses(); }

  operator LLVMContext &() { return getContext(); }

                                         
  bool hasReplaceableUses() const {
    return Ptr.is<ReplaceableMetadataImpl *>();
  }

  LLVMContext &getContext() const {
    if (hasReplaceableUses())
      return getReplaceableUses()->getContext();
    return *Ptr.get<LLVMContext *>();
  }

  ReplaceableMetadataImpl *getReplaceableUses() const {
    if (hasReplaceableUses())
      return Ptr.get<ReplaceableMetadataImpl *>();
    return nullptr;
  }

                                                            
  ReplaceableMetadataImpl *getOrCreateReplaceableUses() {
    if (!hasReplaceableUses())
      makeReplaceable(llvh::make_unique<ReplaceableMetadataImpl>(getContext()));
    return getReplaceableUses();
  }

                                  
     
                                                                               
                   
  void
  makeReplaceable(std::unique_ptr<ReplaceableMetadataImpl> ReplaceableUses) {
    assert(ReplaceableUses && "Expected non-null replaceable uses");
    assert(&ReplaceableUses->getContext() == &getContext() &&
           "Expected same context");
    delete getReplaceableUses();
    Ptr = ReplaceableUses.release();
  }

                        
     
                                                   
  std::unique_ptr<ReplaceableMetadataImpl> takeReplaceableUses() {
    assert(hasReplaceableUses() && "Expected to own replaceable uses");
    std::unique_ptr<ReplaceableMetadataImpl> ReplaceableUses(
        getReplaceableUses());
    Ptr = &ReplaceableUses->getContext();
    return ReplaceableUses;
  }
};

struct TempMDNodeDeleter {
  inline void operator()(MDNode *Node) const;
};

#define HANDLE_MDNODE_LEAF(CLASS)                                              \
  using Temp##CLASS = std::unique_ptr<CLASS, TempMDNodeDeleter>;
#define HANDLE_MDNODE_BRANCH(CLASS) HANDLE_MDNODE_LEAF(CLASS)
#include "llvh/IR/Metadata.def"

                  
   
                                                                          
                                                                             
                                                                         
            
   
                                                                            
                                                                            
                                                                            
                                                                           
                        
   
                                                                      
                                                                               
             
class MDNode : public Metadata {
  friend class ReplaceableMetadataImpl;
  friend class LLVMContextImpl;

  unsigned NumOperands;
  unsigned NumUnresolved;

  ContextAndReplaceableUses Context;

protected:
  MDNode(LLVMContext &Context, unsigned ID, StorageType Storage,
         ArrayRef<Metadata *> Ops1, ArrayRef<Metadata *> Ops2 = None);
  ~MDNode() = default;

  void *operator new(size_t Size, unsigned NumOps);
  void operator delete(void *Mem);

                                        
  void operator delete(void *, unsigned) {
    llvm_unreachable("Constructor throws?");
  }

                                        
  void operator delete(void *, unsigned, bool) {
    llvm_unreachable("Constructor throws?");
  }

  void dropAllReferences();

  MDOperand *mutable_begin() { return mutable_end() - NumOperands; }
  MDOperand *mutable_end() { return reinterpret_cast<MDOperand *>(this); }

  using mutable_op_range = iterator_range<MDOperand *>;

  mutable_op_range mutable_operands() {
    return mutable_op_range(mutable_begin(), mutable_end());
  }

public:
  MDNode(const MDNode &) = delete;
  void operator=(const MDNode &) = delete;
  void *operator new(size_t) = delete;

  static inline MDTuple *get(LLVMContext &Context, ArrayRef<Metadata *> MDs);
  static inline MDTuple *getIfExists(LLVMContext &Context,
                                     ArrayRef<Metadata *> MDs);
  static inline MDTuple *getDistinct(LLVMContext &Context,
                                     ArrayRef<Metadata *> MDs);
  static inline TempMDTuple getTemporary(LLVMContext &Context,
                                         ArrayRef<Metadata *> MDs);

                                         
  TempMDNode clone() const;

                                                
     
                                                                            
                               
  static void deleteTemporary(MDNode *N);

  LLVMContext &getContext() const { return Context.getContext(); }

                                 
  void replaceOperandWith(unsigned I, Metadata *New);

                                      
     
                                                                            
                                  
     
                                                                         
                                                  
     
                                                                       
                                                                           
                                                                            
  bool isResolved() const { return !isTemporary() && !NumUnresolved; }

  bool isUniqued() const { return Storage == Uniqued; }
  bool isDistinct() const { return Storage == Distinct; }
  bool isTemporary() const { return Storage == Temporary; }

                       
     
                                            
  void replaceAllUsesWith(Metadata *MD) {
    assert(isTemporary() && "Expected temporary node");
    if (Context.hasReplaceableUses())
      Context.getReplaceableUses()->replaceAllUsesWith(MD);
  }

                     
     
                                                                          
               
     
                                                                           
  void resolveCycles();

                                        
  void resolve();

                                                    
     
                                                                             
                                                                            
  template <class T>
  static typename std::enable_if<std::is_base_of<MDNode, T>::value, T *>::type
  replaceWithPermanent(std::unique_ptr<T, TempMDNodeDeleter> N) {
    return cast<T>(N.release()->replaceWithPermanentImpl());
  }

                                                  
     
                                                                             
                                                 
     
                                     
  template <class T>
  static typename std::enable_if<std::is_base_of<MDNode, T>::value, T *>::type
  replaceWithUniqued(std::unique_ptr<T, TempMDNodeDeleter> N) {
    return cast<T>(N.release()->replaceWithUniquedImpl());
  }

                                                   
     
                                                                              
                                                 
  template <class T>
  static typename std::enable_if<std::is_base_of<MDNode, T>::value, T *>::type
  replaceWithDistinct(std::unique_ptr<T, TempMDNodeDeleter> N) {
    return cast<T>(N.release()->replaceWithDistinctImpl());
  }

private:
  MDNode *replaceWithPermanentImpl();
  MDNode *replaceWithUniquedImpl();
  MDNode *replaceWithDistinctImpl();

protected:
                     
     
                                                                 
  void setOperand(unsigned I, Metadata *New);

  void storeDistinctInContext();
  template <class T, class StoreT>
  static T *storeImpl(T *N, StorageType Storage, StoreT &Store);
  template <class T> static T *storeImpl(T *N, StorageType Storage);

private:
  void handleChangedOperand(void *Ref, Metadata *New);

                                
  void dropReplaceableUses();

  void resolveAfterOperandChange(Metadata *Old, Metadata *New);
  void decrementUnresolvedOperandCount();
  void countUnresolvedOperands();

                                  
     
                                         
                            
                                         
  void makeUniqued();

                                   
     
                                          
                            
  void makeDistinct();

  void deleteAsSubclass();
  MDNode *uniquify();
  void eraseFromStore();

  template <class NodeTy> struct HasCachedHash;
  template <class NodeTy>
  static void dispatchRecalculateHash(NodeTy *N, std::true_type) {
    N->recalculateHash();
  }
  template <class NodeTy>
  static void dispatchRecalculateHash(NodeTy *, std::false_type) {}
  template <class NodeTy>
  static void dispatchResetHash(NodeTy *N, std::true_type) {
    N->setHash(0);
  }
  template <class NodeTy>
  static void dispatchResetHash(NodeTy *, std::false_type) {}

public:
  using op_iterator = const MDOperand *;
  using op_range = iterator_range<op_iterator>;

  op_iterator op_begin() const {
    return const_cast<MDNode *>(this)->mutable_begin();
  }

  op_iterator op_end() const {
    return const_cast<MDNode *>(this)->mutable_end();
  }

  op_range operands() const { return op_range(op_begin(), op_end()); }

  const MDOperand &getOperand(unsigned I) const {
    assert(I < NumOperands && "Out of range");
    return op_begin()[I];
  }

                                       
  unsigned getNumOperands() const { return NumOperands; }

                                                                       
  static bool classof(const Metadata *MD) {
    switch (MD->getMetadataID()) {
    default:
      return false;
#define HANDLE_MDNODE_LEAF(CLASS)                                              \
  case CLASS##Kind:                                                            \
    return true;
#include "llvh/IR/Metadata.def"
    }
  }

                                              
  bool isTBAAVtableAccess() const;

                                   
  static MDNode *concatenate(MDNode *A, MDNode *B);
  static MDNode *intersect(MDNode *A, MDNode *B);
  static MDNode *getMostGenericTBAA(MDNode *A, MDNode *B);
  static MDNode *getMostGenericFPMath(MDNode *A, MDNode *B);
  static MDNode *getMostGenericRange(MDNode *A, MDNode *B);
  static MDNode *getMostGenericAliasScope(MDNode *A, MDNode *B);
  static MDNode *getMostGenericAlignmentOrDereferenceable(MDNode *A, MDNode *B);
};

                      
   
                                                                       
                                    
class MDTuple : public MDNode {
  friend class LLVMContextImpl;
  friend class MDNode;

  MDTuple(LLVMContext &C, StorageType Storage, unsigned Hash,
          ArrayRef<Metadata *> Vals)
      : MDNode(C, MDTupleKind, Storage, Vals) {
    setHash(Hash);
  }

  ~MDTuple() { dropAllReferences(); }

  void setHash(unsigned Hash) { SubclassData32 = Hash; }
  void recalculateHash();

  static MDTuple *getImpl(LLVMContext &Context, ArrayRef<Metadata *> MDs,
                          StorageType Storage, bool ShouldCreate = true);

  TempMDTuple cloneImpl() const {
    return getTemporary(getContext(),
                        SmallVector<Metadata *, 4>(op_begin(), op_end()));
  }

public:
                           
  unsigned getHash() const { return SubclassData32; }

  static MDTuple *get(LLVMContext &Context, ArrayRef<Metadata *> MDs) {
    return getImpl(Context, MDs, Uniqued);
  }

  static MDTuple *getIfExists(LLVMContext &Context, ArrayRef<Metadata *> MDs) {
    return getImpl(Context, MDs, Uniqued,                    false);
  }

                             
     
                                                                 
  static MDTuple *getDistinct(LLVMContext &Context, ArrayRef<Metadata *> MDs) {
    return getImpl(Context, MDs, Distinct);
  }

                              
     
                                                                             
                                                                   
                      
  static TempMDTuple getTemporary(LLVMContext &Context,
                                  ArrayRef<Metadata *> MDs) {
    return TempMDTuple(getImpl(Context, MDs, Temporary));
  }

                                         
  TempMDTuple clone() const { return cloneImpl(); }

  static bool classof(const Metadata *MD) {
    return MD->getMetadataID() == MDTupleKind;
  }
};

MDTuple *MDNode::get(LLVMContext &Context, ArrayRef<Metadata *> MDs) {
  return MDTuple::get(Context, MDs);
}

MDTuple *MDNode::getIfExists(LLVMContext &Context, ArrayRef<Metadata *> MDs) {
  return MDTuple::getIfExists(Context, MDs);
}

MDTuple *MDNode::getDistinct(LLVMContext &Context, ArrayRef<Metadata *> MDs) {
  return MDTuple::getDistinct(Context, MDs);
}

TempMDTuple MDNode::getTemporary(LLVMContext &Context,
                                 ArrayRef<Metadata *> MDs) {
  return MDTuple::getTemporary(Context, MDs);
}

void TempMDNodeDeleter::operator()(MDNode *Node) const {
  MDNode::deleteTemporary(Node);
}

                                           
   
                                                                              
                                 
template <class T> class TypedMDOperandIterator {
  MDNode::op_iterator I = nullptr;

public:
  using iterator_category = std::input_iterator_tag;
  using value_type = T *;
  using difference_type = std::ptrdiff_t;
  using pointer = void;
  using reference = T *;

  TypedMDOperandIterator() = default;
  explicit TypedMDOperandIterator(MDNode::op_iterator I) : I(I) {}

  T *operator*() const { return cast_or_null<T>(*I); }

  TypedMDOperandIterator &operator++() {
    ++I;
    return *this;
  }

  TypedMDOperandIterator operator++(int) {
    TypedMDOperandIterator Temp(*this);
    ++I;
    return Temp;
  }

  bool operator==(const TypedMDOperandIterator &X) const { return I == X.I; }
  bool operator!=(const TypedMDOperandIterator &X) const { return I != X.I; }
};

                                        
   
                                                                              
                                
template <class T> class MDTupleTypedArrayWrapper {
  const MDTuple *N = nullptr;

public:
  MDTupleTypedArrayWrapper() = default;
  MDTupleTypedArrayWrapper(const MDTuple *N) : N(N) {}

  template <class U>
  MDTupleTypedArrayWrapper(
      const MDTupleTypedArrayWrapper<U> &Other,
      typename std::enable_if<std::is_convertible<U *, T *>::value>::type * =
          nullptr)
      : N(Other.get()) {}

  template <class U>
  explicit MDTupleTypedArrayWrapper(
      const MDTupleTypedArrayWrapper<U> &Other,
      typename std::enable_if<!std::is_convertible<U *, T *>::value>::type * =
          nullptr)
      : N(Other.get()) {}

  explicit operator bool() const { return get(); }
  explicit operator MDTuple *() const { return get(); }

  MDTuple *get() const { return const_cast<MDTuple *>(N); }
  MDTuple *operator->() const { return get(); }
  MDTuple &operator*() const { return *get(); }

                                                  
  unsigned size() const { return N ? N->getNumOperands() : 0u; }
  bool empty() const { return N ? N->getNumOperands() == 0 : true; }
  T *operator[](unsigned I) const { return cast_or_null<T>(N->getOperand(I)); }

                                                  
  using iterator = TypedMDOperandIterator<T>;

  iterator begin() const { return N ? iterator(N->op_begin()) : iterator(); }
  iterator end() const { return N ? iterator(N->op_end()) : iterator(); }
};

#define HANDLE_METADATA(CLASS)                                                 \
  using CLASS##Array = MDTupleTypedArrayWrapper<CLASS>;
#include "llvh/IR/Metadata.def"

                                                          
   
                                                                              
                                                                              
                                                                           
                                                                      
                            
   
                                                                             
                                                                             
                            
   
                                                                         
                                                                       
                                                                    
class DistinctMDOperandPlaceholder : public Metadata {
  friend class MetadataTracking;

  Metadata **Use = nullptr;

public:
  explicit DistinctMDOperandPlaceholder(unsigned ID)
      : Metadata(DistinctMDOperandPlaceholderKind, Distinct) {
    SubclassData32 = ID;
  }

  DistinctMDOperandPlaceholder() = delete;
  DistinctMDOperandPlaceholder(DistinctMDOperandPlaceholder &&) = delete;
  DistinctMDOperandPlaceholder(const DistinctMDOperandPlaceholder &) = delete;

  ~DistinctMDOperandPlaceholder() {
    if (Use)
      *Use = nullptr;
  }

  unsigned getID() const { return SubclassData32; }

                                      
  void replaceUseWith(Metadata *MD) {
    if (!Use)
      return;
    *Use = MD;

    if (*Use)
      MetadataTracking::track(*Use);

    Metadata *T = cast<Metadata>(this);
    MetadataTracking::untrack(T);
    assert(!Use && "Use is still being tracked despite being untracked!");
  }
};

                                                                                
                       
   
                                                           
   
                                                                               
   
                                                                         
class NamedMDNode : public ilist_node<NamedMDNode> {
  friend class LLVMContextImpl;
  friend class Module;

  std::string Name;
  Module *Parent = nullptr;
  void *Operands;                                 

  void setParent(Module *M) { Parent = M; }

  explicit NamedMDNode(const Twine &N);

  template <class T1, class T2> class op_iterator_impl {
    friend class NamedMDNode;

    const NamedMDNode *Node = nullptr;
    unsigned Idx = 0;

    op_iterator_impl(const NamedMDNode *N, unsigned i) : Node(N), Idx(i) {}

  public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = T2;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    op_iterator_impl() = default;

    bool operator==(const op_iterator_impl &o) const { return Idx == o.Idx; }
    bool operator!=(const op_iterator_impl &o) const { return Idx != o.Idx; }

    op_iterator_impl &operator++() {
      ++Idx;
      return *this;
    }

    op_iterator_impl operator++(int) {
      op_iterator_impl tmp(*this);
      operator++();
      return tmp;
    }

    op_iterator_impl &operator--() {
      --Idx;
      return *this;
    }

    op_iterator_impl operator--(int) {
      op_iterator_impl tmp(*this);
      operator--();
      return tmp;
    }

    T1 operator*() const { return Node->getOperand(Idx); }
  };

public:
  NamedMDNode(const NamedMDNode &) = delete;
  ~NamedMDNode();

                                                                 
  void eraseFromParent();

                                            
  void dropAllReferences() { clearOperands(); }
                                                  
  void clearOperands();

                                                               
  inline Module *getParent() { return Parent; }
  inline const Module *getParent() const { return Parent; }

  MDNode *getOperand(unsigned i) const;
  unsigned getNumOperands() const;
  void addOperand(MDNode *M);
  void setOperand(unsigned I, MDNode *New);
  StringRef getName() const;
  void print(raw_ostream &ROS, bool IsForDebug = false) const;
  void print(raw_ostream &ROS, ModuleSlotTracker &MST,
             bool IsForDebug = false) const;
  void dump() const;

                                                                                
                                  
    
  using op_iterator = op_iterator_impl<MDNode *, MDNode>;

  op_iterator op_begin() { return op_iterator(this, 0); }
  op_iterator op_end()   { return op_iterator(this, getNumOperands()); }

  using const_op_iterator = op_iterator_impl<const MDNode *, MDNode>;

  const_op_iterator op_begin() const { return const_op_iterator(this, 0); }
  const_op_iterator op_end()   const { return const_op_iterator(this, getNumOperands()); }

  inline iterator_range<op_iterator>  operands() {
    return make_range(op_begin(), op_end());
  }
  inline iterator_range<const_op_iterator> operands() const {
    return make_range(op_begin(), op_end());
  }
};

                                                                
DEFINE_ISA_CONVERSION_FUNCTIONS(NamedMDNode, LLVMNamedMDNodeRef)

}                      

#endif                      
