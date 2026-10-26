//===- llvm/DataLayout.h - Data size & alignment info -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines layout properties related to datatype size/offset/alignment
// information.  It uses lazy annotations to cache information about how
// structure types are laid out and used.
//
// This structure should be created once, filled in if the defaults are not
// correct and then passed around by const&.  None of the members functions
// require modification to the object.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DATALAYOUT_H
#define LLVM_IR_DATALAYOUT_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/Type.h"
#include "llvh/Pass.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/MathExtras.h"
#include <cassert>
#include <cstdint>
#include <string>

                                                                           
        
using LLVMTargetDataRef = struct LLVMOpaqueTargetData *;

namespace llvh {

class GlobalVariable;
class LLVMContext;
class Module;
class StructLayout;
class Triple;
class Value;

                                                                         
enum AlignTypeEnum {
  INVALID_ALIGN = 0,
  INTEGER_ALIGN = 'i',
  VECTOR_ALIGN = 'v',
  FLOAT_ALIGN = 'f',
  AGGREGATE_ALIGN = 'a'
};

                                                                         
                                                                       
                                                                    
              

                             
   
                                                                              
                                      
   
                                                                           
                                                                
struct LayoutAlignElem {
                                          
  unsigned AlignType : 8;
  unsigned TypeBitWidth : 24;
  unsigned ABIAlign : 16;
  unsigned PrefAlign : 16;

  static LayoutAlignElem get(AlignTypeEnum align_type, unsigned abi_align,
                             unsigned pref_align, uint32_t bit_width);

  bool operator==(const LayoutAlignElem &rhs) const;
};

                                     
   
                                                                                
   
                                                                           
                                                                
struct PointerAlignElem {
  unsigned ABIAlign;
  unsigned PrefAlign;
  uint32_t TypeByteWidth;
  uint32_t AddressSpace;
  uint32_t IndexWidth;

                 
  static PointerAlignElem get(uint32_t AddressSpace, unsigned ABIAlign,
                              unsigned PrefAlign, uint32_t TypeByteWidth,
                              uint32_t IndexWidth);

  bool operator==(const PointerAlignElem &rhs) const;
};

                                                                        
                
   
                                                                           
                                                                            
                              
class DataLayout {
private:
                        
  bool BigEndian;

  unsigned AllocaAddrSpace;
  unsigned StackNaturalAlign;
  unsigned ProgramAddrSpace;

  enum ManglingModeT {
    MM_None,
    MM_ELF,
    MM_MachO,
    MM_WinCOFF,
    MM_WinCOFFX86,
    MM_Mips
  };
  ManglingModeT ManglingMode;

  SmallVector<unsigned char, 8> LegalIntWidths;

                                                                   
                                
  using AlignmentsTy = SmallVector<LayoutAlignElem, 16>;
  AlignmentsTy Alignments;

  AlignmentsTy::const_iterator
  findAlignmentLowerBound(AlignTypeEnum AlignType, uint32_t BitWidth) const {
    return const_cast<DataLayout *>(this)->findAlignmentLowerBound(AlignType,
                                                                   BitWidth);
  }

  AlignmentsTy::iterator
  findAlignmentLowerBound(AlignTypeEnum AlignType, uint32_t BitWidth);

                                                              
  std::string StringRepresentation;

  using PointersTy = SmallVector<PointerAlignElem, 8>;
  PointersTy Pointers;

  PointersTy::const_iterator
  findPointerLowerBound(uint32_t AddressSpace) const {
    return const_cast<DataLayout *>(this)->findPointerLowerBound(AddressSpace);
  }

  PointersTy::iterator findPointerLowerBound(uint32_t AddressSpace);

                                        
  mutable void *LayoutMap = nullptr;

                                                                         
                                          
  SmallVector<unsigned, 8> NonIntegralAddressSpaces;

  void setAlignment(AlignTypeEnum align_type, unsigned abi_align,
                    unsigned pref_align, uint32_t bit_width);
  unsigned getAlignmentInfo(AlignTypeEnum align_type, uint32_t bit_width,
                            bool ABIAlign, Type *Ty) const;
  void setPointerAlignment(uint32_t AddrSpace, unsigned ABIAlign,
                           unsigned PrefAlign, uint32_t TypeByteWidth,
                           uint32_t IndexWidth);

                                                                       
  unsigned getAlignment(Type *Ty, bool abi_or_pref) const;

                                                                        
                
  void parseSpecifier(StringRef LayoutDescription);

                                       
  void clear();

public:
                                                                       
  explicit DataLayout(StringRef LayoutDescription) {
    reset(LayoutDescription);
  }

                                                                  
  explicit DataLayout(const Module *M);

  DataLayout(const DataLayout &DL) { *this = DL; }

  ~DataLayout();                                           

  DataLayout &operator=(const DataLayout &DL) {
    clear();
    StringRepresentation = DL.StringRepresentation;
    BigEndian = DL.isBigEndian();
    AllocaAddrSpace = DL.AllocaAddrSpace;
    StackNaturalAlign = DL.StackNaturalAlign;
    ProgramAddrSpace = DL.ProgramAddrSpace;
    ManglingMode = DL.ManglingMode;
    LegalIntWidths = DL.LegalIntWidths;
    Alignments = DL.Alignments;
    Pointers = DL.Pointers;
    NonIntegralAddressSpaces = DL.NonIntegralAddressSpaces;
    return *this;
  }

  bool operator==(const DataLayout &Other) const;
  bool operator!=(const DataLayout &Other) const { return !(*this == Other); }

  void init(const Module *M);

                                                                   
  void reset(StringRef LayoutDescription);

                          
  bool isLittleEndian() const { return !BigEndian; }
  bool isBigEndian() const { return BigEndian; }

                                                          
     
                                                                      
                                                                             
                                                     
  const std::string &getStringRepresentation() const {
    return StringRepresentation;
  }

                                                                  
  bool isDefault() const { return StringRepresentation.empty(); }

                                                                        
                                
     
                                                                              
                                                                             
     
                                     
  bool isLegalInteger(uint64_t Width) const {
    for (unsigned LegalIntWidth : LegalIntWidths)
      if (LegalIntWidth == Width)
        return true;
    return false;
  }

  bool isIllegalInteger(uint64_t Width) const { return !isLegalInteger(Width); }

                                                                              
  bool exceedsNaturalStackAlignment(unsigned Align) const {
    return (StackNaturalAlign != 0) && (Align > StackNaturalAlign);
  }

  unsigned getStackAlignment() const { return StackNaturalAlign; }
  unsigned getAllocaAddrSpace() const { return AllocaAddrSpace; }

  unsigned getProgramAddressSpace() const { return ProgramAddrSpace; }

  bool hasMicrosoftFastStdCallMangling() const {
    return ManglingMode == MM_WinCOFFX86;
  }

                                                                               
                                                
  bool doNotMangleLeadingQuestionMark() const {
    return ManglingMode == MM_WinCOFF || ManglingMode == MM_WinCOFFX86;
  }

  bool hasLinkerPrivateGlobalPrefix() const { return ManglingMode == MM_MachO; }

  StringRef getLinkerPrivateGlobalPrefix() const {
    if (ManglingMode == MM_MachO)
      return "l";
    return "";
  }

  char getGlobalPrefix() const {
    switch (ManglingMode) {
    case MM_None:
    case MM_ELF:
    case MM_Mips:
    case MM_WinCOFF:
      return '\0';
    case MM_MachO:
    case MM_WinCOFFX86:
      return '_';
    }
    llvm_unreachable("invalid mangling mode");
  }

  StringRef getPrivateGlobalPrefix() const {
    switch (ManglingMode) {
    case MM_None:
      return "";
    case MM_ELF:
    case MM_WinCOFF:
      return ".L";
    case MM_Mips:
      return "$";
    case MM_MachO:
    case MM_WinCOFFX86:
      return "L";
    }
    llvm_unreachable("invalid mangling mode");
  }

  static const char *getManglingComponent(const Triple &T);

                                                                      
                           
     
                                                                              
                                                        
  bool fitsInLegalInteger(unsigned Width) const {
    for (unsigned LegalIntWidth : LegalIntWidths)
      if (Width <= LegalIntWidth)
        return true;
    return false;
  }

                              
  unsigned getPointerABIAlignment(unsigned AS) const;

                                                        
                                                        
                                       
  unsigned getPointerPrefAlignment(unsigned AS = 0) const;

                         
                                                        
                                       
  unsigned getPointerSize(unsigned AS = 0) const;

                                             
  unsigned getIndexSize(unsigned AS) const;

                                                                              
                                                                          
  ArrayRef<unsigned> getNonIntegralAddressSpaces() const {
    return NonIntegralAddressSpaces;
  }

  bool isNonIntegralPointerType(PointerType *PT) const {
    ArrayRef<unsigned> NonIntegralSpaces = getNonIntegralAddressSpaces();
    return find(NonIntegralSpaces, PT->getAddressSpace()) !=
           NonIntegralSpaces.end();
  }

  bool isNonIntegralPointerType(Type *Ty) const {
    auto *PTy = dyn_cast<PointerType>(Ty);
    return PTy && isNonIntegralPointerType(PTy);
  }

                                  
                                                        
                                       
  unsigned getPointerSizeInBits(unsigned AS = 0) const {
    return getPointerSize(AS) * 8;
  }

                                                                          
  unsigned getIndexSizeInBits(unsigned AS) const {
    return getIndexSize(AS) * 8;
  }

                                                                           
                                                                                
                                                                              
                                                                               
                         
  unsigned getPointerTypeSizeInBits(Type *) const;

                                                       
                                                                            
  unsigned getIndexTypeSizeInBits(Type *Ty) const;

  unsigned getPointerTypeSize(Type *Ty) const {
    return getPointerTypeSizeInBits(Ty) / 8;
  }

                    
     
                                                                 
                                                              
                                                   
                                                   
                                                   
                                                   
                                                   
                                                   
                                                   
                                                   
                                                   
     
                                                                          
                                            

                                                                      
     
                                                                               
                                                     
  uint64_t getTypeSizeInBits(Type *Ty) const;

                                                                    
                                 
     
                                                         
  uint64_t getTypeStoreSize(Type *Ty) const {
    return (getTypeSizeInBits(Ty) + 7) / 8;
  }

                                                                   
                                                         
     
                                                          
  uint64_t getTypeStoreSizeInBits(Type *Ty) const {
    return 8 * getTypeStoreSize(Ty);
  }

                                                                   
                                                  
     
                                                                         
                                                            
  uint64_t getTypeAllocSize(Type *Ty) const {
                                               
    return alignTo(getTypeStoreSize(Ty), getABITypeAlignment(Ty));
  }

                                                                  
                                                                          
     
                                                                         
                                                             
  uint64_t getTypeAllocSizeInBits(Type *Ty) const {
    return 8 * getTypeAllocSize(Ty);
  }

                                                                        
  unsigned getABITypeAlignment(Type *Ty) const;

                                                                       
                             
  unsigned getABIIntegerTypeAlignment(unsigned BitWidth) const;

                                                                    
           
     
                                                           
  unsigned getPrefTypeAlignment(Type *Ty) const;

                                                                         
                                         
  unsigned getPreferredTypeAlignmentShift(Type *Ty) const;

                                                                    
                                         
  IntegerType *getIntPtrType(LLVMContext &C, unsigned AddressSpace = 0) const;

                                                                       
                                                                             
  Type *getIntPtrType(Type *) const;

                                                                    
                 
  Type *getSmallestLegalIntType(LLVMContext &C, unsigned Width = 0) const;

                                                                      
  Type *getLargestLegalIntType(LLVMContext &C) const {
    unsigned LargestSize = getLargestLegalIntTypeSizeInBits();
    return (LargestSize == 0) ? nullptr : Type::getIntNTy(C, LargestSize);
  }

                                                                       
              
  unsigned getLargestLegalIntTypeSizeInBits() const;

                                      
                                                                            
                                 
  Type *getIndexType(Type *PtrTy) const;

                                                                         
              
     
                                                                  
                                              
  int64_t getIndexedOffsetInType(Type *ElemTy, ArrayRef<Value *> Indices) const;

                                                                    
                                                      
     
                                                  
  const StructLayout *getStructLayout(StructType *Ty) const;

                                                              
     
                                                                              
  unsigned getPreferredAlignment(const GlobalVariable *GV) const;

                                                                       
                  
     
                                                                              
  unsigned getPreferredAlignmentLog(const GlobalVariable *GV) const;
};

inline DataLayout *unwrap(LLVMTargetDataRef P) {
  return reinterpret_cast<DataLayout *>(P);
}

inline LLVMTargetDataRef wrap(const DataLayout *P) {
  return reinterpret_cast<LLVMTargetDataRef>(const_cast<DataLayout *>(P));
}

                                                                               
                                      
class StructLayout {
  uint64_t StructSize;
  unsigned StructAlignment;
  unsigned IsPadded : 1;
  unsigned NumElements : 31;
  uint64_t MemberOffsets[1];                         

public:
  uint64_t getSizeInBytes() const { return StructSize; }

  uint64_t getSizeInBits() const { return 8 * StructSize; }

  unsigned getAlignment() const { return StructAlignment; }

                                                                       
                                                              
  bool hasPadding() const { return IsPadded; }

                                                                         
                             
  unsigned getElementContainingOffset(uint64_t Offset) const;

  uint64_t getElementOffset(unsigned Idx) const {
    assert(Idx < NumElements && "Invalid element idx!");
    return MemberOffsets[Idx];
  }

  uint64_t getElementOffsetInBits(unsigned Idx) const {
    return getElementOffset(Idx) * 8;
  }

private:
  friend class DataLayout;                                         

  StructLayout(StructType *ST, const DataLayout &DL);
};

                                                                             
                                                                           
inline uint64_t DataLayout::getTypeSizeInBits(Type *Ty) const {
  assert(Ty->isSized() && "Cannot getTypeInfo() on a type that is unsized!");
  switch (Ty->getTypeID()) {
  case Type::LabelTyID:
    return getPointerSizeInBits(0);
  case Type::PointerTyID:
    return getPointerSizeInBits(Ty->getPointerAddressSpace());
  case Type::ArrayTyID: {
    ArrayType *ATy = cast<ArrayType>(Ty);
    return ATy->getNumElements() *
           getTypeAllocSizeInBits(ATy->getElementType());
  }
  case Type::StructTyID:
                                                                      
    return getStructLayout(cast<StructType>(Ty))->getSizeInBits();
  case Type::IntegerTyID:
    return Ty->getIntegerBitWidth();
  case Type::HalfTyID:
    return 16;
  case Type::FloatTyID:
    return 32;
  case Type::DoubleTyID:
  case Type::X86_MMXTyID:
    return 64;
  case Type::PPC_FP128TyID:
  case Type::FP128TyID:
    return 128;
                                                                       
                                      
  case Type::X86_FP80TyID:
    return 80;
  case Type::VectorTyID: {
    VectorType *VTy = cast<VectorType>(Ty);
    return VTy->getNumElements() * getTypeSizeInBits(VTy->getElementType());
  }
  default:
    llvm_unreachable("DataLayout::getTypeSizeInBits(): Unsupported type");
  }
}

}                      

#endif                        
