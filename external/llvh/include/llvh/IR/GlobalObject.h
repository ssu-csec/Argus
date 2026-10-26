//===-- llvm/GlobalObject.h - Class to represent global objects -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This represents an independent object. That is, a function or a global
// variable, but not an alias.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_GLOBALOBJECT_H
#define LLVM_IR_GLOBALOBJECT_H

#include "llvh/ADT/StringRef.h"
#include "llvh/IR/GlobalValue.h"
#include "llvh/IR/Value.h"
#include <string>
#include <utility>

namespace llvh {

class Comdat;
class MDNode;
class Metadata;

class GlobalObject : public GlobalValue {
protected:
  GlobalObject(Type *Ty, ValueTy VTy, Use *Ops, unsigned NumOps,
               LinkageTypes Linkage, const Twine &Name,
               unsigned AddressSpace = 0)
      : GlobalValue(Ty, VTy, Ops, NumOps, Linkage, Name, AddressSpace),
        ObjComdat(nullptr) {
    setGlobalValueSubClassData(0);
  }

  Comdat *ObjComdat;
  enum {
    LastAlignmentBit = 4,
    HasMetadataHashEntryBit,
    HasSectionHashEntryBit,

    GlobalObjectBits,
  };
  static const unsigned GlobalObjectSubClassDataBits =
      GlobalValueSubClassDataBits - GlobalObjectBits;

private:
  static const unsigned AlignmentBits = LastAlignmentBit + 1;
  static const unsigned AlignmentMask = (1 << AlignmentBits) - 1;
  static const unsigned GlobalObjectMask = (1 << GlobalObjectBits) - 1;

public:
  GlobalObject(const GlobalObject &) = delete;

  unsigned getAlignment() const {
    unsigned Data = getGlobalValueSubClassData();
    unsigned AlignmentData = Data & AlignmentMask;
    return (1u << AlignmentData) >> 1;
  }
  void setAlignment(unsigned Align);

  unsigned getGlobalObjectSubClassData() const {
    unsigned ValueData = getGlobalValueSubClassData();
    return ValueData >> GlobalObjectBits;
  }

  void setGlobalObjectSubClassData(unsigned Val) {
    unsigned OldData = getGlobalValueSubClassData();
    setGlobalValueSubClassData((OldData & GlobalObjectMask) |
                               (Val << GlobalObjectBits));
    assert(getGlobalObjectSubClassData() == Val && "representation error");
  }

                                                            
     
                                                                                
             
  bool hasSection() const {
    return getGlobalValueSubClassData() & (1 << HasSectionHashEntryBit);
  }

                                                          
     
                                                                               
                                                                   
  StringRef getSection() const {
    return hasSection() ? getSectionImpl() : StringRef();
  }

                                         
     
                                                                     
                                              
  void setSection(StringRef S);

  bool hasComdat() const { return getComdat() != nullptr; }
  const Comdat *getComdat() const { return ObjComdat; }
  Comdat *getComdat() { return ObjComdat; }
  void setComdat(Comdat *C) { ObjComdat = C; }

                                     
  bool hasMetadata() const { return hasMetadataHashEntry(); }

                                                       
  bool hasMetadata(unsigned KindID) const {
    return getMetadata(KindID) != nullptr;
  }
  bool hasMetadata(StringRef Kind) const {
    return getMetadata(Kind) != nullptr;
  }

                                                                      
     
                                                                                
                                                                                
        
  MDNode *getMetadata(unsigned KindID) const;
  MDNode *getMetadata(StringRef Kind) const;
        

                                                                             
                                                                              
                           
        
  void getMetadata(unsigned KindID, SmallVectorImpl<MDNode *> &MDs) const;
  void getMetadata(StringRef Kind, SmallVectorImpl<MDNode *> &MDs) const;
        

                                                   
     
                                                                              
                                        
        
  void setMetadata(unsigned KindID, MDNode *MD);
  void setMetadata(StringRef Kind, MDNode *MD);
        

                                
        
  void addMetadata(unsigned KindID, MDNode &MD);
  void addMetadata(StringRef Kind, MDNode &MD);
        

                                                                             
                                                                 
  void
  getAllMetadata(SmallVectorImpl<std::pair<unsigned, MDNode *>> &MDs) const;

                                                         
     
                                                
  bool eraseMetadata(unsigned KindID);

                                                          
  void copyMetadata(const GlobalObject *Src, unsigned Offset);

  void addTypeMetadata(unsigned Offset, Metadata *TypeID);

protected:
  void copyAttributesFrom(const GlobalObject *Src);

public:
                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == Value::FunctionVal ||
           V->getValueID() == Value::GlobalVariableVal;
  }

  void clearMetadata();

private:
  void setGlobalObjectFlag(unsigned Bit, bool Val) {
    unsigned Mask = 1 << Bit;
    setGlobalValueSubClassData((~Mask & getGlobalValueSubClassData()) |
                               (Val ? Mask : 0u));
  }

  bool hasMetadataHashEntry() const {
    return getGlobalValueSubClassData() & (1 << HasMetadataHashEntryBit);
  }
  void setHasMetadataHashEntry(bool HasEntry) {
    setGlobalObjectFlag(HasMetadataHashEntryBit, HasEntry);
  }

  StringRef getSectionImpl() const;
};

}                      

#endif                          
