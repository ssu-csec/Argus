//===- DIBuilder.h - Debug Information Builder ------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a DIBuilder that is useful for creating debugging
// information entries in LLVM IR form.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DIBUILDER_H
#define LLVM_IR_DIBUILDER_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/MapVector.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SetVector.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/IR/DebugInfo.h"
#include "llvh/IR/DebugInfoMetadata.h"
#include "llvh/IR/TrackingMDRef.h"
#include "llvh/Support/Casting.h"
#include <algorithm>
#include <cstdint>

namespace llvh {

  class BasicBlock;
  class Constant;
  class Function;
  class Instruction;
  class LLVMContext;
  class Module;
  class Value;

  class DIBuilder {
    Module &M;
    LLVMContext &VMContext;

    DICompileUnit *CUNode;                                                      
    Function *DeclareFn;                          
    Function *ValueFn;                          
    Function *LabelFn;                          

    SmallVector<Metadata *, 4> AllEnumTypes;
                                                                  
    SmallVector<TrackingMDNodeRef, 4> AllRetainTypes;
    SmallVector<Metadata *, 4> AllSubprograms;
    SmallVector<Metadata *, 4> AllGVs;
    SmallVector<TrackingMDNodeRef, 4> AllImportedModules;
                                                                           
                                         
                                                                            
    MapVector<MDNode *, SetVector<Metadata *>> AllMacrosPerParent;

                                           
    SmallVector<TrackingMDNodeRef, 4> UnresolvedNodes;
    bool AllowUnresolvedNodes;

                                                    
       
                                                                          
                                                                             
             
    DenseMap<MDNode *, SmallVector<TrackingMDNodeRef, 1>> PreservedVariables;

                                           
    DenseMap<MDNode *, SmallVector<TrackingMDNodeRef, 1>> PreservedLabels;

                           
       
                                                                       
    void trackIfUnresolved(MDNode *N);

                                          
    Instruction *insertDeclare(llvh::Value *Storage, DILocalVariable *VarInfo,
                               DIExpression *Expr, const DILocation *DL,
                               BasicBlock *InsertBB, Instruction *InsertBefore);

                                        
    Instruction *insertLabel(DILabel *LabelInfo, const DILocation *DL,
                             BasicBlock *InsertBB, Instruction *InsertBefore);

                                                    
    Instruction *
    insertDbgValueIntrinsic(llvh::Value *Val, DILocalVariable *VarInfo,
                            DIExpression *Expr, const DILocation *DL,
                            BasicBlock *InsertBB, Instruction *InsertBefore);

  public:
                                         
       
                                                                              
                                                        
       
                                                                               
    explicit DIBuilder(Module &M, bool AllowUnresolved = true,
                       DICompileUnit *CU = nullptr);
    DIBuilder(const DIBuilder &) = delete;
    DIBuilder &operator=(const DIBuilder &) = delete;

                                                      
    void finalize();

                                                                              
                              
    void finalizeSubprogram(DISubprogram *SP);

                                                          
                                                                  
                                                                                
                                       
                                                                           
                                                                  
                                            
                                                                                
                                               
                                                                         
                                                                      
                                                               
                                                                       
                                                                              
                                         
                                                                             
                                      
                                                                       
                                                                                
                                                                       
                                                                         
                                                        
                                                                  
                                                                    
    DICompileUnit *
    createCompileUnit(unsigned Lang, DIFile *File, StringRef Producer,
                      bool isOptimized, StringRef Flags, unsigned RV,
                      StringRef SplitName = StringRef(),
                      DICompileUnit::DebugEmissionKind Kind =
                          DICompileUnit::DebugEmissionKind::FullDebug,
                      uint64_t DWOId = 0, bool SplitDebugInlining = true,
                      bool DebugInfoForProfiling = false,
                      DICompileUnit::DebugNameTableKind NameTableKind =
                          DICompileUnit::DebugNameTableKind::Default);

                                                                          
                                   
                                   
                                                                              
                                   
                                              
    DIFile *
    createFile(StringRef Filename, StringRef Directory,
               Optional<DIFile::ChecksumInfo<StringRef>> Checksum = None,
               Optional<StringRef> Source = None);

                                                       
                                                          
                                                                        
                                                                
                                     
                                      
    DIMacro *createMacro(DIMacroFile *Parent, unsigned Line, unsigned MacroType,
                         StringRef Name, StringRef Value = StringRef());

                                                                      
                                                                           
                                         
                                                               
                                                                              
                                                                                
    DIMacroFile *createTempMacroFile(DIMacroFile *Parent, unsigned Line,
                                     DIFile *File);

                                         
    DIEnumerator *createEnumerator(StringRef Name, int64_t Val, bool IsUnsigned = false);

                                        
    DIBasicType *createUnspecifiedType(StringRef Name);

                                  
    DIBasicType *createNullPtrType();

                                                      
             
                                     
                                            
                                                                          
                                                                            
    DIBasicType *createBasicType(StringRef Name, uint64_t SizeInBits,
                                 unsigned Encoding,
                                 DINode::DIFlags Flags = DINode::FlagZero);

                                                          
                               
                                                                             
                                     
    DIDerivedType *createQualifiedType(unsigned Tag, DIType *FromTy);

                                                         
                                                              
                                      
                                                      
                                                                
                                                              
    DIDerivedType *createPointerType(DIType *PointeeTy, uint64_t SizeInBits,
                                     uint32_t AlignInBits = 0,
                                     Optional<unsigned> DWARFAddressSpace =
                                         None,
                                     StringRef Name = "");

                                                                   
                                                         
                                
                                                
                                                                      
    DIDerivedType *
    createMemberPointerType(DIType *PointeeTy, DIType *Class,
                            uint64_t SizeInBits, uint32_t AlignInBits = 0,
                            DINode::DIFlags Flags = DINode::FlagZero);

                                                    
                                                 
    DIDerivedType *createReferenceType(unsigned Tag, DIType *RTy,
                                       uint64_t SizeInBits = 0,
                                       uint32_t AlignInBits = 0,
                                       Optional<unsigned> DWARFAddressSpace =
                                           None);

                                                         
                                         
                                        
                                                           
                                       
                                                                   
    DIDerivedType *createTypedef(DIType *Ty, StringRef Name, DIFile *File,
                                 unsigned LineNo, DIScope *Context);

                                                          
    DIDerivedType *createFriend(DIType *Ty, DIType *FriendTy);

                                                       
                                                   
                                          
                                                                
                                        
                                                        
                                                                    
                                        
    DIDerivedType *createInheritance(DIType *Ty, DIType *BaseTy,
                                     uint64_t BaseOffset, uint32_t VBPtrOffset,
                                     DINode::DIFlags Flags);

                                                        
                                         
                                        
                                                              
                                        
                                        
                                             
                                          
                                                                          
                                        
    DIDerivedType *createMemberType(DIScope *Scope, StringRef Name,
                                    DIFile *File, unsigned LineNo,
                                    uint64_t SizeInBits,
                                    uint32_t AlignInBits,
                                    uint64_t OffsetInBits,
                                    DINode::DIFlags Flags, DIType *Ty);

                                                                    
                                                      
                                         
                                        
                                                              
                                        
                                        
                                             
                                          
                                                                          
                                                                      
                                              
                                        
    DIDerivedType *createVariantMemberType(DIScope *Scope, StringRef Name,
					   DIFile *File, unsigned LineNo,
					   uint64_t SizeInBits,
					   uint32_t AlignInBits,
					   uint64_t OffsetInBits,
					   Constant *Discriminant,
					   DINode::DIFlags Flags, DIType *Ty);

                                                                  
                                                
                                               
                                                                     
                                               
                                               
                                                 
                                                         
                                                                    
                                               
    DIDerivedType *createBitFieldMemberType(
        DIScope *Scope, StringRef Name, DIFile *File, unsigned LineNo,
        uint64_t SizeInBits, uint64_t OffsetInBits,
        uint64_t StorageOffsetInBits, DINode::DIFlags Flags, DIType *Ty);

                                                
                               
                                       
                                      
                                                             
                                      
                                                    
                                                                         
                                                          
                                             
    DIDerivedType *createStaticMemberType(DIScope *Scope, StringRef Name,
                                          DIFile *File, unsigned LineNo,
                                          DIType *Ty, DINode::DIFlags Flags,
                                          Constant *Val,
                                          uint32_t AlignInBits = 0);

                                                          
                          
                                        
                                                              
                                        
                                        
                                             
                                          
                                                                          
                                        
                                                               
    DIDerivedType *createObjCIVar(StringRef Name, DIFile *File, unsigned LineNo,
                                  uint64_t SizeInBits, uint32_t AlignInBits,
                                  uint64_t OffsetInBits, DINode::DIFlags Flags,
                                  DIType *Ty, MDNode *PropertyNode);

                                                          
                 
                                          
                                                                
                                        
                                                                             
                                                                             
                                                                  
                                 
    DIObjCProperty *createObjCProperty(StringRef Name, DIFile *File,
                                       unsigned LineNumber,
                                       StringRef GetterName,
                                       StringRef SetterName,
                                       unsigned PropertyAttributes, DIType *Ty);

                                                       
                                                                 
                                       
                                                              
                                        
                                        
                                             
                                          
                                                                          
                                          
                                                                             
                                                          
                                                                          
                                          
                                                      
                                                                  
    DICompositeType *createClassType(
        DIScope *Scope, StringRef Name, DIFile *File, unsigned LineNumber,
        uint64_t SizeInBits, uint32_t AlignInBits, uint64_t OffsetInBits,
        DINode::DIFlags Flags, DIType *DerivedFrom, DINodeArray Elements,
        DIType *VTableHolder = nullptr, MDNode *TemplateParms = nullptr,
        StringRef UniqueIdentifier = "");

                                                        
                                                                  
                                        
                                                              
                                        
                                        
                                             
                                                                          
                                            
                                                                            
                                                                   
    DICompositeType *createStructType(
        DIScope *Scope, StringRef Name, DIFile *File, unsigned LineNumber,
        uint64_t SizeInBits, uint32_t AlignInBits, DINode::DIFlags Flags,
        DIType *DerivedFrom, DINodeArray Elements, unsigned RunTimeLang = 0,
        DIType *VTableHolder = nullptr, StringRef UniqueIdentifier = "");

                                                        
                                                                 
                                       
                                                              
                                        
                                        
                                             
                                                                          
                                           
                                                                            
                                                                  
    DICompositeType *createUnionType(DIScope *Scope, StringRef Name,
                                     DIFile *File, unsigned LineNumber,
                                     uint64_t SizeInBits, uint32_t AlignInBits,
                                     DINode::DIFlags Flags,
                                     DINodeArray Elements,
                                     unsigned RunTimeLang = 0,
                                     StringRef UniqueIdentifier = "");

                                                                 
                                                                     
                                                   
                                                                 
                                       
                                                              
                                        
                                        
                                             
                                                                          
                                                
                                             
                                                                  
    DICompositeType *createVariantPart(DIScope *Scope, StringRef Name,
				       DIFile *File, unsigned LineNumber,
				       uint64_t SizeInBits, uint32_t AlignInBits,
				       DINode::DIFlags Flags,
				       DIDerivedType *Discriminator,
				       DINodeArray Elements,
				       StringRef UniqueIdentifier = "");

                                                 
                       
                                                                
                                                
                                           
    DITemplateTypeParameter *
    createTemplateTypeParameter(DIScope *Scope, StringRef Name, DIType *Ty);

                                                 
                        
                                                                
                                                 
                                           
                                                     
    DITemplateValueParameter *createTemplateValueParameter(DIScope *Scope,
                                                           StringRef Name,
                                                           DIType *Ty,
                                                           Constant *Val);

                                                                       
                                                                
                                                 
                                           
                                                                     
    DITemplateValueParameter *createTemplateTemplateParameter(DIScope *Scope,
                                                              StringRef Name,
                                                              DIType *Ty,
                                                              StringRef Val);

                                                                   
                                                                
                                                 
                                           
                                                          
    DITemplateValueParameter *createTemplateParameterPack(DIScope *Scope,
                                                          StringRef Name,
                                                          DIType *Ty,
                                                          DINodeArray Val);

                                                        
                                       
                                      
                                         
                                       
    DICompositeType *createArrayType(uint64_t Size, uint32_t AlignInBits,
                                     DIType *Ty, DINodeArray Subscripts);

                                                             
                                       
                                      
                                         
                                       
    DICompositeType *createVectorType(uint64_t Size, uint32_t AlignInBits,
                                      DIType *Ty, DINodeArray Subscripts);

                                                 
                    
                                                                         
                                         
                                                                
                                          
                                          
                                               
                                                   
                                                                         
                                                                 
                                                                              
    DICompositeType *createEnumerationType(
        DIScope *Scope, StringRef Name, DIFile *File, unsigned LineNumber,
        uint64_t SizeInBits, uint32_t AlignInBits, DINodeArray Elements,
        DIType *UnderlyingType, StringRef UniqueIdentifier = "", bool IsFixed = false);

                               
                                                                           
                                                                 
                                                     
                                                                             
                                                                           
    DISubroutineType *
    createSubroutineType(DITypeRefArray ParameterTypes,
                         DINode::DIFlags Flags = DINode::FlagZero,
                         unsigned CC = 0);

                                                                 
    static DISubprogram *createArtificialSubprogram(DISubprogram *SP);

                                                                
    static DIType *createArtificialType(DIType *Ty);

                                                                  
                           
    static DIType *createObjectPointerType(DIType *Ty);

                                                 
    DICompositeType *createForwardDecl(unsigned Tag, StringRef Name,
                                       DIScope *Scope, DIFile *F, unsigned Line,
                                       unsigned RuntimeLang = 0,
                                       uint64_t SizeInBits = 0,
                                       uint32_t AlignInBits = 0,
                                       StringRef UniqueIdentifier = "");

                                                 
    DICompositeType *createReplaceableCompositeType(
        unsigned Tag, StringRef Name, DIScope *Scope, DIFile *F, unsigned Line,
        unsigned RuntimeLang = 0, uint64_t SizeInBits = 0,
        uint32_t AlignInBits = 0, DINode::DIFlags Flags = DINode::FlagFwdDecl,
        StringRef UniqueIdentifier = "");

                                                                
                                   
    void retainType(DIScope *T);

                                         
                              
    DIBasicType *createUnspecifiedParameter();

                                                  
    DINodeArray getOrCreateArray(ArrayRef<Metadata *> Elements);

                                                       
    DIMacroNodeArray getOrCreateMacroArray(ArrayRef<Metadata *> Elements);

                                                     
    DITypeRefArray getOrCreateTypeArray(ArrayRef<Metadata *> Elements);

                                                    
                                               
    DISubrange *getOrCreateSubrange(int64_t Lo, int64_t Count);
    DISubrange *getOrCreateSubrange(int64_t Lo, Metadata *CountNode);

                                                           
                                          
                                                
                                                         
                                                               
                                       
                                         
                                                                           
                                                       
                                                                              
                                          
                                                                      
                                                                           
                                     
    DIGlobalVariableExpression *createGlobalVariableExpression(
        DIScope *Context, StringRef Name, StringRef LinkageName, DIFile *File,
        unsigned LineNo, DIType *Ty, bool isLocalToUnit,
        DIExpression *Expr = nullptr, MDNode *Decl = nullptr,
        MDTuple *templateParams = nullptr, uint32_t AlignInBits = 0);

                                         
                                                                              
    DIGlobalVariable *createTempGlobalVariableFwdDecl(
        DIScope *Context, StringRef Name, StringRef LinkageName, DIFile *File,
        unsigned LineNo, DIType *Ty, bool isLocalToUnit, MDNode *Decl = nullptr,
        MDTuple *templateParams = nullptr, uint32_t AlignInBits = 0);

                                                                               
                                           
       
                                                                               
                                   
       
                                                                       
                                                                   
    DILocalVariable *
    createAutoVariable(DIScope *Scope, StringRef Name, DIFile *File,
                       unsigned LineNo, DIType *Ty, bool AlwaysPreserve = false,
                       DINode::DIFlags Flags = DINode::FlagZero,
                       uint32_t AlignInBits = 0);

                                             
       
                                                                               
                                   
    DILabel *
    createLabel(DIScope *Scope, StringRef Name, DIFile *File, unsigned LineNo,
                bool AlwaysPreserve = false);

                                                         
       
                                                                               
                                   
       
                                                                          
                                                                       
                                          
       
                                                                       
                                                                   
    DILocalVariable *
    createParameterVariable(DIScope *Scope, StringRef Name, unsigned ArgNo,
                            DIFile *File, unsigned LineNo, DIType *Ty,
                            bool AlwaysPreserve = false,
                            DINode::DIFlags Flags = DINode::FlagZero);

                                                 
                                                                        
                                                                  
    DIExpression *createExpression(ArrayRef<uint64_t> Addr = None);
    DIExpression *createExpression(ArrayRef<int64_t> Addr);

                                                                              
                                   
    DIExpression *createConstantValueExpression(uint64_t Val) {
      return DIExpression::get(
          VMContext, {dwarf::DW_OP_constu, Val, dwarf::DW_OP_stack_value});
    }

                                                             
                                                                       
                                            
                                           
                                                   
                                                                 
                                         
                                           
                                                                             
                                                                   
                                                                          
                                                                     
                                                                           
                                                        
                                                          
                                                                     
    DISubprogram *createFunction(
        DIScope *Scope, StringRef Name, StringRef LinkageName, DIFile *File,
        unsigned LineNo, DISubroutineType *Ty, bool isLocalToUnit,
        bool isDefinition, unsigned ScopeLine,
        DINode::DIFlags Flags = DINode::FlagZero, bool isOptimized = false,
        DITemplateParameterArray TParams = nullptr,
        DISubprogram *Decl = nullptr, DITypeArray ThrownTypes = nullptr);

                                    
                                                                
    DISubprogram *createTempFunctionFwdDecl(
        DIScope *Scope, StringRef Name, StringRef LinkageName, DIFile *File,
        unsigned LineNo, DISubroutineType *Ty, bool isLocalToUnit,
        bool isDefinition, unsigned ScopeLine,
        DINode::DIFlags Flags = DINode::FlagZero, bool isOptimized = false,
        DITemplateParameterArray TParams = nullptr,
        DISubprogram *Decl = nullptr, DITypeArray ThrownTypes = nullptr);

                                                             
                                                                          
                                            
                                           
                                                   
                                                                 
                                         
                                           
                                                                              
                                                                   
                                                                         
                                              
                                                                                
                                             
                             
                                                                             
                                             
                                                    
                                                                     
                                                                          
                                                        
                                                          
                                                                     
    DISubprogram *createMethod(
        DIScope *Scope, StringRef Name, StringRef LinkageName, DIFile *File,
        unsigned LineNo, DISubroutineType *Ty, bool isLocalToUnit,
        bool isDefinition, unsigned Virtuality = 0, unsigned VTableIndex = 0,
        int ThisAdjustment = 0, DIType *VTableHolder = nullptr,
        DINode::DIFlags Flags = DINode::FlagZero, bool isOptimized = false,
        DITemplateParameterArray TParams = nullptr,
        DITypeArray ThrownTypes = nullptr);

                                                                      
                     
                                          
                                                 
                                                            
    DINamespace *createNameSpace(DIScope *Scope, StringRef Name,
                                 bool ExportSymbols);

                                                                   
                     
                                       
                                              
                                  
                                                                          
                                                                              
                                                           
                                                                      
    DIModule *createModule(DIScope *Scope, StringRef Name,
                           StringRef ConfigurationMacros,
                           StringRef IncludePath,
                           StringRef ISysRoot);

                                                                     
                                                  
                                           
                                         
                                       
                                                            
    DILexicalBlockFile *createLexicalBlockFile(DIScope *Scope, DIFile *File,
                                               unsigned Discriminator = 0);

                                                              
                                 
                                                  
                                         
                                         
                                           
    DILexicalBlock *createLexicalBlock(DIScope *Scope, DIFile *File,
                                       unsigned Line, unsigned Col);

                                                   
                                                             
                                                         
                                                             
                                                      
    DIImportedEntity *createImportedModule(DIScope *Context, DINamespace *NS,
                                           DIFile *File, unsigned Line);

                                                   
                                                              
                                            
                                                             
                                                      
    DIImportedEntity *createImportedModule(DIScope *Context,
                                           DIImportedEntity *NS, DIFile *File,
                                           unsigned Line);

                                                   
                                                              
                                                     
                                                             
                                                      
    DIImportedEntity *createImportedModule(DIScope *Context, DIModule *M,
                                           DIFile *File, unsigned Line);

                                                     
                                                              
                                                                              
                                
                                                             
                                                      
    DIImportedEntity *createImportedDeclaration(DIScope *Context, DINode *Decl,
                                                DIFile *File, unsigned Line,
                                                StringRef Name = "");

                                                     
                                                      
                                                            
                                                         
                                               
                                                          
    Instruction *insertDeclare(llvh::Value *Storage, DILocalVariable *VarInfo,
                               DIExpression *Expr, const DILocation *DL,
                               BasicBlock *InsertAtEnd);

                                                     
                                                       
                                                             
                                                          
                                                
                                                           
    Instruction *insertDeclare(llvh::Value *Storage, DILocalVariable *VarInfo,
                               DIExpression *Expr, const DILocation *DL,
                               Instruction *InsertBefore);

                                                   
                                                          
                                                
                                                           
    Instruction *insertLabel(DILabel *LabelInfo, const DILocation *DL,
                             Instruction *InsertBefore);

                                                   
                                                          
                                                
                                                          
    Instruction *insertLabel(DILabel *LabelInfo, const DILocation *DL,
                             BasicBlock *InsertAtEnd);

                                                   
                                                       
                                                             
                                                          
                                                
                                                          
    Instruction *insertDbgValueIntrinsic(llvh::Value *Val,
                                         DILocalVariable *VarInfo,
                                         DIExpression *Expr,
                                         const DILocation *DL,
                                         BasicBlock *InsertAtEnd);

                                                   
                                                       
                                                             
                                                          
                                                
                                                           
    Instruction *insertDbgValueIntrinsic(llvh::Value *Val,
                                         DILocalVariable *VarInfo,
                                         DIExpression *Expr,
                                         const DILocation *DL,
                                         Instruction *InsertBefore);

                                                    
       
                                                                              
                                                                     
    void replaceVTableHolder(DICompositeType *&T,
                             DIType *VTableHolder);

                                           
       
                                                                              
                                                                        
                       
    void replaceArrays(DICompositeType *&T, DINodeArray Elements,
                       DINodeArray TParams = DINodeArray());

                                 
       
                                                                          
                    
       
                                                                    
                                                                           
                                                                 
    template <class NodeTy>
    NodeTy *replaceTemporary(TempMDNode &&N, NodeTy *Replacement) {
      if (N.get() == Replacement)
        return cast<NodeTy>(MDNode::replaceWithUniqued(std::move(N)));

      N->replaceAllUsesWith(Replacement);
      return Replacement;
    }
  };

                                                                  
  DEFINE_ISA_CONVERSION_FUNCTIONS(DIBuilder, LLVMDIBuilderRef)

}                      

#endif                       
