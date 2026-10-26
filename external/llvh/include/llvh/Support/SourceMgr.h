//===- SourceMgr.h - Manager for Source Buffers & Diagnostics ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the SMDiagnostic and SourceMgr classes.  This
// provides a simple substrate for diagnostics, #include handling, and other low
// level things for simple parsers.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_SOURCEMGR_H
#define LLVM_SUPPORT_SOURCEMGR_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/PointerUnion.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/MemoryBuffer.h"
#include "llvh/Support/SMLoc.h"
#include <algorithm>
#include <cassert>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace llvh {

class raw_ostream;
class SMDiagnostic;
class SMFixIt;

                                                                 
                                     
class SourceMgr {
public:
  enum DiagKind {
    DK_Error,
    DK_Warning,
    DK_Remark,
    DK_Note,
  };

                                                                           
                                                                  
                                                       
  using DiagHandlerTy = void (*)(const SMDiagnostic &, void *Context);

private:
  struct SrcBuffer {
                                       
    std::unique_ptr<MemoryBuffer> Buffer;

                                                                           
                                                                           
                                                                         
                       
    using VariableSizeOffsets = PointerUnion4<std::vector<uint8_t> *,
                                              std::vector<uint16_t> *,
                                              std::vector<uint32_t> *,
                                              std::vector<uint64_t> *>;

                                                                     
                                                                          
                                                                      
                                                                  
                                                                        
                                                    
    mutable VariableSizeOffsets OffsetCache;

                                                     
    template<typename T>
    std::vector<T> *getOffsets() const;

                                                                          
                                                                          
                                                                      
                                                 
                                             
    template<typename T>
    std::pair<StringRef, unsigned> getLineNumber(const char *Ptr) const;

                                                                              
                                                                         
                              
    template<typename T>
    StringRef getLineRef(unsigned line) const;

                                                                                
    SMLoc IncludeLoc;

    SrcBuffer() = default;
    SrcBuffer(SrcBuffer &&);
    SrcBuffer(const SrcBuffer &) = delete;
    SrcBuffer &operator=(const SrcBuffer &) = delete;
    ~SrcBuffer();
  };

                                                          
  std::vector<SrcBuffer> Buffers;

                                       
  std::map<const char *, unsigned> BufferEnds;

                                                                      
  mutable unsigned LastFoundBufId = 0;

                                                                           
  std::vector<std::string> IncludeDirectories;

  DiagHandlerTy DiagHandler = nullptr;
  void *DiagContext = nullptr;

  bool isValidBufferID(unsigned i) const { return i && i <= Buffers.size(); }

public:
  SourceMgr() = default;
  SourceMgr(const SourceMgr &) = delete;
  SourceMgr &operator=(const SourceMgr &) = delete;
  ~SourceMgr() = default;

  void setIncludeDirs(const std::vector<std::string> &Dirs) {
    IncludeDirectories = Dirs;
  }

                                                                           
                                                                   
  void setDiagHandler(DiagHandlerTy DH, void *Ctx = nullptr) {
    DiagHandler = DH;
    DiagContext = Ctx;
  }

  DiagHandlerTy getDiagHandler() const { return DiagHandler; }
  void *getDiagContext() const { return DiagContext; }

  const SrcBuffer &getBufferInfo(unsigned i) const {
    assert(isValidBufferID(i));
    return Buffers[i - 1];
  }

  const MemoryBuffer *getMemoryBuffer(unsigned i) const {
    assert(isValidBufferID(i));
    return Buffers[i - 1].Buffer.get();
  }

  unsigned getNumBuffers() const {
    return Buffers.size();
  }

  unsigned getMainFileID() const {
    assert(getNumBuffers());
    return 1;
  }

  SMLoc getParentIncludeLoc(unsigned i) const {
    assert(isValidBufferID(i));
    return Buffers[i - 1].IncludeLoc;
  }

                                                                             
                        
  unsigned AddNewSourceBuffer(std::unique_ptr<MemoryBuffer> F,
                              SMLoc IncludeLoc) {
    const char * End = F->getBufferEnd();
    SrcBuffer NB;
    NB.Buffer = std::move(F);
    NB.IncludeLoc = IncludeLoc;
    Buffers.push_back(std::move(NB));
    unsigned BufId = Buffers.size();
    BufferEnds.emplace(End, BufId);
    return BufId;
  }

                                                                              
                             
     
                                                                             
                                                                             
                      
  unsigned AddIncludeFile(const std::string &Filename, SMLoc IncludeLoc,
                          std::string &IncludedFile);

                                                                    
     
                                               
  unsigned FindBufferContainingLoc(SMLoc Loc) const;

                                                                            
                                
  unsigned FindLineNumber(SMLoc Loc, unsigned BufferID = 0) const {
    return getLineAndColumn(Loc, BufferID).first;
  }

                                                                            
                                                                
                                
  std::pair<StringRef, unsigned> FindLine(SMLoc Loc, unsigned BufferID = 0) const;

                                                         
                                                                       
                            
  StringRef getLineRef(unsigned line, unsigned BufferID) const;

                                                                       
                                                
  std::pair<unsigned, unsigned> getLineAndColumn(SMLoc Loc,
                                                 unsigned BufferID = 0) const;

                                                                            
     
                                                                            
                                        
  void PrintMessage(raw_ostream &OS, SMLoc Loc, DiagKind Kind,
                    const Twine &Msg,
                    ArrayRef<SMRange> Ranges = None,
                    ArrayRef<SMFixIt> FixIts = None,
                    bool ShowColors = true) const;

                                         
  void PrintMessage(SMLoc Loc, DiagKind Kind, const Twine &Msg,
                    ArrayRef<SMRange> Ranges = None,
                    ArrayRef<SMFixIt> FixIts = None,
                    bool ShowColors = true) const;

                                                                         
     
                                                                            
                                        
  void PrintMessage(raw_ostream &OS, const SMDiagnostic &Diagnostic,
                    bool ShowColors = true) const;

                                                                         
             
     
                                                                          
                              
  SMDiagnostic GetMessage(SMLoc Loc, DiagKind Kind, const Twine &Msg,
                          ArrayRef<SMRange> Ranges = None,
                          ArrayRef<SMFixIt> FixIts = None) const;

                                                                           
                                                                          
                               
     
                                                    
                                            
  void PrintIncludeStack(SMLoc IncludeLoc, raw_ostream &OS) const;
};

                                                                               
class SMFixIt {
  SMRange Range;

  std::string Text;

public:
                                              
  SMFixIt(SMLoc Loc, const Twine &Insertion)
    : Range(Loc, Loc), Text(Insertion.str()) {
    assert(Loc.isValid());
  }

                                              
  SMFixIt(SMRange R, const Twine &Replacement)
    : Range(R), Text(Replacement.str()) {
    assert(R.isValid());
  }

  StringRef getText() const { return Text; }
  SMRange getRange() const { return Range; }

  bool operator<(const SMFixIt &Other) const {
    if (Range.Start.getPointer() != Other.Range.Start.getPointer())
      return Range.Start.getPointer() < Other.Range.Start.getPointer();
    if (Range.End.getPointer() != Other.Range.End.getPointer())
      return Range.End.getPointer() < Other.Range.End.getPointer();
    return Text < Other.Text;
  }
};

                                                                       
                                                    
class SMDiagnostic {
  const SourceMgr *SM = nullptr;
  SMLoc Loc;
  std::string Filename;
  int LineNo = 0;
  int ColumnNo = 0;
  SourceMgr::DiagKind Kind = SourceMgr::DK_Error;
  std::string Message, LineContents;
  std::vector<std::pair<unsigned, unsigned>> Ranges;
  SmallVector<SMFixIt, 4> FixIts;

public:
                     
  SMDiagnostic() = default;
                                                                               
  SMDiagnostic(StringRef filename, SourceMgr::DiagKind Knd, StringRef Msg)
    : Filename(filename), LineNo(-1), ColumnNo(-1), Kind(Knd), Message(Msg) {}

                                
  SMDiagnostic(const SourceMgr &sm, SMLoc L, StringRef FN,
               int Line, int Col, SourceMgr::DiagKind Kind,
               StringRef Msg, StringRef LineStr,
               ArrayRef<std::pair<unsigned,unsigned>> Ranges,
               ArrayRef<SMFixIt> FixIts = None);

  const SourceMgr *getSourceMgr() const { return SM; }
  SMLoc getLoc() const { return Loc; }
  StringRef getFilename() const { return Filename; }
  int getLineNo() const { return LineNo; }
  int getColumnNo() const { return ColumnNo; }
  SourceMgr::DiagKind getKind() const { return Kind; }
  StringRef getMessage() const { return Message; }
  StringRef getLineContents() const { return LineContents; }
  ArrayRef<std::pair<unsigned, unsigned>> getRanges() const { return Ranges; }

  void addFixIt(const SMFixIt &Hint) {
    FixIts.push_back(Hint);
  }

  ArrayRef<SMFixIt> getFixIts() const {
    return FixIts;
  }

  void print(const char *ProgName, raw_ostream &S, bool ShowColors = true,
             bool ShowKindLabel = true) const;
};

}                      

#endif                            
