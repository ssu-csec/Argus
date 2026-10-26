//===- SourceMgr.cpp - Manager for Simple Source Buffers & Diagnostics ----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the SourceMgr class.  This class is used as a simple
// substrate for diagnostics, #include handling, and other low level things for
// simple parsers.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/SourceMgr.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/ErrorOr.h"
#include "llvh/Support/Locale.h"
#include "llvh/Support/MemoryBuffer.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/SMLoc.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <utility>

using namespace llvh;

static const size_t TabStop = 8;

unsigned SourceMgr::AddIncludeFile(const std::string &Filename,
                                   SMLoc IncludeLoc,
                                   std::string &IncludedFile) {
  IncludedFile = Filename;
  ErrorOr<std::unique_ptr<MemoryBuffer>> NewBufOrErr =
    MemoryBuffer::getFile(IncludedFile);

                                                                       
  for (unsigned i = 0, e = IncludeDirectories.size(); i != e && !NewBufOrErr;
       ++i) {
    IncludedFile =
        IncludeDirectories[i] + sys::path::get_separator().data() + Filename;
    NewBufOrErr = MemoryBuffer::getFile(IncludedFile);
  }

  if (!NewBufOrErr)
    return 0;

  return AddNewSourceBuffer(std::move(*NewBufOrErr), IncludeLoc);
}

unsigned SourceMgr::FindBufferContainingLoc(SMLoc Loc) const {
                                                                               
         
  if (LLVM_LIKELY(
          LastFoundBufId &&
          Loc.getPointer() >=
              Buffers[LastFoundBufId - 1].Buffer->getBufferStart() &&
          Loc.getPointer() <=
              Buffers[LastFoundBufId - 1].Buffer->getBufferEnd())) {
    return LastFoundBufId;
  }

  auto it = BufferEnds.lower_bound(Loc.getPointer());
  if (it != BufferEnds.end() &&
      Loc.getPointer() >= Buffers[it->second - 1].Buffer->getBufferStart()) {
    return LastFoundBufId = it->second;
  }

  return 0;
}

template <typename T>
std::vector<T> *SourceMgr::SrcBuffer::getOffsets() const {
                                                                          
                
  if (!OffsetCache.isNull())
    return OffsetCache.get<std::vector<T> *>();

  std::vector<T> *Offsets = new std::vector<T>();
  OffsetCache = Offsets;
  size_t Sz = Buffer->getBufferSize();
  assert(Sz <= std::numeric_limits<T>::max());
  StringRef S = Buffer->getBuffer();
  for (size_t N = 0; N < Sz; ++N) {
    if (S[N] == '\n') {
      Offsets->push_back(static_cast<T>(N));
    }
  }

  return Offsets;
}

template <typename T>
std::pair<StringRef, unsigned> SourceMgr::SrcBuffer::getLineNumber(
    const char *Ptr) const {
  std::vector<T> *Offsets = getOffsets<T>();

  const char *BufStart = Buffer->getBufferStart();
  assert(Ptr >= BufStart && Ptr <= Buffer->getBufferEnd());
  ptrdiff_t PtrDiff = Ptr - BufStart;
  assert(PtrDiff >= 0 && static_cast<size_t>(PtrDiff) <= std::numeric_limits<T>::max());
  T PtrOffset = static_cast<T>(PtrDiff);

                                                                       
                                                                         
                                                                          
                        
  auto EOL = std::lower_bound(Offsets->begin(), Offsets->end(), PtrOffset);

                                                        
  const char *LineStart =
      EOL != Offsets->begin() ? BufStart + EOL[-1] + 1 : BufStart;

                                                                                 
  const char *LineEnd =
      EOL != Offsets->end() ? BufStart + *EOL + 1 : Buffer->getBufferEnd();

                                                                    
  return {StringRef(LineStart, LineEnd - LineStart), static_cast<unsigned>((1 + (EOL - Offsets->begin())))};
}

template<typename T>
StringRef SourceMgr::SrcBuffer::getLineRef(unsigned line) const {
  assert(line >= 1 && "line number must be 1-based");
  --line;

  const char *BufStart = Buffer->getBufferStart();
  std::vector<T> *Offsets = getOffsets<T>();
  size_t size = Offsets->size();
  if (line < size) {
    auto EOL = Offsets->begin() + line;

                                                          
    const char *LineStart =
        EOL != Offsets->begin() ? BufStart + EOL[-1] + 1 : BufStart;

                                                
    const char *LineEnd = BufStart + *EOL + 1;

    return StringRef(LineStart, LineEnd - LineStart);
  } else {
                                
    if (line == size) {
      const char *LineStart =
          size != 0 ? BufStart + Offsets->back() + 1 : BufStart;
      const char *LineEnd = Buffer->getBufferEnd();
      return StringRef(LineStart, LineEnd - LineStart);
    } else {
      return StringRef(Buffer->getBufferEnd(), 0);
    }
  }
}

SourceMgr::SrcBuffer::SrcBuffer(SourceMgr::SrcBuffer &&Other)
  : Buffer(std::move(Other.Buffer)),
    OffsetCache(Other.OffsetCache),
    IncludeLoc(Other.IncludeLoc) {
  Other.OffsetCache = nullptr;
}

SourceMgr::SrcBuffer::~SrcBuffer() {
  if (!OffsetCache.isNull()) {
    if (OffsetCache.is<std::vector<uint8_t>*>())
      delete OffsetCache.get<std::vector<uint8_t>*>();
    else if (OffsetCache.is<std::vector<uint16_t>*>())
      delete OffsetCache.get<std::vector<uint16_t>*>();
    else if (OffsetCache.is<std::vector<uint32_t>*>())
      delete OffsetCache.get<std::vector<uint32_t>*>();
    else
      delete OffsetCache.get<std::vector<uint64_t>*>();
    OffsetCache = nullptr;
  }
}

std::pair<StringRef, unsigned> SourceMgr::FindLine(SMLoc Loc, unsigned int BufferID) const {
  if (!BufferID)
    BufferID = FindBufferContainingLoc(Loc);
  assert(BufferID && "Invalid Location!");

  auto &SB = getBufferInfo(BufferID);
  const char *Ptr = Loc.getPointer();

  size_t Sz = SB.Buffer->getBufferSize();
  if (Sz <= std::numeric_limits<uint8_t>::max())
    return SB.getLineNumber<uint8_t>(Ptr);
  else if (Sz <= std::numeric_limits<uint16_t>::max())
    return SB.getLineNumber<uint16_t>(Ptr);
  else if (Sz <= std::numeric_limits<uint32_t>::max())
    return SB.getLineNumber<uint32_t>(Ptr);
  else
    return SB.getLineNumber<uint64_t>(Ptr);
}

StringRef SourceMgr::getLineRef(unsigned line, unsigned BufferID) const {
  assert(BufferID != 0 && "BufferID must be specified");
  auto &SB = getBufferInfo(BufferID);
  size_t Sz = SB.Buffer->getBufferSize();
  if (Sz <= std::numeric_limits<uint8_t>::max())
    return SB.getLineRef<uint8_t>(line);
  else if (Sz <= std::numeric_limits<uint16_t>::max())
    return SB.getLineRef<uint16_t>(line);
  else if (Sz <= std::numeric_limits<uint32_t>::max())
    return SB.getLineRef<uint32_t>(line);
  else
    return SB.getLineRef<uint64_t>(line);
}

std::pair<unsigned, unsigned>
SourceMgr::getLineAndColumn(SMLoc Loc, unsigned BufferID) const {
  auto LineRefAndNo = FindLine(Loc, BufferID);
  return std::make_pair(LineRefAndNo.second,
                        static_cast<unsigned>(Loc.getPointer() - LineRefAndNo.first.data() + 1));
}

void SourceMgr::PrintIncludeStack(SMLoc IncludeLoc, raw_ostream &OS) const {
  if (IncludeLoc == SMLoc()) return;                  

  unsigned CurBuf = FindBufferContainingLoc(IncludeLoc);
  assert(CurBuf && "Invalid or unspecified location!");

  PrintIncludeStack(getBufferInfo(CurBuf).IncludeLoc, OS);

  OS << "Included from "
     << getBufferInfo(CurBuf).Buffer->getBufferIdentifier()
     << ":" << FindLineNumber(IncludeLoc, CurBuf) << ":\n";
}

SMDiagnostic SourceMgr::GetMessage(SMLoc Loc, SourceMgr::DiagKind Kind,
                                   const Twine &Msg,
                                   ArrayRef<SMRange> Ranges,
                                   ArrayRef<SMFixIt> FixIts) const {
                                                                        
                                          
  SmallVector<std::pair<unsigned, unsigned>, 4> ColRanges;
  std::pair<unsigned, unsigned> LineAndCol;
  StringRef BufferID = "<unknown>";
  std::string LineStr;

  if (Loc.isValid()) {
    unsigned CurBuf = FindBufferContainingLoc(Loc);
    assert(CurBuf && "Invalid or unspecified location!");

    const MemoryBuffer *CurMB = getMemoryBuffer(CurBuf);
    BufferID = CurMB->getBufferIdentifier();

                                                   
    const char *LineStart = Loc.getPointer();
    const char *BufStart = CurMB->getBufferStart();
    while (LineStart != BufStart && LineStart[-1] != '\n' &&
           LineStart[-1] != '\r')
      --LineStart;

                               
    const char *LineEnd = Loc.getPointer();
    const char *BufEnd = CurMB->getBufferEnd();
    while (LineEnd != BufEnd && LineEnd[0] != '\n' && LineEnd[0] != '\r')
      ++LineEnd;
    LineStr = std::string(LineStart, LineEnd);

                                                                              
                
    for (unsigned i = 0, e = Ranges.size(); i != e; ++i) {
      SMRange R = Ranges[i];
      if (!R.isValid()) continue;

                                                                           
      if (R.Start.getPointer() > LineEnd || R.End.getPointer() < LineStart)
        continue;

                                                             
      if (R.Start.getPointer() < LineStart)
        R.Start = SMLoc::getFromPointer(LineStart);
      if (R.End.getPointer() > LineEnd)
        R.End = SMLoc::getFromPointer(LineEnd);

                                                      
                                            
      ColRanges.push_back(std::make_pair(static_cast<unsigned>(R.Start.getPointer()-LineStart),
                                         static_cast<unsigned>(R.End.getPointer()-LineStart)));
    }

    LineAndCol = getLineAndColumn(Loc, CurBuf);
  }

  return SMDiagnostic(*this, Loc, BufferID, LineAndCol.first,
                      LineAndCol.second-1, Kind, Msg.str(),
                      LineStr, ColRanges, FixIts);
}

void SourceMgr::PrintMessage(raw_ostream &OS, const SMDiagnostic &Diagnostic,
                             bool ShowColors) const {
                                                               
  if (DiagHandler) {
    DiagHandler(Diagnostic, DiagContext);
    return;
  }

  if (Diagnostic.getLoc().isValid()) {
    unsigned CurBuf = FindBufferContainingLoc(Diagnostic.getLoc());
    assert(CurBuf && "Invalid or unspecified location!");
    PrintIncludeStack(getBufferInfo(CurBuf).IncludeLoc, OS);
  }

  Diagnostic.print(nullptr, OS, ShowColors);
}

void SourceMgr::PrintMessage(raw_ostream &OS, SMLoc Loc,
                             SourceMgr::DiagKind Kind,
                             const Twine &Msg, ArrayRef<SMRange> Ranges,
                             ArrayRef<SMFixIt> FixIts, bool ShowColors) const {
  PrintMessage(OS, GetMessage(Loc, Kind, Msg, Ranges, FixIts), ShowColors);
}

void SourceMgr::PrintMessage(SMLoc Loc, SourceMgr::DiagKind Kind,
                             const Twine &Msg, ArrayRef<SMRange> Ranges,
                             ArrayRef<SMFixIt> FixIts, bool ShowColors) const {
  PrintMessage(errs(), Loc, Kind, Msg, Ranges, FixIts, ShowColors);
}

                                                                                
                              
                                                                                

SMDiagnostic::SMDiagnostic(const SourceMgr &sm, SMLoc L, StringRef FN,
                           int Line, int Col, SourceMgr::DiagKind Kind,
                           StringRef Msg, StringRef LineStr,
                           ArrayRef<std::pair<unsigned,unsigned>> Ranges,
                           ArrayRef<SMFixIt> Hints)
  : SM(&sm), Loc(L), Filename(FN), LineNo(Line), ColumnNo(Col), Kind(Kind),
    Message(Msg), LineContents(LineStr), Ranges(Ranges.vec()),
    FixIts(Hints.begin(), Hints.end()) {
  llvh::sort(FixIts);
}

static void buildFixItLine(std::string &CaretLine, std::string &FixItLine,
                           ArrayRef<SMFixIt> FixIts, ArrayRef<char> SourceLine){
  if (FixIts.empty())
    return;

  const char *LineStart = SourceLine.begin();
  const char *LineEnd = SourceLine.end();

  size_t PrevHintEndCol = 0;

  for (ArrayRef<SMFixIt>::iterator I = FixIts.begin(), E = FixIts.end();
       I != E; ++I) {
                                                         
    if (I->getText().find_first_of("\n\r\t") != StringRef::npos)
      continue;

    SMRange R = I->getRange();

                                                                         
    if (R.Start.getPointer() > LineEnd || R.End.getPointer() < LineStart)
      continue;

                                      
                                                           
                                                             
    unsigned FirstCol;
    if (R.Start.getPointer() < LineStart)
      FirstCol = 0;
    else
      FirstCol = R.Start.getPointer() - LineStart;

                                                                           
                                                                   
                                                                           
                  
      
                                                                       
                                                                          
    unsigned HintCol = FirstCol;
    if (HintCol < PrevHintEndCol)
      HintCol = PrevHintEndCol + 1;

                                                                             
                                                                         
                                                           
    assert((size_t)sys::locale::columnWidth(I->getText()) ==
           I->getText().size());

                                                             
    unsigned LastColumnModified = HintCol + I->getText().size();
    if (LastColumnModified > FixItLine.size())
      FixItLine.resize(LastColumnModified, ' ');

    std::copy(I->getText().begin(), I->getText().end(),
              FixItLine.begin() + HintCol);

    PrevHintEndCol = LastColumnModified;

                                                         
                                                             
    unsigned LastCol;
    if (R.End.getPointer() >= LineEnd)
      LastCol = LineEnd - LineStart;
    else
      LastCol = R.End.getPointer() - LineStart;

    std::fill(&CaretLine[FirstCol], &CaretLine[LastCol], '~');
  }
}

static void printSourceLine(raw_ostream &S, StringRef LineContents) {
                                                                              
  for (unsigned i = 0, e = LineContents.size(), OutCol = 0; i != e; ++i) {
    size_t NextTab = LineContents.find('\t', i);
                                                               
    if (NextTab == StringRef::npos) {
      S << LineContents.drop_front(i);
      break;
    }

                                          
    S << LineContents.slice(i, NextTab);
    OutCol += NextTab - i;
    i = NextTab;

                                                                             
    do {
      S << ' ';
      ++OutCol;
    } while ((OutCol % TabStop) != 0);
  }
  S << '\n';
}

static bool isNonASCII(char c) {
  return c & 0x80;
}

void SMDiagnostic::print(const char *ProgName, raw_ostream &S, bool ShowColors,
                         bool ShowKindLabel) const {
                                               
  ShowColors &= S.has_colors();

  if (ShowColors)
    S.changeColor(raw_ostream::SAVEDCOLOR, true);

  if (ProgName && ProgName[0])
    S << ProgName << ": ";

  if (!Filename.empty()) {
    if (Filename == "-")
      S << "<stdin>";
    else
      S << Filename;

    if (LineNo != -1) {
      S << ':' << LineNo;
      if (ColumnNo != -1)
        S << ':' << (ColumnNo+1);
    }
    S << ": ";
  }

  if (ShowKindLabel) {
    switch (Kind) {
    case SourceMgr::DK_Error:
      if (ShowColors)
        S.changeColor(raw_ostream::RED, true);
      S << "error: ";
      break;
    case SourceMgr::DK_Warning:
      if (ShowColors)
        S.changeColor(raw_ostream::MAGENTA, true);
      S << "warning: ";
      break;
    case SourceMgr::DK_Note:
      if (ShowColors)
        S.changeColor(raw_ostream::BLACK, true);
      S << "note: ";
      break;
    case SourceMgr::DK_Remark:
      if (ShowColors)
        S.changeColor(raw_ostream::BLUE, true);
      S << "remark: ";
      break;
    }

    if (ShowColors) {
      S.resetColor();
      S.changeColor(raw_ostream::SAVEDCOLOR, true);
    }
  }

  S << Message << '\n';

  if (ShowColors)
    S.resetColor();

  if (LineNo == -1 || ColumnNo == -1)
    return;

                                                                                
                                                                               
                                                                        
                                                                             
                                                    
  if (find_if(LineContents, isNonASCII) != LineContents.end()) {
    printSourceLine(S, LineContents);
    return;
  }
  size_t NumColumns = LineContents.size();

                                              
  std::string CaretLine(NumColumns+1, ' ');

                       
  for (unsigned r = 0, e = Ranges.size(); r != e; ++r) {
    std::pair<unsigned, unsigned> R = Ranges[r];
    std::fill(&CaretLine[R.first],
              &CaretLine[std::min((size_t)R.second, CaretLine.size())],
              '~');
  }

                     
                                                                             
  std::string FixItInsertionLine;
  buildFixItLine(CaretLine, FixItInsertionLine, FixIts,
                 makeArrayRef(Loc.getPointer() - ColumnNo,
                              LineContents.size()));

                                
  if (unsigned(ColumnNo) <= NumColumns)
    CaretLine[ColumnNo] = '^';
  else
    CaretLine[NumColumns] = '^';

                                                                              
                                                                                
           
  CaretLine.erase(CaretLine.find_last_not_of(' ')+1);

  printSourceLine(S, LineContents);

  if (ShowColors)
    S.changeColor(raw_ostream::GREEN, true);

                                                                
  for (unsigned i = 0, e = CaretLine.size(), OutCol = 0; i != e; ++i) {
    if (i >= LineContents.size() || LineContents[i] != '\t') {
      S << CaretLine[i];
      ++OutCol;
      continue;
    }

                                                                         
    do {
      S << CaretLine[i];
      ++OutCol;
    } while ((OutCol % TabStop) != 0);
  }
  S << '\n';

  if (ShowColors)
    S.resetColor();

                                                                      
  if (FixItInsertionLine.empty())
    return;

  for (size_t i = 0, e = FixItInsertionLine.size(), OutCol = 0; i < e; ++i) {
    if (i >= LineContents.size() || LineContents[i] != '\t') {
      S << FixItInsertionLine[i];
      ++OutCol;
      continue;
    }

                                                                         
    do {
      S << FixItInsertionLine[i];
                                                                                
                                                                           
                                                                            
                                                                           
                                         
      if (FixItInsertionLine[i] != ' ')
        ++i;
      ++OutCol;
    } while (((OutCol % TabStop) != 0) && i != e);
  }
  S << '\n';
}
