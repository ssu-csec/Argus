/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Support/SourceErrorManager.h"
#include "hermes/Support/UTF8.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/Support/raw_ostream.h"

namespace hermes {

static const char sTooManyErrors[] = "too many errors emitted";

SourceErrorManager::ICoordTranslator::~ICoordTranslator() = default;

SourceErrorManager::SourceErrorManager()
    : warningStatuses_((unsigned)Warning::_NumWarnings, true),
      warningsAreErrors_((unsigned)Warning::_NumWarnings, false) {
  sm_.setDiagHandler(SourceErrorManager::printDiagnostic, this);
}

void SourceErrorManager::BufferedMessage::addNote(
    std::vector<MessageData> &bufferedNotes,
    DiagKind dk,
    SMLoc loc,
    SMRange sm,
    std::string &&msg) {
  bufferedNotes.emplace_back(dk, loc, sm, std::move(msg));

  if (!noteCount_)
    firstNote_ = bufferedNotes.size() - 1;
  ++noteCount_;
}

llvh::iterator_range<const SourceErrorManager::MessageData *>
SourceErrorManager::BufferedMessage::notes(
    const std::vector<MessageData> &bufferedNotes) const {
  if (!noteCount_)
    return {nullptr, nullptr};
  return {
      bufferedNotes.data() + firstNote_,
      bufferedNotes.data() + firstNote_ + noteCount_};
}

void SourceErrorManager::enableBuffering() {
  ++bufferingEnabled_;
  assert(bufferingEnabled_ != 0 && "unsigned counter overflow");
}

void SourceErrorManager::disableBuffering() {
  assert(bufferingEnabled_ != 0 && "unsigned counter underflow");

  if (--bufferingEnabled_ != 0)
    return;

                       
  std::sort(
      bufferedMessages_.begin(),
      bufferedMessages_.end(),
      [](const BufferedMessage &a, const BufferedMessage &b) {
                                                                  
        if (a.dk == DK_Error && !a.loc.isValid() && a.msg == sTooManyErrors)
          return false;
        if (b.dk == DK_Error && !b.loc.isValid() && b.msg == sTooManyErrors)
          return true;
        return a.loc.getPointer() < b.loc.getPointer();
      });

                
  for (const auto &bm : bufferedMessages_) {
    doPrintMessage(bm.dk, bm.loc, bm.sm, bm.msg);
    for (const auto &note : bm.notes(bufferedNotes_))
      doPrintMessage(note.dk, note.loc, note.sm, note.msg);
  }

                      
  bufferedMessages_.clear();
  bufferedNotes_.clear();
}

unsigned SourceErrorManager::addNewSourceBuffer(
    std::unique_ptr<llvh::MemoryBuffer> f) {
  unsigned bufId = sm_.AddNewSourceBuffer(std::move(f), SMLoc{});
  assert(
      !isVirtualBufferId(bufId) && "unexpected virtual buf id from SourceMgr");
  return bufId;
}

                                                                        
                                                                            
                        
unsigned SourceErrorManager::addNewVirtualSourceBuffer(
    llvh::StringRef fileName) {
  return indexToVirtualBufferId(virtualBufferNames_.insert(fileName));
}

llvh::StringRef SourceErrorManager::getBufferFileName(unsigned bufId) const {
  if (isVirtualBufferId(bufId))
    return virtualBufferNames_[virtualBufferIdToIndex(bufId)];
  else
    return sm_.getMemoryBuffer(bufId)->getBufferIdentifier();
}

void SourceErrorManager::dumpCoords(
    llvh::raw_ostream &OS,
    const SourceCoords &coords) {
  if (coords.isValid()) {
    OS << getSourceUrl(coords.bufId) << ":" << coords.line << "," << coords.col;
  } else {
    OS << "none:0,0";
  }
}

void SourceErrorManager::dumpCoords(llvh::raw_ostream &OS, SMLoc loc) {
  SourceCoords coords;
  findBufferLineAndLoc(loc, coords);
  dumpCoords(OS, coords);
}

void SourceErrorManager::countAndGenMessage(
    DiagKind dk,
    SMLoc loc,
    SMRange sm,
    const Twine &msg) {
  ++messageCount_[dk];
  doGenMessage(dk, loc, sm, msg);

  if (LLVM_UNLIKELY(dk == DK_Error && messageCount_[DK_Error] == errorLimit_)) {
    errorLimitReached_ = true;
    doGenMessage(DK_Error, {}, {}, sTooManyErrors);
  }
}

void SourceErrorManager::doGenMessage(
    hermes::SourceErrorManager::DiagKind dk,
    llvh::SMLoc loc,
    llvh::SMRange sm,
    llvh::Twine const &msg) {
  if (bufferingEnabled_) {
                                                                            
                                                                             
                                                                 
    if (dk == DK_Note && !bufferedMessages_.empty()) {
      bufferedMessages_.back().addNote(bufferedNotes_, dk, loc, sm, msg.str());
    } else {
      bufferedMessages_.emplace_back(dk, loc, sm, msg.str());
    }
  } else {
    doPrintMessage(dk, loc, sm, msg);
  }
}

void SourceErrorManager::doPrintMessage(
    DiagKind dk,
    SMLoc loc,
    SMRange sm,
    const Twine &msg) {
  sm_.PrintMessage(
      loc,
      static_cast<llvh::SourceMgr::DiagKind>(dk),
      msg,
      sm.isValid() ? llvh::ArrayRef<SMRange>(sm)
                   : llvh::ArrayRef<SMRange>(llvh::None),
      llvh::None,
      outputOptions_.showColors);
}

void SourceErrorManager::message(
    hermes::SourceErrorManager::DiagKind dk,
    llvh::SMLoc loc,
    llvh::SMRange sm,
    llvh::Twine const &msg,
    hermes::Warning w,
    Subsystem subsystem) {
  assert(dk <= DK_Note);
  if (suppressMessages_) {
    if (*suppressMessages_ == Subsystem::Unspecified) {
      return;
    }
    if (subsystem == *suppressMessages_) {
      return;
    }
  }
                                                                 
  if (LLVM_UNLIKELY(errorLimitReached_))
    return;
  if (dk == DK_Warning && !isWarningEnabled(w)) {
    lastMessageSuppressed_ = true;
    return;
  }
                                                                     
  if (dk == DK_Note && lastMessageSuppressed_)
    return;
  lastMessageSuppressed_ = false;

                                              
  if (dk == DK_Warning && isWarningAnError(w)) {
    dk = DK_Error;
  }
  assert(static_cast<unsigned>(dk) < kMessageCountSize && "bounds check");

  if (externalMessageBuffer_) {
    externalMessageBuffer_->addMessage(dk, loc, sm, msg);
    return;
  }

  countAndGenMessage(dk, loc, sm, msg);
}

void SourceErrorManager::message(
    DiagKind dk,
    SMLoc loc,
    SMRange sm,
    const Twine &msg,
    Subsystem subsystem) {
  message(dk, loc, sm, msg, Warning::NoWarning, subsystem);
}

void SourceErrorManager::message(
    DiagKind dk,
    SMRange sm,
    const Twine &msg,
    Subsystem subsystem) {
  message(dk, sm.Start, sm, msg, subsystem);
}

void SourceErrorManager::message(
    DiagKind dk,
    SMLoc loc,
    const Twine &msg,
    Subsystem subsystem) {
  message(dk, loc, SMRange{}, msg, subsystem);
}

auto SourceErrorManager::findBufferAndLine(SMLoc loc) const
    -> llvh::Optional<LineCoord> {
  if (!loc.isValid())
    return llvh::None;

  auto bufId = sm_.FindBufferContainingLoc(loc);
  if (!bufId)
    return llvh::None;

  auto lineRefAndNo = sm_.FindLine(loc, bufId);

  return LineCoord{bufId, lineRefAndNo.second, lineRefAndNo.first};
}

                                                                              
                                      
static inline SMLoc adjustSourceLocation(const char *bufStart, SMLoc loc) {
  const char *ptr = loc.getPointer();
                                                                             
                                                                             
                             
  if (LLVM_UNLIKELY(*ptr == '\r') ||
      LLVM_UNLIKELY(isUTF8ContinuationByte(*ptr))) {
    do {
      if (LLVM_UNLIKELY(ptr == bufStart)) {
                                                                              
                                                          
        break;
      }
      --ptr;
    } while (*ptr == '\r' || isUTF8ContinuationByte(*ptr));
  }
  return SMLoc::getFromPointer(ptr);
}

static bool locInside(llvh::StringRef str, SMLoc loc) {
  const char *ptr = loc.getPointer();
  return ptr >= str.begin() && ptr < str.end();
}

inline void SourceErrorManager::FindLineCache::fillCoords(
    SMLoc loc,
    SourceCoords &result) {
  loc = adjustSourceLocation(lineRef.data(), loc);
  result.bufId = bufferId;
  result.line = lineNo;
  result.col = loc.getPointer() - lineRef.data() + 1;
}

bool SourceErrorManager::findBufferLineAndLoc(SMLoc loc, SourceCoords &result) {
  if (!loc.isValid()) {
    result.bufId = 0;
    return false;
  }

  if (findLineCache_.bufferId) {
                                                                               
                     
    if (locInside(findLineCache_.lineRef, loc)) {
      findLineCache_.fillCoords(loc, result);
      return true;
    }
    if (locInside(findLineCache_.nextLineRef, loc)) {
      ++findLineCache_.lineNo;
      findLineCache_.lineRef = findLineCache_.nextLineRef;
      findLineCache_.nextLineRef =
          sm_.getLineRef(findLineCache_.lineNo + 1, findLineCache_.bufferId);

      findLineCache_.fillCoords(loc, result);
      return true;
    }

    findLineCache_.bufferId = 0;
  }

  auto lineCoord = findBufferAndLine(loc);
  if (!lineCoord) {
    result.bufId = 0;
    return false;
  }

                        
  findLineCache_.bufferId = lineCoord->bufId;
  findLineCache_.lineNo = lineCoord->lineNo;
  findLineCache_.lineRef = lineCoord->lineRef;
  findLineCache_.nextLineRef =
      sm_.getLineRef(findLineCache_.lineNo + 1, lineCoord->bufId);

  findLineCache_.fillCoords(loc, result);
  return true;
}

bool SourceErrorManager::findBufferLineAndLoc(
    llvh::SMLoc loc,
    hermes::SourceErrorManager::SourceCoords &result,
    bool translate) {
  if (!findBufferLineAndLoc(loc, result))
    return false;
  if (translate && translator_)
    translator_->translate(result);
  return true;
}

uint32_t SourceErrorManager::findBufferIdForLoc(SMLoc loc) const {
  return sm_.FindBufferContainingLoc(loc);
}

const llvh::MemoryBuffer *SourceErrorManager::findBufferForLoc(
    SMLoc loc) const {
  uint32_t bufID = findBufferIdForLoc(loc);
  if (bufID == 0) {
    return nullptr;
  }
  return sm_.getMemoryBuffer(bufID);
}

SMLoc SourceErrorManager::findSMLocFromCoords(SourceCoords coords) {
  if (!coords.isValid())
    return {};

                                           
  auto *buffer = getSourceBuffer(coords.bufId);
  if (!buffer)
    return {};

  const char *cur = buffer->getBufferStart();
  const char *end = buffer->getBufferEnd();

                                                 
  unsigned lineNumber = 1;
  const char *lineEnd;
  while ((lineEnd = (const char *)std::memchr(cur, '\n', end - cur)) !=
             nullptr &&
         lineNumber != coords.line) {
    ++lineNumber;
    cur = lineEnd + 1;
  }

                                                                        
  if (!lineEnd)
    lineEnd = end;

                                                                           
                         
  if (lineNumber != coords.line)
    return {};

                                                                      
  if (cur != lineEnd && *cur == '\r')
    ++cur;
  if (cur != lineEnd && *(lineEnd - 1) == '\r')
    --lineEnd;

                                 
  if (cur == lineEnd) {
                                                  
    if (coords.col <= 1)
      return SMLoc::getFromPointer(cur);
    return {};
  }

                                 
  bool utf8 = false;
  for (const char *p = cur; p != lineEnd; ++p) {
    if (LLVM_UNLIKELY(*p & 0x80)) {
      utf8 = true;
      break;
    }
  }

                                         
  if (LLVM_LIKELY(!utf8)) {
                              
    if (coords.col > (size_t)(lineEnd - cur))
      return {};
    return SMLoc::getFromPointer(cur + coords.col - 1);
  }

                                                                    
  unsigned column = 0;
  for (; cur != lineEnd; ++cur) {
                               
    if (isUTF8ContinuationByte(*cur))
      continue;
    if (++column == coords.col)
      return SMLoc::getFromPointer(cur);
  }

  return {};
}

                                                                               
                  
std::pair<std::string, std::string> SourceErrorManager::buildSourceAndCaretLine(
    const llvh::SMDiagnostic &diag,
    SourceErrorOutputOptions opts) {
                                     
                                                                   
                                            
                                            
  std::vector<uint32_t> narrowByteToColumn;
  std::u32string sourceLine;
  std::string narrowSourceLine = diag.getLineContents();
  const char *cursor = narrowSourceLine.c_str();
  while (*cursor) {
    const char *prev = cursor;
    sourceLine.push_back(decodeUTF8<true>(cursor, [](const llvh::Twine &) {}));
    while (prev++ < cursor) {
      narrowByteToColumn.push_back(sourceLine.size() - 1);
    }
  }
  const size_t numColumns = sourceLine.size();

                    
  auto widenColumn = [&](unsigned narrowColumn) -> unsigned {
    return narrowColumn < narrowByteToColumn.size()
        ? narrowByteToColumn[narrowColumn]
        : numColumns;
  };

                                                    
                                         
  assert(diag.getColumnNo() >= 0);
  const size_t columnNo = widenColumn(diag.getColumnNo());
  std::vector<std::pair<unsigned, unsigned>> ranges;
  for (const auto &r : diag.getRanges()) {
    ranges.emplace_back(widenColumn(r.first), widenColumn(r.second));
  }

                                              
  std::string caretLine(numColumns + 1, ' ');
  for (const auto &range : ranges) {
    if (range.first < caretLine.size()) {
      std::fill(
          &caretLine[range.first],
          &caretLine[std::min((size_t)range.second, caretLine.size())],
          '~');
    }
  }
  caretLine[std::min(size_t(columnNo), numColumns)] = '^';
  caretLine.erase(caretLine.find_last_not_of(' ') + 1);

                                                            
  const size_t tabStop = SourceErrorOutputOptions::TabStop;
  for (size_t pos = sourceLine.find('\t'); pos < sourceLine.size();
       pos = sourceLine.find('\t', pos)) {
    size_t expandCount = tabStop - (pos % tabStop);
    sourceLine.replace(pos, 1, expandCount, ' ');
    if (pos < caretLine.size()) {
                                                                               
                    
      caretLine.replace(pos, 1, expandCount, caretLine[pos]);
    }
    pos += expandCount;
  }

                                                     
                                                            
                                                                     
  int focusStart = columnNo;
  int focusLength = 1;
  for (const auto &r : ranges) {
    if (r.first <= size_t(columnNo) && size_t(columnNo) < r.second) {
      focusStart = r.first;
      focusLength = r.second - r.first;
      break;
    }
  }
  size_t desiredLineLength = std::max(
      opts.preferredMaxErrorWidth,
      focusLength + SourceErrorOutputOptions::MinimumSourceContext);
  if (sourceLine.size() > desiredLineLength) {
    int focusCenter = focusStart + focusLength / 2;
    int leftTrimAmount = focusCenter - desiredLineLength / 2;
    if (leftTrimAmount > 0) {
      caretLine.erase(0, leftTrimAmount);
      sourceLine.erase(0, leftTrimAmount);
      std::fill(sourceLine.begin(), sourceLine.begin() + 3, '.');
    }
    if (sourceLine.size() > desiredLineLength) {
                          
      caretLine.erase(std::min(caretLine.size(), desiredLineLength));
      sourceLine.erase(desiredLineLength);
      std::fill(sourceLine.end() - 3, sourceLine.end(), '.');
    }
  }

                                      
  narrowSourceLine.clear();
  for (uint32_t c : sourceLine) {
    char buffer[UTF8CodepointMaxBytes] = {};
    char *buffCursor = buffer;
    encodeUTF8(buffCursor, c);
    narrowSourceLine.append(buffer, buffCursor);
  }
  return {std::move(narrowSourceLine), std::move(caretLine)};
}

void SourceErrorManager::printDiagnostic(
    const llvh::SMDiagnostic &diag,
    void *ctx) {
  using llvh::raw_ostream;
  const SourceErrorManager *self = static_cast<SourceErrorManager *>(ctx);
  const SourceErrorOutputOptions opts = self->outputOptions_;
  auto &S = llvh::errs();

  llvh::StringRef filename = diag.getFilename();
  int lineNo = diag.getLineNo();
  int columnNo = diag.getColumnNo();

                                                  
  auto changeColor = [&](raw_ostream::Colors color) {
    if (opts.showColors)
      S.changeColor(color, true);
  };

  auto resetColor = [&]() {
    if (opts.showColors)
      S.resetColor();
  };

  changeColor(raw_ostream::SAVEDCOLOR);
  if (!filename.empty()) {
    S << (filename == "-" ? "<stdin>" : filename);
    if (lineNo != -1) {
      S << ':' << lineNo;
      if (columnNo != -1)
        S << ':' << (columnNo + 1);
    }
    S << ": ";
  }

  switch (diag.getKind()) {
    case llvh::SourceMgr::DK_Error:
      changeColor(raw_ostream::RED);
      S << "error: ";
      break;
    case llvh::SourceMgr::DK_Warning:
      changeColor(raw_ostream::MAGENTA);
      S << "warning: ";
      break;
    case llvh::SourceMgr::DK_Note:
      changeColor(raw_ostream::BLACK);
      S << "note: ";
      break;
    case llvh::SourceMgr::DK_Remark:
      changeColor(raw_ostream::BLACK);
      S << "remark: ";
      break;
  }

  resetColor();
  changeColor(raw_ostream::SAVEDCOLOR);
  S << diag.getMessage() << '\n';
  resetColor();

  if (lineNo == -1 || columnNo == -1)
    return;

  std::string sourceLine;
  std::string caretLine;
  std::tie(sourceLine, caretLine) = buildSourceAndCaretLine(diag, opts);

                                                               
                                                      
                                                                               
                
  bool showCaret = isAllASCII(sourceLine.begin(), sourceLine.end());

  S << sourceLine << '\n';
  if (showCaret) {
    changeColor(raw_ostream::GREEN);
    S << caretLine << '\n';
    resetColor();
  }
}

SMLoc SourceErrorManager::convertEndToLocation(SMRange range) {
                                                      
  if (range.Start == range.End)
    return range.Start;

  return SMLoc::getFromPointer(range.End.getPointer() - 1);
}

}                    
