/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SOURCEERRORMANAGER_H
#define HERMES_SUPPORT_SOURCEERRORMANAGER_H

#include "hermes/Support/OptValue.h"
#include "hermes/Support/StringSetVector.h"
#include "hermes/Support/Warning.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/SmallBitVector.h"
#include "llvh/Support/SourceMgr.h"

#include <cassert>
#include <string>

namespace hermes {

using llvh::DenseSet;
using llvh::SMLoc;
using llvh::SMRange;
using llvh::Twine;

class CollectMessagesRAII;

                                 
struct SourceErrorOutputOptions {
                                                  
  bool showColors = true;

                                             
                                                                              
                  
  size_t preferredMaxErrorWidth = UnlimitedWidth;

                                                  
  static constexpr size_t UnlimitedWidth = std::numeric_limits<size_t>::max();

                    
  static constexpr size_t TabStop = 8;

                                                                              
                                                              
  static constexpr size_t MinimumSourceContext = 16;
};

                                                                        
enum class Subsystem {
                                  
                                                                          
                                                                          
  Unspecified,
                                                           
  Lexer,
                                                                        
  Parser,
};

                                                                                
           
class SourceErrorManager {
 public:
  enum DiagKind {
    DK_Error = llvh::SourceMgr::DK_Error,
    DK_Warning = llvh::SourceMgr::DK_Warning,
    DK_Note = llvh::SourceMgr::DK_Note,
  };

                                                                            
                                                                               
  class SourceCoords {
   public:
    unsigned bufId = 0;
    unsigned line = 0;
    unsigned col = 0;

    SourceCoords() = default;
    SourceCoords(unsigned bufId, unsigned line, unsigned col)
        : bufId(bufId), line(line), col(col) {}

    bool isValid() const {
      return bufId != 0;
    }

    bool isSameSourceLineAs(const SourceCoords &c) const {
      return isValid() && bufId == c.bufId && line == c.line;
    }

    bool less(const SourceCoords &o) const {
      if (bufId != o.bufId)
        return bufId < o.bufId;
      if (line != o.line)
        return line < o.line;
      return col < o.col;
    }
  };

                                                                            
                                                                               
  struct LineCoord {
                          
    unsigned bufId = 0;
                            
    unsigned lineNo = 0;
                                                                      
    llvh::StringRef lineRef;
  };

  struct ICoordTranslator {
    virtual ~ICoordTranslator() = 0;
    virtual void translate(SourceCoords &coords) = 0;
  };

  using DiagHandlerTy = llvh::SourceMgr::DiagHandlerTy;

 private:
  llvh::SourceMgr sm_{};
  SourceErrorOutputOptions outputOptions_;
  std::shared_ptr<ICoordTranslator> translator_{};

                                                                                
                                                                              
                                                            
                                                                              
                                                                            
                                                                             
                                                                           
                
  struct FindLineCache {
                                                    
    unsigned bufferId = 0;
                            
    unsigned lineNo = 0;
                            
    llvh::StringRef lineRef{};
                           
    llvh::StringRef nextLineRef{};

                                                                               
                  
    void fillCoords(SMLoc loc, SourceCoords &result);
  } findLineCache_;

                                                     
  static constexpr unsigned kVirtualBufIdTag = 1u
      << (sizeof(unsigned) * CHAR_BIT - 1);

                                   
  hermes::StringSetVector virtualBufferNames_{};

  static constexpr unsigned kMessageCountSize = 4;

  unsigned messageCount_[kMessageCountSize]{0, 0, 0, 0};

                                                
  unsigned errorLimit_ = UINT_MAX;

                                                        
  bool errorLimitReached_ = false;

                                                                  
                                                                             
                                       
  llvh::SmallBitVector warningStatuses_;

                                                                              
                                                                              
                                                                                
             
  llvh::SmallBitVector warningsAreErrors_;

                                                            
                                                                      
  OptValue<Subsystem> suppressMessages_{llvh::None};

                                                                           
                                                
  bool lastMessageSuppressed_{false};

                                          
                                                                     
  llvh::DenseMap<unsigned, std::string> sourceMappingUrls_{};

                                                 
                                                                            
  llvh::DenseMap<unsigned, std::string> sourceUrls_{};

                                                                               
                                                                 
  unsigned bufferingEnabled_{0};

                                
  class MessageData {
   public:
    DiagKind dk;
    SMLoc loc;
    SMRange sm;
    std::string msg;

    MessageData(DiagKind dk, SMLoc loc, SMRange sm, std::string &&msg)
        : dk(dk), loc(loc), sm(sm), msg(std::move(msg)) {}
  };

                                                                     
  class BufferedMessage : public MessageData {
   public:
    using MessageData::MessageData;

                                        
    void addNote(
        std::vector<MessageData> &bufferedNotes,
        DiagKind dk,
        SMLoc loc,
        SMRange sm,
        std::string &&msg);

    llvh::iterator_range<const MessageData *> notes(
        const std::vector<MessageData> &bufferedNotes) const;

   private:
                                                     
    unsigned noteCount_ = 0;
                                                                           
    unsigned firstNote_;
  };

                                                                              
                                                 
  CollectMessagesRAII *externalMessageBuffer_{nullptr};

                                                                           
  std::vector<BufferedMessage> bufferedMessages_{};

                                                      
  std::vector<MessageData> bufferedNotes_{};

                                                                             
  static void printDiagnostic(const llvh::SMDiagnostic &, void *ctx);

  friend class SaveAndSuppressMessages;
  friend class SaveAndBufferMessages;
  friend class CollectMessagesRAII;

  bool isWarningEnabled(Warning warning) {
    return warningStatuses_.test((unsigned)warning);
  }

 public:
  SourceErrorManager();

                                                                              
                                                                       
                                                                        
                                                                              
                              
  void enableBuffering();

                                                                           
                                                                              
                              
  void disableBuffering();

                                                                             
                                           
  void setErrorLimit(unsigned errorLimit) {
    errorLimit_ = errorLimit == 0 ? UINT_MAX : errorLimit;
  }
                                                       
  unsigned int getErrorLimit() const {
    return errorLimit_ == UINT_MAX ? 0 : errorLimit_;
  }

                                                       
  bool isErrorLimitReached() const {
    return errorLimitReached_;
  }

                                                                       
  void clearErrorLimitReached() {
    messageCount_[DK_Error] = 0;
    errorLimitReached_ = false;
  }

                                                                                
                   
  bool isWarningAnError(Warning warning) const {
    return warningsAreErrors_.test((unsigned)warning);
  }

                                                                            
                                    
  void setWarningIsError(Warning warning, bool warningIsError) {
    warningsAreErrors_[(unsigned)warning] = warningIsError;
  }

                                                                              
                                   
  void setWarningsAreErrors(bool warningsAreErrors) {
    if (warningsAreErrors) {
      warningsAreErrors_.set();
    } else {
      warningsAreErrors_.reset();
    }
  }

  void disableAllWarnings() {
    warningStatuses_.reset();
  }

  void setWarningStatus(Warning warning, bool enabled) {
    warningStatuses_[(unsigned)warning] = enabled;
  }

  SourceErrorOutputOptions getOutputOptions() const {
    return outputOptions_;
  }

  void setOutputOptions(SourceErrorOutputOptions opts) {
    outputOptions_ = opts;
  }

                                                                           
                                                                   
  void setDiagHandler(DiagHandlerTy DH, void *ctx = nullptr) {
    sm_.setDiagHandler(DH, ctx);
  }

                                       
  DiagHandlerTy getDiagHandler() const {
    return sm_.getDiagHandler();
  }

                                               
  void *getDiagContext() const {
    return sm_.getDiagContext();
  }

  const std::shared_ptr<ICoordTranslator> &getTranslator() const {
    return translator_;
  }
  void setTranslator(const std::shared_ptr<ICoordTranslator> &translator) {
    translator_ = translator;
  }

                                                                             
                        
                                               
  unsigned addNewSourceBuffer(std::unique_ptr<llvh::MemoryBuffer> f);

                                                                          
                                                                              
                                                                            
  unsigned addNewVirtualSourceBuffer(llvh::StringRef fileName);

                                                        
                                  
  inline bool isVirtualBufferId(unsigned bufId) const {
    return (bufId & kVirtualBufIdTag) != 0;
  }

                                                                                
  llvh::StringRef getBufferFileName(unsigned bufId) const;

  const llvh::MemoryBuffer *getSourceBuffer(unsigned bufId) const {
    assert(!isVirtualBufferId(bufId) && "virtual buffers cannot be accessed");
    return sm_.getMemoryBuffer(bufId);
  }

                                                         
                                           
  void setSourceMappingUrl(unsigned bufId, llvh::StringRef url) {
    if (!url.empty())
      sourceMappingUrls_[bufId] = url;
    else
      sourceMappingUrls_.erase(bufId);
  }

                                                   
                                                         
  llvh::StringRef getSourceMappingUrl(unsigned bufId) const {
    const auto it = sourceMappingUrls_.find(bufId);
    if (it == sourceMappingUrls_.end()) {
      return "";
    }
    return it->second;
  }

                                                                
                                           
  void setSourceUrl(unsigned bufId, llvh::StringRef url) {
    if (!url.empty())
      sourceUrls_[bufId] = url;
    else
      sourceUrls_.erase(bufId);
  }

                                                                                
                                                       
  llvh::StringRef getSourceUrl(unsigned bufId) const {
    const auto it = sourceUrls_.find(bufId);
    if (it != sourceUrls_.end()) {
      return it->second;
    }
    return getBufferFileName(bufId);
  }

                                                         
  uint32_t findBufferIdForLoc(SMLoc loc) const;

                                                                   
                                                                       
  llvh::Optional<LineCoord> findBufferAndLine(SMLoc loc) const;

                                                         
                                                                       
                            
  llvh::StringRef getLineRef(unsigned bufId, unsigned line) const {
    return sm_.getLineRef(line, bufId);
  }

                                                                          
                                                                         
                                                   
  bool findBufferLineAndLoc(SMLoc loc, SourceCoords &result);

                                                                          
                                                                   
                   
                                                                         
                                                   
  bool findBufferLineAndLoc(SMLoc loc, SourceCoords &result, bool translate);

                                                                
                                                 
  const llvh::MemoryBuffer *findBufferForLoc(SMLoc loc) const;

                                                                      
  SMLoc findSMLocFromCoords(SourceCoords coords);

                                                                           
                          
  static std::pair<std::string, std::string> buildSourceAndCaretLine(
      const llvh::SMDiagnostic &diag,
      SourceErrorOutputOptions opts);

                                                                               
  void dumpCoords(llvh::raw_ostream &OS, const SourceCoords &coords);

                                                                                
           
  void dumpCoords(llvh::raw_ostream &OS, SMLoc loc);

  void message(
      DiagKind dk,
      SMLoc loc,
      SMRange sm,
      const Twine &msg,
      Warning w,
      Subsystem subsystem);
  void message(
      DiagKind dk,
      SMLoc loc,
      SMRange sm,
      const Twine &msg,
      Subsystem subsystem);
  void message(DiagKind dk, SMRange sm, const Twine &msg, Subsystem subsystem);
  void message(DiagKind dk, SMLoc loc, const Twine &msg, Subsystem subsystem);

  void error(
      SMLoc loc,
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Error, loc, rng, msg, subsystem);
  }
  void warning(
      SMLoc loc,
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    warning(Warning::Misc, loc, rng, msg, subsystem);
  }
  void warning(
      Warning w,
      SMLoc loc,
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Warning, loc, rng, msg, w, subsystem);
  }
  void note(
      SMLoc loc,
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Note, loc, rng, msg, subsystem);
  }

  void error(
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Error, rng, msg, subsystem);
  }
  void warning(
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    warning(Warning::Misc, rng, msg, subsystem);
  }
  void warning(
      Warning w,
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Warning, rng.Start, rng, msg, w, subsystem);
  }
  void note(
      SMRange rng,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Note, rng, msg, subsystem);
  }

  void error(
      SMLoc loc,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Error, loc, msg, subsystem);
  }
  void warning(
      SMLoc loc,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    warning(Warning::Misc, loc, msg, subsystem);
  }
  void warning(
      Warning w,
      SMLoc loc,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Warning, loc, SMRange{}, msg, w, subsystem);
  }
  void note(
      SMLoc loc,
      const llvh::Twine &msg,
      Subsystem subsystem = Subsystem::Unspecified) {
    message(DK_Note, loc, msg, subsystem);
  }

  unsigned getMessageCount(DiagKind dk) const {
    assert(dk <= DK_Note);
    return messageCount_[dk];
  }

  unsigned getErrorCount() const {
    return getMessageCount(DK_Error);
  }
  unsigned getWarningCount() const {
    return getMessageCount(DK_Warning);
  }
  unsigned getNoteCount() const {
    return getMessageCount(DK_Note);
  }

                                                                        
  static SMRange combineIntoRange(SMLoc a, SMLoc b) {
    if (a.getPointer() < b.getPointer())
      return SMRange(a, SMLoc::getFromPointer(b.getPointer() + 1));
    else
      return SMRange(b, SMLoc::getFromPointer(a.getPointer() + 1));
  }

                                                                        
                                                
  static SMLoc convertEndToLocation(SMRange range);

                                                                          
                                
  class SaveAndSuppressMessages {
    SourceErrorManager *const sm_;
    OptValue<Subsystem> messagesSuppressed_;

   public:
    SaveAndSuppressMessages(
        SourceErrorManager *sm,
        Subsystem subsystem = Subsystem::Unspecified)
        : sm_(sm), messagesSuppressed_(sm->suppressMessages_) {
      sm->suppressMessages_ = subsystem;
    }
    ~SaveAndSuppressMessages() {
      sm_->suppressMessages_ = messagesSuppressed_;
    }
  };

                                                                        
                               
  class SaveAndBufferMessages {
    SourceErrorManager *const sm_;

   public:
    SaveAndBufferMessages(SourceErrorManager *sm) : sm_(sm) {
      sm->enableBuffering();
    }
    ~SaveAndBufferMessages() {
      sm_->disableBuffering();
    }
  };

 private:
                                                                           
  void countAndGenMessage(DiagKind dk, SMLoc loc, SMRange sm, const Twine &msg);

                                             
  void doGenMessage(DiagKind dk, SMLoc loc, SMRange sm, const Twine &msg);

                                                                               
  void doPrintMessage(DiagKind dk, SMLoc loc, SMRange sm, const Twine &msg);

                                              
  unsigned virtualBufferIdToIndex(unsigned bufId) const {
    assert(isVirtualBufferId(bufId) && "bufId is not virtual");
    return bufId & ~kVirtualBufIdTag;
  }

                                              
  unsigned indexToVirtualBufferId(unsigned index) const {
    return index | kVirtualBufIdTag;
  }
};

                                                                      
                                                                   
                                                                              
                                               
class CollectMessagesRAII {
  SourceErrorManager *const sm_;
  CollectMessagesRAII *oldExternalMessageBuffer_;

                                                           
  bool discardMessages_;

  class StoredMessage {
   public:
    SourceErrorManager::DiagKind dk;
    SMLoc loc;
    SMRange sm;
    std::string msg;

    StoredMessage(
        SourceErrorManager::DiagKind dk,
        SMLoc loc,
        SMRange sm,
        Twine const &msg)
        : dk(dk), loc(loc), sm(sm), msg(msg.str()) {}
  };

  std::vector<StoredMessage> storage_{};

 public:
  CollectMessagesRAII(SourceErrorManager *sm, bool discardMessages)
      : sm_(sm), discardMessages_(discardMessages) {
    sm->enableBuffering();
    oldExternalMessageBuffer_ = sm->externalMessageBuffer_;
    sm->externalMessageBuffer_ = this;
  }

  ~CollectMessagesRAII() {
    if (!discardMessages_) {
      for (StoredMessage &msg : storage_) {
        sm_->countAndGenMessage(msg.dk, msg.loc, msg.sm, std::move(msg.msg));
      }
    }
    sm_->disableBuffering();
    sm_->externalMessageBuffer_ = oldExternalMessageBuffer_;
  }

  void addMessage(
      SourceErrorManager::DiagKind dk,
      SMLoc loc,
      SMRange sm,
      Twine const &msg) {
    storage_.emplace_back(dk, loc, sm, msg);
  }

  void setDiscardMessages(bool discardMessages) {
    discardMessages_ = discardMessages;
  }
};

}                    

#endif                                       
