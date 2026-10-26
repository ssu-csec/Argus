/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

  
                                                                               
                                                                         
                                                                          
                                                                              
                                                                       
                          
   

#include "hermes/Parser/FlowHelpers.h"
#include "hermes/Parser/JSParser.h"
#include "hermes/Support/SimpleDiagHandler.h"
#include "llvh/ADT/StringRef.h"

                                                                            
#if defined(__GNUC__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#endif

using namespace hermes;
using namespace hermes::ESTree;

                                                                               
                                                                               
                   
                                                                              
                             
namespace {
template <class T>
struct ReturnType {
  using Type = T;
  static inline Type get(T x) {
    return x;
  }
};

template <>
struct ReturnType<NodeList> {
  using Type = const NodeList *;
  static inline Type get(const NodeList &x) {
    return &x;
  }
};
}             

#define ESTREE_FIRST(NAME, ...)
#define ESTREE_NODE_0_ARGS(NAME, ...)

                                        

#define ESTREE_NODE_1_ARGS(NAME, BASE, ARG0TY, ARG0NM, ARG0OPT)     \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }

#define ESTREE_NODE_2_ARGS(                                         \
    NAME, BASE, ARG0TY, ARG0NM, ARG0OPT, ARG1TY, ARG1NM, ARG1OPT)   \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }

#define ESTREE_NODE_3_ARGS(                                         \
    NAME,                                                           \
    BASE,                                                           \
    ARG0TY,                                                         \
    ARG0NM,                                                         \
    ARG0OPT,                                                        \
    ARG1TY,                                                         \
    ARG1NM,                                                         \
    ARG1OPT,                                                        \
    ARG2TY,                                                         \
    ARG2NM,                                                         \
    ARG2OPT)                                                        \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG2TY>::Type hermes_get_##NAME##_##ARG2NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG2TY>::get(node->_##ARG2NM);                \
  }

#define ESTREE_NODE_4_ARGS(                                         \
    NAME,                                                           \
    BASE,                                                           \
    ARG0TY,                                                         \
    ARG0NM,                                                         \
    ARG0OPT,                                                        \
    ARG1TY,                                                         \
    ARG1NM,                                                         \
    ARG1OPT,                                                        \
    ARG2TY,                                                         \
    ARG2NM,                                                         \
    ARG2OPT,                                                        \
    ARG3TY,                                                         \
    ARG3NM,                                                         \
    ARG3OPT)                                                        \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG2TY>::Type hermes_get_##NAME##_##ARG2NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG2TY>::get(node->_##ARG2NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG3TY>::Type hermes_get_##NAME##_##ARG3NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG3TY>::get(node->_##ARG3NM);                \
  }

#define ESTREE_NODE_5_ARGS(                                         \
    NAME,                                                           \
    BASE,                                                           \
    ARG0TY,                                                         \
    ARG0NM,                                                         \
    ARG0OPT,                                                        \
    ARG1TY,                                                         \
    ARG1NM,                                                         \
    ARG1OPT,                                                        \
    ARG2TY,                                                         \
    ARG2NM,                                                         \
    ARG2OPT,                                                        \
    ARG3TY,                                                         \
    ARG3NM,                                                         \
    ARG3OPT,                                                        \
    ARG4TY,                                                         \
    ARG4NM,                                                         \
    ARG4OPT)                                                        \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG2TY>::Type hermes_get_##NAME##_##ARG2NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG2TY>::get(node->_##ARG2NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG3TY>::Type hermes_get_##NAME##_##ARG3NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG3TY>::get(node->_##ARG3NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG4TY>::Type hermes_get_##NAME##_##ARG4NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG4TY>::get(node->_##ARG4NM);                \
  }

#define ESTREE_NODE_6_ARGS(                                         \
    NAME,                                                           \
    BASE,                                                           \
    ARG0TY,                                                         \
    ARG0NM,                                                         \
    ARG0OPT,                                                        \
    ARG1TY,                                                         \
    ARG1NM,                                                         \
    ARG1OPT,                                                        \
    ARG2TY,                                                         \
    ARG2NM,                                                         \
    ARG2OPT,                                                        \
    ARG3TY,                                                         \
    ARG3NM,                                                         \
    ARG3OPT,                                                        \
    ARG4TY,                                                         \
    ARG4NM,                                                         \
    ARG4OPT,                                                        \
    ARG5TY,                                                         \
    ARG5NM,                                                         \
    ARG5OPT)                                                        \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG2TY>::Type hermes_get_##NAME##_##ARG2NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG2TY>::get(node->_##ARG2NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG3TY>::Type hermes_get_##NAME##_##ARG3NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG3TY>::get(node->_##ARG3NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG4TY>::Type hermes_get_##NAME##_##ARG4NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG4TY>::get(node->_##ARG4NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG5TY>::Type hermes_get_##NAME##_##ARG5NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG5TY>::get(node->_##ARG5NM);                \
  }

#define ESTREE_NODE_7_ARGS(                                         \
    NAME,                                                           \
    BASE,                                                           \
    ARG0TY,                                                         \
    ARG0NM,                                                         \
    ARG0OPT,                                                        \
    ARG1TY,                                                         \
    ARG1NM,                                                         \
    ARG1OPT,                                                        \
    ARG2TY,                                                         \
    ARG2NM,                                                         \
    ARG2OPT,                                                        \
    ARG3TY,                                                         \
    ARG3NM,                                                         \
    ARG3OPT,                                                        \
    ARG4TY,                                                         \
    ARG4NM,                                                         \
    ARG4OPT,                                                        \
    ARG5TY,                                                         \
    ARG5NM,                                                         \
    ARG5OPT,                                                        \
    ARG6TY,                                                         \
    ARG6NM,                                                         \
    ARG6OPT)                                                        \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG2TY>::Type hermes_get_##NAME##_##ARG2NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG2TY>::get(node->_##ARG2NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG3TY>::Type hermes_get_##NAME##_##ARG3NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG3TY>::get(node->_##ARG3NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG4TY>::Type hermes_get_##NAME##_##ARG4NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG4TY>::get(node->_##ARG4NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG5TY>::Type hermes_get_##NAME##_##ARG5NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG5TY>::get(node->_##ARG5NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG6TY>::Type hermes_get_##NAME##_##ARG6NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG6TY>::get(node->_##ARG6NM);                \
  }

#define ESTREE_NODE_8_ARGS(                                         \
    NAME,                                                           \
    BASE,                                                           \
    ARG0TY,                                                         \
    ARG0NM,                                                         \
    ARG0OPT,                                                        \
    ARG1TY,                                                         \
    ARG1NM,                                                         \
    ARG1OPT,                                                        \
    ARG2TY,                                                         \
    ARG2NM,                                                         \
    ARG2OPT,                                                        \
    ARG3TY,                                                         \
    ARG3NM,                                                         \
    ARG3OPT,                                                        \
    ARG4TY,                                                         \
    ARG4NM,                                                         \
    ARG4OPT,                                                        \
    ARG5TY,                                                         \
    ARG5NM,                                                         \
    ARG5OPT,                                                        \
    ARG6TY,                                                         \
    ARG6NM,                                                         \
    ARG6OPT,                                                        \
    ARG7TY,                                                         \
    ARG7NM,                                                         \
    ARG7OPT)                                                        \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG2TY>::Type hermes_get_##NAME##_##ARG2NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG2TY>::get(node->_##ARG2NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG3TY>::Type hermes_get_##NAME##_##ARG3NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG3TY>::get(node->_##ARG3NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG4TY>::Type hermes_get_##NAME##_##ARG4NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG4TY>::get(node->_##ARG4NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG5TY>::Type hermes_get_##NAME##_##ARG5NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG5TY>::get(node->_##ARG5NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG6TY>::Type hermes_get_##NAME##_##ARG6NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG6TY>::get(node->_##ARG6NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG7TY>::Type hermes_get_##NAME##_##ARG7NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG7TY>::get(node->_##ARG7NM);                \
  }

#define ESTREE_NODE_9_ARGS(                                         \
    NAME,                                                           \
    BASE,                                                           \
    ARG0TY,                                                         \
    ARG0NM,                                                         \
    ARG0OPT,                                                        \
    ARG1TY,                                                         \
    ARG1NM,                                                         \
    ARG1OPT,                                                        \
    ARG2TY,                                                         \
    ARG2NM,                                                         \
    ARG2OPT,                                                        \
    ARG3TY,                                                         \
    ARG3NM,                                                         \
    ARG3OPT,                                                        \
    ARG4TY,                                                         \
    ARG4NM,                                                         \
    ARG4OPT,                                                        \
    ARG5TY,                                                         \
    ARG5NM,                                                         \
    ARG5OPT,                                                        \
    ARG6TY,                                                         \
    ARG6NM,                                                         \
    ARG6OPT,                                                        \
    ARG7TY,                                                         \
    ARG7NM,                                                         \
    ARG7OPT,                                                        \
    ARG8TY,                                                         \
    ARG8NM,                                                         \
    ARG8OPT)                                                        \
  extern "C" ReturnType<ARG0TY>::Type hermes_get_##NAME##_##ARG0NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG0TY>::get(node->_##ARG0NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG1TY>::Type hermes_get_##NAME##_##ARG1NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG1TY>::get(node->_##ARG1NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG2TY>::Type hermes_get_##NAME##_##ARG2NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG2TY>::get(node->_##ARG2NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG3TY>::Type hermes_get_##NAME##_##ARG3NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG3TY>::get(node->_##ARG3NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG4TY>::Type hermes_get_##NAME##_##ARG4NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG4TY>::get(node->_##ARG4NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG5TY>::Type hermes_get_##NAME##_##ARG5NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG5TY>::get(node->_##ARG5NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG6TY>::Type hermes_get_##NAME##_##ARG6NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG6TY>::get(node->_##ARG6NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG7TY>::Type hermes_get_##NAME##_##ARG7NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG7TY>::get(node->_##ARG7NM);                \
  }                                                                 \
  extern "C" ReturnType<ARG8TY>::Type hermes_get_##NAME##_##ARG8NM( \
      const NAME##Node *node) {                                     \
    return ReturnType<ARG8TY>::get(node->_##ARG8NM);                \
  }

#include "hermes/AST/ESTree.def"

namespace {

enum class ParserDialect : uint8_t {
                  
  JavaScript,
                                 
  Flow,
                                                                              
                                                                               
                 
     
                                                                          
                                                                               
                                                    
  FlowUnambiguous,
                                                                      
                                                                         
                                                             
  FlowDetect,
                       
  TypeScript,
};

                                                 
struct ParserFlags {
                                   
  bool strictMode = false;
                         
  bool enableJSX = false;
                      
  ParserDialect dialect = ParserDialect::JavaScript;
                                                     
  bool storeDocBlock = false;
                        
  bool storeComments = false;
};

enum class DiagKind : uint32_t {
  Error,
  Warning,
  Remark,
  Note,
};

DiagKind toDiagKind(llvh::SourceMgr::DiagKind k) {
  switch (k) {
    default:
      assert(false && "Invalid DiagKind");
      abort();
    case llvh::SourceMgr::DK_Error:
      return DiagKind::Error;
    case llvh::SourceMgr::DK_Warning:
      return DiagKind::Warning;
    case llvh::SourceMgr::DK_Remark:
      return DiagKind::Remark;
    case llvh::SourceMgr::DK_Note:
      return DiagKind::Note;
  }
}

struct DataRef {
  const void *data;
  size_t length;
};

template <typename T>
inline DataRef toDataRef(const T &ref) {
  return {ref.data(), ref.size()};
}

                                                                            
                                         
struct Coord {
              
  unsigned line = 0;
                                        
  unsigned offset = 0;

  Coord() = default;
  Coord(int lineNo, int offset) : line(lineNo), offset(offset) {}
};

                                                                            
                                                                 
struct LineCoord {
                          
  unsigned lineNo = 0;
                                                                  
  DataRef lineRef;
};

                                                                     
struct DiagMessage {
               
  SMLoc loc{};
                        
  Coord coord{};
                           
  DiagKind diagKind = DiagKind::Error;
                    
  llvh::StringRef message{};
                                 
  llvh::StringRef lineContents{};

  DiagMessage() = default;

  DiagMessage(const llvh::SMDiagnostic &diag)
      : loc(diag.getLoc()),
        coord(diag.getLineNo(), diag.getColumnNo()),
        diagKind(toDiagKind(diag.getKind())),
        message(diag.getMessage()),
        lineContents(diag.getLineContents()) {}
};

enum class MagicCommentKind : uint32_t {
  SourceUrl = 0,
  SourceMappingUrl = 1,
};

                                                 
struct ParserContext {
                                                        
  Context context_{};
                                                        
  unsigned bufId_ = ~0u;
                                                                            
                  
  std::deque<llvh::SMDiagnostic> ourMessages_{};
                                                
  std::vector<DiagMessage> convertedMessages_{};

                               
  llvh::Optional<size_t> firstError_;
          
  ESTree::ProgramNode *ast_ = nullptr;

                                       
  std::string docBlock_{};

              
  std::vector<parser::StoredComment> comments_{};

  explicit ParserContext() {
    context_.getSourceErrorManager().setDiagHandler(
        [](const llvh::SMDiagnostic &diag, void *ctx) {
          static_cast<ParserContext *>(ctx)->addMessage(diag);
        },
        this);
  }

  void setInputBuffer(llvh::StringRef str) {
    assert(!haveBufferId() && "input buffer has already been set");
    assert(str.back() == 0 && "input source must be 0-terminated");
    bufId_ = context_.getSourceErrorManager().addNewSourceBuffer(
        llvh::MemoryBuffer::getMemBuffer(str.drop_back(), "JavaScript", true));
  }

  bool haveBufferId() const {
    return bufId_ != ~0u;
  }

  unsigned getBufferId() const {
    assert(haveBufferId() && "input buffer has not been set");
    return bufId_;
  }

  void addMessage(const llvh::SMDiagnostic &diag) {
    if (diag.getKind() <= llvh::SourceMgr::DK_Error && !firstError_)
      firstError_ = ourMessages_.size();
    ourMessages_.push_back(diag);
    convertedMessages_.push_back(ourMessages_.back());
  }

  void addError(const char *msg) {
    context_.getSourceErrorManager().error(
        SMLoc{}, "Input is not zero terminated");
  }
};

}             

                                                                  
extern "C" ParserContext *
hermes_parser_parse(ParserFlags flags, const char *source, size_t len) {
  std::unique_ptr<ParserContext> parserCtx(new ParserContext());

  parserCtx->context_.setStrictMode(flags.strictMode);
  parserCtx->context_.setParseJSX(flags.enableJSX);

  if (len == 0 || source[len - 1] != 0) {
    parserCtx->addError("Input is not zero terminated");
    return parserCtx.release();
  }

  parserCtx->setInputBuffer(llvh::StringRef(source, len));

  parserCtx->context_.setParseTS(false);
  parserCtx->context_.setParseFlow(hermes::ParseFlowSetting::NONE);

  std::vector<parser::StoredComment> comments;
  if (flags.dialect == ParserDialect::FlowDetect || flags.storeDocBlock) {
    comments = parser::getCommentsInDocBlock(
        parserCtx->context_, parserCtx->getBufferId());
  }

  switch (flags.dialect) {
    case ParserDialect::JavaScript:
      break;
    case ParserDialect::Flow:
      parserCtx->context_.setParseFlow(hermes::ParseFlowSetting::ALL);
      parserCtx->context_.setParseFlowComponentSyntax(true);
      break;
    case ParserDialect::FlowUnambiguous:
      parserCtx->context_.setParseFlow(hermes::ParseFlowSetting::UNAMBIGUOUS);
      parserCtx->context_.setParseFlowComponentSyntax(true);
      break;
    case ParserDialect::FlowDetect:
      parserCtx->context_.setParseFlow(
          parser::hasFlowPragma(comments) ? ParseFlowSetting::ALL
                                          : ParseFlowSetting::UNAMBIGUOUS);
      parserCtx->context_.setParseFlowComponentSyntax(true);
      break;
    case ParserDialect::TypeScript:
      parserCtx->context_.setParseTS(true);
      break;
  }

  if (flags.storeDocBlock) {
    parserCtx->docBlock_ = parser::getDocBlock(comments);
  }

  parser::JSParser parser(
      parserCtx->context_, parserCtx->bufId_, hermes::parser::FullParse);

  if (flags.storeComments) {
    parser.setStoreComments(true);
  }

  auto ast = parser.parse();

  if (!parserCtx->firstError_) {
    if (!ast) {
                      
      parserCtx->addError("Internal error");
    } else {
      parser.registerMagicURLs();
      parserCtx->ast_ = *ast;
      if (flags.storeComments) {
        parserCtx->comments_ = parser.moveStoredComments();
      }
    }
  }
  return parserCtx.release();
}

extern "C" void hermes_parser_free(ParserContext *parserCtx) {
  delete parserCtx;
}

                                                            
extern "C" ssize_t hermes_parser_get_first_error(
    const ParserContext *parserCtx) {
  return parserCtx->firstError_ ? (int)*parserCtx->firstError_ : -1;
}

extern "C" DataRef hermes_parser_get_messages(const ParserContext *parserCtx) {
  return toDataRef(parserCtx->convertedMessages_);
}

extern "C" ESTree::ProgramNode *hermes_parser_get_ast(
    const ParserContext *parserCtx) {
  return parserCtx->ast_;
}

extern "C" bool
hermes_parser_find_location(ParserContext *parserCtx, SMLoc loc, Coord *res) {
  SourceErrorManager::SourceCoords coords;
  if (!parserCtx->context_.getSourceErrorManager().findBufferLineAndLoc(
          loc, coords)) {
    res->line = res->offset = 0;
    return false;
  }

  res->line = coords.line;
  res->offset = coords.col - 1;
  return true;
}

                                                                          
                                                                        
                                                          
extern "C" bool hermes_parser_find_line(
    const ParserContext *parserCtx,
    SMLoc loc,
    LineCoord *res) {
  auto coord =
      parserCtx->context_.getSourceErrorManager().findBufferAndLine(loc);
  if (!coord)
    return false;

  res->lineNo = coord->lineNo;
  res->lineRef = toDataRef(coord->lineRef);
  return true;
}

                                                       
                                                                     
                          
extern "C" DataRef hermes_parser_get_line_ref(
    const ParserContext *parserCtx,
    unsigned line) {
  return toDataRef(parserCtx->context_.getSourceErrorManager().getLineRef(
      parserCtx->getBufferId(), line));
}

                                                                         
                                            
extern "C" DataRef hermes_parser_get_magic_comment(
    const ParserContext *parserCtx,
    MagicCommentKind kind) {
                                                                              
                                                                              
                  
  if (!parserCtx->haveBufferId() || !parserCtx->ast_)
    return {nullptr, 0};

  llvh::StringRef res{};
  switch (kind) {
    case MagicCommentKind::SourceUrl:
      res = parserCtx->context_.getSourceErrorManager().getSourceUrl(
          parserCtx->getBufferId());
      break;
    case MagicCommentKind::SourceMappingUrl:
      res = parserCtx->context_.getSourceErrorManager().getSourceMappingUrl(
          parserCtx->getBufferId());
      break;
  }

  return toDataRef(res);
}

extern "C" DataRef hermes_get_node_name(ESTree::Node *n) {
  return toDataRef(n->getNodeName());
}

                                                                       
               
extern "C" DataRef hermes_parser_get_doc_block(ParserContext *parserCtx) {
  return toDataRef(parserCtx->docBlock_);
}

                                                                      
               
extern "C" DataRef hermes_parser_get_comments(ParserContext *parserCtx) {
  return toDataRef(parserCtx->comments_);
}
