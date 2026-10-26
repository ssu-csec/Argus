/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "repl.h"

#include "llvh/ADT/SmallString.h"
#include "llvh/Support/CommandLine.h"
#include "llvh/Support/ConvertUTF.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/PrettyStackTrace.h"
#include "llvh/Support/Signals.h"
#include "llvh/Support/raw_ostream.h"

#include "hermes/ConsoleHost/ConsoleHost.h"
#include "hermes/Parser/JSLexer.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSError.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/SmallXString.h"
#include "hermes/VM/StringView.h"

#if HAVE_LIBREADLINE
#include <readline/history.h>
#include <readline/readline.h>
#endif

#ifndef _WINDOWS
#include <unistd.h>
#endif

#include <csetjmp>
#include <csignal>
#include <iostream>
#include <stack>

#define C_STRING(x) #x

#if HAVE_LIBREADLINE
static const std::string kHistoryFileBaseName = ".hermes_history";
static const int kHistoryMaxEntries = 500;
#endif

using namespace hermes;

static llvh::cl::opt<std::string> PromptString(
    "prompt",
    llvh::cl::init(">> "),
    llvh::cl::desc("Prompt string for the REPL."));

static llvh::cl::opt<std::string> Prompt2String(
    "prompt2",
    llvh::cl::init("...  "),
    llvh::cl::desc("Prompt string for continuation lines in the REPL."));

namespace {
enum class ReadResult {
  SUCCESS,
  FAILURE,
  INTERRUPT,
};
}

                                                                               
                  
                                                                      
                                                                
                                                                          
                                                                     
                                                                      
static ReadResult readInputLine(const char *prompt, std::string &line);

#ifdef _WINDOWS

static ReadResult readInputLine(const char *prompt, std::string &line) {
  llvh::outs() << prompt;
  std::string current{};
  bool success = !!std::getline(std::cin, current);

  if (!success) {
    return ReadResult::FAILURE;
  }
  line.append(current);
  return ReadResult::SUCCESS;
}

#else

static std::jmp_buf readlineJmpBuf;

                                                  
static struct sigaction oldAction;

                                   
                                                                              
static void handleSignal(int sig) {
  if (sig == SIGINT) {
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = oldAction.sa_handler;
    ::sigaction(SIGINT, &action, &oldAction);
    ::longjmp(readlineJmpBuf, 1);
  }
}

static ReadResult readInputLine(const char *prompt, std::string &line) {
#ifndef __EMSCRIPTEN__
  struct sigaction action;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;

  if (setjmp(readlineJmpBuf) != 0) {
    return ReadResult::INTERRUPT;
  }

  action.sa_handler = handleSignal;
  ::sigaction(SIGINT, &action, &oldAction);

#if HAVE_LIBREADLINE
  if (oscompat::isatty(STDIN_FILENO)) {
    char *rl = ::readline(prompt);
    action.sa_handler = oldAction.sa_handler;
    ::sigaction(SIGINT, &action, &oldAction);

    if (!rl)
      return ReadResult::FAILURE;
    line.append(rl);
    ::add_history(rl);
    ::free(rl);
    return ReadResult::SUCCESS;
  }
#endif
#else
                                    
  (void)handleSignal;
#endif
  llvh::outs() << prompt;
  std::string current{};
  bool success = !!std::getline(std::cin, current);
#ifndef __EMSCRIPTEN__
  action.sa_handler = oldAction.sa_handler;
  ::sigaction(SIGINT, &action, &oldAction);
#endif
  if (!success) {
    return ReadResult::FAILURE;
  }
  line.append(current);
  return ReadResult::SUCCESS;
}
#endif

                                                                    
                                                                
                                                                             
                       
                                                                         
static bool needsAnotherLine(llvh::StringRef input) {
  SourceErrorManager sm;
  SourceErrorManager::SaveAndSuppressMessages suppress(&sm);
  hermes::BumpPtrAllocator allocator{};
  parser::JSLexer lexer(input, sm, allocator, nullptr, false);

  std::stack<parser::TokenKind> stack{};

  if (input.empty()) {
    return false;
  }

  if (input.back() == '\\') {
    return true;
  }

                                                                        
  auto getLeft = [](const parser::TokenKind kind) {
    switch (kind) {
      case parser::TokenKind::r_brace:
        return parser::TokenKind::l_brace;
      case parser::TokenKind::r_paren:
        return parser::TokenKind::l_paren;
      case parser::TokenKind::r_square:
        return parser::TokenKind::l_square;
      default:
        llvm_unreachable("getLeft executed with unsupported kind");
    }
  };

                                                                              
                                       
                                                                               
  auto isRegexPossible = [](OptValue<parser::TokenKind> previousTokenKind) {
    if (!previousTokenKind) {
      return true;
    }
    switch (*previousTokenKind) {
      case parser::TokenKind::rw_break:
      case parser::TokenKind::rw_case:
      case parser::TokenKind::rw_continue:
      case parser::TokenKind::rw_delete:
      case parser::TokenKind::rw_do:
      case parser::TokenKind::rw_else:
      case parser::TokenKind::rw_finally:
      case parser::TokenKind::rw_in:
      case parser::TokenKind::rw_instanceof:
      case parser::TokenKind::rw_return:
      case parser::TokenKind::rw_throw:
      case parser::TokenKind::rw_try:
      case parser::TokenKind::rw_typeof:
      case parser::TokenKind::rw_void:
      case parser::TokenKind::plus:
      case parser::TokenKind::minus:
      case parser::TokenKind::period:
      case parser::TokenKind::slash:
      case parser::TokenKind::comma:
      case parser::TokenKind::star:
      case parser::TokenKind::exclaim:
      case parser::TokenKind::percent:
      case parser::TokenKind::amp:
      case parser::TokenKind::l_paren:
      case parser::TokenKind::colon:
      case parser::TokenKind::semi:
      case parser::TokenKind::less:
      case parser::TokenKind::equal:
      case parser::TokenKind::greater:
      case parser::TokenKind::question:
      case parser::TokenKind::l_square:
      case parser::TokenKind::caret:
      case parser::TokenKind::l_brace:
      case parser::TokenKind::pipe:
      case parser::TokenKind::r_brace:
      case parser::TokenKind::tilde:
        return true;
      default:
        return false;
    }
  };

  OptValue<parser::TokenKind> previousTokenKind;

                                                                           
                                                    
  while (const parser::Token *token = lexer.advance(
             isRegexPossible(previousTokenKind)
                 ? parser::JSLexer::GrammarContext::AllowRegExp
                 : parser::JSLexer::GrammarContext::AllowDiv)) {
    if (token->getKind() == parser::TokenKind::eof) {
      break;
    }
    switch (token->getKind()) {
      case parser::TokenKind::l_brace:
      case parser::TokenKind::l_paren:
      case parser::TokenKind::l_square:
                                         
        stack.push(token->getKind());
        break;
      case parser::TokenKind::r_brace:
      case parser::TokenKind::r_paren:
      case parser::TokenKind::r_square: {
                                                                        
                                        
        auto left = getLeft(token->getKind());
        if (!stack.empty() && stack.top() == left) {
                                                            
          stack.pop();
        } else {
                                                         
          return false;
        }
        break;
      }
      default:
                                           
        break;
    }
    previousTokenKind = token->getKind();
  }

                                                                 
                                                                        
                                                      
  return !stack.empty();
}

#if HAVE_LIBREADLINE
                                 
static std::error_code loadHistoryFile(llvh::SmallString<128> &historyFile) {
  if (!llvh::sys::path::home_directory(historyFile)) {
                                                                
    return std::error_code(ENOENT, std::system_category());
  }

  llvh::sys::path::append(historyFile, kHistoryFileBaseName);

  auto err = ::read_history(historyFile.c_str());
  if (err != 0) {
                                                   
    return std::error_code(err, std::system_category());
  }

  return std::error_code();
}
#endif

                                                                            
                                  
static void printError(const char *message, bool hasColors) {
  llvh::raw_ostream &errs = hasColors
      ? llvh::errs().changeColor(llvh::raw_ostream::Colors::RED)
      : llvh::errs();
  errs << message;
  llvh::errs().resetColor();
}

                         
int repl(const vm::RuntimeConfig &config) {
  std::shared_ptr<vm::Runtime> runtime = vm::Runtime::create(config);

  vm::GCScope gcScope(*runtime);
  ConsoleHostContext ctx{*runtime};
  installConsoleBindings(*runtime, ctx);

  std::string code;
  code.reserve(256);

  auto global = runtime->getGlobal();
  auto propRes = vm::JSObject::getNamed_RJS(
      global, *runtime, vm::Predefined::getSymbolID(vm::Predefined::eval));
  if (propRes == vm::ExecutionStatus::EXCEPTION) {
    runtime->printException(
        llvh::outs(), runtime->makeHandle(runtime->getThrownValue()));
    return 1;
  }
  auto evalFn = runtime->makeHandle<vm::Callable>(std::move(*propRes));

  llvh::StringRef evaluateLineString =
#include "evaluate-line.js"
      ;
  bool hasColors = oscompat::should_color(STDOUT_FILENO);

  auto callRes = evalFn->executeCall1(
      evalFn,
      *runtime,
      global,
      vm::StringPrimitive::createNoThrow(*runtime, evaluateLineString)
          .getHermesValue());
  if (callRes == vm::ExecutionStatus::EXCEPTION) {
    printError("Unable to get REPL util function: evaluateLine.\n", hasColors);
    llvh::raw_ostream &outs = hasColors
        ? llvh::outs().changeColor(llvh::raw_ostream::Colors::RED)
        : llvh::outs();
    runtime->printException(
        outs, runtime->makeHandle(runtime->getThrownValue()));
    return 1;
  }
  auto evaluateLineFn =
      runtime->makeHandle<vm::JSFunction>(std::move(*callRes));

  runtime->getHeap().runtimeWillExecute();

#if HAVE_LIBREADLINE
  llvh::SmallString<128> historyFile{};
  auto historyErr = loadHistoryFile(historyFile);
  if (historyErr && historyErr.value() != ENOENT) {
    llvh::errs() << "Could not load history file: " << historyErr.message()
                 << '\n';
  }
#endif

  vm::MutableHandle<> resHandle{*runtime};
                                                                        
                                                                          
                                                                              
  llvh::outs().SetUnbuffered();
  while (true) {
                
    auto readResult = readInputLine(
        code.empty() ? PromptString.c_str() : Prompt2String.c_str(), code);
    if (readResult == ReadResult::FAILURE ||
        (readResult == ReadResult::INTERRUPT && code.empty())) {
                                                   
      llvh::outs() << '\n';
#if HAVE_LIBREADLINE
      if (history_length > 0) {
        ::stifle_history(kHistoryMaxEntries);
        ::write_history(historyFile.c_str());
      }
#endif
      return 0;
    }

    if (readResult == ReadResult::INTERRUPT) {
                                         
      code.clear();
      llvh::outs() << '\n';
      continue;
    }

    if (needsAnotherLine(code)) {
      code += '\n';
      continue;
    }

    llvh::SmallVector<llvh::UTF16, 16> utf16Buf;
    if (!llvh::convertUTF8ToUTF16String(code, utf16Buf)) {
      code.clear();
      printError("Input not valid UTF-8\n", hasColors);
      continue;
    }
    static_assert(sizeof(llvh::UTF16) == sizeof(char16_t));
    llvh::ArrayRef<char16_t> utf16Code = llvh::makeArrayRef(
        reinterpret_cast<const char16_t *>(utf16Buf.data()), utf16Buf.size());

                                                 
    vm::GCScopeMarkerRAII gcMarker{*runtime};

    bool threwException = false;

    if ((callRes = evaluateLineFn->executeCall2(
             evaluateLineFn,
             *runtime,
             global,
             vm::StringPrimitive::createNoThrow(*runtime, utf16Code)
                 .getHermesValue(),
             vm::HermesValue::encodeBoolValue(hasColors))) ==
        vm::ExecutionStatus::EXCEPTION) {
      runtime->printException(
          hasColors ? llvh::outs().changeColor(llvh::raw_ostream::Colors::RED)
                    : llvh::outs(),
          runtime->makeHandle(runtime->getThrownValue()));
      llvh::outs().resetColor();
      code.clear();
      threwException = true;
    } else {
      resHandle = std::move(*callRes);
    }

                                                           
    microtask::performCheckpoint(*runtime);

    if (!ctx.tasksEmpty()) {
                                               
      vm::MutableHandle<vm::Callable> task{*runtime};
      while (auto optTask = ctx.dequeueTask()) {
        task = std::move(*optTask);
        auto taskCallRes = vm::Callable::executeCall0(
            task, *runtime, vm::Runtime::getUndefinedValue(), false);
        if (LLVM_UNLIKELY(taskCallRes == vm::ExecutionStatus::EXCEPTION)) {
          threwException = true;
          runtime->printException(
              hasColors
                  ? llvh::outs().changeColor(llvh::raw_ostream::Colors::RED)
                  : llvh::outs(),
              runtime->makeHandle(runtime->getThrownValue()));
          llvh::outs().resetColor();
          code.clear();
        }

                                                                        
        microtask::performCheckpoint(*runtime);
      }
    }

    if (threwException) {
      continue;
    }

    if (resHandle->isUndefined()) {
      code.clear();
      continue;
    }

                                               
    vm::SmallU16String<32> tmp;
    vm::operator<<(
        llvh::outs(),
        vm::StringPrimitive::createStringView(
            *runtime, vm::Handle<vm::StringPrimitive>::vmcast(resHandle))
            .getUTF16Ref(tmp))
        << "\n";
    code.clear();
  }

  return 0;
}
