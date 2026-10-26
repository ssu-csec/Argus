//===-- Debug.cpp - An easy way to add debug output to your code ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a handy way of adding debugging information to your
// code, without it being enabled all of the time, and without having to add
// command line options to enable it.
//
// In particular, just wrap your code with the LLVM_DEBUG() macro, and it will
// be enabled automatically if you specify '-debug' on the command-line.
// Alternatively, you can also use the SET_DEBUG_TYPE("foo") macro to specify
// that your debug code belongs to class "foo".  Then, on the command line, you
// can specify '-debug-only=foo' to enable JUST the debug information for the
// foo class.
//
// When compiling without assertions, the -debug-* options and all code in
// LLVM_DEBUG() statements disappears, so it does not affect the runtime of the
// code.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/Debug.h"
#include "llvh/Support/CommandLine.h"
#include "llvh/Support/ManagedStatic.h"
#include "llvh/Support/Signals.h"
#include "llvh/Support/circular_raw_ostream.h"
#include "llvh/Support/raw_ostream.h"

#undef isCurrentDebugType
#undef setCurrentDebugType
#undef setCurrentDebugTypes

using namespace llvh;

                                                                            
                                                                          
namespace llvh {
                                              
bool DebugFlag = false;

static ManagedStatic<std::vector<std::string>> CurrentDebugType;

                                                         
                                                                               
                                  
bool isCurrentDebugType(const char *DebugType) {
  if (CurrentDebugType->empty())
    return true;
                                                                              
                                                  
  for (auto &d : *CurrentDebugType) {
    if (d == DebugType)
      return true;
  }
  return false;
}

                                                       
                                                                                
                                
   
void setCurrentDebugTypes(const char **Types, unsigned Count);

void setCurrentDebugType(const char *Type) {
  setCurrentDebugTypes(&Type, 1);
}

void setCurrentDebugTypes(const char **Types, unsigned Count) {
  CurrentDebugType->clear();
  for (size_t T = 0; T < Count; ++T)
    CurrentDebugType->push_back(Types[T]);
}
}                  

                                                       
#ifndef NDEBUG

                                                                             
                                                 
static cl::opt<bool, true>
Debug("debug", cl::desc("Enable debug output"), cl::Hidden,
      cl::location(DebugFlag));

                                                                    
                            
static cl::opt<unsigned>
DebugBufferSize("debug-buffer-size",
                cl::desc("Buffer the last N characters of debug output "
                         "until program termination. "
                         "[default 0 -- immediate print-out]"),
                cl::Hidden,
                cl::init(0));

namespace {

struct DebugOnlyOpt {
  void operator=(const std::string &Val) const {
    if (Val.empty())
      return;
    DebugFlag = true;
    SmallVector<StringRef,8> dbgTypes;
    StringRef(Val).split(dbgTypes, ',', -1, false);
    for (auto dbgType : dbgTypes)
      CurrentDebugType->push_back(dbgType);
  }
};

}

static DebugOnlyOpt DebugOnlyOptLoc;

static cl::opt<DebugOnlyOpt, true, cl::parser<std::string> >
DebugOnly("debug-only", cl::desc("Enable a specific type of debug output (comma separated list of types)"),
          cl::Hidden, cl::ZeroOrMore, cl::value_desc("debug string"),
          cl::location(DebugOnlyOptLoc), cl::ValueRequired);
                                                      
static void debug_user_sig_handler(void *Cookie) {
                                                                  
                                                           
                                                                
                                           
  llvh::circular_raw_ostream &dbgout =
      static_cast<circular_raw_ostream &>(llvh::dbgs());
  dbgout.flushBufferWithBanner();
}

                                                   
raw_ostream &llvh::dbgs() {
                                                     
  static struct dbgstream {
    circular_raw_ostream strm;

    dbgstream() :
        strm(errs(), "*** Debug Log Output ***\n",
             (!EnableDebugBuffering || !DebugFlag) ? 0 : DebugBufferSize) {
      if (EnableDebugBuffering && DebugFlag && DebugBufferSize != 0)
                                                                        
                              
        sys::AddSignalHandler(&debug_user_sig_handler, nullptr);
                                                                    
                                                                        
    }
  } thestrm;

  return thestrm.strm;
}

#else
                                  
namespace llvh {
                           
  raw_ostream &dbgs() {
    return errs();
  }
}

#endif

                                                               
   
bool llvh::EnableDebugBuffering = false;
