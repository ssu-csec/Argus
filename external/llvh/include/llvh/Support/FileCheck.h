//==-- llvm/Support/FileCheck.h ---------------------------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// \file This file has some utilities to use FileCheck as an API
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FILECHECK_H
#define LLVM_SUPPORT_FILECHECK_H

#include "llvh/ADT/StringMap.h"
#include "llvh/Support/MemoryBuffer.h"
#include "llvh/Support/Regex.h"
#include "llvh/Support/SourceMgr.h"
#include <vector>
#include <map>

namespace llvh {

                                                  
struct FileCheckRequest {
  std::vector<std::string> CheckPrefixes;
  bool NoCanonicalizeWhiteSpace = false;
  std::vector<std::string> ImplicitCheckNot;
  std::vector<std::string> GlobalDefines;
  bool AllowEmptyInput = false;
  bool MatchFullLines = false;
  bool EnableVarScope = false;
  bool AllowDeprecatedDagOverlap = false;
  bool Verbose = false;
  bool VerboseVerbose = false;
};


                                                                                
                         
                                                                                

namespace Check {
enum FileCheckType {
  CheckNone = 0,
  CheckPlain,
  CheckNext,
  CheckSame,
  CheckNot,
  CheckDAG,
  CheckLabel,
  CheckEmpty,

                                                                          
                          
  CheckEOF,

                                                                               
  CheckBadNot
};
}

class FileCheckPattern {
  SMLoc PatternLoc;

                                                                              
                    
  StringRef FixedStr;

                                                                              
                              
  std::string RegExStr;

                                                                           
                                                                            
                                                                            
                      
  std::vector<std::pair<StringRef, unsigned>> VariableUses;

                                                                           
     
                                                                             
        
  std::map<StringRef, unsigned> VariableDefs;

  Check::FileCheckType CheckTy;

                                                     
  unsigned LineNumber;

public:
  explicit FileCheckPattern(Check::FileCheckType Ty)
      : CheckTy(Ty) {}

                                          
  SMLoc getLoc() const { return PatternLoc; }

  bool ParsePattern(StringRef PatternStr, StringRef Prefix, SourceMgr &SM,
                    unsigned LineNumber, const FileCheckRequest &Req);
  size_t Match(StringRef Buffer, size_t &MatchLen,
               StringMap<StringRef> &VariableTable) const;
  void PrintVariableUses(const SourceMgr &SM, StringRef Buffer,
                         const StringMap<StringRef> &VariableTable,
                         SMRange MatchRange = None) const;
  void PrintFuzzyMatch(const SourceMgr &SM, StringRef Buffer,
                       const StringMap<StringRef> &VariableTable) const;

  bool hasVariable() const {
    return !(VariableUses.empty() && VariableDefs.empty());
  }

  Check::FileCheckType getCheckTy() const { return CheckTy; }

private:
  bool AddRegExToRegEx(StringRef RS, unsigned &CurParen, SourceMgr &SM);
  void AddBackrefToRegEx(unsigned BackrefNum);
  unsigned
  ComputeMatchDistance(StringRef Buffer,
                       const StringMap<StringRef> &VariableTable) const;
  bool EvaluateExpression(StringRef Expr, std::string &Value) const;
  size_t FindRegexVarEnd(StringRef Str, SourceMgr &SM);
};

                                                                                
                 
                                                                                

                                            
struct FileCheckString {
                           
  FileCheckPattern Pat;

                                           
  StringRef Prefix;

                                                                         
  SMLoc Loc;

                                                                              
                                                     
  std::vector<FileCheckPattern> DagNotStrings;

  FileCheckString(const FileCheckPattern &P, StringRef S, SMLoc L)
      : Pat(P), Prefix(S), Loc(L) {}

  size_t Check(const SourceMgr &SM, StringRef Buffer, bool IsLabelScanMode,
               size_t &MatchLen, StringMap<StringRef> &VariableTable,
               FileCheckRequest &Req) const;

  bool CheckNext(const SourceMgr &SM, StringRef Buffer) const;
  bool CheckSame(const SourceMgr &SM, StringRef Buffer) const;
  bool CheckNot(const SourceMgr &SM, StringRef Buffer,
                const std::vector<const FileCheckPattern *> &NotStrings,
                StringMap<StringRef> &VariableTable,
                const FileCheckRequest &Req) const;
  size_t CheckDag(const SourceMgr &SM, StringRef Buffer,
                  std::vector<const FileCheckPattern *> &NotStrings,
                  StringMap<StringRef> &VariableTable,
                  const FileCheckRequest &Req) const;
};

                                                                      
                                     
class FileCheck {
  FileCheckRequest Req;

public:
  FileCheck(FileCheckRequest Req) : Req(Req) {}

                                                                               
                             
    
                                                                          
             
  Regex buildCheckPrefixRegex();

                                                                            
     
                                                                               
                                
  bool ReadCheckFile(SourceMgr &SM, StringRef Buffer, Regex &PrefixRE,
                     std::vector<FileCheckString> &CheckStrings);

  bool ValidateCheckPrefixes();

                                                                          
                      
  StringRef CanonicalizeFile(MemoryBuffer &MB,
                             SmallVectorImpl<char> &OutputBuffer);

                                                                           
                                            
     
                                                             
  bool CheckInput(SourceMgr &SM, StringRef Buffer,
                  ArrayRef<FileCheckString> CheckStrings);
};
}                  
#endif
