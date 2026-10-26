//===- FileCheck.cpp - Check that File's Contents match what is expected --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// FileCheck does a line-by line check of a file that validates whether it
// contains the expected content.  This is useful for regression tests etc.
//
// This file implements most of the API that will be used by the FileCheck utility
// as well as various unittests.
//===----------------------------------------------------------------------===//

#include "llvh/Support/FileCheck.h"
#include "llvh/ADT/StringSet.h"
#include <list>
#include <map>

using namespace llvh;

                                             
   
                                                                        
                                                                             
                                                                          
                                      
bool FileCheckPattern::ParsePattern(StringRef PatternStr, StringRef Prefix,
                           SourceMgr &SM, unsigned LineNumber,
                           const FileCheckRequest &Req) {
  bool MatchFullLinesHere = Req.MatchFullLines && CheckTy != Check::CheckNot;

  this->LineNumber = LineNumber;
  PatternLoc = SMLoc::getFromPointer(PatternStr.data());

  if (!(Req.NoCanonicalizeWhiteSpace && Req.MatchFullLines))
                                  
    while (!PatternStr.empty() &&
           (PatternStr.back() == ' ' || PatternStr.back() == '\t'))
      PatternStr = PatternStr.substr(0, PatternStr.size() - 1);

                                               
  if (PatternStr.empty() && CheckTy != Check::CheckEmpty) {
    SM.PrintMessage(PatternLoc, SourceMgr::DK_Error,
                    "found empty check string with prefix '" + Prefix + ":'");
    return true;
  }

  if (!PatternStr.empty() && CheckTy == Check::CheckEmpty) {
    SM.PrintMessage(
        PatternLoc, SourceMgr::DK_Error,
        "found non-empty check string for empty check with prefix '" + Prefix +
            ":'");
    return true;
  }

  if (CheckTy == Check::CheckEmpty) {
    RegExStr = "(\n$)";
    return false;
  }

                                                                       
  if (!MatchFullLinesHere &&
      (PatternStr.size() < 2 || (PatternStr.find("{{") == StringRef::npos &&
                                 PatternStr.find("[[") == StringRef::npos))) {
    FixedStr = PatternStr;
    return false;
  }

  if (MatchFullLinesHere) {
    RegExStr += '^';
    if (!Req.NoCanonicalizeWhiteSpace)
      RegExStr += " *";
  }

                                                                           
                           
  unsigned CurParen = 1;

                                                                              
                                                                              
  while (!PatternStr.empty()) {
                     
    if (PatternStr.startswith("{{")) {
                                                              
      size_t End = PatternStr.find("}}");
      if (End == StringRef::npos) {
        SM.PrintMessage(SMLoc::getFromPointer(PatternStr.data()),
                        SourceMgr::DK_Error,
                        "found start of regex string with no end '}}'");
        return true;
      }

                                                                             
                                                                            
                                                                            
                                                               
      RegExStr += '(';
      ++CurParen;

      if (AddRegExToRegEx(PatternStr.substr(2, End - 2), CurParen, SM))
        return true;
      RegExStr += ')';

      PatternStr = PatternStr.substr(End + 2);
      continue;
    }

                                                                                
                                                                                
                                                                             
                                                                               
                                                
    if (PatternStr.startswith("[[")) {
                                                                               
                                                              
      size_t End = FindRegexVarEnd(PatternStr.substr(2), SM);

      if (End == StringRef::npos) {
        SM.PrintMessage(SMLoc::getFromPointer(PatternStr.data()),
                        SourceMgr::DK_Error,
                        "invalid named regex reference, no ]] found");
        return true;
      }

      StringRef MatchStr = PatternStr.substr(2, End);
      PatternStr = PatternStr.substr(End + 4);

                                         
      size_t NameEnd = MatchStr.find(':');
      StringRef Name = MatchStr.substr(0, NameEnd);

      if (Name.empty()) {
        SM.PrintMessage(SMLoc::getFromPointer(Name.data()), SourceMgr::DK_Error,
                        "invalid name in named regex: empty name");
        return true;
      }

                                                                            
                                                                               
                                                                             
      bool IsExpression = false;
      for (unsigned i = 0, e = Name.size(); i != e; ++i) {
        if (i == 0) {
          if (Name[i] == '$')                               
            continue;
          if (Name[i] == '@') {
            if (NameEnd != StringRef::npos) {
              SM.PrintMessage(SMLoc::getFromPointer(Name.data()),
                              SourceMgr::DK_Error,
                              "invalid name in named regex definition");
              return true;
            }
            IsExpression = true;
            continue;
          }
        }
        if (Name[i] != '_' && !isalnum(Name[i]) &&
            (!IsExpression || (Name[i] != '+' && Name[i] != '-'))) {
          SM.PrintMessage(SMLoc::getFromPointer(Name.data() + i),
                          SourceMgr::DK_Error, "invalid name in named regex");
          return true;
        }
      }

                                       
      if (isdigit(static_cast<unsigned char>(Name[0]))) {
        SM.PrintMessage(SMLoc::getFromPointer(Name.data()), SourceMgr::DK_Error,
                        "invalid name in named regex");
        return true;
      }

                        
      if (NameEnd == StringRef::npos) {
                                                                         
                                    
        if (VariableDefs.find(Name) != VariableDefs.end()) {
          unsigned VarParenNum = VariableDefs[Name];
          if (VarParenNum < 1 || VarParenNum > 9) {
            SM.PrintMessage(SMLoc::getFromPointer(Name.data()),
                            SourceMgr::DK_Error,
                            "Can't back-reference more than 9 variables");
            return true;
          }
          AddBackrefToRegEx(VarParenNum);
        } else {
          VariableUses.push_back(std::make_pair(Name, RegExStr.size()));
        }
        continue;
      }

                           
      VariableDefs[Name] = CurParen;
      RegExStr += '(';
      ++CurParen;

      if (AddRegExToRegEx(MatchStr.substr(NameEnd + 1), CurParen, SM))
        return true;

      RegExStr += ')';
    }

                                   
                                                          
    size_t FixedMatchEnd = PatternStr.find("{{");
    FixedMatchEnd = std::min(FixedMatchEnd, PatternStr.find("[["));
    RegExStr += Regex::escape(PatternStr.substr(0, FixedMatchEnd));
    PatternStr = PatternStr.substr(FixedMatchEnd);
  }

  if (MatchFullLinesHere) {
    if (!Req.NoCanonicalizeWhiteSpace)
      RegExStr += " *";
    RegExStr += '$';
  }

  return false;
}

bool FileCheckPattern::AddRegExToRegEx(StringRef RS, unsigned &CurParen, SourceMgr &SM) {
  Regex R(RS);
  std::string Error;
  if (!R.isValid(Error)) {
    SM.PrintMessage(SMLoc::getFromPointer(RS.data()), SourceMgr::DK_Error,
                    "invalid regex: " + Error);
    return true;
  }

  RegExStr += RS.str();
  CurParen += R.getNumMatches();
  return false;
}

void FileCheckPattern::AddBackrefToRegEx(unsigned BackrefNum) {
  assert(BackrefNum >= 1 && BackrefNum <= 9 && "Invalid backref number");
  std::string Backref = std::string("\\") + std::string(1, '0' + BackrefNum);
  RegExStr += Backref;
}

                                                           
   
                                                                             
bool FileCheckPattern::EvaluateExpression(StringRef Expr, std::string &Value) const {
                                                      
  if (!Expr.startswith("@LINE"))
    return false;
  Expr = Expr.substr(StringRef("@LINE").size());
  int Offset = 0;
  if (!Expr.empty()) {
    if (Expr[0] == '+')
      Expr = Expr.substr(1);
    else if (Expr[0] != '-')
      return false;
    if (Expr.getAsInteger(10, Offset))
      return false;
  }
  Value = llvh::itostr(LineNumber + Offset);
  return true;
}

                                                                 
   
                                                                              
                                                                      
             
   
                                                                           
                                                              
size_t FileCheckPattern::Match(StringRef Buffer, size_t &MatchLen,
                      StringMap<StringRef> &VariableTable) const {
                                                      
  if (CheckTy == Check::CheckEOF) {
    MatchLen = 0;
    return Buffer.size();
  }

                                                          
  if (!FixedStr.empty()) {
    MatchLen = FixedStr.size();
    return Buffer.find(FixedStr);
  }

                 

                                                                              
                  
  StringRef RegExToMatch = RegExStr;
  std::string TmpStr;
  if (!VariableUses.empty()) {
    TmpStr = RegExStr;

    unsigned InsertOffset = 0;
    for (const auto &VariableUse : VariableUses) {
      std::string Value;

      if (VariableUse.first[0] == '@') {
        if (!EvaluateExpression(VariableUse.first, Value))
          return StringRef::npos;
      } else {
        StringMap<StringRef>::iterator it =
            VariableTable.find(VariableUse.first);
                                                         
        if (it == VariableTable.end())
          return StringRef::npos;

                                                                                
        Value += Regex::escape(it->second);
      }

                                                       
      TmpStr.insert(TmpStr.begin() + VariableUse.second + InsertOffset,
                    Value.begin(), Value.end());
      InsertOffset += Value.size();
    }

                                         
    RegExToMatch = TmpStr;
  }

  SmallVector<StringRef, 4> MatchInfo;
  if (!Regex(RegExToMatch, Regex::Newline).match(Buffer, &MatchInfo))
    return StringRef::npos;

                            
  assert(!MatchInfo.empty() && "Didn't get any match");
  StringRef FullMatch = MatchInfo[0];

                                                          
  for (const auto &VariableDef : VariableDefs) {
    assert(VariableDef.second < MatchInfo.size() && "Internal paren error");
    VariableTable[VariableDef.first] = MatchInfo[VariableDef.second];
  }

                                                                            
                                                                            
                                            
  size_t MatchStartSkip = CheckTy == Check::CheckEmpty;
  MatchLen = FullMatch.size() - MatchStartSkip;
  return FullMatch.data() - Buffer.data() + MatchStartSkip;
}


                                                                              
                                                                             
          
unsigned
FileCheckPattern::ComputeMatchDistance(StringRef Buffer,
                              const StringMap<StringRef> &VariableTable) const {
                                                                                
                                                                 
    
                                                                             
                                                                          
            
  StringRef ExampleString(FixedStr);
  if (ExampleString.empty())
    ExampleString = RegExStr;

                                                                         
  StringRef BufferPrefix = Buffer.substr(0, ExampleString.size());
  BufferPrefix = BufferPrefix.split('\n').first;
  return BufferPrefix.edit_distance(ExampleString);
}

void FileCheckPattern::PrintVariableUses(const SourceMgr &SM, StringRef Buffer,
                                const StringMap<StringRef> &VariableTable,
                                SMRange MatchRange) const {
                                                                        
                     
  if (!VariableUses.empty()) {
    for (const auto &VariableUse : VariableUses) {
      SmallString<256> Msg;
      raw_svector_ostream OS(Msg);
      StringRef Var = VariableUse.first;
      if (Var[0] == '@') {
        std::string Value;
        if (EvaluateExpression(Var, Value)) {
          OS << "with expression \"";
          OS.write_escaped(Var) << "\" equal to \"";
          OS.write_escaped(Value) << "\"";
        } else {
          OS << "uses incorrect expression \"";
          OS.write_escaped(Var) << "\"";
        }
      } else {
        StringMap<StringRef>::const_iterator it = VariableTable.find(Var);

                                                   
        if (it == VariableTable.end()) {
          OS << "uses undefined variable \"";
          OS.write_escaped(Var) << "\"";
        } else {
          OS << "with variable \"";
          OS.write_escaped(Var) << "\" equal to \"";
          OS.write_escaped(it->second) << "\"";
        }
      }

      if (MatchRange.isValid())
        SM.PrintMessage(MatchRange.Start, SourceMgr::DK_Note, OS.str(),
                        {MatchRange});
      else
        SM.PrintMessage(SMLoc::getFromPointer(Buffer.data()),
                        SourceMgr::DK_Note, OS.str());
    }
  }
}

void FileCheckPattern::PrintFuzzyMatch(
    const SourceMgr &SM, StringRef Buffer,
    const StringMap<StringRef> &VariableTable) const {
                                                                            
                                                                               
                                                                               
                                                           
  size_t NumLinesForward = 0;
  size_t Best = StringRef::npos;
  double BestQuality = 0;

                                                         
  for (size_t i = 0, e = std::min(size_t(4096), Buffer.size()); i != e; ++i) {
    if (Buffer[i] == '\n')
      ++NumLinesForward;

                                                                         
                                                        
    if (Buffer[i] == ' ' || Buffer[i] == '\t')
      continue;

                                                                             
                                                                           
    unsigned Distance = ComputeMatchDistance(Buffer.substr(i), VariableTable);
    double Quality = Distance + (NumLinesForward / 100.);

    if (Quality < BestQuality || Best == StringRef::npos) {
      Best = i;
      BestQuality = Quality;
    }
  }

                                                                        
                                                                           
          
  if (Best && Best != StringRef::npos && BestQuality < 50) {
    SM.PrintMessage(SMLoc::getFromPointer(Buffer.data() + Best),
                    SourceMgr::DK_Note, "possible intended match here");

                                                                            
                                                                          
  }
}

                                                                       
   
                                                                           
                                                                             
                                
size_t FileCheckPattern::FindRegexVarEnd(StringRef Str, SourceMgr &SM) {
                                                                  
  size_t Offset = 0;
                        
  size_t BracketDepth = 0;

  while (!Str.empty()) {
    if (Str.startswith("]]") && BracketDepth == 0)
      return Offset;
    if (Str[0] == '\\') {
                                                                           
      Str = Str.substr(2);
      Offset += 2;
    } else {
      switch (Str[0]) {
      default:
        break;
      case '[':
        BracketDepth++;
        break;
      case ']':
        if (BracketDepth == 0) {
          SM.PrintMessage(SMLoc::getFromPointer(Str.data()),
                          SourceMgr::DK_Error,
                          "missing closing \"]\" for regex variable");
          exit(1);
        }
        BracketDepth--;
        break;
      }
      Str = Str.substr(1);
      Offset++;
    }
  }

  return StringRef::npos;
}

                                                                        
                    
StringRef
llvh::FileCheck::CanonicalizeFile(MemoryBuffer &MB,
                                  SmallVectorImpl<char> &OutputBuffer) {
  OutputBuffer.reserve(MB.getBufferSize());

  for (const char *Ptr = MB.getBufferStart(), *End = MB.getBufferEnd();
       Ptr != End; ++Ptr) {
                                    
    if (Ptr <= End - 2 && Ptr[0] == '\r' && Ptr[1] == '\n') {
      continue;
    }

                                                                      
                                                                        
    if (Req.NoCanonicalizeWhiteSpace || (*Ptr != ' ' && *Ptr != '\t')) {
      OutputBuffer.push_back(*Ptr);
      continue;
    }

                                                                   
    OutputBuffer.push_back(' ');
    while (Ptr + 1 != End && (Ptr[1] == ' ' || Ptr[1] == '\t'))
      ++Ptr;
  }

                                                       
  OutputBuffer.push_back('\0');
  return StringRef(OutputBuffer.data(), OutputBuffer.size() - 1);
}

static bool IsPartOfWord(char c) {
  return (isalnum(c) || c == '-' || c == '_');
}

                                        
static size_t CheckTypeSize(Check::FileCheckType Ty) {
  switch (Ty) {
  case Check::CheckNone:
  case Check::CheckBadNot:
    return 0;

  case Check::CheckPlain:
    return sizeof(":") - 1;

  case Check::CheckNext:
    return sizeof("-NEXT:") - 1;

  case Check::CheckSame:
    return sizeof("-SAME:") - 1;

  case Check::CheckNot:
    return sizeof("-NOT:") - 1;

  case Check::CheckDAG:
    return sizeof("-DAG:") - 1;

  case Check::CheckLabel:
    return sizeof("-LABEL:") - 1;

  case Check::CheckEmpty:
    return sizeof("-EMPTY:") - 1;

  case Check::CheckEOF:
    llvm_unreachable("Should not be using EOF size");
  }

  llvm_unreachable("Bad check type");
}

                                 
static std::string CheckTypeName(StringRef Prefix, Check::FileCheckType Ty) {
  switch (Ty) {
  case Check::CheckNone:
    return "invalid";
  case Check::CheckPlain:
    return Prefix;
  case Check::CheckNext:
    return Prefix.str() + "-NEXT";
  case Check::CheckSame:
    return Prefix.str() + "-SAME";
  case Check::CheckNot:
    return Prefix.str() + "-NOT";
  case Check::CheckDAG:
    return Prefix.str() + "-DAG";
  case Check::CheckLabel:
    return Prefix.str() + "-LABEL";
  case Check::CheckEmpty:
    return Prefix.str() + "-EMPTY";
  case Check::CheckEOF:
    return "implicit EOF";
  case Check::CheckBadNot:
    return "bad NOT";
  }
  llvm_unreachable("unknown FileCheckType");
}

static Check::FileCheckType FindCheckType(StringRef Buffer, StringRef Prefix) {
  if (Buffer.size() <= Prefix.size())
    return Check::CheckNone;

  char NextChar = Buffer[Prefix.size()];

                                                   
  if (NextChar == ':')
    return Check::CheckPlain;

  if (NextChar != '-')
    return Check::CheckNone;

  StringRef Rest = Buffer.drop_front(Prefix.size() + 1);
  if (Rest.startswith("NEXT:"))
    return Check::CheckNext;

  if (Rest.startswith("SAME:"))
    return Check::CheckSame;

  if (Rest.startswith("NOT:"))
    return Check::CheckNot;

  if (Rest.startswith("DAG:"))
    return Check::CheckDAG;

  if (Rest.startswith("LABEL:"))
    return Check::CheckLabel;

  if (Rest.startswith("EMPTY:"))
    return Check::CheckEmpty;

                                                
  if (Rest.startswith("DAG-NOT:") || Rest.startswith("NOT-DAG:") ||
      Rest.startswith("NEXT-NOT:") || Rest.startswith("NOT-NEXT:") ||
      Rest.startswith("SAME-NOT:") || Rest.startswith("NOT-SAME:") ||
      Rest.startswith("EMPTY-NOT:") || Rest.startswith("NOT-EMPTY:"))
    return Check::CheckBadNot;

  return Check::CheckNone;
}

                                                                   
static size_t SkipWord(StringRef Str, size_t Loc) {
  while (Loc < Str.size() && IsPartOfWord(Str[Loc]))
    ++Loc;
  return Loc;
}

                                                                            
   
                                                                              
                                     
                                                                         
                      
                                                                              
                           
   
                                                                               
                                                                 
   
                                                                            
                                                                              
                                                                            
                                        
   
                                                                             
                   
static StringRef FindFirstMatchingPrefix(Regex &PrefixRE, StringRef &Buffer,
                                         unsigned &LineNumber,
                                         Check::FileCheckType &CheckTy) {
  SmallVector<StringRef, 2> Matches;

  while (!Buffer.empty()) {
                                                   
    if (!PrefixRE.match(Buffer, &Matches))
                               
      return StringRef();

    StringRef Prefix = Matches[0];
    Matches.clear();

    assert(Prefix.data() >= Buffer.data() &&
           Prefix.data() < Buffer.data() + Buffer.size() &&
           "Prefix doesn't start inside of buffer!");
    size_t Loc = Prefix.data() - Buffer.data();
    StringRef Skipped = Buffer.substr(0, Loc);
    Buffer = Buffer.drop_front(Loc);
    LineNumber += Skipped.count('\n');

                                                                            
            
                                                                             
                                                                         
                                                          
    if (Skipped.empty() || !IsPartOfWord(Skipped.back())) {
                              
      CheckTy = FindCheckType(Buffer, Prefix);

                                                                       
      if (CheckTy != Check::CheckNone)
        return Prefix;
    }

                                                                            
                                                                         
                                                                
    Buffer = Buffer.drop_front(SkipWord(Buffer, Prefix.size()));
  }

                                                                    
  return StringRef();
}

                                                                          
   
                                                                             
                              
bool llvh::FileCheck::ReadCheckFile(SourceMgr &SM, StringRef Buffer,
                                    Regex &PrefixRE,
                                    std::vector<FileCheckString> &CheckStrings) {
  std::vector<FileCheckPattern> ImplicitNegativeChecks;
  for (const auto &PatternString : Req.ImplicitCheckNot) {
                                                                             
                                                                           
    std::string Prefix = "-implicit-check-not='";
    std::string Suffix = "'";
    std::unique_ptr<MemoryBuffer> CmdLine = MemoryBuffer::getMemBufferCopy(
        Prefix + PatternString + Suffix, "command line");

    StringRef PatternInBuffer =
        CmdLine->getBuffer().substr(Prefix.size(), PatternString.size());
    SM.AddNewSourceBuffer(std::move(CmdLine), SMLoc());

    ImplicitNegativeChecks.push_back(FileCheckPattern(Check::CheckNot));
    ImplicitNegativeChecks.back().ParsePattern(PatternInBuffer,
                                               "IMPLICIT-CHECK", SM, 0, Req);
  }

  std::vector<FileCheckPattern> DagNotMatches = ImplicitNegativeChecks;

                                                                          
           
  unsigned LineNumber = 1;

  while (1) {
    Check::FileCheckType CheckTy;

                                                   
    StringRef UsedPrefix = FindFirstMatchingPrefix(PrefixRE, Buffer, LineNumber,
                                                   CheckTy);
    if (UsedPrefix.empty())
      break;
    assert(UsedPrefix.data() == Buffer.data() &&
           "Failed to move Buffer's start forward, or pointed prefix outside "
           "of the buffer!");

                                          
    const char *UsedPrefixStart = UsedPrefix.data();

                                  
    Buffer = Buffer.drop_front(UsedPrefix.size() + CheckTypeSize(CheckTy));

                                                              
    if (CheckTy == Check::CheckBadNot) {
      SM.PrintMessage(SMLoc::getFromPointer(Buffer.data()), SourceMgr::DK_Error,
                      "unsupported -NOT combo on prefix '" + UsedPrefix + "'");
      return true;
    }

                                                                                
                          
    if (!(Req.NoCanonicalizeWhiteSpace && Req.MatchFullLines))
      Buffer = Buffer.substr(Buffer.find_first_not_of(" \t"));

                                     
    size_t EOL = Buffer.find_first_of("\n\r");

                                                                          
    SMLoc PatternLoc = SMLoc::getFromPointer(Buffer.data());

                         
    FileCheckPattern P(CheckTy);
    if (P.ParsePattern(Buffer.substr(0, EOL), UsedPrefix, SM, LineNumber, Req))
      return true;

                                                                   
    if ((CheckTy == Check::CheckLabel) && P.hasVariable()) {
      SM.PrintMessage(
          SMLoc::getFromPointer(UsedPrefixStart), SourceMgr::DK_Error,
          "found '" + UsedPrefix + "-LABEL:'"
                                   " with variable definition or use");
      return true;
    }

    Buffer = Buffer.substr(EOL);

                                                                                        
    if ((CheckTy == Check::CheckNext || CheckTy == Check::CheckSame ||
         CheckTy == Check::CheckEmpty) &&
        CheckStrings.empty()) {
      StringRef Type = CheckTy == Check::CheckNext
                           ? "NEXT"
                           : CheckTy == Check::CheckEmpty ? "EMPTY" : "SAME";
      SM.PrintMessage(SMLoc::getFromPointer(UsedPrefixStart),
                      SourceMgr::DK_Error,
                      "found '" + UsedPrefix + "-" + Type +
                          "' without previous '" + UsedPrefix + ": line");
      return true;
    }

                             
    if (CheckTy == Check::CheckDAG || CheckTy == Check::CheckNot) {
      DagNotMatches.push_back(P);
      continue;
    }

                                                                         
    CheckStrings.emplace_back(P, UsedPrefix, PatternLoc);
    std::swap(DagNotMatches, CheckStrings.back().DagNotStrings);
    DagNotMatches = ImplicitNegativeChecks;
  }

                                                                           
                                              
  if (!DagNotMatches.empty()) {
    CheckStrings.emplace_back(FileCheckPattern(Check::CheckEOF), *Req.CheckPrefixes.begin(),
                              SMLoc::getFromPointer(Buffer.data()));
    std::swap(DagNotMatches, CheckStrings.back().DagNotStrings);
  }

  if (CheckStrings.empty()) {
    errs() << "error: no check strings found with prefix"
           << (Req.CheckPrefixes.size() > 1 ? "es " : " ");
    auto I = Req.CheckPrefixes.begin();
    auto E = Req.CheckPrefixes.end();
    if (I != E) {
      errs() << "\'" << *I << ":'";
      ++I;
    }
    for (; I != E; ++I)
      errs() << ", \'" << *I << ":'";

    errs() << '\n';
    return true;
  }

  return false;
}

static void PrintMatch(bool ExpectedMatch, const SourceMgr &SM,
                       StringRef Prefix, SMLoc Loc, const FileCheckPattern &Pat,
                       StringRef Buffer, StringMap<StringRef> &VariableTable,
                       size_t MatchPos, size_t MatchLen,
                       const FileCheckRequest &Req) {
  if (ExpectedMatch) {
    if (!Req.Verbose)
      return;
    if (!Req.VerboseVerbose && Pat.getCheckTy() == Check::CheckEOF)
      return;
  }
  SMLoc MatchStart = SMLoc::getFromPointer(Buffer.data() + MatchPos);
  SMLoc MatchEnd = SMLoc::getFromPointer(Buffer.data() + MatchPos + MatchLen);
  SMRange MatchRange(MatchStart, MatchEnd);
  SM.PrintMessage(
      Loc, ExpectedMatch ? SourceMgr::DK_Remark : SourceMgr::DK_Error,
      CheckTypeName(Prefix, Pat.getCheckTy()) + ": " +
          (ExpectedMatch ? "expected" : "excluded") +
          " string found in input");
  SM.PrintMessage(MatchStart, SourceMgr::DK_Note, "found here", {MatchRange});
  Pat.PrintVariableUses(SM, Buffer, VariableTable, MatchRange);
}

static void PrintMatch(bool ExpectedMatch, const SourceMgr &SM,
                       const FileCheckString &CheckStr, StringRef Buffer,
                       StringMap<StringRef> &VariableTable, size_t MatchPos,
                       size_t MatchLen, FileCheckRequest &Req) {
  PrintMatch(ExpectedMatch, SM, CheckStr.Prefix, CheckStr.Loc, CheckStr.Pat,
             Buffer, VariableTable, MatchPos, MatchLen, Req);
}

static void PrintNoMatch(bool ExpectedMatch, const SourceMgr &SM,
                         StringRef Prefix, SMLoc Loc, const FileCheckPattern &Pat,
                         StringRef Buffer,
                         StringMap<StringRef> &VariableTable,
                         bool VerboseVerbose) {
  if (!ExpectedMatch && !VerboseVerbose)
    return;

                                                        
  SM.PrintMessage(Loc,
                  ExpectedMatch ? SourceMgr::DK_Error : SourceMgr::DK_Remark,
                  CheckTypeName(Prefix, Pat.getCheckTy()) + ": " +
                      (ExpectedMatch ? "expected" : "excluded") +
                      " string not found in input");

                                                                            
                                                          
  Buffer = Buffer.substr(Buffer.find_first_not_of(" \t\n\r"));

  SM.PrintMessage(SMLoc::getFromPointer(Buffer.data()), SourceMgr::DK_Note,
                  "scanning from here");

                                                                  
  Pat.PrintVariableUses(SM, Buffer, VariableTable);
  if (ExpectedMatch)
    Pat.PrintFuzzyMatch(SM, Buffer, VariableTable);
}

static void PrintNoMatch(bool ExpectedMatch, const SourceMgr &SM,
                         const FileCheckString &CheckStr, StringRef Buffer,
                         StringMap<StringRef> &VariableTable,
                         bool VerboseVerbose) {
  PrintNoMatch(ExpectedMatch, SM, CheckStr.Prefix, CheckStr.Loc, CheckStr.Pat,
               Buffer, VariableTable, VerboseVerbose);
}

                                                        
static unsigned CountNumNewlinesBetween(StringRef Range,
                                        const char *&FirstNewLine) {
  unsigned NumNewLines = 0;
  while (1) {
                        
    Range = Range.substr(Range.find_first_of("\n\r"));
    if (Range.empty())
      return NumNewLines;

    ++NumNewLines;

                                                
    if (Range.size() > 1 && (Range[1] == '\n' || Range[1] == '\r') &&
        (Range[0] != Range[1]))
      Range = Range.substr(1);
    Range = Range.substr(1);

    if (NumNewLines == 1)
      FirstNewLine = Range.begin();
  }
}

                                                                  
size_t FileCheckString::Check(const SourceMgr &SM, StringRef Buffer,
                          bool IsLabelScanMode, size_t &MatchLen,
                          StringMap<StringRef> &VariableTable,
                          FileCheckRequest &Req) const {
  size_t LastPos = 0;
  std::vector<const FileCheckPattern *> NotStrings;

                                                                             
                                                                                
                                                                             
                                                                          
  if (!IsLabelScanMode) {
                                                             
    LastPos = CheckDag(SM, Buffer, NotStrings, VariableTable, Req);
    if (LastPos == StringRef::npos)
      return StringRef::npos;
  }

                                                                  
  StringRef MatchBuffer = Buffer.substr(LastPos);
  size_t MatchPos = Pat.Match(MatchBuffer, MatchLen, VariableTable);
  if (MatchPos == StringRef::npos) {
    PrintNoMatch(true, SM, *this, MatchBuffer, VariableTable, Req.VerboseVerbose);
    return StringRef::npos;
  }
  PrintMatch(true, SM, *this, MatchBuffer, VariableTable, MatchPos, MatchLen, Req);

                                                                              
                 
  if (!IsLabelScanMode) {
    StringRef SkippedRegion = Buffer.substr(LastPos, MatchPos);

                                                                             
                                                                       
    if (CheckNext(SM, SkippedRegion))
      return StringRef::npos;

                                                                             
                                                                  
    if (CheckSame(SM, SkippedRegion))
      return StringRef::npos;

                                                                           
                      
    if (CheckNot(SM, SkippedRegion, NotStrings, VariableTable, Req))
      return StringRef::npos;
  }

  return LastPos + MatchPos;
}

                                                      
bool FileCheckString::CheckNext(const SourceMgr &SM, StringRef Buffer) const {
  if (Pat.getCheckTy() != Check::CheckNext &&
      Pat.getCheckTy() != Check::CheckEmpty)
    return false;

  Twine CheckName =
      Prefix +
      Twine(Pat.getCheckTy() == Check::CheckEmpty ? "-EMPTY" : "-NEXT");

                                                                          
  assert(Buffer.data() !=
             SM.getMemoryBuffer(SM.FindBufferContainingLoc(
                                    SMLoc::getFromPointer(Buffer.data())))
                 ->getBufferStart() &&
         "CHECK-NEXT and CHECK-EMPTY can't be the first check in a file");

  const char *FirstNewLine = nullptr;
  unsigned NumNewLines = CountNumNewlinesBetween(Buffer, FirstNewLine);

  if (NumNewLines == 0) {
    SM.PrintMessage(Loc, SourceMgr::DK_Error,
                    CheckName + ": is on the same line as previous match");
    SM.PrintMessage(SMLoc::getFromPointer(Buffer.end()), SourceMgr::DK_Note,
                    "'next' match was here");
    SM.PrintMessage(SMLoc::getFromPointer(Buffer.data()), SourceMgr::DK_Note,
                    "previous match ended here");
    return true;
  }

  if (NumNewLines != 1) {
    SM.PrintMessage(Loc, SourceMgr::DK_Error,
                    CheckName +
                        ": is not on the line after the previous match");
    SM.PrintMessage(SMLoc::getFromPointer(Buffer.end()), SourceMgr::DK_Note,
                    "'next' match was here");
    SM.PrintMessage(SMLoc::getFromPointer(Buffer.data()), SourceMgr::DK_Note,
                    "previous match ended here");
    SM.PrintMessage(SMLoc::getFromPointer(FirstNewLine), SourceMgr::DK_Note,
                    "non-matching line after previous match is here");
    return true;
  }

  return false;
}

                                                   
bool FileCheckString::CheckSame(const SourceMgr &SM, StringRef Buffer) const {
  if (Pat.getCheckTy() != Check::CheckSame)
    return false;

                                                                          
  assert(Buffer.data() !=
             SM.getMemoryBuffer(SM.FindBufferContainingLoc(
                                    SMLoc::getFromPointer(Buffer.data())))
                 ->getBufferStart() &&
         "CHECK-SAME can't be the first check in a file");

  const char *FirstNewLine = nullptr;
  unsigned NumNewLines = CountNumNewlinesBetween(Buffer, FirstNewLine);

  if (NumNewLines != 0) {
    SM.PrintMessage(Loc, SourceMgr::DK_Error,
                    Prefix +
                        "-SAME: is not on the same line as the previous match");
    SM.PrintMessage(SMLoc::getFromPointer(Buffer.end()), SourceMgr::DK_Note,
                    "'next' match was here");
    SM.PrintMessage(SMLoc::getFromPointer(Buffer.data()), SourceMgr::DK_Note,
                    "previous match ended here");
    return true;
  }

  return false;
}

                                                        
bool FileCheckString::CheckNot(const SourceMgr &SM, StringRef Buffer,
                           const std::vector<const FileCheckPattern *> &NotStrings,
                           StringMap<StringRef> &VariableTable,
                           const FileCheckRequest &Req) const {
  for (const FileCheckPattern *Pat : NotStrings) {
    assert((Pat->getCheckTy() == Check::CheckNot) && "Expect CHECK-NOT!");

    size_t MatchLen = 0;
    size_t Pos = Pat->Match(Buffer, MatchLen, VariableTable);

    if (Pos == StringRef::npos) {
      PrintNoMatch(false, SM, Prefix, Pat->getLoc(), *Pat, Buffer,
                   VariableTable, Req.VerboseVerbose);
      continue;
    }

    PrintMatch(false, SM, Prefix, Pat->getLoc(), *Pat, Buffer, VariableTable,
               Pos, MatchLen, Req);

    return true;
  }

  return false;
}

                                                      
size_t FileCheckString::CheckDag(const SourceMgr &SM, StringRef Buffer,
                             std::vector<const FileCheckPattern *> &NotStrings,
                             StringMap<StringRef> &VariableTable,
                             const FileCheckRequest &Req) const {
  if (DagNotStrings.empty())
    return 0;

                                   
  size_t StartPos = 0;

  struct MatchRange {
    size_t Pos;
    size_t End;
  };
                                                                          
                                                                           
           
  std::list<MatchRange> MatchRanges;

                                                                         
                                                        
  for (auto PatItr = DagNotStrings.begin(), PatEnd = DagNotStrings.end();
       PatItr != PatEnd; ++PatItr) {
    const FileCheckPattern &Pat = *PatItr;
    assert((Pat.getCheckTy() == Check::CheckDAG ||
            Pat.getCheckTy() == Check::CheckNot) &&
           "Invalid CHECK-DAG or CHECK-NOT!");

    if (Pat.getCheckTy() == Check::CheckNot) {
      NotStrings.push_back(&Pat);
      continue;
    }

    assert((Pat.getCheckTy() == Check::CheckDAG) && "Expect CHECK-DAG!");

                                               
    size_t MatchLen = 0, MatchPos = StartPos;

                                                                       
                       
    for (auto MI = MatchRanges.begin(), ME = MatchRanges.end(); true; ++MI) {
      StringRef MatchBuffer = Buffer.substr(MatchPos);
      size_t MatchPosBuf = Pat.Match(MatchBuffer, MatchLen, VariableTable);
                                                                            
                                                    
      if (MatchPosBuf == StringRef::npos) {
        PrintNoMatch(true, SM, Prefix, Pat.getLoc(), Pat, MatchBuffer,
                     VariableTable, Req.VerboseVerbose);
        return StringRef::npos;
      }
                                                                               
      MatchPos += MatchPosBuf;
      if (Req.VerboseVerbose)
        PrintMatch(true, SM, Prefix, Pat.getLoc(), Pat, Buffer, VariableTable,
                   MatchPos, MatchLen, Req);
      MatchRange M{MatchPos, MatchPos + MatchLen};
      if (Req.AllowDeprecatedDagOverlap) {
                                                                               
                                                                         
                   
        if (MatchRanges.empty())
          MatchRanges.insert(MatchRanges.end(), M);
        else {
          auto Block = MatchRanges.begin();
          Block->Pos = std::min(Block->Pos, M.Pos);
          Block->End = std::max(Block->End, M.End);
        }
        break;
      }
                                                                             
      bool Overlap = false;
      for (; MI != ME; ++MI) {
        if (M.Pos < MI->End) {
                                                                               
                                                          
          Overlap = MI->Pos < M.End;
          break;
        }
      }
      if (!Overlap) {
                                                  
        MatchRanges.insert(MI, M);
        break;
      }
      if (Req.VerboseVerbose) {
        SMLoc OldStart = SMLoc::getFromPointer(Buffer.data() + MI->Pos);
        SMLoc OldEnd = SMLoc::getFromPointer(Buffer.data() + MI->End);
        SMRange OldRange(OldStart, OldEnd);
        SM.PrintMessage(OldStart, SourceMgr::DK_Note,
                        "match discarded, overlaps earlier DAG match here",
                        {OldRange});
      }
      MatchPos = MI->End;
    }
    if (!Req.VerboseVerbose)
      PrintMatch(true, SM, Prefix, Pat.getLoc(), Pat, Buffer, VariableTable,
                 MatchPos, MatchLen, Req);

                                           
    if (std::next(PatItr) == PatEnd ||
        std::next(PatItr)->getCheckTy() == Check::CheckNot) {
      if (!NotStrings.empty()) {
                                                                          
                                                                             
                  
        StringRef SkippedRegion =
            Buffer.slice(StartPos, MatchRanges.begin()->Pos);
        if (CheckNot(SM, SkippedRegion, NotStrings, VariableTable, Req))
          return StringRef::npos;
                               
        NotStrings.clear();
      }
                                                                            
                                                   
      StartPos = MatchRanges.rbegin()->End;
                                                                         
      MatchRanges.clear();
    }
  }

  return StartPos;
}

                                                                          
static bool ValidateCheckPrefix(StringRef CheckPrefix) {
  Regex Validator("^[a-zA-Z0-9_-]*$");
  return Validator.match(CheckPrefix);
}

bool llvh::FileCheck::ValidateCheckPrefixes() {
  StringSet<> PrefixSet;

  for (StringRef Prefix : Req.CheckPrefixes) {
                             
    if (Prefix == "")
      return false;

    if (!PrefixSet.insert(Prefix).second)
      return false;

    if (!ValidateCheckPrefix(Prefix))
      return false;
  }

  return true;
}

                                                                             
                           
  
                                                                        
           
Regex llvh::FileCheck::buildCheckPrefixRegex() {
                                                                          
                                                 
  if (Req.CheckPrefixes.empty())
    Req.CheckPrefixes.push_back("CHECK");

                                                                           
                          
  SmallString<32> PrefixRegexStr;
  for (StringRef Prefix : Req.CheckPrefixes) {
    if (Prefix != Req.CheckPrefixes.front())
      PrefixRegexStr.push_back('|');

    PrefixRegexStr.append(Prefix);
  }

  return Regex(PrefixRegexStr);
}

                                                                 
                                  
static void ClearLocalVars(StringMap<StringRef> &VariableTable) {
  SmallVector<StringRef, 16> LocalVars;
  for (const auto &Var : VariableTable)
    if (Var.first()[0] != '$')
      LocalVars.push_back(Var.first());

  for (const auto &Var : LocalVars)
    VariableTable.erase(Var);
}

                                                                         
                                          
   
                                                           
bool llvh::FileCheck::CheckInput(SourceMgr &SM, StringRef Buffer,
                ArrayRef<FileCheckString> CheckStrings) {
  bool ChecksFailed = false;

                                                                     
  StringMap<StringRef> VariableTable;

  for (const auto& Def : Req.GlobalDefines)
    VariableTable.insert(StringRef(Def).split('='));

  unsigned i = 0, j = 0, e = CheckStrings.size();
  while (true) {
    StringRef CheckRegion;
    if (j == e) {
      CheckRegion = Buffer;
    } else {
      const FileCheckString &CheckLabelStr = CheckStrings[j];
      if (CheckLabelStr.Pat.getCheckTy() != Check::CheckLabel) {
        ++j;
        continue;
      }

                                                                         
      size_t MatchLabelLen = 0;
      size_t MatchLabelPos =
          CheckLabelStr.Check(SM, Buffer, true, MatchLabelLen, VariableTable,
                              Req);
      if (MatchLabelPos == StringRef::npos)
                                                                         
        return false;

      CheckRegion = Buffer.substr(0, MatchLabelPos + MatchLabelLen);
      Buffer = Buffer.substr(MatchLabelPos + MatchLabelLen);
      ++j;
    }

    if (Req.EnableVarScope)
      ClearLocalVars(VariableTable);

    for (; i != j; ++i) {
      const FileCheckString &CheckStr = CheckStrings[i];

                                                                              
                                                                     
      size_t MatchLen = 0;
      size_t MatchPos =
          CheckStr.Check(SM, CheckRegion, false, MatchLen, VariableTable, Req);

      if (MatchPos == StringRef::npos) {
        ChecksFailed = true;
        i = j;
        break;
      }

      CheckRegion = CheckRegion.substr(MatchPos + MatchLen);
    }

    if (j == e)
      break;
  }

                                 
  return !ChecksFailed;
}
