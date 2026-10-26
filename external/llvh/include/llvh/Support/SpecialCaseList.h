//===-- SpecialCaseList.h - special case list for sanitizers ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//===----------------------------------------------------------------------===//
//
// This is a utility class used to parse user-provided text files with
// "special case lists" for code sanitizers. Such files are used to
// define an "ABI list" for DataFlowSanitizer and blacklists for sanitizers
// like AddressSanitizer or UndefinedBehaviorSanitizer.
//
// Empty lines and lines starting with "#" are ignored. Sections are defined
// using a '[section_name]' header and can be used to specify sanitizers the
// entries below it apply to. Section names are regular expressions, and
// entries without a section header match all sections (e.g. an '[*]' header
// is assumed.)
// The remaining lines should have the form:
//   prefix:wildcard_expression[=category]
// If category is not specified, it is assumed to be empty string.
// Definitions of "prefix" and "category" are sanitizer-specific. For example,
// sanitizer blacklists support prefixes "src", "fun" and "global".
// Wildcard expressions define, respectively, source files, functions or
// globals which shouldn't be instrumented.
// Examples of categories:
//   "functional": used in DFSan to list functions with pure functional
//                 semantics.
//   "init": used in ASan blacklist to disable initialization-order bugs
//           detection for certain globals or source files.
// Full special case list file example:
// ---
// [address]
// # Blacklisted items:
// fun:*_ZN4base6subtle*
// global:*global_with_bad_access_or_initialization*
// global:*global_with_initialization_issues*=init
// type:*Namespace::ClassName*=init
// src:file_with_tricky_code.cc
// src:ignore-global-initializers-issues.cc=init
//
// [dataflow]
// # Functions with pure functional semantics:
// fun:cos=functional
// fun:sin=functional
// ---
// Note that the wild card is in fact an llvh::Regex, but * is automatically
// replaced with .*
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_SPECIALCASELIST_H
#define LLVM_SUPPORT_SPECIALCASELIST_H

#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringSet.h"
#include "llvh/Support/Regex.h"
#include "llvh/Support/TrigramIndex.h"
#include <string>
#include <vector>

namespace llvh {
class MemoryBuffer;
class Regex;
class StringRef;

class SpecialCaseList {
public:
                                                                          
                                              
  static std::unique_ptr<SpecialCaseList>
  create(const std::vector<std::string> &Paths, std::string &Error);
                                                                            
                                              
  static std::unique_ptr<SpecialCaseList> create(const MemoryBuffer *MB,
                                                 std::string &Error);
                                                                            
                  
  static std::unique_ptr<SpecialCaseList>
  createOrDie(const std::vector<std::string> &Paths);

  ~SpecialCaseList();

                                                        
           
                             
              
                                                                         
  bool inSection(StringRef Section, StringRef Prefix, StringRef Query,
                 StringRef Category = StringRef()) const;

                                                                             
                                           
           
                             
              
                                                                         
                                                                       
                 
  unsigned inSectionBlame(StringRef Section, StringRef Prefix, StringRef Query,
                          StringRef Category = StringRef()) const;

protected:
                                                                                
             
  bool createInternal(const std::vector<std::string> &Paths,
                      std::string &Error);
  bool createInternal(const MemoryBuffer *MB, std::string &Error);

  SpecialCaseList() = default;
  SpecialCaseList(SpecialCaseList const &) = delete;
  SpecialCaseList &operator=(SpecialCaseList const &) = delete;

                                                                             
                                                                          
                                                                             
                                 
  class Matcher {
  public:
    bool insert(std::string Regexp, unsigned LineNumber, std::string &REError);
                                                                             
                                         
    unsigned match(StringRef Query) const;

  private:
    StringMap<unsigned> Strings;
    TrigramIndex Trigrams;
    std::vector<std::pair<std::unique_ptr<Regex>, unsigned>> RegExes;
  };

  using SectionEntries = StringMap<StringMap<Matcher>>;

  struct Section {
    Section(std::unique_ptr<Matcher> M) : SectionMatcher(std::move(M)){};

    std::unique_ptr<Matcher> SectionMatcher;
    SectionEntries Entries;
  };

  std::vector<Section> Sections;

                                                                           
  bool parse(const MemoryBuffer *MB, StringMap<size_t> &SectionsMap,
             std::string &Error);

                                                                               
                                                     
  unsigned inSectionBlame(const SectionEntries &Entries, StringRef Prefix,
                          StringRef Query, StringRef Category) const;
};

}                   

#endif                                   

