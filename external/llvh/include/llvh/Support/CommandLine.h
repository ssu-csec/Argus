//===- llvm/Support/CommandLine.h - Command line handler --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class implements a command line argument processor that is useful when
// creating a tool.  It provides a simple, minimalistic interface that is easily
// extensible and supports nonlocal (library) command line options.
//
// Note that rather than trying to figure out what this code does, you should
// read the library documentation located in docs/CommandLine.html or looks at
// the many example usages in tools/*/*.cpp
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_COMMANDLINE_H
#define LLVM_SUPPORT_COMMANDLINE_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/ManagedStatic.h"
#include "llvh/Support/raw_ostream.h"
#include <cassert>
#include <climits>
#include <cstddef>
#include <functional>
#include <initializer_list>
#include <string>
#include <type_traits>
#include <vector>

namespace llvh {

class StringSaver;
class raw_ostream;

                                                                         
                                                                             
                  
namespace cl {

                                                                                
                                                                        
  
                                                                           
                                                                           
                                                                    
bool ParseCommandLineOptions(int argc, const char *const *argv,
                             StringRef Overview = "",
                             raw_ostream *Errs = nullptr);

                                                                                
                                                                             
                                         
  
void ParseEnvironmentOptions(const char *progName, const char *envvar,
                             const char *Overview = "");

                                                          
using VersionPrinterTy = std::function<void(raw_ostream &)>;

                                                                                
                                                                            
                                                                             
                                                                                
                                                                                
void SetVersionPrinter(VersionPrinterTy func);

                                                                                
                                                                           
                                                                            
                                                                             
                                                                              
                                                                               
                                                              
void AddExtraVersionPrinter(VersionPrinterTy func);

                                           
                                                                               
                                                   
                                            
void PrintOptionValues();

                                                                                
class Option;

                                                                       
   
                                  
                                                                       
   
                                                                               
                                                                
void AddLiteralOption(Option &O, StringRef Name);

                                                                                
                                                         
  

enum NumOccurrencesFlag {                                               
  Optional = 0x00,                                 
  ZeroOrMore = 0x01,                                         
  Required = 0x02,                                  
  OneOrMore = 0x03,                                          

                                                                               
                                                                            
                                                                             
                                                                              
                                                                          
                                                     
    
  ConsumeAfter = 0x04
};

enum ValueExpected {                                       
                                            
  ValueOptional = 0x01,                                   
  ValueRequired = 0x02,                                     
  ValueDisallowed = 0x03                                            
};

enum OptionHidden {                                             
  NotHidden = 0x00,                                             
  Hidden = 0x01,                                             
  ReallyHidden = 0x02                                                
};

                                                                               
                                            
  
                                                                              
                                                                                
                                                                          
                                                                         
                                                                         
            
  
                                                                              
                                                                             
                                                                          
  

enum FormattingFlags {
  NormalFormatting = 0x00,                   
  Positional = 0x01,                                                   
  Prefix = 0x02,                                                        
  Grouping = 0x03                                                      
};

enum MiscFlags {                                                      
  CommaSeparated = 0x01,                                                  
  PositionalEatsArgs = 0x02,                                              
  Sink = 0x04                                                                
};

                                                                                
                        
  
class OptionCategory {
private:
  StringRef const Name;
  StringRef const Description;

  void registerCategory();

public:
  OptionCategory(StringRef const Name,
                 StringRef const Description = "")
      : Name(Name), Description(Description) {
    registerCategory();
  }

  StringRef getName() const { return Name; }
  StringRef getDescription() const { return Description; }
};

                                                          
extern OptionCategory GeneralCategory;

                                                                                
                   
  
class SubCommand {
private:
  StringRef Name;
  StringRef Description;

protected:
  void registerSubCommand();
  void unregisterSubCommand();

public:
  SubCommand(StringRef Name, StringRef Description = "")
      : Name(Name), Description(Description) {
        registerSubCommand();
  }
  SubCommand() = default;

  void reset();

  explicit operator bool() const;

  StringRef getName() const { return Name; }
  StringRef getDescription() const { return Description; }

  SmallVector<Option *, 4> PositionalOpts;
  SmallVector<Option *, 4> SinkOpts;
  StringMap<Option *> OptionsMap;

  Option *ConsumeAfterOpt = nullptr;                                         
};

                                                  
extern ManagedStatic<SubCommand> TopLevelSubCommand;

                                                                               
extern ManagedStatic<SubCommand> AllSubCommands;

                                                                                
                    
  
class Option {
  friend class alias;

                                                                                
                                                                          
                                          
    
  virtual bool handleOccurrence(unsigned pos, StringRef ArgName,
                                StringRef Arg) = 0;

  virtual enum ValueExpected getValueExpectedFlagDefault() const {
    return ValueOptional;
  }

                                                                
  virtual void anchor();

  int NumOccurrences = 0;                                 
                                                                            
                                             
  unsigned Occurrences : 3;                           
                                                                          
                                      
  unsigned Value : 2;
  unsigned HiddenFlag : 2;                     
  unsigned Formatting : 2;                        
  unsigned Misc : 3;
  unsigned Position = 0;                                                   
  unsigned AdditionalVals = 0;                                           

public:
  StringRef ArgStr;                                                  
  StringRef HelpStr;                                           
  StringRef ValueStr;                                                      
  OptionCategory *Category;                                       
  SmallPtrSet<SubCommand *, 4> Subs;                                           
  bool FullyInitialized = false;                                

  inline enum NumOccurrencesFlag getNumOccurrencesFlag() const {
    return (enum NumOccurrencesFlag)Occurrences;
  }

  inline enum ValueExpected getValueExpectedFlag() const {
    return Value ? ((enum ValueExpected)Value) : getValueExpectedFlagDefault();
  }

  inline enum OptionHidden getOptionHiddenFlag() const {
    return (enum OptionHidden)HiddenFlag;
  }

  inline enum FormattingFlags getFormattingFlag() const {
    return (enum FormattingFlags)Formatting;
  }

  inline unsigned getMiscFlags() const { return Misc; }
  inline unsigned getPosition() const { return Position; }
  inline unsigned getNumAdditionalVals() const { return AdditionalVals; }

                                                
  bool hasArgStr() const { return !ArgStr.empty(); }
  bool isPositional() const { return getFormattingFlag() == cl::Positional; }
  bool isSink() const { return getMiscFlags() & cl::Sink; }

  bool isConsumeAfter() const {
    return getNumOccurrencesFlag() == cl::ConsumeAfter;
  }

  bool isInAllSubCommands() const {
    return any_of(Subs, [](const SubCommand *SC) {
      return SC == &*AllSubCommands;
    });
  }

                                                                                
                                              
    
  void setArgStr(StringRef S);
  void setDescription(StringRef S) { HelpStr = S; }
  void setValueStr(StringRef S) { ValueStr = S; }
  void setNumOccurrencesFlag(enum NumOccurrencesFlag Val) { Occurrences = Val; }
  void setValueExpectedFlag(enum ValueExpected Val) { Value = Val; }
  void setHiddenFlag(enum OptionHidden Val) { HiddenFlag = Val; }
  void setFormattingFlag(enum FormattingFlags V) { Formatting = V; }
  void setMiscFlag(enum MiscFlags M) { Misc |= M; }
  void setPosition(unsigned pos) { Position = pos; }
  void setCategory(OptionCategory &C) { Category = &C; }
  void addSubCommand(SubCommand &S) { Subs.insert(&S); }

protected:
  explicit Option(enum NumOccurrencesFlag OccurrencesFlag,
                  enum OptionHidden Hidden)
      : Occurrences(OccurrencesFlag), Value(0), HiddenFlag(Hidden),
        Formatting(NormalFormatting), Misc(0), Category(&GeneralCategory) {}

  inline void setNumAdditionalVals(unsigned n) { AdditionalVals = n; }

public:
  virtual ~Option() = default;

                                                                      
    
  void addArgument();

                                                          
     
                                                            
                                
  void removeArgument();

                                                       
  virtual size_t getOptionWidth() const = 0;

                                                                    
                                         
    
  virtual void printOptionInfo(size_t GlobalWidth) const = 0;

  virtual void printOptionValue(size_t GlobalWidth, bool Force) const = 0;

  virtual void setDefault() = 0;

  static void printHelpStr(StringRef HelpStr, size_t Indent,
                           size_t FirstLineIndentedBy);

  virtual void getExtraOptionNames(SmallVectorImpl<StringRef> &) {}

                                                                         
    
  virtual bool addOccurrence(unsigned pos, StringRef ArgName, StringRef Value,
                             bool MultiArg = false);

                                                                  
  bool error(const Twine &Message, StringRef ArgName = StringRef(), raw_ostream &Errs = llvh::errs());
  bool error(const Twine &Message, raw_ostream &Errs) {
    return error(Message, StringRef(), Errs);
  }

  inline int getNumOccurrences() const { return NumOccurrences; }
  inline void reset() { NumOccurrences = 0; }
};

                                                                                
                                                                           
                                 
  

                                                                      
struct desc {
  StringRef Desc;

  desc(StringRef Str) : Desc(Str) {}

  void apply(Option &O) const { O.setDescription(Desc); }
};

                                                                        
            
struct value_desc {
  StringRef Desc;

  value_desc(StringRef Str) : Desc(Str) {}

  void apply(Option &O) const { O.setValueStr(Desc); }
};

                                                                             
                                                                           
                                                                         
  
template <class Ty> struct initializer {
  const Ty &Init;
  initializer(const Ty &Val) : Init(Val) {}

  template <class Opt> void apply(Opt &O) const { O.setInitialValue(Init); }
};

template <class Ty> initializer<Ty> init(const Ty &Val) {
  return initializer<Ty>(Val);
}

                                                                            
                                                                                
                                         
  
template <class Ty> struct LocationClass {
  Ty &Loc;

  LocationClass(Ty &L) : Loc(L) {}

  template <class Opt> void apply(Opt &O) const { O.setLocation(O, Loc); }
};

template <class Ty> LocationClass<Ty> location(Ty &L) {
  return LocationClass<Ty>(L);
}

                                                                             
      
struct cat {
  OptionCategory &Category;

  cat(OptionCategory &c) : Category(c) {}

  template <class Opt> void apply(Opt &O) const { O.setCategory(Category); }
};

                                                            
struct sub {
  SubCommand &Sub;

  sub(SubCommand &S) : Sub(S) {}

  template <class Opt> void apply(Opt &O) const { O.addSubCommand(Sub); }
};

                                                                                
                    

                                                 
struct GenericOptionValue {
  virtual bool compare(const GenericOptionValue &V) const = 0;

protected:
  GenericOptionValue() = default;
  GenericOptionValue(const GenericOptionValue&) = default;
  GenericOptionValue &operator=(const GenericOptionValue &) = default;
  ~GenericOptionValue() = default;

private:
  virtual void anchor();
};

template <class DataType> struct OptionValue;

                                                                       
               
template <class DataType, bool isClass>
struct OptionValueBase : public GenericOptionValue {
                                            
  using WrapperType = OptionValue<DataType>;

  bool hasValue() const { return false; }

  const DataType &getValue() const { llvm_unreachable("no default value"); }

                                                                  
  template <class DT> void setValue(const DT &      ) {}

  bool compare(const DataType &      ) const { return false; }

  bool compare(const GenericOptionValue &      ) const override {
    return false;
  }

protected:
  ~OptionValueBase() = default;
};

                                   
template <class DataType> class OptionValueCopy : public GenericOptionValue {
  DataType Value;
  bool Valid = false;

protected:
  OptionValueCopy(const OptionValueCopy&) = default;
  OptionValueCopy &operator=(const OptionValueCopy &) = default;
  ~OptionValueCopy() = default;

public:
  OptionValueCopy() = default;

  bool hasValue() const { return Valid; }

  const DataType &getValue() const {
    assert(Valid && "invalid option value");
    return Value;
  }

  void setValue(const DataType &V) {
    Valid = true;
    Value = V;
  }

  bool compare(const DataType &V) const { return Valid && (Value != V); }

  bool compare(const GenericOptionValue &V) const override {
    const OptionValueCopy<DataType> &VC =
        static_cast<const OptionValueCopy<DataType> &>(V);
    if (!VC.hasValue())
      return false;
    return compare(VC.getValue());
  }
};

                           
template <class DataType>
struct OptionValueBase<DataType, false> : OptionValueCopy<DataType> {
  using WrapperType = DataType;

protected:
  OptionValueBase() = default;
  OptionValueBase(const OptionValueBase&) = default;
  OptionValueBase &operator=(const OptionValueBase &) = default;
  ~OptionValueBase() = default;
};

                          
template <class DataType>
struct OptionValue final
    : OptionValueBase<DataType, std::is_class<DataType>::value> {
  OptionValue() = default;

  OptionValue(const DataType &V) { this->setValue(V); }

                                                                  
  template <class DT> OptionValue<DataType> &operator=(const DT &V) {
    this->setValue(V);
    return *this;
  }
};

                                                   
enum boolOrDefault { BOU_UNSET, BOU_TRUE, BOU_FALSE };
template <>
struct OptionValue<cl::boolOrDefault> final
    : OptionValueCopy<cl::boolOrDefault> {
  using WrapperType = cl::boolOrDefault;

  OptionValue() = default;

  OptionValue(const cl::boolOrDefault &V) { this->setValue(V); }

  OptionValue<cl::boolOrDefault> &operator=(const cl::boolOrDefault &V) {
    setValue(V);
    return *this;
  }

private:
  void anchor() override;
};

template <>
struct OptionValue<std::string> final : OptionValueCopy<std::string> {
  using WrapperType = StringRef;

  OptionValue() = default;

  OptionValue(const std::string &V) { this->setValue(V); }

  OptionValue<std::string> &operator=(const std::string &V) {
    setValue(V);
    return *this;
  }

private:
  void anchor() override;
};

                                                                                
                                  
  

                                                                           
struct OptionEnumValue {
  StringRef Name;
  int Value;
  StringRef Description;
};

#define clEnumVal(ENUMVAL, DESC)                                               \
  llvh::cl::OptionEnumValue { #ENUMVAL, int(ENUMVAL), DESC }
#define clEnumValN(ENUMVAL, FLAGNAME, DESC)                                    \
  llvh::cl::OptionEnumValue { FLAGNAME, int(ENUMVAL), DESC }

                                                                              
                                                                       
  
class ValuesClass {
                                                                      
                                                                           
                                                    
  SmallVector<OptionEnumValue, 4> Values;

public:
  ValuesClass(std::initializer_list<OptionEnumValue> Options)
      : Values(Options) {}

  template <class Opt> void apply(Opt &O) const {
    for (auto Value : Values)
      O.getParser().addLiteralOption(Value.Name, Value.Value,
                                     Value.Description);
  }
};

                                                                              
                                                          
template <typename... OptsTy> ValuesClass values(OptsTy... Options) {
  return ValuesClass({Options...});
}

                                                                                
                                                                               
                                                                              
                                                                          
                                                                             
                                                  

                                                    
                                                                             
                                                                           
                                              
  
class generic_parser_base {
protected:
  class GenericOptionInfo {
  public:
    GenericOptionInfo(StringRef name, StringRef helpStr)
        : Name(name), HelpStr(helpStr) {}
    StringRef Name;
    StringRef HelpStr;
  };

public:
  generic_parser_base(Option &O) : Owner(O) {}

  virtual ~generic_parser_base() = default;
                                              

                                                                        
                                             
    
  virtual unsigned getNumOptions() const = 0;

                                      
  virtual StringRef getOption(unsigned N) const = 0;

                                          
  virtual StringRef getDescription(unsigned N) const = 0;

                                                       
  virtual size_t getOptionWidth(const Option &O) const;

  virtual const GenericOptionValue &getOptionValue(unsigned N) const = 0;

                                                                    
                                         
    
  virtual void printOptionInfo(const Option &O, size_t GlobalWidth) const;

  void printGenericOptionDiff(const Option &O, const GenericOptionValue &V,
                              const GenericOptionValue &Default,
                              size_t GlobalWidth) const;

                                                                     
    
                                                                          
                                            
  template <class AnyOptionValue>
  void printOptionDiff(const Option &O, const AnyOptionValue &V,
                       const AnyOptionValue &Default,
                       size_t GlobalWidth) const {
    printGenericOptionDiff(O, V, Default, GlobalWidth);
  }

  void initialize() {}

  void getExtraOptionNames(SmallVectorImpl<StringRef> &OptionNames) {
                                                                               
                                                                             
                      
    if (!Owner.hasArgStr())
      for (unsigned i = 0, e = getNumOptions(); i != e; ++i)
        OptionNames.push_back(getOption(i));
  }

  enum ValueExpected getValueExpectedFlagDefault() const {
                                                                
      
                                            
      
                                                                             
                                          
      
                                                                 
      
                                                    
      
    if (Owner.hasArgStr())
      return ValueRequired;
    else
      return ValueDisallowed;
  }

                                                                         
                                                                               
    
  unsigned findOption(StringRef Name);

protected:
  Option &Owner;
};

                                                                          
                                                                              
                                                                                
                                                                               
                                         
  
template <class DataType> class parser : public generic_parser_base {
protected:
  class OptionInfo : public GenericOptionInfo {
  public:
    OptionInfo(StringRef name, DataType v, StringRef helpStr)
        : GenericOptionInfo(name, helpStr), V(v) {}

    OptionValue<DataType> V;
  };
  SmallVector<OptionInfo, 8> Values;

public:
  parser(Option &O) : generic_parser_base(O) {}

  using parser_data_type = DataType;

                                                              
  unsigned getNumOptions() const override { return unsigned(Values.size()); }
  StringRef getOption(unsigned N) const override { return Values[N].Name; }
  StringRef getDescription(unsigned N) const override {
    return Values[N].HelpStr;
  }

                                                        
  const GenericOptionValue &getOptionValue(unsigned N) const override {
    return Values[N].V;
  }

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg, DataType &V) {
    StringRef ArgVal;
    if (Owner.hasArgStr())
      ArgVal = Arg;
    else
      ArgVal = ArgName;

    for (size_t i = 0, e = Values.size(); i != e; ++i)
      if (Values[i].Name == ArgVal) {
        V = Values[i].V.getValue();
        return false;
      }

    return O.error("Cannot find option named '" + ArgVal + "'!");
  }

                                                           
     
  template <class DT>
  void addLiteralOption(StringRef Name, const DT &V, StringRef HelpStr) {
    assert(findOption(Name) == Values.size() && "Option already exists!");
    OptionInfo X(Name, static_cast<DataType>(V), HelpStr);
    Values.push_back(X);
    AddLiteralOption(Owner, Name);
  }

                                                        
     
  void removeLiteralOption(StringRef Name) {
    unsigned N = findOption(Name);
    assert(N != Values.size() && "Option not found!");
    Values.erase(Values.begin() + N);
  }
};

                                                    
                                                                    
  
class basic_parser_impl {                                                  
public:
  basic_parser_impl(Option &) {}

  enum ValueExpected getValueExpectedFlagDefault() const {
    return ValueRequired;
  }

  void getExtraOptionNames(SmallVectorImpl<StringRef> &) {}

  void initialize() {}

                                                       
  size_t getOptionWidth(const Option &O) const;

                                                                    
                                         
    
  void printOptionInfo(const Option &O, size_t GlobalWidth) const;

                                                                                
                       
  void printOptionNoValue(const Option &O, size_t GlobalWidth) const;

                                                                           
  virtual StringRef getValueName() const { return "value"; }

                                                                      
  virtual void anchor();

protected:
  ~basic_parser_impl() = default;

                                                
  void printOptionName(const Option &O, size_t GlobalWidth) const;
};

                                                                                
                                        
  
template <class DataType> class basic_parser : public basic_parser_impl {
public:
  using parser_data_type = DataType;
  using OptVal = OptionValue<DataType>;

  basic_parser(Option &O) : basic_parser_impl(O) {}

protected:
  ~basic_parser() = default;
};

                                                    
               
  
template <> class parser<bool> final : public basic_parser<bool> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg, bool &Val);

  void initialize() {}

  enum ValueExpected getValueExpectedFlagDefault() const {
    return ValueOptional;
  }

                                                 
  StringRef getValueName() const override { return StringRef(); }

  void printOptionDiff(const Option &O, bool V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<bool>;

                                                    
                        
template <>
class parser<boolOrDefault> final : public basic_parser<boolOrDefault> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg, boolOrDefault &Val);

  enum ValueExpected getValueExpectedFlagDefault() const {
    return ValueOptional;
  }

                                                 
  StringRef getValueName() const override { return StringRef(); }

  void printOptionDiff(const Option &O, boolOrDefault V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<boolOrDefault>;

                                                    
              
  
template <> class parser<int> final : public basic_parser<int> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg, int &Val);

                                                                           
  StringRef getValueName() const override { return "int"; }

  void printOptionDiff(const Option &O, int V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<int>;

                                                    
                   
  
template <> class parser<unsigned> final : public basic_parser<unsigned> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg, unsigned &Val);

                                                                           
  StringRef getValueName() const override { return "uint"; }

  void printOptionDiff(const Option &O, unsigned V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<unsigned>;

                                                    
                             
  
template <>
class parser<unsigned long long> final
    : public basic_parser<unsigned long long> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg,
             unsigned long long &Val);

                                                                           
  StringRef getValueName() const override { return "uint"; }

  void printOptionDiff(const Option &O, unsigned long long V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<unsigned long long>;

                                                    
                 
  
template <> class parser<double> final : public basic_parser<double> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg, double &Val);

                                                                           
  StringRef getValueName() const override { return "number"; }

  void printOptionDiff(const Option &O, double V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<double>;

                                                    
                
  
template <> class parser<float> final : public basic_parser<float> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &O, StringRef ArgName, StringRef Arg, float &Val);

                                                                           
  StringRef getValueName() const override { return "number"; }

  void printOptionDiff(const Option &O, float V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<float>;

                                                    
                      
  
template <> class parser<std::string> final : public basic_parser<std::string> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &, StringRef, StringRef Arg, std::string &Value) {
    Value = Arg.str();
    return false;
  }

                                                                           
  StringRef getValueName() const override { return "string"; }

  void printOptionDiff(const Option &O, StringRef V, const OptVal &Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<std::string>;

                                                    
               
  
template <> class parser<char> final : public basic_parser<char> {
public:
  parser(Option &O) : basic_parser(O) {}

                                  
  bool parse(Option &, StringRef, StringRef Arg, char &Value) {
    Value = Arg[0];
    return false;
  }

                                                                           
  StringRef getValueName() const override { return "char"; }

  void printOptionDiff(const Option &O, char V, OptVal Default,
                       size_t GlobalWidth) const;

                                                                      
  void anchor() override;
};

extern template class basic_parser<char>;

                                                    
                  
  
                                                                              
                                               

                                                              
template <class ParserClass, class DT>
void printOptionDiff(const Option &O, const generic_parser_base &P, const DT &V,
                     const OptionValue<DT> &Default, size_t GlobalWidth) {
  OptionValue<DT> OV = V;
  P.printOptionDiff(O, OV, Default, GlobalWidth);
}

                                                                               
                                                
template <class ParserDT, class ValDT> struct OptionDiffPrinter {
  void print(const Option &O, const parser<ParserDT> &P, const ValDT &      ,
             const OptionValue<ValDT> &            , size_t GlobalWidth) {
    P.printOptionNoValue(O, GlobalWidth);
  }
};

                                                                            
                            
template <class DT> struct OptionDiffPrinter<DT, DT> {
  void print(const Option &O, const parser<DT> &P, const DT &V,
             const OptionValue<DT> &Default, size_t GlobalWidth) {
    P.printOptionDiff(O, V, Default, GlobalWidth);
  }
};

                                                                              
                                       
template <class ParserClass, class ValDT>
void printOptionDiff(
    const Option &O,
    const basic_parser<typename ParserClass::parser_data_type> &P,
    const ValDT &V, const OptionValue<ValDT> &Default, size_t GlobalWidth) {

  OptionDiffPrinter<typename ParserClass::parser_data_type, ValDT> printer;
  printer.print(O, static_cast<const ParserClass &>(P), V, Default,
                GlobalWidth);
}

                                                                                
                                                                    
                                                                                
                                                                              
                                                                         
  
template <class Mod> struct applicator {
  template <class Opt> static void opt(const Mod &M, Opt &O) { M.apply(O); }
};

                                          
template <unsigned n> struct applicator<char[n]> {
  template <class Opt> static void opt(StringRef Str, Opt &O) {
    O.setArgStr(Str);
  }
};
template <unsigned n> struct applicator<const char[n]> {
  template <class Opt> static void opt(StringRef Str, Opt &O) {
    O.setArgStr(Str);
  }
};
template <> struct applicator<StringRef > {
  template <class Opt> static void opt(StringRef Str, Opt &O) {
    O.setArgStr(Str);
  }
};

template <> struct applicator<NumOccurrencesFlag> {
  static void opt(NumOccurrencesFlag N, Option &O) {
    O.setNumOccurrencesFlag(N);
  }
};

template <> struct applicator<ValueExpected> {
  static void opt(ValueExpected VE, Option &O) { O.setValueExpectedFlag(VE); }
};

template <> struct applicator<OptionHidden> {
  static void opt(OptionHidden OH, Option &O) { O.setHiddenFlag(OH); }
};

template <> struct applicator<FormattingFlags> {
  static void opt(FormattingFlags FF, Option &O) { O.setFormattingFlag(FF); }
};

template <> struct applicator<MiscFlags> {
  static void opt(MiscFlags MF, Option &O) { O.setMiscFlag(MF); }
};

                                                                  
template <class Opt, class Mod, class... Mods>
void apply(Opt *O, const Mod &M, const Mods &... Ms) {
  applicator<Mod>::opt(M, *O);
  apply(O, Ms...);
}

template <class Opt, class Mod> void apply(Opt *O, const Mod &M) {
  applicator<Mod>::opt(M, *O);
}

                                                                                
                    

                                                                           
                                                                           
                            
  
template <class DataType, bool ExternalStorage, bool isClass>
class opt_storage {
  DataType *Location = nullptr;                                
  OptionValue<DataType> Default;

  void check_location() const {
    assert(Location && "cl::location(...) not specified for a command "
                       "line option with external storage, "
                       "or cl::init specified before cl::location()!!");
  }

public:
  opt_storage() = default;

  bool setLocation(Option &O, DataType &L) {
    if (Location)
      return O.error("cl::location(x) specified more than once!");
    Location = &L;
    Default = L;
    return false;
  }

  template <class T> void setValue(const T &V, bool initial = false) {
    check_location();
    *Location = V;
    if (initial)
      Default = V;
  }

  DataType &getValue() {
    check_location();
    return *Location;
  }
  const DataType &getValue() const {
    check_location();
    return *Location;
  }

  operator DataType() const { return this->getValue(); }

  const OptionValue<DataType> &getDefault() const { return Default; }
};

                                                                          
                                                                             
                                       
  
template <class DataType>
class opt_storage<DataType, false, true> : public DataType {
public:
  OptionValue<DataType> Default;

  template <class T> void setValue(const T &V, bool initial = false) {
    DataType::operator=(V);
    if (initial)
      Default = V;
  }

  DataType &getValue() { return *this; }
  const DataType &getValue() const { return *this; }

  const OptionValue<DataType> &getDefault() const { return Default; }
};

                                                                               
                                                                              
                       
  
template <class DataType> class opt_storage<DataType, false, false> {
public:
  DataType Value;
  OptionValue<DataType> Default;

                                                                           
          
  opt_storage() : Value(DataType()), Default(DataType()) {}

  template <class T> void setValue(const T &V, bool initial = false) {
    Value = V;
    if (initial)
      Default = V;
  }
  DataType &getValue() { return Value; }
  DataType getValue() const { return Value; }

  const OptionValue<DataType> &getDefault() const { return Default; }

  operator DataType() const { return getValue(); }

                                                    
  DataType operator->() const { return Value; }
};

                                                                                
                                      
  
template <class DataType, bool ExternalStorage = false,
          class ParserClass = parser<DataType>>
class opt : public Option,
            public opt_storage<DataType, ExternalStorage,
                               std::is_class<DataType>::value> {
  ParserClass Parser;

  bool handleOccurrence(unsigned pos, StringRef ArgName,
                        StringRef Arg) override {
    typename ParserClass::parser_data_type Val =
        typename ParserClass::parser_data_type();
    if (Parser.parse(*this, ArgName, Arg, Val))
      return true;                
    this->setValue(Val);
    this->setPosition(pos);
    return false;
  }

  enum ValueExpected getValueExpectedFlagDefault() const override {
    return Parser.getValueExpectedFlagDefault();
  }

  void getExtraOptionNames(SmallVectorImpl<StringRef> &OptionNames) override {
    return Parser.getExtraOptionNames(OptionNames);
  }

                                            
  size_t getOptionWidth() const override {
    return Parser.getOptionWidth(*this);
  }

  void printOptionInfo(size_t GlobalWidth) const override {
    Parser.printOptionInfo(*this, GlobalWidth);
  }

  void printOptionValue(size_t GlobalWidth, bool Force) const override {
    if (Force || this->getDefault().compare(this->getValue())) {
      cl::printOptionDiff<ParserClass>(*this, Parser, this->getValue(),
                                       this->getDefault(), GlobalWidth);
    }
  }

  template <class T, class = typename std::enable_if<
            std::is_assignable<T&, T>::value>::type>
  void setDefaultImpl() {
    const OptionValue<DataType> &V = this->getDefault();
    if (V.hasValue())
      this->setValue(V.getValue());
  }

  template <class T, class = typename std::enable_if<
            !std::is_assignable<T&, T>::value>::type>
  void setDefaultImpl(...) {}

  void setDefault() override { setDefaultImpl<DataType>(); }

  void done() {
    addArgument();
    Parser.initialize();
  }

public:
                                                
  opt(const opt &) = delete;
  opt &operator=(const opt &) = delete;

                                                       
  void setInitialValue(const DataType &V) { this->setValue(V, true); }

  ParserClass &getParser() { return Parser; }

  template <class T> DataType &operator=(const T &Val) {
    this->setValue(Val);
    return this->getValue();
  }

  template <class... Mods>
  explicit opt(const Mods &... Ms)
      : Option(Optional, NotHidden), Parser(*this) {
    apply(this, Ms...);
    done();
  }
};

extern template class opt<unsigned>;
extern template class opt<int>;
extern template class opt<std::string>;
extern template class opt<char>;
extern template class opt<bool>;

                                                                                
                     

                                                                           
                                                                           
                            
  
template <class DataType, class StorageClass> class list_storage {
  StorageClass *Location = nullptr;                                

public:
  list_storage() = default;

  bool setLocation(Option &O, StorageClass &L) {
    if (Location)
      return O.error("cl::location(x) specified more than once!");
    Location = &L;
    return false;
  }

  template <class T> void addValue(const T &V) {
    assert(Location != 0 && "cl::location(...) not specified for a command "
                            "line option with external storage!");
    Location->push_back(V);
  }
};

                                                            
                                                                             
                                                                             
                                                                           
                                                        
  
                                                                
  
template <class DataType> class list_storage<DataType, bool> {
  std::vector<DataType> Storage;

public:
  using iterator = typename std::vector<DataType>::iterator;

  iterator begin() { return Storage.begin(); }
  iterator end() { return Storage.end(); }

  using const_iterator = typename std::vector<DataType>::const_iterator;

  const_iterator begin() const { return Storage.begin(); }
  const_iterator end() const { return Storage.end(); }

  using size_type = typename std::vector<DataType>::size_type;

  size_type size() const { return Storage.size(); }

  bool empty() const { return Storage.empty(); }

  void push_back(const DataType &value) { Storage.push_back(value); }
  void push_back(DataType &&value) { Storage.push_back(value); }

  using reference = typename std::vector<DataType>::reference;
  using const_reference = typename std::vector<DataType>::const_reference;

  reference operator[](size_type pos) { return Storage[pos]; }
  const_reference operator[](size_type pos) const { return Storage[pos]; }

  iterator erase(const_iterator pos) { return Storage.erase(pos); }
  iterator erase(const_iterator first, const_iterator last) {
    return Storage.erase(first, last);
  }

  iterator erase(iterator pos) { return Storage.erase(pos); }
  iterator erase(iterator first, iterator last) {
    return Storage.erase(first, last);
  }

  iterator insert(const_iterator pos, const DataType &value) {
    return Storage.insert(pos, value);
  }
  iterator insert(const_iterator pos, DataType &&value) {
    return Storage.insert(pos, value);
  }

  iterator insert(iterator pos, const DataType &value) {
    return Storage.insert(pos, value);
  }
  iterator insert(iterator pos, DataType &&value) {
    return Storage.insert(pos, value);
  }

  reference front() { return Storage.front(); }
  const_reference front() const { return Storage.front(); }

  operator std::vector<DataType>&() { return Storage; }
  operator ArrayRef<DataType>() { return Storage; }
  std::vector<DataType> *operator&() { return &Storage; }
  const std::vector<DataType> *operator&() const { return &Storage; }

  template <class T> void addValue(const T &V) { Storage.push_back(V); }
};

                                                                                
                                         
  
template <class DataType, class StorageClass = bool,
          class ParserClass = parser<DataType>>
class list : public Option, public list_storage<DataType, StorageClass> {
  std::vector<unsigned> Positions;
  ParserClass Parser;

  enum ValueExpected getValueExpectedFlagDefault() const override {
    return Parser.getValueExpectedFlagDefault();
  }

  void getExtraOptionNames(SmallVectorImpl<StringRef> &OptionNames) override {
    return Parser.getExtraOptionNames(OptionNames);
  }

  bool handleOccurrence(unsigned pos, StringRef ArgName,
                        StringRef Arg) override {
    typename ParserClass::parser_data_type Val =
        typename ParserClass::parser_data_type();
    if (Parser.parse(*this, ArgName, Arg, Val))
      return true;                
    list_storage<DataType, StorageClass>::addValue(Val);
    setPosition(pos);
    Positions.push_back(pos);
    return false;
  }

                                            
  size_t getOptionWidth() const override {
    return Parser.getOptionWidth(*this);
  }

  void printOptionInfo(size_t GlobalWidth) const override {
    Parser.printOptionInfo(*this, GlobalWidth);
  }

                                                                           
  void printOptionValue(size_t                , bool          ) const override {
  }

  void setDefault() override {}

  void done() {
    addArgument();
    Parser.initialize();
  }

public:
                                                
  list(const list &) = delete;
  list &operator=(const list &) = delete;

  ParserClass &getParser() { return Parser; }

  unsigned getPosition(unsigned optnum) const {
    assert(optnum < this->size() && "Invalid option index");
    return Positions[optnum];
  }

  void setNumAdditionalVals(unsigned n) { Option::setNumAdditionalVals(n); }

  template <class... Mods>
  explicit list(const Mods &... Ms)
      : Option(ZeroOrMore, NotHidden), Parser(*this) {
    apply(this, Ms...);
    done();
  }
};

                                                               
struct multi_val {
  unsigned AdditionalVals;
  explicit multi_val(unsigned N) : AdditionalVals(N) {}

  template <typename D, typename S, typename P>
  void apply(list<D, S, P> &L) const {
    L.setNumAdditionalVals(AdditionalVals);
  }
};

                                                                                
                     

                                                                           
                                                                           
                            
  
template <class DataType, class StorageClass> class bits_storage {
  unsigned *Location = nullptr;                              

  template <class T> static unsigned Bit(const T &V) {
    unsigned BitPos = reinterpret_cast<unsigned>(V);
    assert(BitPos < sizeof(unsigned) * CHAR_BIT &&
           "enum exceeds width of bit vector!");
    return 1 << BitPos;
  }

public:
  bits_storage() = default;

  bool setLocation(Option &O, unsigned &L) {
    if (Location)
      return O.error("cl::location(x) specified more than once!");
    Location = &L;
    return false;
  }

  template <class T> void addValue(const T &V) {
    assert(Location != nullptr && "cl::location(...) not specified for a command "
                            "line option with external storage!");
    *Location |= Bit(V);
  }

  unsigned getBits() { return *Location; }

  template <class T> bool isSet(const T &V) {
    return (*Location & Bit(V)) != 0;
  }
};

                                                                         
                                                                               
  
template <class DataType> class bits_storage<DataType, bool> {
  unsigned Bits;                              

  template <class T> static unsigned Bit(const T &V) {
    unsigned BitPos = (unsigned)V;
    assert(BitPos < sizeof(unsigned) * CHAR_BIT &&
           "enum exceeds width of bit vector!");
    return 1 << BitPos;
  }

public:
  template <class T> void addValue(const T &V) { Bits |= Bit(V); }

  unsigned getBits() { return Bits; }

  template <class T> bool isSet(const T &V) { return (Bits & Bit(V)) != 0; }
};

                                                                                
                                          
  
template <class DataType, class Storage = bool,
          class ParserClass = parser<DataType>>
class bits : public Option, public bits_storage<DataType, Storage> {
  std::vector<unsigned> Positions;
  ParserClass Parser;

  enum ValueExpected getValueExpectedFlagDefault() const override {
    return Parser.getValueExpectedFlagDefault();
  }

  void getExtraOptionNames(SmallVectorImpl<StringRef> &OptionNames) override {
    return Parser.getExtraOptionNames(OptionNames);
  }

  bool handleOccurrence(unsigned pos, StringRef ArgName,
                        StringRef Arg) override {
    typename ParserClass::parser_data_type Val =
        typename ParserClass::parser_data_type();
    if (Parser.parse(*this, ArgName, Arg, Val))
      return true;                
    this->addValue(Val);
    setPosition(pos);
    Positions.push_back(pos);
    return false;
  }

                                            
  size_t getOptionWidth() const override {
    return Parser.getOptionWidth(*this);
  }

  void printOptionInfo(size_t GlobalWidth) const override {
    Parser.printOptionInfo(*this, GlobalWidth);
  }

                                                                            
  void printOptionValue(size_t                , bool          ) const override {
  }

  void setDefault() override {}

  void done() {
    addArgument();
    Parser.initialize();
  }

public:
                                                
  bits(const bits &) = delete;
  bits &operator=(const bits &) = delete;

  ParserClass &getParser() { return Parser; }

  unsigned getPosition(unsigned optnum) const {
    assert(optnum < this->size() && "Invalid option index");
    return Positions[optnum];
  }

  template <class... Mods>
  explicit bits(const Mods &... Ms)
      : Option(ZeroOrMore, NotHidden), Parser(*this) {
    apply(this, Ms...);
    done();
  }
};

                                                                                
                                                                      
  

class alias : public Option {
  Option *AliasFor;

  bool handleOccurrence(unsigned pos, StringRef            ,
                        StringRef Arg) override {
    return AliasFor->handleOccurrence(pos, AliasFor->ArgStr, Arg);
  }

  bool addOccurrence(unsigned pos, StringRef            , StringRef Value,
                     bool MultiArg = false) override {
    return AliasFor->addOccurrence(pos, AliasFor->ArgStr, Value, MultiArg);
  }

                             
  size_t getOptionWidth() const override;
  void printOptionInfo(size_t GlobalWidth) const override;

                                               
  void printOptionValue(size_t                , bool          ) const override {
  }

  void setDefault() override { AliasFor->setDefault(); }

  ValueExpected getValueExpectedFlagDefault() const override {
    return AliasFor->getValueExpectedFlag();
  }

  void done() {
    if (!hasArgStr())
      error("cl::alias must have argument name specified!");
    if (!AliasFor)
      error("cl::alias must have an cl::aliasopt(option) specified!");
    Subs = AliasFor->Subs;
    addArgument();
  }

public:
                                                
  alias(const alias &) = delete;
  alias &operator=(const alias &) = delete;

  void setAliasFor(Option &O) {
    if (AliasFor)
      error("cl::alias must only have one cl::aliasopt(...) specified!");
    AliasFor = &O;
  }

  template <class... Mods>
  explicit alias(const Mods &... Ms)
      : Option(Optional, Hidden), AliasFor(nullptr) {
    apply(this, Ms...);
    done();
  }
};

                                                          
struct aliasopt {
  Option &Opt;

  explicit aliasopt(Option &O) : Opt(O) {}

  void apply(alias &A) const { A.setAliasFor(Opt); }
};

                                                                    
                                                                   
                                                                
                  
struct extrahelp {
  StringRef morehelp;

  explicit extrahelp(StringRef help);
};

void PrintVersionMessage();

                                                                              
                                                                    
   
                                                   
                                                          
void PrintHelpMessage(bool Hidden = false, bool Categorized = false);

                                                                                
                                                     
  

                                                               
                                                           
   
                                                                              
   
                                                                          
                                                               
   
                  
         
                                 
                                                                          
                                   
                                                                      
                
                                                 
               
     
            
   
                                                                               
                                                                            
                                        
   
                                                                               
                                                                              
                                           
StringMap<Option *> &getRegisteredOptions(SubCommand &Sub = *TopLevelSubCommand);

                                                                        
   
                                                                          
   
                  
         
                                  
                                                    
                                                            
                 
                                                                             
                                                       
         
       
     
            
   
                                                                      
                                                                 
iterator_range<typename SmallPtrSet<SubCommand *, 4>::iterator>
getRegisteredSubcommands();

                                                                                
                                                
  

                                                                 
  
                                                                      
                                                                             
                                                                               
                                                                              
   
                                                                        
                                                                             
                                                                               
                                                                          
                                                                    
void TokenizeGNUCommandLine(StringRef Source, StringSaver &Saver,
                            SmallVectorImpl<const char *> &NewArgv,
                            bool MarkEOLs = false);

                                                                         
           
   
                                                                              
                                                                                  
   
                                                                        
                                                                             
                                                                               
                                                                          
                                                                    
void TokenizeWindowsCommandLine(StringRef Source, StringSaver &Saver,
                                SmallVectorImpl<const char *> &NewArgv,
                                bool MarkEOLs = false);

                                                                        
                                            
using TokenizerCallback = void (*)(StringRef Source, StringSaver &Saver,
                                   SmallVectorImpl<const char *> &NewArgv,
                                   bool MarkEOLs);

                                            
   
                                                                      
                                                                             
                                                                    
                                                                        
   
                                                                            
   
void tokenizeConfigFile(StringRef Source, StringSaver &Saver,
                        SmallVectorImpl<const char *> &NewArgv,
                        bool MarkEOLs = false);

                                                                 
   
                                                       
                                                            
                                                                
                                                   
   
                                                                            
                                                                         
                        
   
bool readConfigFile(StringRef CfgFileName, StringSaver &Saver,
                    SmallVectorImpl<const char *> &Argv);

                                                                       
                                                                                
                                                                           
                                                                            
                                                                            
                                                                           
         
   
                                                                             
                                                                           
                                                                          
                                                                           
                                     
                                                                            
                                        
                                                                             
bool ExpandResponseFiles(StringSaver &Saver, TokenizerCallback Tokenizer,
                         SmallVectorImpl<const char *> &Argv,
                         bool MarkEOLs = false, bool RelativeNames = false);

/// Mark all options not part of this category as cl::ReallyHidden.
///
/// \param Category the category of options to keep displaying
///
/// Some tools (like clang-format) like to be able to hide all options that are
/// not specific to the tool. This function allows a tool to specify a single
/// option category to display in the -help output.
void HideUnrelatedOptions(cl::OptionCategory &Category,
                          SubCommand &Sub = *TopLevelSubCommand);

/// Mark all options not part of the categories as cl::ReallyHidden.
///
/// \param Categories the categories of options to keep displaying.
///
/// Some tools (like clang-format) like to be able to hide all options that are
/// not specific to the tool. This function allows a tool to specify a single
/// option category to display in the -help output.
void HideUnrelatedOptions(ArrayRef<const cl::OptionCategory *> Categories,
                          SubCommand &Sub = *TopLevelSubCommand);

                                                                        
                                                                               
                                                                        
void ResetAllOptionOccurrences();

                                                                  
           
                                                                              
                                   
void ResetCommandLineParser();

}                    

}                      

#endif                              
