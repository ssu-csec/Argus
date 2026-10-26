//===- YAMLParser.h - Simple YAML parser ------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This is a YAML 1.2 parser.
//
//  See http://www.yaml.org/spec/1.2/spec.html for the full standard.
//
//  This currently does not implement the following:
//    * Multi-line literal folding.
//    * Tag resolution.
//    * UTF-16.
//    * BOMs anywhere other than the first Unicode scalar value in the file.
//
//  The most important class here is Stream. This represents a YAML stream with
//  0, 1, or many documents.
//
//  SourceMgr sm;
//  StringRef input = getInput();
//  yaml::Stream stream(input, sm);
//
//  for (yaml::document_iterator di = stream.begin(), de = stream.end();
//       di != de; ++di) {
//    yaml::Node *n = di->getRoot();
//    if (n) {
//      // Do something with n...
//    } else
//      break;
//  }
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_YAMLPARSER_H
#define LLVM_SUPPORT_YAMLPARSER_H

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/SMLoc.h"
#include <cassert>
#include <cstddef>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <system_error>

namespace llvh {

class MemoryBufferRef;
class SourceMgr;
class raw_ostream;
class Twine;

namespace yaml {

class Document;
class document_iterator;
class Node;
class Scanner;
struct Token;

                                             
                                                         
bool dumpTokens(StringRef Input, raw_ostream &);

                                                                       
                                          
                                                         
bool scanTokens(StringRef Input);

                                                                     
                                                                         
                                                                              
                                  
std::string escape(StringRef Input, bool EscapePrintable = true);

                                                                       
                     
class Stream {
public:
                                                                  
  Stream(StringRef Input, SourceMgr &, bool ShowColors = true,
         std::error_code *EC = nullptr);

  Stream(MemoryBufferRef InputBuffer, SourceMgr &, bool ShowColors = true,
         std::error_code *EC = nullptr);
  ~Stream();

  document_iterator begin();
  document_iterator end();
  void skip();
  bool failed();

  bool validate() {
    skip();
    return !failed();
  }

  void printError(Node *N, const Twine &Msg);

private:
  friend class Document;

  std::unique_ptr<Scanner> scanner;
  std::unique_ptr<Document> CurrentDoc;
};

                                      
class Node {
  virtual void anchor();

public:
  enum NodeKind {
    NK_Null,
    NK_Scalar,
    NK_BlockScalar,
    NK_KeyValue,
    NK_Mapping,
    NK_Sequence,
    NK_Alias
  };

  Node(unsigned int Type, std::unique_ptr<Document> &, StringRef Anchor,
       StringRef Tag);

                                                                                
                          
  Node(const Node &) = delete;
  void operator=(const Node &) = delete;

  void *operator new(size_t Size, BumpPtrAllocator &Alloc,
                     size_t Alignment = 16) noexcept {
    return Alloc.Allocate(Size, Alignment);
  }

  void operator delete(void *Ptr, BumpPtrAllocator &Alloc,
                       size_t Size) noexcept {
    Alloc.Deallocate(Ptr, Size);
  }

  void operator delete(void *) noexcept = delete;

                                                                       
                                                    
  StringRef getAnchor() const { return Anchor; }

                                                                  
                               
  StringRef getRawTag() const { return Tag; }

                                                                         
                         
  std::string getVerbatimTag() const;

  SMRange getSourceRange() const { return SourceRange; }
  void setSourceRange(SMRange SR) { SourceRange = SR; }

                                                     
  Token &peekNext();
  Token getNext();
  Node *parseBlockNode();
  BumpPtrAllocator &getAllocator();
  void setError(const Twine &Message, Token &Location) const;
  bool failed() const;

  virtual void skip() {}

  unsigned int getType() const { return TypeID; }

protected:
  std::unique_ptr<Document> &Doc;
  SMRange SourceRange;

  ~Node() = default;

private:
  unsigned int TypeID;
  StringRef Anchor;
                                       
  StringRef Tag;
};

                 
   
            
                 
class NullNode final : public Node {
  void anchor() override;

public:
  NullNode(std::unique_ptr<Document> &D)
      : Node(NK_Null, D, StringRef(), StringRef()) {}

  static bool classof(const Node *N) { return N->getType() == NK_Null; }
};

                                                               
                                                        
   
            
           
class ScalarNode final : public Node {
  void anchor() override;

public:
  ScalarNode(std::unique_ptr<Document> &D, StringRef Anchor, StringRef Tag,
             StringRef Val)
      : Node(NK_Scalar, D, Anchor, Tag), Value(Val) {
    SMLoc Start = SMLoc::getFromPointer(Val.begin());
    SMLoc End = SMLoc::getFromPointer(Val.end());
    SourceRange = SMRange(Start, End);
  }

                                                                               
                                                                           
           
  StringRef getRawValue() const { return Value; }

                                                 
     
                                                                               
                                                                             
                                                                          
  StringRef getValue(SmallVectorImpl<char> &Storage) const;

  static bool classof(const Node *N) {
    return N->getType() == NK_Scalar;
  }

private:
  StringRef Value;

  StringRef unescapeDoubleQuoted(StringRef UnquotedValue,
                                 StringRef::size_type Start,
                                 SmallVectorImpl<char> &Storage) const;
};

                                                                     
                                                        
   
            
       
             
             
class BlockScalarNode final : public Node {
  void anchor() override;

public:
  BlockScalarNode(std::unique_ptr<Document> &D, StringRef Anchor, StringRef Tag,
                  StringRef Value, StringRef RawVal)
      : Node(NK_BlockScalar, D, Anchor, Tag), Value(Value) {
    SMLoc Start = SMLoc::getFromPointer(RawVal.begin());
    SMLoc End = SMLoc::getFromPointer(RawVal.end());
    SourceRange = SMRange(Start, End);
  }

                                                 
  StringRef getValue() const { return Value; }

  static bool classof(const Node *N) {
    return N->getType() == NK_BlockScalar;
  }

private:
  StringRef Value;
};

                                                                     
                                                                     
   
                                                   
   
            
                    
class KeyValueNode final : public Node {
  void anchor() override;

public:
  KeyValueNode(std::unique_ptr<Document> &D)
      : Node(NK_KeyValue, D, StringRef(), StringRef()) {}

                               
     
                                        
     
                                                       
  Node *getKey();

                                 
     
                                        
     
                                                         
  Node *getValue();

  void skip() override {
    if (Node *Key = getKey()) {
      Key->skip();
      if (Node *Val = getValue())
        Val->skip();
    }
  }

  static bool classof(const Node *N) {
    return N->getType() == NK_KeyValue;
  }

private:
  Node *Key = nullptr;
  Node *Value = nullptr;
};

                                                                        
                              
   
                                                                             
                                                                           
template <class BaseT, class ValueT>
class basic_collection_iterator {
public:
  using iterator_category = std::input_iterator_tag;
  using value_type = ValueT;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

  basic_collection_iterator() = default;
  basic_collection_iterator(BaseT *B) : Base(B) {}

  ValueT *operator->() const {
    assert(Base && Base->CurrentEntry && "Attempted to access end iterator!");
    return Base->CurrentEntry;
  }

  ValueT &operator*() const {
    assert(Base && Base->CurrentEntry &&
           "Attempted to dereference end iterator!");
    return *Base->CurrentEntry;
  }

  operator ValueT *() const {
    assert(Base && Base->CurrentEntry && "Attempted to access end iterator!");
    return Base->CurrentEntry;
  }

                                 
     
                                     
                                                       
                                                                       
                                                                   
                                        
  bool operator==(const basic_collection_iterator &Other) const {
    if (Base && (Base == Other.Base)) {
      assert((Base->CurrentEntry == Other.Base->CurrentEntry)
             && "Equal Bases expected to point to equal Entries");
    }

    return Base == Other.Base;
  }

  bool operator!=(const basic_collection_iterator &Other) const {
    return !(Base == Other.Base);
  }

  basic_collection_iterator &operator++() {
    assert(Base && "Attempted to advance iterator past end!");
    Base->increment();
                              
    if (!Base->CurrentEntry)
      Base = nullptr;
    return *this;
  }

private:
  BaseT *Base = nullptr;
};

                                                                               
template <class CollectionType>
typename CollectionType::iterator begin(CollectionType &C) {
  assert(C.IsAtBeginning && "You may only iterate over a collection once!");
  C.IsAtBeginning = false;
  typename CollectionType::iterator ret(&C);
  ++ret;
  return ret;
}

template <class CollectionType> void skip(CollectionType &C) {
                                                                     
  assert((C.IsAtBeginning || C.IsAtEnd) && "Cannot skip mid parse!");
  if (C.IsAtBeginning)
    for (typename CollectionType::iterator i = begin(C), e = C.end(); i != e;
         ++i)
      i->skip();
}

                                                                         
   
                                                         
   
            
                 
                   
class MappingNode final : public Node {
  void anchor() override;

public:
  enum MappingType {
    MT_Block,
    MT_Flow,
    MT_Inline                                                        
  };

  MappingNode(std::unique_ptr<Document> &D, StringRef Anchor, StringRef Tag,
              MappingType MT)
      : Node(NK_Mapping, D, Anchor, Tag), Type(MT) {}

  friend class basic_collection_iterator<MappingNode, KeyValueNode>;

  using iterator = basic_collection_iterator<MappingNode, KeyValueNode>;

  template <class T> friend typename T::iterator yaml::begin(T &);
  template <class T> friend void yaml::skip(T &);

  iterator begin() { return yaml::begin(*this); }

  iterator end() { return iterator(); }

  void skip() override { yaml::skip(*this); }

  static bool classof(const Node *N) {
    return N->getType() == NK_Mapping;
  }

private:
  MappingType Type;
  bool IsAtBeginning = true;
  bool IsAtEnd = false;
  KeyValueNode *CurrentEntry = nullptr;

  void increment();
};

                                                                         
                         
   
                                                         
   
            
             
             
class SequenceNode final : public Node {
  void anchor() override;

public:
  enum SequenceType {
    ST_Block,
    ST_Flow,
               
      
           
             
             
      
                                                                        
    ST_Indentless
  };

  SequenceNode(std::unique_ptr<Document> &D, StringRef Anchor, StringRef Tag,
               SequenceType ST)
      : Node(NK_Sequence, D, Anchor, Tag), SeqType(ST) {}

  friend class basic_collection_iterator<SequenceNode, Node>;

  using iterator = basic_collection_iterator<SequenceNode, Node>;

  template <class T> friend typename T::iterator yaml::begin(T &);
  template <class T> friend void yaml::skip(T &);

  void increment();

  iterator begin() { return yaml::begin(*this); }

  iterator end() { return iterator(); }

  void skip() override { yaml::skip(*this); }

  static bool classof(const Node *N) {
    return N->getType() == NK_Sequence;
  }

private:
  SequenceType SeqType;
  bool IsAtBeginning = true;
  bool IsAtEnd = false;
  bool WasPreviousTokenFlowEntry = true;                                
  Node *CurrentEntry = nullptr;
};

                                                 
   
            
                 
class AliasNode final : public Node {
  void anchor() override;

public:
  AliasNode(std::unique_ptr<Document> &D, StringRef Val)
      : Node(NK_Alias, D, StringRef(), StringRef()), Name(Val) {}

  StringRef getName() const { return Name; }
  Node *getTarget();

  static bool classof(const Node *N) { return N->getType() == NK_Alias; }

private:
  StringRef Name;
};

                                                                        
                
class Document {
public:
  Document(Stream &ParentStream);

                                                     
  Node *parseBlockNode();

                                                                      
                                          
  bool skip();

                                           
  Node *getRoot() {
    if (Root)
      return Root;
    return Root = parseBlockNode();
  }

  const std::map<StringRef, StringRef> &getTagMap() const { return TagMap; }

private:
  friend class Node;
  friend class document_iterator;

                                 
  Stream &stream;

                                                                        
                                                       
  BumpPtrAllocator NodeAllocator;

                                                                
                      
  Node *Root;

                                           
  std::map<StringRef, StringRef> TagMap;

  Token &peekNext();
  Token getNext();
  void setError(const Twine &Message, Token &Location) const;
  bool failed() const;

                                                                     
  bool parseDirectives();

                 
  void parseYAMLDirective();

                
  void parseTAGDirective();

                                                          
  bool expectToken(int TK);
};

                                                     
class document_iterator {
public:
  document_iterator() = default;
  document_iterator(std::unique_ptr<Document> &D) : Doc(&D) {}

  bool operator==(const document_iterator &Other) const {
    if (isAtEnd() || Other.isAtEnd())
      return isAtEnd() && Other.isAtEnd();

    return Doc == Other.Doc;
  }
  bool operator!=(const document_iterator &Other) const {
    return !(*this == Other);
  }

  document_iterator operator++() {
    assert(Doc && "incrementing iterator past the end.");
    if (!(*Doc)->skip()) {
      Doc->reset(nullptr);
    } else {
      Stream &S = (*Doc)->stream;
      Doc->reset(new Document(S));
    }
    return *this;
  }

  Document &operator*() { return *Doc->get(); }

  std::unique_ptr<Document> &operator->() { return *Doc; }

private:
  bool isAtEnd() const { return !Doc || !*Doc; }

  std::unique_ptr<Document> *Doc = nullptr;
};

}                      

}                      

#endif                             
