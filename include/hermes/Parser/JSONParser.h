/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PARSER_JSONPARSER_H
#define HERMES_PARSER_JSONPARSER_H

#include <algorithm>
#include <cstddef>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <utility>

#include "hermes/Parser/JSLexer.h"
#include "hermes/Parser/pack.h"
#include "hermes/Support/Conversions.h"
#include "hermes/Support/JSONEmitter.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/FoldingSet.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/Casting.h"

namespace hermes {
namespace parser {

class JSONFactory;
class JSONParser;

enum class JSONKind {
  Object,
  Array,
  String,
  Number,
  Boolean,
  Null,
};

                                 
const char *JSONKindToString(JSONKind kind);

                                                                 
class JSONValue {
  JSONKind const kind_;

  JSONValue(const JSONValue &) = delete;
  JSONValue &operator=(const JSONValue &) = delete;

 public:
  explicit constexpr JSONValue(JSONKind kind) : kind_(kind) {};

  JSONKind getKind() const {
    return kind_;
  }

                                             
  void emitInto(JSONEmitter &emitter) const;
};

                                                           
class JSONScalar : public JSONValue {
 public:
  explicit constexpr JSONScalar(JSONKind kind) : JSONValue(kind) {}

  static bool classof(const JSONValue *v) {
    return v->getKind() >= JSONKind::String;
  }
};

class JSONNull : public JSONScalar {
  constexpr JSONNull() : JSONScalar(JSONKind::Null) {};

  static JSONNull instance_;

 public:
  static JSONNull *getInstance() {
    return &instance_;
  }

  static bool classof(const JSONValue *v) {
    return v->getKind() == JSONKind::Null;
  }
};

class JSONBoolean : public JSONScalar {
  bool const value_;

  explicit constexpr JSONBoolean(bool value)
      : JSONScalar(JSONKind::Boolean), value_(value) {};

  static JSONBoolean true_;
  static JSONBoolean false_;

 public:
  static JSONBoolean *getInstance(bool v) {
    return v ? &true_ : &false_;
  };

  bool getValue() const {
    return value_;
  }
  explicit operator bool() const {
    return getValue();
  }

  static bool classof(const JSONValue *v) {
    return v->getKind() == JSONKind::Boolean;
  }
};

class JSONString : public JSONScalar, public llvh::FoldingSetNode {
  UniqueString *const value_;

 public:
  explicit JSONString(UniqueString *value)
      : JSONScalar(JSONKind::String), value_(value) {}

  UniqueString *stringBase() const {
    return value_;
  }

  const llvh::StringRef &str() const {
    return value_->str();
  }
  explicit operator llvh::StringRef() const {
    return value_->str();
  }
  const char *c_str() const {
    return value_->c_str();
  }

  static void Profile(llvh::FoldingSetNodeID &id, UniqueString *str) {
    id.AddPointer(str);
  }

  void Profile(llvh::FoldingSetNodeID &id) {
    JSONString::Profile(id, value_);
  }

  static bool classof(const JSONValue *v) {
    return v->getKind() == JSONKind::String;
  }
};

class JSONNumber : public JSONScalar, public llvh::FoldingSetNode {
  double const value_;

 public:
  explicit JSONNumber(double value)
      : JSONScalar(JSONKind::Number), value_(value) {}

  double getValue() const {
    return value_;
  }
  explicit operator double() const {
    return getValue();
  }

  static void Profile(llvh::FoldingSetNodeID &id, double value) {
    id.AddInteger(llvh::DoubleToBits(value));
  }

  void Profile(llvh::FoldingSetNodeID &id) {
    JSONNumber::Profile(id, value_);
  }

  static bool classof(const JSONValue *v) {
    return v->getKind() == JSONKind::Number;
  }
};

                                                                          
                                                        
class JSONHiddenClass {
  size_t size_;
  JSONString *keys_[];

  struct NameComparator {
    bool operator()(llvh::StringRef a, JSONString *b) const {
      return a < b->str();
    }
    bool operator()(JSONString *a, llvh::StringRef b) const {
      return a->str() < b;
    }
  };

  JSONHiddenClass(const JSONHiddenClass &) = delete;
  JSONHiddenClass &operator=(const JSONHiddenClass &) = delete;

  template <typename FwIt>
  JSONHiddenClass(size_t size, FwIt b, FwIt e) : size_(size) {
    std::copy(b, e, keys_);
  }

              
    
  template <class Allocator>
  static void *operator new(size_t size, Allocator &alloc, size_t count) {
    return alloc.Allocate(
        offsetof(JSONHiddenClass, keys_) + sizeof(keys_[0]) * count,
        alignof(JSONHiddenClass));
  }

  friend class JSONFactory;

 public:
  using iterator = hermes::parser::JSONString *const *;

  size_t size() const {
    return size_;
  }
  iterator begin() const {
    return keys_;
  }
  iterator end() const {
    return keys_ + size_;
  }

  llvh::Optional<size_t> find(llvh::StringRef name) {
    auto e = end();
    auto it = std::lower_bound(begin(), e, name, NameComparator{});
    if (it != e && (*it)->str() == name)
      return it - begin();
    else
      return llvh::None;
  }
};

                                                                           
                                                                       
                                                                        
                    
class JSONObject : public JSONValue {
  JSONHiddenClass *const hiddenClass_;

  inline JSONValue **values() {
    return Pack<JSONObject, JSONValue *>::values(this);
  }

  inline JSONValue *const *values() const {
    return Pack<JSONObject, JSONValue *>::values(this);
  }

                                                                              
         
                   
  template <typename FwId>
  JSONObject(JSONHiddenClass *hiddenClass, FwId b, FwId e)
      : JSONValue(JSONKind::Object), hiddenClass_(hiddenClass) {
    JSONValue *const *oe = std::copy(b, e, values());
    assert(oe - values() == (ptrdiff_t)hiddenClass_->size());
    (void)oe;
  }

                                                               
  JSONObject(JSONHiddenClass *hiddenClass, JSONValue *fillValue)
      : JSONValue(JSONKind::Object), hiddenClass_(hiddenClass) {
    JSONValue **v = values();
    std::fill(v, v + hiddenClass->size(), fillValue);
  }

              

  template <class Allocator>
  void *operator new(size_t size, Allocator &alloc, size_t count) {
    return Pack<JSONObject, JSONValue *>::allocate(alloc, count);
  }

  friend class JSONFactory;

 public:
  JSONHiddenClass *getHiddenClass() const {
    return hiddenClass_;
  }
  size_t size() const {
    return hiddenClass_->size();
  }

                                                     
  JSONValue *get(llvh::StringRef name) const {
    if (auto res = hiddenClass_->find(name))
      return values()[res.getValue()];
    else
      return nullptr;
  }

                                                                                
                                       
  JSONValue *at(llvh::StringRef name) const {
    if (auto res = hiddenClass_->find(name))
      return values()[res.getValue()];

    assert(false && "name not found");
    return nullptr;
  }

                                                                             
  JSONValue *operator[](llvh::StringRef name) const {
    return values()[hiddenClass_->find(name).getValue()];
  }
                                                                             
  JSONValue *&operator[](llvh::StringRef name) {
    return values()[hiddenClass_->find(name).getValue()];
  }
                              
  JSONValue *operator[](size_t index) const {
    assert(index < size());
    return values()[index];
  }
                              
  JSONValue *&operator[](size_t index) {
    assert(index < size());
    return values()[index];
  }

                                      
  size_t count(llvh::StringRef name) const {
    return hiddenClass_->find(name) ? 1 : 0;
  }

                                                                           
                                                                                
                   
  class iterator {
    JSONObject *obj_;
    size_t index_;

    iterator(JSONObject *obj, size_t index) : obj_(obj), index_(index) {}
    friend class JSONObject;
    friend class const_iterator;

   public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = std::pair<JSONString *, JSONValue *&>;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    iterator(const iterator &) = default;
    iterator &operator=(const iterator &) = default;

    value_type operator*() const {
      return value_type{obj_->hiddenClass_->begin()[index_], (*obj_)[index_]};
    }

    iterator &operator++() {
      ++index_;
      return *this;
    }

    iterator &operator--() {
      --index_;
      return *this;
    }

    difference_type operator-(const iterator &x) const {
      assert(obj_ == x.obj_);
      return (difference_type)(index_ - x.index_);
    }

    bool operator==(const iterator &it) const {
      return obj_ == it.obj_ && index_ == it.index_;
    }
    bool operator!=(const iterator &it) const {
      return obj_ != it.obj_ || index_ != it.index_;
    }
  };
  class const_iterator {
    const JSONObject *obj_;
    size_t index_;

    const_iterator(const JSONObject *obj, size_t index)
        : obj_(obj), index_(index) {}
    friend class JSONObject;

   public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = std::pair<JSONString *, JSONValue *>;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    const_iterator(const const_iterator &) = default;
    const_iterator &operator=(const const_iterator &) = default;

    explicit const_iterator(const JSONObject::iterator &it)
        : obj_(it.obj_), index_(it.index_) {}
    const_iterator &operator=(const JSONObject::iterator &it) {
      obj_ = it.obj_;
      index_ = it.index_;
      return *this;
    }

    value_type operator*() const {
      return value_type{obj_->hiddenClass_->begin()[index_], (*obj_)[index_]};
    }

    const_iterator &operator++() {
      ++index_;
      return *this;
    }

    const_iterator &operator--() {
      --index_;
      return *this;
    }

    difference_type operator-(const const_iterator &x) const {
      assert(obj_ == x.obj_);
      return (difference_type)(index_ - x.index_);
    }

    bool operator==(const const_iterator &it) const {
      return obj_ == it.obj_ && index_ == it.index_;
    }
    bool operator!=(const const_iterator &it) const {
      return obj_ != it.obj_ || index_ != it.index_;
    }
  };

  iterator begin() {
    return iterator(this, 0);
  }
  iterator end() {
    return iterator(this, size());
  }
  const_iterator begin() const {
    return const_iterator(this, 0);
  }
  const_iterator end() const {
    return const_iterator(this, size());
  }

  iterator find(llvh::StringRef name) {
    if (auto res = hiddenClass_->find(name))
      return iterator(this, res.getValue());
    else
      return end();
  }
  const_iterator find(llvh::StringRef name) const {
    if (auto res = hiddenClass_->find(name))
      return const_iterator(this, res.getValue());
    else
      return end();
  }

  static bool classof(const JSONValue *v) {
    return v->getKind() == JSONKind::Object;
  }
};

class JSONArray : public JSONValue {
  size_t const size_;

  inline JSONValue **values() {
    return Pack<JSONArray, JSONValue *>::values(this);
  }

  inline JSONValue *const *values() const {
    return Pack<JSONArray, JSONValue *>::values(this);
  }

                                                     
  template <class FwdIt>
  JSONArray(size_t size, FwdIt b, FwdIt e)
      : JSONValue(JSONKind::Array), size_(size) {
    std::copy(b, e, values());
  }

                                                               
  JSONArray(size_t size, JSONValue *fillValue)
      : JSONValue(JSONKind::Array), size_(size) {
    JSONValue **v = values();
    std::fill(v, v + size_, fillValue);
  }

              

  template <class Allocator>
  inline void *operator new(size_t size, Allocator &alloc, size_t count) {
    return Pack<JSONArray, JSONValue *>::allocate(alloc, count);
  }

  friend class JSONFactory;

 public:
  using iterator = const hermes::parser::JSONValue *const *;

  size_t size() const {
    return size_;
  }

  iterator begin() const {
    return values();
  };
  iterator end() const {
    return values() + size_;
  }

  const JSONValue *at(size_t pos) const {
    assert(pos < size_);
    return values()[pos];
  };

  const JSONValue *operator[](size_t pos) const {
    assert(pos < size_);
    return values()[pos];
  }

  static bool classof(const JSONValue *v) {
    return v->getKind() == JSONKind::Array;
  }
};

                                                                       
                                                                        
                                                
class JSONFactory {
 public:
  using Allocator = hermes::BumpPtrAllocator;

                                                                              
            
                                                                         
                    
                                  
  using HiddenClassKey = std::pair<size_t, JSONString *const *>;

                        
  using Prop = std::pair<JSONString *, JSONValue *>;

  struct LessHiddenClassKey {
    bool operator()(const HiddenClassKey &a, const HiddenClassKey &b) const;
  };

 private:
  Allocator &allocator_;

                                                                         
                 
  std::unique_ptr<StringTable> ownStrTab_;
                                                                                
           
  StringTable &strTab_;

                                                                              
  llvh::FoldingSet<JSONString> strings_;
  llvh::FoldingSet<JSONNumber> numbers_;

  std::map<HiddenClassKey, JSONHiddenClass *, LessHiddenClassKey>
      hiddenClasses_;

 public:
  explicit JSONFactory(Allocator &allocator, StringTable *strTab = nullptr);

  Allocator &getAllocator() {
    return allocator_;
  }
  StringTable &getStringTable() {
    return strTab_;
  }

                                                                               
                                                                                
                 

  JSONString *getString(UniqueString *lit);
  JSONString *getString(llvh::StringRef str);
  JSONNumber *getNumber(double value);
  static JSONBoolean *getBoolean(bool v) {
    return JSONBoolean::getInstance(v);
  }
  static JSONNull *getNull() {
    return JSONNull::getInstance();
  }

                                                                   
  JSONHiddenClass *getHiddenClass(const HiddenClassKey &key);

                                                                            
                                                                               
                                            
  static JSONString *sortProps(Prop *from, Prop *to);

                                                                              
                                                                            
                      
                                                                            
                                                                        
  JSONObject *newObject(Prop *from, Prop *to, bool propsAreSorted = false);

                                                                              
                                                                              
                                                           
  template <typename FwIt>
  JSONObject *newObject(JSONHiddenClass *hiddenClass, FwIt b, FwIt e) const {
    return new (allocator_, hiddenClass->size()) JSONObject(hiddenClass, b, e);
  }
                                                                               
                     
  JSONObject *newObject(
      JSONHiddenClass *hiddenClass,
      JSONValue *fillValue = JSONNull::getInstance()) const {
    return new (allocator_, hiddenClass->size())
        JSONObject(hiddenClass, fillValue);
  }

                                                                          
                                                                               
            
  template <class FwIt>
  JSONArray *newArray(size_t size, FwIt b, FwIt e) const {
    return new (allocator_, size) JSONArray(size, b, e);
  }
                                                                               
            
  JSONArray *newArray(
      size_t size,
      JSONValue *fillValue = JSONNull::getInstance()) const {
    return new (allocator_, size) JSONArray(size, fillValue);
  }
};

class JSONParser {
 private:
  JSONFactory &factory_;
  JSLexer lexer_;
  SourceErrorManager &sm_;

 public:
  JSONParser(
      JSONFactory &factory,
      std::unique_ptr<llvh::MemoryBuffer> input,
      SourceErrorManager &sm,
      bool convertSurrogates = false);

  JSONParser(
      JSONFactory &factory,
      llvh::StringRef input,
      SourceErrorManager &sm,
      bool convertSurrogates = false)
      : JSONParser(
            factory,
            llvh::MemoryBuffer::getMemBuffer(input, "json"),
            sm,
            convertSurrogates) {}

  JSONParser(
      JSONFactory &factory,
      llvh::MemoryBufferRef input,
      SourceErrorManager &sm,
      bool showColors = true,
      bool convertSurrogates = false)
      : JSONParser(factory, llvh::MemoryBuffer::getMemBuffer(input), sm) {}

                                                                               
                                                
  llvh::Optional<JSONValue *> parse();

  void error(const llvh::Twine &msg) {
    sm_.error(lexer_.getCurToken()->getSourceRange(), msg, Subsystem::Parser);
  }

 private:
  llvh::Optional<JSONValue *> parseValue();
  llvh::Optional<JSONValue *> parseArray();
  llvh::Optional<JSONValue *> parseObject();
};

                                                                
class JSONSharedValue {
 public:
  using Allocator = hermes::BumpPtrAllocator;

 private:
  const JSONValue *value_;
  std::shared_ptr<const Allocator> allocator_;

 public:
  JSONSharedValue(
      const JSONValue *value,
      std::shared_ptr<const Allocator> allocator)
      : value_(value), allocator_(std::move(allocator)) {}

  const JSONValue *operator*() const {
    return value_;
  }

  const JSONValue *operator->() const {
    return value_;
  }
};

}                    
}                    

#endif                              
