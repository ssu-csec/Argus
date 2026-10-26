/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_STRINGPRIMITIVE_H
#define HERMES_VM_STRINGPRIMITIVE_H

#include "hermes/Support/CheckedMalloc.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/VM/CopyableBasicString.h"
#include "hermes/VM/GC.h"
#include "hermes/VM/GCBase.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/StringRefUtils.h"

#include "llvh/Support/TrailingObjects.h"

#include <type_traits>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

class StringView;

                                                                           
                                                                     
                                                                        
class StringPrimitive : public VariableSizeRuntimeCell {
  friend class detail::IdentifierHashTable;
  friend class IdentifierTable;
  friend class StringBuilder;
  friend class StringView;
  template <typename T>
  friend class BufferedStringPrimitive;

  friend llvh::raw_ostream &operator<<(
      llvh::raw_ostream &OS,
      const StringPrimitive *str);

                                                
                                                                 
                                                                               
         
  template <typename T>
  static CallResult<HermesValue> createEfficientImpl(
      Runtime &runtime,
      llvh::ArrayRef<T> str,
      std::basic_string<T> *optStorage = nullptr);

                                                                             
                                               
  static CallResult<HermesValue> createDynamic(Runtime &runtime, UTF16Ref str);

                                                                         
                                                         
  static CallResult<HermesValue>
  createDynamicWithKnownEncoding(Runtime &runtime, UTF16Ref str, bool isASCII);

                                                                  
                                                                               
                                                                                
                                                                           
                                                                            
                          
  template <typename CharT, size_t N>
  static CallResult<HermesValue> create(Runtime &, const CharT (&Arr)[N]);

                                                     
  template <typename CharT, size_t N>
  static CallResult<HermesValue> createLongLived(
      Runtime &,
      const CharT (&Arr)[N]);

                                                               
  template <typename CharT>
  static std::basic_string<CharT> arrayToString(llvh::ArrayRef<CharT> arr) {
    return std::basic_string<CharT>{arr.begin(), arr.end()};
  }

 protected:
                                                                      
                                                                         
                                                   
                                                                               
                   
                                                                         
                                               
  static constexpr uint32_t LENGTH_FLAG_UNIQUED = uint32_t(1) << 31;

                                                                            
                                     
  uint32_t lengthAndUniquedFlag_;

                                                   
  explicit StringPrimitive(uint32_t length) : lengthAndUniquedFlag_(length) {}

                                                                               
                                                                               
                                  
  static bool isExternalLength(uint32_t length) {
    return length >= EXTERNAL_STRING_THRESHOLD;
  }

                                                                               
                              
  static bool isSafeExternalLength(uint32_t length) {
    return length >= EXTERNAL_STRING_MIN_SIZE;
  }

 public:
                                                                     
  static constexpr uint32_t MAX_STRING_LENGTH = 256 * 1024 * 1024;

                                                                        
                                                                              
                                       
  static constexpr uint32_t EXTERNAL_STRING_THRESHOLD = 64 * 1024;

                                                                        
                                                                             
                                                                                
                                                                               
                                                                               
                                                                               
                                                                     
  static constexpr uint32_t EXTERNAL_STRING_MIN_SIZE =
      COPYABLE_BASIC_STRING_MIN_LENGTH;

                                                             
                                                                      
                                        
  static constexpr uint32_t CONCAT_STRING_MIN_SIZE =
      std::max(256u, EXTERNAL_STRING_MIN_SIZE);

  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::StringPrimitiveKind_first,
        CellKind::StringPrimitiveKind_last);
  }

                                                                                
                                                                                
                                       
  static CallResult<HermesValue>
  create(Runtime &runtime, uint32_t length, bool asciiNotUTF16);

                                                                             
  static CallResult<HermesValue> create(Runtime &runtime, ASCIIRef str);

                                                                           
           
  static CallResult<HermesValue> create(Runtime &runtime, UTF16Ref str);

                                                                           
           
  static CallResult<HermesValue>
  createWithKnownEncoding(Runtime &runtime, UTF16Ref str, bool isASCII);

                                                                              
                                                             
                                              
  static CallResult<HermesValue> createEfficient(
      Runtime &runtime,
      ASCIIRef str);

  static CallResult<HermesValue> createEfficient(
      Runtime &runtime,
      UTF16Ref str);

                                                                              
                                                                                
                                                                              
                                                                                
                                                                            
             
  static CallResult<HermesValue> createEfficient(
      Runtime &runtime,
      UTF8Ref str,
      bool IgnoreInputErrors = false);

                                                                         
                                                                               
                                                                          
  static CallResult<HermesValue> createEfficient(
      Runtime &runtime,
      std::basic_string<char> &&str);

  static CallResult<HermesValue> createEfficient(
      Runtime &runtime,
      std::basic_string<char16_t> &&str);

                                                              
                                                                      
                    
  static CallResult<HermesValue> createLongLived(
      Runtime &runtime,
      ASCIIRef str);
  static CallResult<HermesValue> createLongLived(
      Runtime &runtime,
      UTF16Ref str);

                                                                    
                                                                           
                          
  static inline Handle<StringPrimitive> createNoThrow(
      Runtime &runtime,
      UTF16Ref str);

                                                                    
                                                                           
                          
  static inline Handle<StringPrimitive> createNoThrow(
      Runtime &runtime,
      llvh::StringRef ascii);

                                                        
  uint32_t getStringLength() const {
    return lengthAndUniquedFlag_ & ~LENGTH_FLAG_UNIQUED;
  }

                                            
  bool isUniqued() const {
    return (lengthAndUniquedFlag_ & LENGTH_FLAG_UNIQUED) != 0;
  }

                                                             
                                                                           
                                             
  bool sliceEquals(
      uint32_t start,
      uint32_t length,
      const StringPrimitive *other) const;

                                                                
  bool equals(const StringPrimitive *other) const;

                                                                          
  bool equals(const StringView &other) const;

                                                
                                                                           
  int compare(const StringPrimitive *other) const;

                                                                    
                                                                               
  static CallResult<HermesValue> concat(
      Runtime &runtime,
      Handle<StringPrimitive> xHandle,
      Handle<StringPrimitive> yHandle);

                                                                            
                                                                  
  static CallResult<HermesValue> slice(
      Runtime &runtime,
      Handle<StringPrimitive> str,
      size_t start,
      size_t length);

                                                                        
  static Handle<StringPrimitive> ensureFlat(
      Runtime &runtime,
      Handle<StringPrimitive> self) {
                                                                        
                                 
    runtime.potentiallyMoveHeap();
    return self;
                                                       
  }

                                         
  bool isFlat() const {
    return true;
  }

                                                                              
                                                                  
  static StringView createStringView(
      Runtime &runtime,
      Handle<StringPrimitive> self);

                                                                             
                                                                            
                                                                        
  void appendUTF16String(llvh::SmallVectorImpl<char16_t> &str) const;

                                        
                                                   
  inline char16_t at(uint32_t index) const;

                                      
  inline bool isASCII() const;

                                         
  inline bool isExternal() const;

                                                                               
                                     
  template <typename T>
  llvh::ArrayRef<T> getStringRef() const {
    return llvh::ArrayRef<T>{castToPointer<T>(), getStringLength()};
  }

 private:
                                                                         
                                                                              
                                             
  void appendUTF16String(char16_t *ptr) const;

                                                                         
  const char *castToASCIIPointer() const;

                                                                             
  const char16_t *castToUTF16Pointer() const;

                                                                             
                       
  template <typename T>
  inline const T *castToPointer() const;

                                                                        
  char *castToASCIIPointerForWrite();

                                                                            
  char16_t *castToUTF16PointerForWrite();

                                                                      
  UTF16Ref castToUTF16Ref(uint32_t start, uint32_t length) const {
    return UTF16Ref(castToUTF16Pointer() + start, length);
  }

                                                                     
  ASCIIRef castToASCIIRef(uint32_t start, uint32_t length) const {
    return ASCIIRef(castToASCIIPointer() + start, length);
  }

  UTF16Ref castToUTF16Ref() const {
    return castToUTF16Ref(0, getStringLength());
  }

  ASCIIRef castToASCIIRef() const {
    return castToASCIIRef(0, getStringLength());
  }

                                                                             
                                                                          
  static StringView createStringViewMustBeFlat(Handle<StringPrimitive> self);

 protected:
                                                                              
                                   
  inline bool canBeUniqued() const;

                                                            
                                             
  inline void convertToUniqued(SymbolID uniqueID);

                            
                                                           
  SymbolID getUniqueID() const;

                                                                           
                                                   
  void clearUniquedBit() {
    lengthAndUniquedFlag_ &= ~LENGTH_FLAG_UNIQUED;
  }

#ifdef HERMES_MEMORY_INSTRUMENTATION
  static std::string _snapshotNameImpl(GCCell *cell, GC &gc);
#endif
};

                                                          
                                                        
                                                                         
                        
class SymbolStringPrimitive : public StringPrimitive {
                                                                        
                                                     
                                                                             
                                                                          
               
                                                                            
                                                                               
                               
  SymbolID weakUniqueID_{};

 public:
  using StringPrimitive::StringPrimitive;

  static bool classof(const GCCell *cell) {
    static_assert(
        cellKindsContiguousAscending(
            CellKind::DynamicUniquedUTF16StringPrimitiveKind,
            CellKind::DynamicUniquedASCIIStringPrimitiveKind,
            CellKind::ExternalUTF16StringPrimitiveKind,
            CellKind::ExternalASCIIStringPrimitiveKind),
        "Unexpected CellKind ordering");
    return kindInRange(
        cell->getKind(),
        CellKind::DynamicUniquedUTF16StringPrimitiveKind,
        CellKind::ExternalASCIIStringPrimitiveKind);
  }

 protected:
  friend class StringPrimitive;

                                                                            
                   
  void updateUniqueID(SymbolID id) {
    assert(isUniqued() && "StringPrimitive is not uniqued");
    weakUniqueID_ = id;
  }

                            
  SymbolID getUniqueID() const {
    assert(isUniqued() && "StringPrimitive is not uniqued");
    return weakUniqueID_;
  }
};

                                                                              
template <bool Uniqued>
using OptSymbolStringPrimitive = typename std::
    conditional<Uniqued, SymbolStringPrimitive, StringPrimitive>::type;

                                                                     
                                                           
                                                      
template <typename T, bool Uniqued>
class DynamicStringPrimitive final
    : public OptSymbolStringPrimitive<Uniqued>,
      private llvh::TrailingObjects<DynamicStringPrimitive<T, Uniqued>, T> {
  friend class IdentifierTable;
  friend class llvh::TrailingObjects<DynamicStringPrimitive<T, Uniqued>, T>;
  friend class StringBuilder;
  friend class StringPrimitive;
  friend void DynamicASCIIStringPrimitiveBuildMeta(
      const GCCell *,
      Metadata::Builder &);
  friend void DynamicUTF16StringPrimitiveBuildMeta(
      const GCCell *,
      Metadata::Builder &);
  friend void DynamicUniquedASCIIStringPrimitiveBuildMeta(
      const GCCell *,
      Metadata::Builder &);
  friend void DynamicUniquedUTF16StringPrimitiveBuildMeta(
      const GCCell *,
      Metadata::Builder &);
  using OptSymbolStringPrimitive<Uniqued>::isExternalLength;
  using OptSymbolStringPrimitive<Uniqued>::getStringLength;

  using Ref = llvh::ArrayRef<T>;

 public:
                                            
  static constexpr CellKind getCellKind() {
    return std::is_same<T, char16_t>::value
        ? (Uniqued ? CellKind::DynamicUniquedUTF16StringPrimitiveKind
                   : CellKind::DynamicUTF16StringPrimitiveKind)
        : (Uniqued ? CellKind::DynamicUniquedASCIIStringPrimitiveKind
                   : CellKind::DynamicASCIIStringPrimitiveKind);
  }

  static bool classof(const GCCell *cell) {
    return cell->getKind() == DynamicStringPrimitive::getCellKind();
  }

 private:
  static const VTable vt;

 public:
                                                                       
                                                                       
  explicit DynamicStringPrimitive(uint32_t length)
      : OptSymbolStringPrimitive<Uniqued>(length) {
    assert(!isExternalLength(length) && "length should not be external");
  }

  explicit DynamicStringPrimitive(Ref src);

 private:
                                                                              
                                                                              
  static CallResult<HermesValue> create(Runtime &runtime, Ref str);

                                                             
                                                                      
                    
  static CallResult<HermesValue> createLongLived(Runtime &runtime, Ref str);

                                                                       
                                                                         
                                                                    
                                                                            
  static CallResult<HermesValue> create(Runtime &runtime, uint32_t length);

                                                                        
             
  static uint32_t allocationSize(uint32_t length) {
                                                                        
                                           
    return std::max(
        DynamicStringPrimitive::template totalSizeToAlloc<T>(length),
        static_cast<size_t>(GC::minAllocationSize()));
  }

  const T *getRawPointer() const {
    return this->template getTrailingObjects<T>();
  }

                                                                             
                                                                           
                                                                             
                          
  T *getRawPointerForWrite() {
    return this->template getTrailingObjects<T>();
  }
};

                                                                               
                                                                          
                                                                       
                                                                               
                                                                                
             
template <typename T>
class ExternalStringPrimitive final : public SymbolStringPrimitive {
  friend class IdentifierTable;
  friend class StringBuilder;
  friend class StringPrimitive;
                                                                             
                               
  template <typename U>
  friend class BufferedStringPrimitive;
  friend PseudoHandle<StringPrimitive> internalConcatStringPrimitives(
      Runtime &runtime,
      Handle<StringPrimitive> leftHnd,
      Handle<StringPrimitive> rightHnd);
  friend void ExternalASCIIStringPrimitiveBuildMeta(
      const GCCell *,
      Metadata::Builder &);
  friend void ExternalUTF16StringPrimitiveBuildMeta(
      const GCCell *,
      Metadata::Builder &);

  using Ref = llvh::ArrayRef<T>;
  using StdString = std::basic_string<T>;
  using CopyableStdString = CopyableBasicString<T>;

 public:
                                            
  static constexpr CellKind getCellKind() {
    return std::is_same<T, char16_t>::value
        ? CellKind::ExternalUTF16StringPrimitiveKind
        : CellKind::ExternalASCIIStringPrimitiveKind;
  }

  static bool classof(const GCCell *cell) {
    return cell->getKind() == ExternalStringPrimitive::getCellKind();
  }

 private:
  static const VTable vt;

  size_t calcExternalMemorySize() const {
    return contents_.capacity() * sizeof(T);
  }

 public:
                                                                             
                  
  template <class BasicString>
  ExternalStringPrimitive(BasicString &&contents);

 private:
                                                  
  ~ExternalStringPrimitive() = default;

                                                                          
                                                                              
  template <class BasicString>
  static CallResult<HermesValue> create(Runtime &runtime, BasicString &&str);

                                                                            
                                                                            
                                                                        
                                                   
  static CallResult<HermesValue> createLongLived(
      Runtime &runtime,
      StdString &&str);

                                                                       
                                                                         
                                                                    
                                                                            
  static CallResult<HermesValue> create(Runtime &runtime, uint32_t length);

  const T *getRawPointer() const {
                                                                  
    return &contents_[0];
  }

                                                                             
                                                                           
                                                                             
                          
  T *getRawPointerForWrite() {
                                                                  
    return &contents_[0];
  }

                                                
  static void _finalizeImpl(GCCell *cell, GC &gc);

                                                                               
                                               
  static size_t _mallocSizeImpl(GCCell *cell);

#ifdef HERMES_MEMORY_INSTRUMENTATION
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif

                                                                                
                                                                     
  CopyableStdString contents_{};
};

                                                                   
                                                                               
                                                                              
                                                                              
                                                                            
   
                                                                              
                                                                             
                                            
         
                                 
                                            
            
                                                                          
                                          
   
                                                                              
                                                                                
                                                                              
                                                                       
template <typename T>
class BufferedStringPrimitive final : public StringPrimitive {
  friend class IdentifierTable;
  friend class StringBuilder;
  friend class StringPrimitive;
  friend PseudoHandle<StringPrimitive> internalConcatStringPrimitives(
      Runtime &runtime,
      Handle<StringPrimitive> leftHnd,
      Handle<StringPrimitive> rightHnd);
  friend void BufferedASCIIStringPrimitiveBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);
  friend void BufferedUTF16StringPrimitiveBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

  using Ref = llvh::ArrayRef<T>;
  using StdString = std::basic_string<T>;

 public:
                                            
  static constexpr CellKind getCellKind() {
    return std::is_same<T, char16_t>::value
        ? CellKind::BufferedUTF16StringPrimitiveKind
        : CellKind::BufferedASCIIStringPrimitiveKind;
  }

  static bool classof(const GCCell *cell) {
    return cell->getKind() == BufferedStringPrimitive::getCellKind();
  }

#ifdef UNIT_TEST
                                                     
  ExternalStringPrimitive<T> *testGetConcatBuffer() const {
    return vmcast<ExternalStringPrimitive<T>>(concatBufferHV_);
  }
#endif

 private:
  static const VTable vt;

 public:
                                                                             
                                                                              
                                                                    
  BufferedStringPrimitive(
      Runtime &runtime,
      uint32_t length,
      Handle<ExternalStringPrimitive<T>> concatBuffer)
      : StringPrimitive(length) {
    concatBufferHV_.set(
        HermesValue::encodeObjectValue(*concatBuffer), runtime.getHeap());
    assert(
        concatBuffer->contents_.size() >= length &&
        "length exceeds size of concatenation buffer");
  }

 private:
                                                                            
                                                                              
                                                                    
  static PseudoHandle<StringPrimitive> create(
      Runtime &runtime,
      uint32_t length,
      Handle<ExternalStringPrimitive<T>> storage);

                                                                        
                                                      
                                                                              
                                               
                                                                      
  static PseudoHandle<StringPrimitive> append(
      Handle<BufferedStringPrimitive<T>> selfHnd,
      Runtime &runtime,
      Handle<StringPrimitive> rightHnd);

                                                                             
                                                                               
                                                                             
             
                                                                              
                                                                 
                                                                    
  static PseudoHandle<StringPrimitive> create(
      Runtime &runtime,
      Handle<StringPrimitive> leftHnd,
      Handle<StringPrimitive> rightHnd);

                                                                               
                                    
                                        
  static void appendToCopyableString(
      CopyableBasicString<T> &res,
      const StringPrimitive *str);

                                                                   
  const T *getRawPointer() const {
    return getConcatBuffer()->getRawPointer();
  }

                                                               
                                 
                                                                         
  ExternalStringPrimitive<T> *getConcatBuffer() const {
    return vmcast<ExternalStringPrimitive<T>>(concatBufferHV_);
  }

  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);

                                                                             
                                                           
                              
                                                                        
                                                                             
                                                          
  GCHermesValue concatBufferHV_;
};

                                                                       
inline bool isBufferedStringPrimitive(const GCCell *cell) {
  return cell->getKind() == CellKind::BufferedUTF16StringPrimitiveKind ||
      cell->getKind() == CellKind::BufferedASCIIStringPrimitiveKind;
}

                                                                         
                                                                          
                                                                            
                                                                
                                                                         
                                                                                
            
                                                               
                                                      
                              
                                                         
                                                                    
PseudoHandle<StringPrimitive> internalConcatStringPrimitives(
    Runtime &runtime,
    Handle<StringPrimitive> leftHnd,
    Handle<StringPrimitive> rightHnd);

template <typename T, bool Uniqued>
const VTable DynamicStringPrimitive<T, Uniqued>::vt = VTable(
    DynamicStringPrimitive<T, Uniqued>::getCellKind(),
    0,
    nullptr,
    nullptr,
    nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
    ,
    VTable::HeapSnapshotMetadata{
        HeapSnapshot::NodeType::String,
        DynamicStringPrimitive<T, Uniqued>::_snapshotNameImpl,
        nullptr,
        nullptr,
        nullptr}
#endif
);

using DynamicUTF16StringPrimitive =
    DynamicStringPrimitive<char16_t, false                  >;
using DynamicASCIIStringPrimitive =
    DynamicStringPrimitive<char, false                  >;
using DynamicUniquedUTF16StringPrimitive =
    DynamicStringPrimitive<char16_t, true              >;
using DynamicUniquedASCIIStringPrimitive =
    DynamicStringPrimitive<char, true              >;

template <typename T>
const VTable ExternalStringPrimitive<T>::vt = VTable(
    ExternalStringPrimitive<T>::getCellKind(),
    0,
    ExternalStringPrimitive<T>::_finalizeImpl,
    ExternalStringPrimitive<T>::_mallocSizeImpl,
    nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
    ,
    VTable::HeapSnapshotMetadata{
        HeapSnapshot::NodeType::String,
        ExternalStringPrimitive<T>::_snapshotNameImpl,
        ExternalStringPrimitive<T>::_snapshotAddEdgesImpl,
        ExternalStringPrimitive<T>::_snapshotAddNodesImpl,
        nullptr}
#endif
);

using ExternalUTF16StringPrimitive = ExternalStringPrimitive<char16_t>;
using ExternalASCIIStringPrimitive = ExternalStringPrimitive<char>;

template <typename T>
const VTable BufferedStringPrimitive<T>::vt = VTable(
    BufferedStringPrimitive<T>::getCellKind(),
    0,
    nullptr,             
    nullptr,              
    nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
    ,
    VTable::HeapSnapshotMetadata{
        HeapSnapshot::NodeType::String,
        BufferedStringPrimitive<T>::_snapshotNameImpl,
        BufferedStringPrimitive<T>::_snapshotAddEdgesImpl,
        BufferedStringPrimitive<T>::_snapshotAddNodesImpl,
        nullptr}
#endif
);

using BufferedUTF16StringPrimitive = BufferedStringPrimitive<char16_t>;
using BufferedASCIIStringPrimitive = BufferedStringPrimitive<char>;

                                                                                
                                  

inline llvh::raw_ostream &operator<<(
    llvh::raw_ostream &OS,
    const StringPrimitive *str) {
  if (str->isASCII()) {
    return OS << str->castToASCIIRef();
  }
  return OS << str->castToUTF16Ref();
}

           inline Handle<StringPrimitive> StringPrimitive::createNoThrow(
    Runtime &runtime,
    UTF16Ref str) {
  auto strRes = create(runtime, str);
  if (strRes == ExecutionStatus::EXCEPTION) {
    hermes_fatal("String allocation failed");
  }
  return runtime.makeHandle<StringPrimitive>(*strRes);
}

           inline Handle<StringPrimitive> StringPrimitive::createNoThrow(
    Runtime &runtime,
    llvh::StringRef ascii) {
  auto strRes = create(runtime, ASCIIRef(ascii.data(), ascii.size()));
  if (strRes == ExecutionStatus::EXCEPTION) {
    hermes_fatal("String allocation failed");
  }
  return runtime.makeHandle<StringPrimitive>(*strRes);
}

inline CallResult<HermesValue>
StringPrimitive::create(Runtime &runtime, uint32_t length, bool asciiNotUTF16) {
  static_assert(
      EXTERNAL_STRING_THRESHOLD < MAX_STRING_LENGTH,
      "External string threshold should be smaller than max string size.");
  if (LLVM_LIKELY(!isExternalLength(length))) {
    if (asciiNotUTF16) {
      return DynamicASCIIStringPrimitive::create(runtime, length);
    } else {
      return DynamicUTF16StringPrimitive::create(runtime, length);
    }
  } else {
    if (asciiNotUTF16) {
      return ExternalStringPrimitive<char>::create(runtime, length);
    } else {
      return ExternalStringPrimitive<char16_t>::create(runtime, length);
    }
  }
}

inline CallResult<HermesValue> StringPrimitive::create(
    Runtime &runtime,
    ASCIIRef str) {
  static_assert(
      EXTERNAL_STRING_THRESHOLD < MAX_STRING_LENGTH,
      "External string threshold should be smaller than max string size.");
  if (LLVM_LIKELY(!isExternalLength(str.size()))) {
    return DynamicASCIIStringPrimitive::create(runtime, str);
  } else {
    return ExternalStringPrimitive<char>::create(runtime, arrayToString(str));
  }
}

inline CallResult<HermesValue> StringPrimitive::create(
    Runtime &runtime,
    UTF16Ref str) {
  static_assert(
      EXTERNAL_STRING_THRESHOLD < MAX_STRING_LENGTH,
      "External string threshold should be smaller than max string size.");
  if (LLVM_LIKELY(!isExternalLength(str.size()))) {
    return createDynamic(runtime, str);
  } else {
    return ExternalStringPrimitive<char16_t>::create(
        runtime, arrayToString(str));
  }
}

inline CallResult<HermesValue> StringPrimitive::createWithKnownEncoding(
    Runtime &runtime,
    UTF16Ref str,
    bool isASCII) {
  static_assert(
      EXTERNAL_STRING_THRESHOLD < MAX_STRING_LENGTH,
      "External string threshold should be smaller than max string size.");
  if (LLVM_LIKELY(!isExternalLength(str.size()))) {
    return createDynamicWithKnownEncoding(runtime, str, isASCII);
  } else {
    return ExternalStringPrimitive<char16_t>::create(
        runtime, arrayToString(str));
  }
}

inline CallResult<HermesValue> StringPrimitive::createLongLived(
    Runtime &runtime,
    ASCIIRef str) {
  static_assert(
      EXTERNAL_STRING_THRESHOLD < MAX_STRING_LENGTH,
      "External string threshold should be smaller than max string size.");
  if (LLVM_LIKELY(!isExternalLength(str.size()))) {
    return DynamicASCIIStringPrimitive::createLongLived(runtime, str);
  } else {
    return ExternalStringPrimitive<char>::createLongLived(
        runtime, arrayToString(str));
  }
}

inline CallResult<HermesValue> StringPrimitive::createLongLived(
    Runtime &runtime,
    UTF16Ref str) {
  static_assert(
      EXTERNAL_STRING_THRESHOLD < MAX_STRING_LENGTH,
      "External string threshold should be smaller than max string size.");
  if (LLVM_LIKELY(!isExternalLength(str.size()))) {
    return DynamicUTF16StringPrimitive::createLongLived(runtime, str);
  } else {
    return ExternalStringPrimitive<char16_t>::createLongLived(
        runtime, arrayToString(str));
  }
}

inline bool StringPrimitive::canBeUniqued() const {
  return vmisa<SymbolStringPrimitive>(this);
}

inline void StringPrimitive::convertToUniqued(hermes::vm::SymbolID uniqueID) {
  assert(canBeUniqued() && "StringPrimitive cannot be uniqued");
  assert(!isUniqued() && "StringPrimitive is already uniqued");
  assert(
      uniqueID.isValid() && uniqueID.isUniqued() &&
      "uniqueID SymbolID is not valid and uniqued");
  this->lengthAndUniquedFlag_ |= LENGTH_FLAG_UNIQUED;
  vmcast<SymbolStringPrimitive>(this)->updateUniqueID(uniqueID);
}

template <>
inline const char *StringPrimitive::castToPointer<char>() const {
  return castToASCIIPointer();
}
template <>
inline const char16_t *StringPrimitive::castToPointer<char16_t>() const {
  return castToUTF16Pointer();
}

inline const char *StringPrimitive::castToASCIIPointer() const {
  if (LLVM_UNLIKELY(isExternal())) {
    return vmcast<ExternalASCIIStringPrimitive>(this)->getRawPointer();
  } else if (vmisa<DynamicUniquedASCIIStringPrimitive>(this)) {
    return vmcast<DynamicUniquedASCIIStringPrimitive>(this)->getRawPointer();
  } else if (vmisa<DynamicASCIIStringPrimitive>(this)) {
    return vmcast<DynamicASCIIStringPrimitive>(this)->getRawPointer();
  } else {
    return vmcast<BufferedASCIIStringPrimitive>(this)->getRawPointer();
  }
}

inline const char16_t *StringPrimitive::castToUTF16Pointer() const {
  if (LLVM_UNLIKELY(isExternal())) {
    return vmcast<ExternalUTF16StringPrimitive>(this)->getRawPointer();
  } else if (vmisa<DynamicUniquedUTF16StringPrimitive>(this)) {
    return vmcast<DynamicUniquedUTF16StringPrimitive>(this)->getRawPointer();
  } else if (vmisa<DynamicUTF16StringPrimitive>(this)) {
    return vmcast<DynamicUTF16StringPrimitive>(this)->getRawPointer();
  } else {
    return vmcast<BufferedUTF16StringPrimitive>(this)->getRawPointer();
  }
}

inline char *StringPrimitive::castToASCIIPointerForWrite() {
  if (LLVM_UNLIKELY(isExternal())) {
    return vmcast<ExternalASCIIStringPrimitive>(this)->getRawPointerForWrite();
  } else if (vmisa<DynamicUniquedASCIIStringPrimitive>(this)) {
    return vmcast<DynamicUniquedASCIIStringPrimitive>(this)
        ->getRawPointerForWrite();
  } else {
    return vmcast<DynamicASCIIStringPrimitive>(this)->getRawPointerForWrite();
  }
}

inline char16_t *StringPrimitive::castToUTF16PointerForWrite() {
  if (LLVM_UNLIKELY(isExternal())) {
    return vmcast<ExternalUTF16StringPrimitive>(this)->getRawPointerForWrite();
  } else if (vmisa<DynamicUniquedUTF16StringPrimitive>(this)) {
    return vmcast<DynamicUniquedUTF16StringPrimitive>(this)
        ->getRawPointerForWrite();
  } else {
    return vmcast<DynamicUTF16StringPrimitive>(this)->getRawPointerForWrite();
  }
}

inline SymbolID StringPrimitive::getUniqueID() const {
  assert(this->isUniqued() && "StringPrimitive is not uniqued");
  return vmcast<SymbolStringPrimitive>(this)->getUniqueID();
}

inline char16_t StringPrimitive::at(uint32_t index) const {
  assert(index < getStringLength() && "Index out of bound");
  if (isASCII()) {
    return *(castToASCIIPointer() + index);
  } else {
    return *(castToUTF16Pointer() + index);
  }
}

inline bool StringPrimitive::isASCII() const {
                                                
                                                                     
                                                                            
                                                                    
                                                                              
                                                                    
                                
  static_assert(
      cellKindsContiguousAscending(
          CellKind::DynamicUTF16StringPrimitiveKind,
          CellKind::DynamicASCIIStringPrimitiveKind,
          CellKind::BufferedUTF16StringPrimitiveKind,
          CellKind::BufferedASCIIStringPrimitiveKind,
          CellKind::DynamicUniquedUTF16StringPrimitiveKind,
          CellKind::DynamicUniquedASCIIStringPrimitiveKind,
          CellKind::ExternalUTF16StringPrimitiveKind,
          CellKind::ExternalASCIIStringPrimitiveKind),
      "Cell kinds in unexpected order");
                                                                          
          
  return (static_cast<uint32_t>(getKind()) & 1u) ==
      (static_cast<uint32_t>(CellKind::DynamicASCIIStringPrimitiveKind) & 1u);
}

inline bool StringPrimitive::isExternal() const {
                                                                           
  static_assert(
      cellKindsContiguousAscending(
          CellKind::DynamicUTF16StringPrimitiveKind,
          CellKind::DynamicASCIIStringPrimitiveKind,
          CellKind::BufferedUTF16StringPrimitiveKind,
          CellKind::BufferedASCIIStringPrimitiveKind,
          CellKind::DynamicUniquedUTF16StringPrimitiveKind,
          CellKind::DynamicUniquedASCIIStringPrimitiveKind,
          CellKind::ExternalUTF16StringPrimitiveKind,
          CellKind::ExternalASCIIStringPrimitiveKind),
      "Cell kinds in unexpected order");
  return getKind() >= CellKind::ExternalUTF16StringPrimitiveKind;
}

}                
}                    

#pragma GCC diagnostic pop
#endif                               
