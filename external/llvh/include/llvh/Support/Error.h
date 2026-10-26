//===- llvm/Support/Error.h - Recoverable error handling --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines an API used to report recoverable errors.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ERROR_H
#define LLVM_SUPPORT_ERROR_H

#include "llvh-c/Error.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Config/abi-breaking.h"
#include "llvh/Support/AlignOf.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/ErrorOr.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <new>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace llvh {

class ErrorSuccess;

                                                                          
                                            
class ErrorInfoBase {
public:
  virtual ~ErrorInfoBase() = default;

                                                 
  virtual void log(raw_ostream &OS) const = 0;

                                           
  virtual std::string message() const {
    std::string Msg;
    raw_string_ostream OS(Msg);
    log(OS);
    return OS.str();
  }

                                              
     
                                                                      
                                                              
  virtual std::error_code convertToErrorCode() const = 0;

                                        
  static const void *classID() { return &ID; }

                                                                              
  virtual const void *dynamicClassID() const = 0;

                                                                         
             
  virtual bool isA(const void *const ClassID) const {
    return ClassID == classID();
  }

                                                             
  template <typename ErrorInfoT> bool isA() const {
    return isA(ErrorInfoT::classID());
  }

private:
  virtual void anchor();

  static char ID;
};

                                                                      
   
                                                                        
                                                                      
                                                                      
                                        
   
                                                                        
                                                                            
                                                                          
                                                   
   
                                                                           
                                                                    
                                                                  
   
                 
                       
   
                              
                                                             
                                                                               
                   
              
   
                                                                                
                                                                            
                    
   
                                                                     
                                                                        
   
                 
                                                         
                             
        
   
                                                               
   
                                                                      
                 
                       
                                    
                                   
            
                                                      
                                
                              
                                      
             
                                                                         
                                       
            
                                                                        
                              
              
   
                                                                     
                                                                             
                                                                           
                                                                    
   
                                                                     
                                                                               
                                                                              
class LLVM_NODISCARD Error {
                                                                       
                                                         
  friend class ErrorList;
  friend class FileError;

                                                           
  template <typename... HandlerTs>
  friend Error handleErrors(Error E, HandlerTs &&... Handlers);

                                                                               
           
  template <typename T> friend class Expected;

                                                
  friend LLVMErrorRef wrap(Error);

protected:
                                                                             
  Error() {
    setPtr(nullptr);
    setChecked(false);
  }

public:
                             
  static ErrorSuccess success();

                                       
  Error(const Error &Other) = delete;

                                                                              
                                                                              
                                                                        
  Error(Error &&Other) {
    setChecked(true);
    *this = std::move(Other);
  }

                                                                        
                                                                             
  Error(std::unique_ptr<ErrorInfoBase> Payload) {
    setPtr(Payload.release());
    setChecked(false);
  }

                                    
  Error &operator=(const Error &Other) = delete;

                                                                               
                                                                        
                                                                             
                                       
  Error &operator=(Error &&Other) {
                                                   
    assertIsChecked();
    setPtr(Other.getPtr());

                                                                     
    setChecked(false);

                                                        
    Other.setPtr(nullptr);
    Other.setChecked(true);

    return *this;
  }

                                                                   
                
  ~Error() {
    assertIsChecked();
    delete getPtr();
  }

                                                                        
                                                                               
                                    
  explicit operator bool() {
    setChecked(getPtr() == nullptr);
    return getPtr() != nullptr;
  }

                                                       
  template <typename ErrT> bool isA() const {
    return getPtr() && getPtr()->isA(ErrT::classID());
  }

                                                                              
            
  const void* dynamicClassID() const {
    if (!getPtr())
      return nullptr;
    return getPtr()->dynamicClassID();
  }

private:
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
                                                                              
                                                                                
                                                                             
                                                                                
             
  LLVM_ATTRIBUTE_NORETURN
  void fatalUncheckedError() const;
#endif

  void assertIsChecked() {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    if (LLVM_UNLIKELY(!getChecked() || getPtr()))
      fatalUncheckedError();
#endif
  }

  ErrorInfoBase *getPtr() const {
    return reinterpret_cast<ErrorInfoBase*>(
             reinterpret_cast<uintptr_t>(Payload) &
             ~static_cast<uintptr_t>(0x1));
  }

  void setPtr(ErrorInfoBase *EI) {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    Payload = reinterpret_cast<ErrorInfoBase*>(
                (reinterpret_cast<uintptr_t>(EI) &
                 ~static_cast<uintptr_t>(0x1)) |
                (reinterpret_cast<uintptr_t>(Payload) & 0x1));
#else
    Payload = EI;
#endif
  }

  bool getChecked() const {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    return (reinterpret_cast<uintptr_t>(Payload) & 0x1) == 0;
#else
    return true;
#endif
  }

  void setChecked(bool V) {
    Payload = reinterpret_cast<ErrorInfoBase*>(
                (reinterpret_cast<uintptr_t>(Payload) &
                  ~static_cast<uintptr_t>(0x1)) |
                  (V ? 0 : 1));
  }

  std::unique_ptr<ErrorInfoBase> takePayload() {
    std::unique_ptr<ErrorInfoBase> Tmp(getPtr());
    setPtr(nullptr);
    setChecked(true);
    return Tmp;
  }

  friend raw_ostream &operator<<(raw_ostream &OS, const Error &E) {
    if (auto P = E.getPtr())
      P->log(OS);
    else
      OS << "success";
    return OS;
  }

  ErrorInfoBase *Payload = nullptr;
};

                                                                             
                                                                              
                 
class ErrorSuccess final : public Error {};

inline ErrorSuccess Error::success() { return ErrorSuccess(); }

                                                                         
         
template <typename ErrT, typename... ArgTs> Error make_error(ArgTs &&... Args) {
  return Error(llvh::make_unique<ErrT>(std::forward<ArgTs>(Args)...));
}

                                                                           
         
   
                                               
          
      
   
                                                                    
                                                   
template <typename ThisErrT, typename ParentErrT = ErrorInfoBase>
class ErrorInfo : public ParentErrT {
public:
  using ParentErrT::ParentErrT;                        

  static const void *classID() { return &ThisErrT::ID; }

  const void *dynamicClassID() const override { return &ThisErrT::ID; }

  bool isA(const void *const ClassID) const override {
    return ClassID == classID() || ParentErrT::isA(ClassID);
  }
};

                                                                 
                                                         
class ErrorList final : public ErrorInfo<ErrorList> {
                                                                    
               
  template <typename... HandlerTs>
  friend Error handleErrors(Error E, HandlerTs &&... Handlers);

                                                
  friend Error joinErrors(Error, Error);

public:
  void log(raw_ostream &OS) const override {
    OS << "Multiple errors:\n";
    for (auto &ErrPayload : Payloads) {
      ErrPayload->log(OS);
      OS << "\n";
    }
  }

  std::error_code convertToErrorCode() const override;

                                
  static char ID;

private:
  ErrorList(std::unique_ptr<ErrorInfoBase> Payload1,
            std::unique_ptr<ErrorInfoBase> Payload2) {
    assert(!Payload1->isA<ErrorList>() && !Payload2->isA<ErrorList>() &&
           "ErrorList constructor payloads should be singleton errors");
    Payloads.push_back(std::move(Payload1));
    Payloads.push_back(std::move(Payload2));
  }

  static Error join(Error E1, Error E2) {
    if (!E1)
      return E2;
    if (!E2)
      return E1;
    if (E1.isA<ErrorList>()) {
      auto &E1List = static_cast<ErrorList &>(*E1.getPtr());
      if (E2.isA<ErrorList>()) {
        auto E2Payload = E2.takePayload();
        auto &E2List = static_cast<ErrorList &>(*E2Payload);
        for (auto &Payload : E2List.Payloads)
          E1List.Payloads.push_back(std::move(Payload));
      } else
        E1List.Payloads.push_back(E2.takePayload());

      return E1;
    }
    if (E2.isA<ErrorList>()) {
      auto &E2List = static_cast<ErrorList &>(*E2.getPtr());
      E2List.Payloads.insert(E2List.Payloads.begin(), E1.takePayload());
      return E2;
    }
    return Error(std::unique_ptr<ErrorList>(
        new ErrorList(E1.takePayload(), E2.takePayload())));
  }

  std::vector<std::unique_ptr<ErrorInfoBase>> Payloads;
};

                                                                          
                                                          
                                          
inline Error joinErrors(Error E1, Error E2) {
  return ErrorList::join(std::move(E1), std::move(E2));
}

                                               
   
                                                                           
                                                               
                                                                             
                     
template <class T> class LLVM_NODISCARD Expected {
  template <class T1> friend class ExpectedAsOutParameter;
  template <class OtherT> friend class Expected;

  static const bool isRef = std::is_reference<T>::value;

  using wrap = std::reference_wrapper<typename std::remove_reference<T>::type>;

  using error_type = std::unique_ptr<ErrorInfoBase>;

public:
  using storage_type = typename std::conditional<isRef, wrap, T>::type;
  using value_type = T;

private:
  using reference = typename std::remove_reference<T>::type &;
  using const_reference = const typename std::remove_reference<T>::type &;
  using pointer = typename std::remove_reference<T>::type *;
  using const_pointer = const typename std::remove_reference<T>::type *;

public:
                                                             
  Expected(Error Err)
      : HasError(true)
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
                                                                   
        , Unchecked(true)
#endif
  {
    assert(Err && "Cannot create Expected<T> from Error success value.");
    new (getErrorStorage()) error_type(Err.takePayload());
  }

                                                                            
                                                                             
                                       
  Expected(ErrorSuccess) = delete;

                                                                            
                               
  template <typename OtherT>
  Expected(OtherT &&Val,
           typename std::enable_if<std::is_convertible<OtherT, T>::value>::type
               * = nullptr)
      : HasError(false)
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
                                                                   
        , Unchecked(true)
#endif
  {
    new (getStorage()) storage_type(std::forward<OtherT>(Val));
  }

                                          
  Expected(Expected &&Other) { moveConstruct(std::move(Other)); }

                                                                                
                               
  template <class OtherT>
  Expected(Expected<OtherT> &&Other,
           typename std::enable_if<std::is_convertible<OtherT, T>::value>::type
               * = nullptr) {
    moveConstruct(std::move(Other));
  }

                                                                                
                             
  template <class OtherT>
  explicit Expected(
      Expected<OtherT> &&Other,
      typename std::enable_if<!std::is_convertible<OtherT, T>::value>::type * =
          nullptr) {
    moveConstruct(std::move(Other));
  }

                                           
  Expected &operator=(Expected &&Other) {
    moveAssign(std::move(Other));
    return *this;
  }

                             
  ~Expected() {
    assertIsChecked();
    if (!HasError)
      getStorage()->~storage_type();
    else
      getErrorStorage()->~error_type();
  }

                                        
  explicit operator bool() {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    Unchecked = HasError;
#endif
    return !HasError;
  }

                                                
  reference get() {
    assertIsChecked();
    return *getStorage();
  }

                                                      
  const_reference get() const {
    assertIsChecked();
    return const_cast<Expected<T> *>(this)->get();
  }

                                                           
  template <typename ErrT> bool errorIsA() const {
    return HasError && (*getErrorStorage())->template isA<ErrT>();
  }

                                         
                                                                              
                                                                                
                                       
  Error takeError() {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    Unchecked = false;
#endif
    return HasError ? Error(std::move(*getErrorStorage())) : Error::success();
  }

                                              
  pointer operator->() {
    assertIsChecked();
    return toPointer(getStorage());
  }

                                                    
  const_pointer operator->() const {
    assertIsChecked();
    return toPointer(getStorage());
  }

                                                
  reference operator*() {
    assertIsChecked();
    return *getStorage();
  }

                                                      
  const_reference operator*() const {
    assertIsChecked();
    return *getStorage();
  }

private:
  template <class T1>
  static bool compareThisIfSameType(const T1 &a, const T1 &b) {
    return &a == &b;
  }

  template <class T1, class T2>
  static bool compareThisIfSameType(const T1 &a, const T2 &b) {
    return false;
  }

  template <class OtherT> void moveConstruct(Expected<OtherT> &&Other) {
    HasError = Other.HasError;
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    Unchecked = true;
    Other.Unchecked = false;
#endif

    if (!HasError)
      new (getStorage()) storage_type(std::move(*Other.getStorage()));
    else
      new (getErrorStorage()) error_type(std::move(*Other.getErrorStorage()));
  }

  template <class OtherT> void moveAssign(Expected<OtherT> &&Other) {
    assertIsChecked();

    if (compareThisIfSameType(*this, Other))
      return;

    this->~Expected();
    new (this) Expected(std::move(Other));
  }

  pointer toPointer(pointer Val) { return Val; }

  const_pointer toPointer(const_pointer Val) const { return Val; }

  pointer toPointer(wrap *Val) { return &Val->get(); }

  const_pointer toPointer(const wrap *Val) const { return &Val->get(); }

  storage_type *getStorage() {
    assert(!HasError && "Cannot get value when an error exists!");
    return reinterpret_cast<storage_type *>(TStorage.buffer);
  }

  const storage_type *getStorage() const {
    assert(!HasError && "Cannot get value when an error exists!");
    return reinterpret_cast<const storage_type *>(TStorage.buffer);
  }

  error_type *getErrorStorage() {
    assert(HasError && "Cannot get error when a value exists!");
    return reinterpret_cast<error_type *>(ErrorStorage.buffer);
  }

  const error_type *getErrorStorage() const {
    assert(HasError && "Cannot get error when a value exists!");
    return reinterpret_cast<const error_type *>(ErrorStorage.buffer);
  }

                                                              
  void setUnchecked() {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    Unchecked = true;
#endif
  }

#if LLVM_ENABLE_ABI_BREAKING_CHECKS
  LLVM_ATTRIBUTE_NORETURN
  LLVM_ATTRIBUTE_NOINLINE
  void fatalUncheckedExpected() const {
    dbgs() << "Expected<T> must be checked before access or destruction.\n";
    if (HasError) {
      dbgs() << "Unchecked Expected<T> contained error:\n";
      (*getErrorStorage())->log(dbgs());
    } else
      dbgs() << "Expected<T> value was in success state. (Note: Expected<T> "
                "values in success mode must still be checked prior to being "
                "destroyed).\n";
    abort();
  }
#endif

  void assertIsChecked() {
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
    if (LLVM_UNLIKELY(Unchecked))
      fatalUncheckedExpected();
#endif
  }

  union {
    AlignedCharArrayUnion<storage_type> TStorage;
    AlignedCharArrayUnion<error_type> ErrorStorage;
  };
  bool HasError : 1;
#if LLVM_ENABLE_ABI_BREAKING_CHECKS
  bool Unchecked : 1;
#endif
};

                                                                    
                    
LLVM_ATTRIBUTE_NORETURN void report_fatal_error(Error Err,
                                                bool gen_crash_diag = true);

                                                   
   
                                                                              
                                                                
   
                 
                                                                           
                                                                      
                          
                                          
   
                           
              
inline void cantFail(Error Err, const char *Msg = nullptr) {
  if (Err) {
    if (!Msg)
      Msg = "Failure value returned from cantFail wrapped call";
    llvm_unreachable(Msg);
  }
}

                                                                              
                                
   
                                                                              
                                                                
   
                 
                                                                           
                                                                              
                                                  
   
                                   
              
template <typename T>
T cantFail(Expected<T> ValOrErr, const char *Msg = nullptr) {
  if (ValOrErr)
    return std::move(*ValOrErr);
  else {
    if (!Msg)
      Msg = "Failure value returned from cantFail wrapped call";
    llvm_unreachable(Msg);
  }
}

                                                                              
                                    
   
                                                                              
                                                                
   
                 
                                                                           
                                                                              
                                                   
   
                                    
              
template <typename T>
T& cantFail(Expected<T&> ValOrErr, const char *Msg = nullptr) {
  if (ValOrErr)
    return *ValOrErr;
  else {
    if (!Msg)
      Msg = "Failure value returned from cantFail wrapped call";
    llvm_unreachable(Msg);
  }
}

                                                                   
                    
template <typename HandlerT>
class ErrorHandlerTraits
    : public ErrorHandlerTraits<decltype(
          &std::remove_reference<HandlerT>::type::operator())> {};

                                                              
template <typename ErrT> class ErrorHandlerTraits<Error (&)(ErrT &)> {
public:
  static bool appliesTo(const ErrorInfoBase &E) {
    return E.template isA<ErrT>();
  }

  template <typename HandlerT>
  static Error apply(HandlerT &&H, std::unique_ptr<ErrorInfoBase> E) {
    assert(appliesTo(*E) && "Applying incorrect handler");
    return H(static_cast<ErrT &>(*E));
  }
};

                                                             
template <typename ErrT> class ErrorHandlerTraits<void (&)(ErrT &)> {
public:
  static bool appliesTo(const ErrorInfoBase &E) {
    return E.template isA<ErrT>();
  }

  template <typename HandlerT>
  static Error apply(HandlerT &&H, std::unique_ptr<ErrorInfoBase> E) {
    assert(appliesTo(*E) && "Applying incorrect handler");
    H(static_cast<ErrT &>(*E));
    return Error::success();
  }
};

                                                                             
template <typename ErrT>
class ErrorHandlerTraits<Error (&)(std::unique_ptr<ErrT>)> {
public:
  static bool appliesTo(const ErrorInfoBase &E) {
    return E.template isA<ErrT>();
  }

  template <typename HandlerT>
  static Error apply(HandlerT &&H, std::unique_ptr<ErrorInfoBase> E) {
    assert(appliesTo(*E) && "Applying incorrect handler");
    std::unique_ptr<ErrT> SubE(static_cast<ErrT *>(E.release()));
    return H(std::move(SubE));
  }
};

                                                                            
template <typename ErrT>
class ErrorHandlerTraits<void (&)(std::unique_ptr<ErrT>)> {
public:
  static bool appliesTo(const ErrorInfoBase &E) {
    return E.template isA<ErrT>();
  }

  template <typename HandlerT>
  static Error apply(HandlerT &&H, std::unique_ptr<ErrorInfoBase> E) {
    assert(appliesTo(*E) && "Applying incorrect handler");
    std::unique_ptr<ErrT> SubE(static_cast<ErrT *>(E.release()));
    H(std::move(SubE));
    return Error::success();
  }
};

                                                                        
template <typename C, typename RetT, typename ErrT>
class ErrorHandlerTraits<RetT (C::*)(ErrT &)>
    : public ErrorHandlerTraits<RetT (&)(ErrT &)> {};

                                                                              
template <typename C, typename RetT, typename ErrT>
class ErrorHandlerTraits<RetT (C::*)(ErrT &) const>
    : public ErrorHandlerTraits<RetT (&)(ErrT &)> {};

                                                                        
template <typename C, typename RetT, typename ErrT>
class ErrorHandlerTraits<RetT (C::*)(const ErrT &)>
    : public ErrorHandlerTraits<RetT (&)(ErrT &)> {};

                                                                              
template <typename C, typename RetT, typename ErrT>
class ErrorHandlerTraits<RetT (C::*)(const ErrT &) const>
    : public ErrorHandlerTraits<RetT (&)(ErrT &)> {};

                                                   
                                   
template <typename C, typename RetT, typename ErrT>
class ErrorHandlerTraits<RetT (C::*)(std::unique_ptr<ErrT>)>
    : public ErrorHandlerTraits<RetT (&)(std::unique_ptr<ErrT>)> {};

                                                   
                                         
template <typename C, typename RetT, typename ErrT>
class ErrorHandlerTraits<RetT (C::*)(std::unique_ptr<ErrT>) const>
    : public ErrorHandlerTraits<RetT (&)(std::unique_ptr<ErrT>)> {};

inline Error handleErrorImpl(std::unique_ptr<ErrorInfoBase> Payload) {
  return Error(std::move(Payload));
}

template <typename HandlerT, typename... HandlerTs>
Error handleErrorImpl(std::unique_ptr<ErrorInfoBase> Payload,
                      HandlerT &&Handler, HandlerTs &&... Handlers) {
  if (ErrorHandlerTraits<HandlerT>::appliesTo(*Payload))
    return ErrorHandlerTraits<HandlerT>::apply(std::forward<HandlerT>(Handler),
                                               std::move(Payload));
  return handleErrorImpl(std::move(Payload),
                         std::forward<HandlerTs>(Handlers)...);
}

                                                                          
                                                                             
             
                                                                           
                                                                       
                                                                       
template <typename... HandlerTs>
Error handleErrors(Error E, HandlerTs &&... Hs) {
  if (!E)
    return Error::success();

  std::unique_ptr<ErrorInfoBase> Payload = E.takePayload();

  if (Payload->isA<ErrorList>()) {
    ErrorList &List = static_cast<ErrorList &>(*Payload);
    Error R;
    for (auto &P : List.Payloads)
      R = ErrorList::join(
          std::move(R),
          handleErrorImpl(std::move(P), std::forward<HandlerTs>(Hs)...));
    return R;
  }

  return handleErrorImpl(std::move(Payload), std::forward<HandlerTs>(Hs)...);
}

                                                                        
                                                                            
                                                                      
template <typename... HandlerTs>
void handleAllErrors(Error E, HandlerTs &&... Handlers) {
  cantFail(handleErrors(std::move(E), std::forward<HandlerTs>(Handlers)...));
}

                                              
                                                      
inline void handleAllErrors(Error E) {
  cantFail(std::move(E));
}

                                                                               
   
                                                                             
                                                                             
                                                                             
                                                                        
                                                             
   
                                            
   
                 
                                                    
                                       
   
                        
                       
                          
                                             
                                        
                                                                              
                        
             
   
              
template <typename T, typename RecoveryFtor, typename... HandlerTs>
Expected<T> handleExpected(Expected<T> ValOrErr, RecoveryFtor &&RecoveryPath,
                           HandlerTs &&... Handlers) {
  if (ValOrErr)
    return ValOrErr;

  if (auto Err = handleErrors(ValOrErr.takeError(),
                              std::forward<HandlerTs>(Handlers)...))
    return std::move(Err);

  return RecoveryPath();
}

                                                                            
                                                                             
                     
   
                                                                               
                                                                           
                            
void logAllUnhandledErrors(Error E, raw_ostream &OS, Twine ErrorBanner);

                                                                             
                                       
inline std::string toString(Error E) {
  SmallVector<std::string, 2> Errors;
  handleAllErrors(std::move(E), [&Errors](const ErrorInfoBase &EI) {
    Errors.push_back(EI.message());
  });
  return join(Errors.begin(), Errors.end(), "\n");
}

                                                                      
                                                                          
          
   
                                                                              
                                                                            
                                                              
inline void consumeError(Error Err) {
  handleAllErrors(std::move(Err), [](const ErrorInfoBase &) {});
}

                                             
   
                                                                           
                                                                          
                                                                     
inline bool errorToBool(Error Err) {
  bool IsError = static_cast<bool>(Err);
  if (IsError)
    consumeError(std::move(Err));
  return IsError;
}

                                             
   
                                                                                
                                                                               
                                                                               
                                                                              
                                                                                
                                                                               
         
   
                 
                              
                                                                      
                        
                                                                           
       
              
   
                                                                            
                                                                              
                                                                             
                                                                            
                                                                             
             
class ErrorAsOutParameter {
public:
  ErrorAsOutParameter(Error *Err) : Err(Err) {
                                               
    if (Err)
      (void)!!*Err;
  }

  ~ErrorAsOutParameter() {
                             
    if (Err && !*Err)
      *Err = Error::success();
  }

private:
  Error *Err;
};

                                                   
   
                            
template <typename T>
class ExpectedAsOutParameter {
public:
  ExpectedAsOutParameter(Expected<T> *ValOrErr)
    : ValOrErr(ValOrErr) {
    if (ValOrErr)
      (void)!!*ValOrErr;
  }

  ~ExpectedAsOutParameter() {
    if (ValOrErr)
      ValOrErr->setUnchecked();
  }

private:
  Expected<T> *ValOrErr;
};

                                                  
   
                                                                      
                                                              
                     
class ECError : public ErrorInfo<ECError> {
  friend Error errorCodeToError(std::error_code);

public:
  void setErrorCode(std::error_code EC) { this->EC = EC; }
  std::error_code convertToErrorCode() const override { return EC; }
  void log(raw_ostream &OS) const override { OS << EC.message(); }

                                
  static char ID;

protected:
  ECError() = default;
  ECError(std::error_code EC) : EC(EC) {}

  std::error_code EC;
};

                                                                               
                                                                             
                                                                              
                                                                               
                                                                               
                                         
std::error_code inconvertibleErrorCode();

                                                        
Error errorCodeToError(std::error_code EC);

                                                          
   
                                                                        
                                   
std::error_code errorToErrorCode(Error Err);

                                            
template <typename T> Expected<T> errorOrToExpected(ErrorOr<T> &&EO) {
  if (auto EC = EO.getError())
    return errorCodeToError(EC);
  return std::move(*EO);
}

                                            
template <typename T> ErrorOr<T> expectedToErrorOr(Expected<T> &&E) {
  if (auto Err = E.takeError())
    return errorToErrorCode(std::move(Err));
  return std::move(*E);
}

                                          
   
                                                                              
                                                                               
                                                  
   
                                                                             
                                                                              
                             
                                                   
                  
                                             
   
                                                                              
                                                                        
                                         
   
                 
                           
                                                                              
                                                                     
       
              
   
class StringError : public ErrorInfo<StringError> {
public:
  static char ID;

                                     
  StringError(std::error_code EC, const Twine &S = Twine());

                                
  StringError(const Twine &S, std::error_code EC);

  void log(raw_ostream &OS) const override;
  std::error_code convertToErrorCode() const override;

  const std::string &getMessage() const { return Msg; }

private:
  std::string Msg;
  std::error_code EC;
  const bool PrintMsgOnly = false;
};

                                        
template <typename... Ts>
Error createStringError(std::error_code EC, char const *Fmt,
                        const Ts &... Vals) {
  std::string Buffer;
  raw_string_ostream Stream(Buffer);
  Stream << format(Fmt, Vals...);
  return make_error<StringError>(Stream.str(), EC);
}

Error createStringError(std::error_code EC, char const *Msg);

                                                  
   
                                                                            
                                               
class FileError final : public ErrorInfo<FileError> {

  friend Error createFileError(std::string, Error);

public:
  void log(raw_ostream &OS) const override {
    assert(Err && !FileName.empty() && "Trying to log after takeError().");
    OS << "'" << FileName << "': ";
    Err->log(OS);
  }

  Error takeError() { return Error(std::move(Err)); }

  std::error_code convertToErrorCode() const override;

                                
  static char ID;

private:
  FileError(std::string F, std::unique_ptr<ErrorInfoBase> E) {
    assert(E && "Cannot create FileError from Error success value.");
    assert(!F.empty() &&
           "The file name provided to FileError must not be empty.");
    FileName = F;
    Err = std::move(E);
  }

  static Error build(std::string F, Error E) {
    return Error(std::unique_ptr<FileError>(new FileError(F, E.takePayload())));
  }

  std::string FileName;
  std::unique_ptr<ErrorInfoBase> Err;
};

                                                                           
                       
inline Error createFileError(std::string F, Error E) {
  return FileError::build(F, std::move(E));
}

Error createFileError(std::string F, ErrorSuccess) = delete;

                                             
   
                                                   
   
class ExitOnError {
public:
                                     
  ExitOnError(std::string Banner = "", int DefaultErrorExitCode = 1)
      : Banner(std::move(Banner)),
        GetExitCode([=](const Error &) { return DefaultErrorExitCode; }) {}

                                                                
  void setBanner(std::string Banner) { this->Banner = std::move(Banner); }

                                        
  void setExitCodeMapper(std::function<int(const Error &)> GetExitCode) {
    this->GetExitCode = std::move(GetExitCode);
  }

                                                                      
  void operator()(Error Err) const { checkError(std::move(Err)); }

                                                                             
                                                        
  template <typename T> T operator()(Expected<T> &&E) const {
    checkError(E.takeError());
    return std::move(*E);
  }

                                                                                 
                                                        
  template <typename T> T& operator()(Expected<T&> &&E) const {
    checkError(E.takeError());
    return *E;
  }

private:
  void checkError(Error Err) const {
    if (Err) {
      int ExitCode = GetExitCode(Err);
      logAllUnhandledErrors(std::move(Err), errs(), Banner);
      exit(ExitCode);
    }
  }

  std::string Banner;
  std::function<int(const Error &)> GetExitCode;
};

                                                               
inline LLVMErrorRef wrap(Error Err) {
  return reinterpret_cast<LLVMErrorRef>(Err.takePayload().release());
}

                                                               
inline Error unwrap(LLVMErrorRef ErrRef) {
  return Error(std::unique_ptr<ErrorInfoBase>(
      reinterpret_cast<ErrorInfoBase *>(ErrRef)));
}

}                      

#endif                        
