/*===--- ConvertUTF.h - Universal Character Names conversions ---------------===
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *==------------------------------------------------------------------------==*/
/*
 * Copyright 2001-2004 Unicode, Inc.
 *
 * Disclaimer
 *
 * This source code is provided as is by Unicode, Inc. No claims are
 * made as to fitness for any particular purpose. No warranties of any
 * kind are expressed or implied. The recipient agrees to determine
 * applicability of information provided. If this file has been
 * purchased on magnetic or optical media from Unicode, Inc., the
 * sole remedy for any claim will be exchange of defective media
 * within 90 days of receipt.
 *
 * Limitations on Rights to Redistribute This Code
 *
 * Unicode, Inc. hereby grants the right to freely use the information
 * supplied in this file in the creation of products supporting the
 * Unicode Standard, and to make copies of this file in any form
 * for internal or external distribution as long as this notice
 * remains attached.
 */

                                                                        

                                                               

                                                                 
                                                                 
                                                   

                                                                     
                                          

                                                                      
                                                               
                                                                     
                                      

                                                                      
                                                                        
                                                      

                                                                
                                                                      
                           

                     
                                                                
                                                                   
                                                            
                                                                         
                                                                       
                                                        

                                                                         
                                                                           
                                                                         
                                                    

                                                                           
                                                                             
                                                                          
                                     

                                                                           
                                                                            
                             

                      
                                                                             
                                                                            
                                                                            
                                                                            
                           

                                
                                                        
                                    

                                                                           

#ifndef LLVM_SUPPORT_CONVERTUTF_H
#define LLVM_SUPPORT_CONVERTUTF_H

#include <cstddef>
#include <string>
#include <system_error>

                                                                            
                                              

namespace llvh {

                                                                        
                                                      
                                                               
                                                                
                                                                
                                
                                                                           

typedef unsigned int    UTF32;                        
typedef unsigned short  UTF16;                        
typedef unsigned char   UTF8;                         
typedef unsigned char   Boolean;             

                                
#define UNI_REPLACEMENT_CHAR (UTF32)0x0000FFFD
#define UNI_MAX_BMP (UTF32)0x0000FFFF
#define UNI_MAX_UTF16 (UTF32)0x0010FFFF
#define UNI_MAX_UTF32 (UTF32)0x7FFFFFFF
#define UNI_MAX_LEGAL_UTF32 (UTF32)0x0010FFFF

#define UNI_MAX_UTF8_BYTES_PER_CODE_POINT 4

#define UNI_UTF16_BYTE_ORDER_MARK_NATIVE  0xFEFF
#define UNI_UTF16_BYTE_ORDER_MARK_SWAPPED 0xFFFE

typedef enum {
  conversionOK,                                      
  sourceExhausted,                                                      
  targetExhausted,                                                   
  sourceIllegal                                                     
} ConversionResult;

typedef enum {
  strictConversion = 0,
  lenientConversion
} ConversionFlags;

ConversionResult ConvertUTF8toUTF16 (
  const UTF8** sourceStart, const UTF8* sourceEnd,
  UTF16** targetStart, UTF16* targetEnd, ConversionFlags flags);

   
                                                                        
                                                             
   
ConversionResult ConvertUTF8toUTF32Partial(
  const UTF8** sourceStart, const UTF8* sourceEnd,
  UTF32** targetStart, UTF32* targetEnd, ConversionFlags flags);

   
                                                                        
                                                           
   
ConversionResult ConvertUTF8toUTF32(
  const UTF8** sourceStart, const UTF8* sourceEnd,
  UTF32** targetStart, UTF32* targetEnd, ConversionFlags flags);

ConversionResult ConvertUTF16toUTF8 (
  const UTF16** sourceStart, const UTF16* sourceEnd,
  UTF8** targetStart, UTF8* targetEnd, ConversionFlags flags);

ConversionResult ConvertUTF32toUTF8 (
  const UTF32** sourceStart, const UTF32* sourceEnd,
  UTF8** targetStart, UTF8* targetEnd, ConversionFlags flags);

ConversionResult ConvertUTF16toUTF32 (
  const UTF16** sourceStart, const UTF16* sourceEnd,
  UTF32** targetStart, UTF32* targetEnd, ConversionFlags flags);

ConversionResult ConvertUTF32toUTF16 (
  const UTF32** sourceStart, const UTF32* sourceEnd,
  UTF16** targetStart, UTF16* targetEnd, ConversionFlags flags);

Boolean isLegalUTF8Sequence(const UTF8 *source, const UTF8 *sourceEnd);

Boolean isLegalUTF8String(const UTF8 **source, const UTF8 *sourceEnd);

unsigned getNumBytesForUTF8(UTF8 firstByte);

                                                                           
                                                              

template <typename T> class ArrayRef;
template <typename T> class SmallVectorImpl;
class StringRef;

   
                                                                  
                                                                            
                                                                           
                                                                           
                                                                             
                                                    
                           
   
bool ConvertUTF8toWide(unsigned WideCharWidth, llvh::StringRef Source,
                       char *&ResultPtr, const UTF8 *&ErrorPtr);

   
                                               
                          
  
bool ConvertUTF8toWide(llvh::StringRef Source, std::wstring &Result);

   
                                              
                          
  
bool ConvertUTF8toWide(const char *Source, std::wstring &Result);

   
                                                         
                          
  
bool convertWideToUTF8(const std::wstring &Source, std::string &Result);


   
                                                  
  
                                      
                                                                               
                                                                          
                                                  
  
                            
   
bool ConvertCodePointToUTF8(unsigned Source, char *&ResultPtr);

   
                                                                        
              
  
                                                                           
                                                                            
                                 
                                                                     
                                         
                                                            
  
                                   
  
                         
   
inline ConversionResult convertUTF8Sequence(const UTF8 **source,
                                            const UTF8 *sourceEnd,
                                            UTF32 *target,
                                            ConversionFlags flags) {
  if (*source == sourceEnd)
    return sourceExhausted;
  unsigned size = getNumBytesForUTF8(**source);
  if ((ptrdiff_t)size > sourceEnd - *source)
    return sourceExhausted;
  return ConvertUTF8toUTF32(source, *source + size, &target, target + 1, flags);
}

   
                                                                                
              
   
bool hasUTF16ByteOrderMark(ArrayRef<char> SrcBytes);

   
                                                                              
  
                                                                              
                                                              
                           
   
bool convertUTF16ToUTF8String(ArrayRef<char> SrcBytes, std::string &Out);

   
                                                  
 
                                                  
                                                             
                          
  
bool convertUTF16ToUTF8String(ArrayRef<UTF16> Src, std::string &Out);

   
                                                                       
  
                           
   
bool convertUTF8ToUTF16String(StringRef SrcUTF8,
                              SmallVectorImpl<UTF16> &DstUTF16);

#if defined(_WIN32)
namespace sys {
namespace windows {
std::error_code UTF8ToUTF16(StringRef utf8, SmallVectorImpl<wchar_t> &utf16);
                                                                  
std::error_code CurCPToUTF16(StringRef utf8, SmallVectorImpl<wchar_t> &utf16);
std::error_code UTF16ToUTF8(const wchar_t *utf16, size_t utf16_len,
                            SmallVectorImpl<char> &utf8);
                                                                  
std::error_code UTF16ToCurCP(const wchar_t *utf16, size_t utf16_len,
                             SmallVectorImpl<char> &utf8);
}                     
}                 
#endif

}                         

#endif
