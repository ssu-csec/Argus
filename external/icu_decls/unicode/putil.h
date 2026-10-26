/*
******************************************************************************
*
*   Copyright (C) 1997-2011, International Business Machines
*   Corporation and others.  All Rights Reserved.
*
******************************************************************************
*
*  FILE NAME : putil.h
*
*   Date        Name        Description
*   05/14/98    nos         Creation (content moved here from utypes.h).
*   06/17/99    erm         Added IEEE_754
*   07/22/98    stephen     Added IEEEremainder, max, min, trunc
*   08/13/98    stephen     Added isNegativeInfinity, isPositiveInfinity
*   08/24/98    stephen     Added longBitsFromDouble
*   03/02/99    stephen     Removed openFile().  Added AS400 support.
*   04/15/99    stephen     Converted to C
*   11/15/99    helena      Integrated S/390 changes for IEEE support.
*   01/11/00    helena      Added u_getVersion.
******************************************************************************
*/

#ifndef PUTIL_H
#define PUTIL_H

#include "unicode/utypes.h"
    
         
                                    
    

                                                                              
                                                                              
                                                                              

   
                                                               
                                                                   
                                           
   

   
                                  
                                                                        
                                                               
                                                                  
                                                                 
                             
  
                                               
                                                                    
                                                                      
                                                        
              
        
                                      
           
                    
                                               
  
                                                                               
                          
     
                  
   
U_STABLE const char* U_EXPORT2 u_getDataDirectory(void);

    
                               
                                                                        
                                                               
                                                                  
                                                                 
                             
  
                                                                       
                                                                           
                 
                                                                        
                    
  
                                            
  
              
                  
   
U_STABLE void U_EXPORT2 u_setDataDirectory(const char *directory);

   
     
                                                 
                                                         
                  
   
#if U_PLATFORM == U_PF_CLASSIC_MACOS
#   define U_FILE_SEP_CHAR ':'
#   define U_FILE_ALT_SEP_CHAR ':'
#   define U_PATH_SEP_CHAR ';'
#   define U_FILE_SEP_STRING ":"
#   define U_FILE_ALT_SEP_STRING ":"
#   define U_PATH_SEP_STRING ";"
#elif U_PLATFORM_USES_ONLY_WIN32_API
#   define U_FILE_SEP_CHAR '\\'
#   define U_FILE_ALT_SEP_CHAR '/'
#   define U_PATH_SEP_CHAR ';'
#   define U_FILE_SEP_STRING "\\"
#   define U_FILE_ALT_SEP_STRING "/"
#   define U_PATH_SEP_STRING ";"
#else
#   define U_FILE_SEP_CHAR '/'
#   define U_FILE_ALT_SEP_CHAR '/'
#   define U_PATH_SEP_CHAR ':'
#   define U_FILE_SEP_STRING "/"
#   define U_FILE_ALT_SEP_STRING "/"
#   define U_PATH_SEP_STRING ":"
#endif

         

   
                                               
                                                                  
                                                     
                                                                
                                                        
                                     
  
                                                        
                                                                    
                                                                    
                                
                                                              
                                                          
  
                        
                  
   
U_STABLE void U_EXPORT2
u_charsToUChars(const char *cs, UChar *us, int32_t length);

   
                                               
                                                                  
                                                        
                                                                
                                                        
                                     
  
                                                        
                                                            
                                                                
                                                                    
                             
                                                              
                                                          
  
                        
                  
   
U_STABLE void U_EXPORT2
u_UCharsToChars(const UChar *us, char *cs, int32_t length);

#endif
