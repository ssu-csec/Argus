/*
*******************************************************************************
*   Copyright (C) 2000-2014, International Business Machines
*   Corporation and others.  All Rights Reserved.
*******************************************************************************
*
*   file name:  uvernum.h
*   encoding:   US-ASCII
*   tab size:   8 (not used)
*   indentation:4
*
*   Created by: Vladimir Weinstein
*   Updated by: Steven R. Loomis
*
*/

   
        
                                                   
  
                                                                               
                                                                       
   

 /*
  * IMPORTANT: When updating version, the following things need to be done:
  * source/common/unicode/uvernum.h - this file: update major, minor,
  *        patchlevel, suffix, version, short version constants, namespace,
  *                    renaming macro, and copyright
  *
  * The following files need to be updated as well, which can be done
  *  by running the UNIX makefile target 'update-windows-makefiles' in icu/source.
  *
  *
  * source/common/common.vcproj - update 'Output file name' on the link tab so
  *                   that it contains the new major/minor combination
  * source/i18n/i18n.vcproj - same as for the common.vcproj
  * source/layout/layout.vcproj - same as for the common.vcproj
  * source/layoutex/layoutex.vcproj - same
  * source/stubdata/stubdata.vcproj - same as for the common.vcproj
  * source/io/io.vcproj - same as for the common.vcproj
  * source/data/makedata.mak - change U_ICUDATA_NAME so that it contains
  *                            the new major/minor combination and the Unicode version.
  */

#ifndef UVERNUM_H
#define UVERNUM_H

/** The standard copyright notice that gets compiled into each library.
 *  This value will change in the subsequent releases of ICU
 *  @stable ICU 2.4
 */
#define U_COPYRIGHT_STRING \
  " Copyright (C) 2014, International Business Machines Corporation and others. All Rights Reserved. "

                                                
                                                            
                   
   
#define U_ICU_VERSION_MAJOR_NUM 53

                                                
                                                            
                   
   
#define U_ICU_VERSION_MINOR_NUM 1

                                                     
                                                            
                   
   
#define U_ICU_VERSION_PATCHLEVEL_NUM 0

                                                      
                                                           
                   
   
#ifndef U_ICU_VERSION_BUILDLEVEL_NUM
#define U_ICU_VERSION_BUILDLEVEL_NUM 0
#endif

                                     
                                                            
                   
   
#define U_ICU_VERSION_SUFFIX _53

   
                                     
            
   
   
                                    
            
   
                                              
                                                             
                                                                                            
                                                                                     
                                 
                   
   

#ifndef U_ICU_ENTRY_POINT_RENAME
#ifdef U_HAVE_LIB_SUFFIX
#define U_DEF_ICU_ENTRY_POINT_RENAME(x,y,z) x ## y ##  z
#define U_DEF2_ICU_ENTRY_POINT_RENAME(x,y,z) U_DEF_ICU_ENTRY_POINT_RENAME(x,y,z)
#define U_ICU_ENTRY_POINT_RENAME(x)    U_DEF2_ICU_ENTRY_POINT_RENAME(x,U_ICU_VERSION_SUFFIX,U_LIB_SUFFIX_C_NAME)
#else
#define U_DEF_ICU_ENTRY_POINT_RENAME(x,y) x ## y
#define U_DEF2_ICU_ENTRY_POINT_RENAME(x,y) U_DEF_ICU_ENTRY_POINT_RENAME(x,y)
#define U_ICU_ENTRY_POINT_RENAME(x)    U_DEF2_ICU_ENTRY_POINT_RENAME(x,U_ICU_VERSION_SUFFIX)
#endif
#endif

                                                                              
                                               
                                                            
                   
   
#define U_ICU_VERSION "53.1"

                                                                                                    
                                                            
                   
   
#define U_ICU_VERSION_SHORT "53"

#ifndef U_HIDE_INTERNAL_API
                          
                                      
    
#define U_ICU_DATA_VERSION "53.1"
#endif                           

                                                                             
                                              
                                                                         
                                                                          
                                                                             
   

   
                                                           
                                                                                 
                                                       
                  
   
#define UCOL_RUNTIME_VERSION 8

   
                                  
                                                          
                                                            
                                                       
                  
   
#define UCOL_BUILDER_VERSION 9

   
                                               
                                                       
                  
   
#define UCOL_TAILORINGS_VERSION 1

#endif
