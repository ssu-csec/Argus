/*-
 * This code is derived from OpenBSD's libc/regex, original license follows:
 *
 * Copyright (c) 1992, 1993, 1994 Henry Spencer.
 * Copyright (c) 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Henry Spencer.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)regex2.h	8.4 (Berkeley) 3/20/94
 */

#ifndef LLVM_SUPPORT_REGEX2_H
#define LLVM_SUPPORT_REGEX2_H

#include "regutils.h"
#include <stddef.h>

  
                       
   
#define	MAGIC1	((('r'^0200)<<8) | 'e')

  
                                                          
                                                                   
                                                                    
                                                                     
                                                                        
                                                                    
               
  
                                                         
                                                              
                                                                        
                                                                       
                                                                      
                                         
  
                                                                       
                                                        
   
typedef unsigned long sop;	                    
typedef long sopno;
#define	OPRMASK	0xf8000000LU
#define	OPDMASK	0x07ffffffLU
#define	OPSHIFT	((unsigned)27)
#define	OP(n)	((n)&OPRMASK)
#define	OPND(n)	((n)&OPDMASK)
#define	SOP(op, opnd)	((op)|(opnd))
                                      
                                  
#define	OEND	(1LU<<OPSHIFT)	                   
#define	OCHAR	(2LU<<OPSHIFT)	                              
#define	OBOL	(3LU<<OPSHIFT)	                     
#define	OEOL	(4LU<<OPSHIFT)	                      
#define	OANY	(5LU<<OPSHIFT)	            
#define	OANYOF	(6LU<<OPSHIFT)	                       
#define	OBACK_	(7LU<<OPSHIFT)	                            
#define	O_BACK	(8LU<<OPSHIFT)	                          
#define	OPLUS_	(9LU<<OPSHIFT)	                             
#define	O_PLUS	(10LU<<OPSHIFT)	                              
#define	OQUEST_	(11LU<<OPSHIFT)	                             
#define	O_QUEST	(12LU<<OPSHIFT)	                              
#define	OLPAREN	(13LU<<OPSHIFT)	                  
#define	ORPAREN	(14LU<<OPSHIFT)	                   
#define	OCH_	(15LU<<OPSHIFT)	                               
#define	OOR1	(16LU<<OPSHIFT)	                                  
#define	OOR2	(17LU<<OPSHIFT)	                                 
#define	O_CH	(18LU<<OPSHIFT)	                              
#define	OBOW	(19LU<<OPSHIFT)	                    
#define	OEOW	(20LU<<OPSHIFT)	                  

  
                                                                     
                                                                   
                                                                     
                                                                     
                                                          
  
                                                                    
                                                                      
                                                                   
                       
   
typedef struct {
	uch *ptr;		                       
	uch mask;		                      
	uch hash;		               
	size_t smultis;
	char *multis;		                                     
} cset;
                                                                      
#define	CHadd(cs, c)	((cs)->ptr[(uch)(c)] |= (cs)->mask, (cs)->hash += (c))
#define	CHsub(cs, c)	((cs)->ptr[(uch)(c)] &= ~(cs)->mask, (cs)->hash -= (c))
#define	CHIN(cs, c)	((cs)->ptr[(uch)(c)] & (cs)->mask)
#define	MCadd(p, cs, cp)	mcadd(p, cs, cp)	                                 
#define	MCsub(p, cs, cp)	mcsub(p, cs, cp)
#define	MCin(p, cs, cp)	mcin(p, cs, cp)

                                    
typedef unsigned char cat_t;

  
                                     
   
struct re_guts {
	int magic;
#		define	MAGIC2	((('R'^0200)<<8)|'E')
	sop *strip;		                             
	int csetsize;		                                     
	int ncsets;		                            
	cset *sets;		                      
	uch *setbits;		                                       
	int cflags;		                                            
	sopno nstates;		                      
	sopno firststate;	                                   
	sopno laststate;	                    
	int iflags;		                    
#		define	USEBOL	01	            
#		define	USEEOL	02	            
#		define	REGEX_BAD	04	                     
	int nbol;		                      
	int neol;		                      
	int ncategories;	                                   
	cat_t *categories;	                           
	char *must;		                                    
	int mlen;		                    
	size_t nsub;		                     
	int backrefs;		                                  
	sopno nplus;		                               
	                           
	cat_t catspace[1];	                   
};

                    
#define	OUT	(CHAR_MAX+1)	                           
#define	ISWORD(c)	(isalnum(c&0xff) || (c) == '_')

#endif
