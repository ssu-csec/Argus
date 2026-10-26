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
 *	@(#)regcomp.c	8.5 (Berkeley) 3/20/94
 */

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include "regex_impl.h"

#include "regutils.h"
#include "regex2.h"

#include "llvh/Config/config.h"

#if defined __has_attribute
  #if __has_attribute(fallthrough)
    #define FALLTHROUGH __attribute__ ((fallthrough))
  #else
    #define FALLTHROUGH (void)0
  #endif
#else
  #define FALLTHROUGH (void)0
#endif

                           
static struct cclass {
	const char *name;
	const char *chars;
	const char *multis;
} cclasses[] = {
	{ "alnum",	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
0123456789",				""} ,
	{ "alpha",	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
					""} ,
	{ "blank",	" \t",		""} ,
	{ "cntrl",	"\007\b\t\n\v\f\r\1\2\3\4\5\6\16\17\20\21\22\23\24\
\25\26\27\30\31\32\33\34\35\36\37\177",	""} ,
	{ "digit",	"0123456789",	""} ,
	{ "graph",	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
					""} ,
	{ "lower",	"abcdefghijklmnopqrstuvwxyz",
					""} ,
	{ "print",	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ",
					""} ,
	{ "punct",	"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
					""} ,
	{ "space",	"\t\n\v\f\r ",	""} ,
	{ "upper",	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
					""} ,
	{ "xdigit",	"0123456789ABCDEFabcdef",
					""} ,
	{ NULL,		0,		"" }
};

                          
static struct cname {
	const char *name;
	char code;
} cnames[] = {
	{ "NUL",			'\0' },
	{ "SOH",			'\001' },
	{ "STX",			'\002' },
	{ "ETX",			'\003' },
	{ "EOT",			'\004' },
	{ "ENQ",			'\005' },
	{ "ACK",			'\006' },
	{ "BEL",			'\007' },
	{ "alert",			'\007' },
	{ "BS",				'\010' },
	{ "backspace",			'\b' },
	{ "HT",				'\011' },
	{ "tab",			'\t' },
	{ "LF",				'\012' },
	{ "newline",			'\n' },
	{ "VT",				'\013' },
	{ "vertical-tab",		'\v' },
	{ "FF",				'\014' },
	{ "form-feed",			'\f' },
	{ "CR",				'\015' },
	{ "carriage-return",		'\r' },
	{ "SO",				'\016' },
	{ "SI",				'\017' },
	{ "DLE",			'\020' },
	{ "DC1",			'\021' },
	{ "DC2",			'\022' },
	{ "DC3",			'\023' },
	{ "DC4",			'\024' },
	{ "NAK",			'\025' },
	{ "SYN",			'\026' },
	{ "ETB",			'\027' },
	{ "CAN",			'\030' },
	{ "EM",				'\031' },
	{ "SUB",			'\032' },
	{ "ESC",			'\033' },
	{ "IS4",			'\034' },
	{ "FS",				'\034' },
	{ "IS3",			'\035' },
	{ "GS",				'\035' },
	{ "IS2",			'\036' },
	{ "RS",				'\036' },
	{ "IS1",			'\037' },
	{ "US",				'\037' },
	{ "space",			' ' },
	{ "exclamation-mark",		'!' },
	{ "quotation-mark",		'"' },
	{ "number-sign",		'#' },
	{ "dollar-sign",		'$' },
	{ "percent-sign",		'%' },
	{ "ampersand",			'&' },
	{ "apostrophe",			'\'' },
	{ "left-parenthesis",		'(' },
	{ "right-parenthesis",		')' },
	{ "asterisk",			'*' },
	{ "plus-sign",			'+' },
	{ "comma",			',' },
	{ "hyphen",			'-' },
	{ "hyphen-minus",		'-' },
	{ "period",			'.' },
	{ "full-stop",			'.' },
	{ "slash",			'/' },
	{ "solidus",			'/' },
	{ "zero",			'0' },
	{ "one",			'1' },
	{ "two",			'2' },
	{ "three",			'3' },
	{ "four",			'4' },
	{ "five",			'5' },
	{ "six",			'6' },
	{ "seven",			'7' },
	{ "eight",			'8' },
	{ "nine",			'9' },
	{ "colon",			':' },
	{ "semicolon",			';' },
	{ "less-than-sign",		'<' },
	{ "equals-sign",		'=' },
	{ "greater-than-sign",		'>' },
	{ "question-mark",		'?' },
	{ "commercial-at",		'@' },
	{ "left-square-bracket",	'[' },
	{ "backslash",			'\\' },
	{ "reverse-solidus",		'\\' },
	{ "right-square-bracket",	']' },
	{ "circumflex",			'^' },
	{ "circumflex-accent",		'^' },
	{ "underscore",			'_' },
	{ "low-line",			'_' },
	{ "grave-accent",		'`' },
	{ "left-brace",			'{' },
	{ "left-curly-bracket",		'{' },
	{ "vertical-line",		'|' },
	{ "right-brace",		'}' },
	{ "right-curly-bracket",	'}' },
	{ "tilde",			'~' },
	{ "DEL",			'\177' },
	{ NULL,				0 }
};

  
                                                                    
                     
   
struct parse {
	char *next;		                          
	char *end;		                                     
	int error;		                             
	sop *strip;		                    
	sopno ssize;		                                     
	sopno slen;		                                  
	int ncsalloc;		                               
	struct re_guts *g;
#	define	NPAREN	10	                                              
	sopno pbegin[NPAREN];	                       
	sopno pend[NPAREN];	                       
};

static void p_ere(struct parse *, int);
static void p_ere_exp(struct parse *);
static void p_str(struct parse *);
static void p_bre(struct parse *, int, int);
static int p_simp_re(struct parse *, int);
static int p_count(struct parse *);
static void p_bracket(struct parse *);
static void p_b_term(struct parse *, cset *);
static void p_b_cclass(struct parse *, cset *);
static void p_b_eclass(struct parse *, cset *);
static char p_b_symbol(struct parse *);
static char p_b_coll_elem(struct parse *, int);
static char othercase(int);
static void bothcases(struct parse *, int);
static void ordinary(struct parse *, int);
static void nonnewline(struct parse *);
static void repeat(struct parse *, sopno, int, int);
static int seterr(struct parse *, int);
static cset *allocset(struct parse *);
static void freeset(struct parse *, cset *);
static int freezeset(struct parse *, cset *);
static int firstch(struct parse *, cset *);
static int nch(struct parse *, cset *);
static void mcadd(struct parse *, cset *, const char *);
static void mcinvert(struct parse *, cset *);
static void mccase(struct parse *, cset *);
static int isinsets(struct re_guts *, int);
static int samesets(struct re_guts *, int, int);
static void categorize(struct parse *, struct re_guts *);
static sopno dupl(struct parse *, sopno, sopno);
static void doemit(struct parse *, sop, size_t);
static void doinsert(struct parse *, sop, size_t, sopno);
static void dofwd(struct parse *, sopno, sop);
static void enlarge(struct parse *, sopno);
static void stripsnug(struct parse *, struct re_guts *);
static void findmust(struct parse *, struct re_guts *);
static sopno pluscount(struct parse *, struct re_guts *);

static char nuls[10];		                                              

  
                                      
                                                                
   
#define	PEEK()	(*p->next)
#define	PEEK2()	(*(p->next+1))
#define	MORE()	(p->next < p->end)
#define	MORE2()	(p->next+1 < p->end)
#define	SEE(c)	(MORE() && PEEK() == (c))
#define	SEETWO(a, b)	(MORE() && MORE2() && PEEK() == (a) && PEEK2() == (b))
#define	EAT(c)	((SEE(c)) ? (NEXT(), 1) : 0)
#define	EATTWO(a, b)	((SEETWO(a, b)) ? (NEXT2(), 1) : 0)
#define	NEXT()	(p->next++)
#define	NEXT2()	(p->next += 2)
#define	NEXTn(n)	(p->next += (n))
#define	GETNEXT()	(*p->next++)
#define	SETERROR(e)	seterr(p, (e))
#define	REQUIRE(co, e)	(void)((co) || SETERROR(e))
#define	MUSTSEE(c, e)	(REQUIRE(MORE() && PEEK() == (c), e))
#define	MUSTEAT(c, e)	(REQUIRE(MORE() && GETNEXT() == (c), e))
#define	MUSTNOTSEE(c, e)	(REQUIRE(!MORE() || PEEK() != (c), e))
#define	EMIT(op, sopnd)	doemit(p, (sop)(op), (size_t)(sopnd))
#define	INSERT(op, pos)	doinsert(p, (sop)(op), HERE()-(pos)+1, pos)
#define	AHEAD(pos)		dofwd(p, pos, HERE()-(pos))
#define	ASTERN(sop, pos)	EMIT(sop, HERE()-pos)
#define	HERE()		(p->slen)
#define	THERE()		(p->slen - 1)
#define	THERETHERE()	(p->slen - 2)
#define	DROP(n)	(p->slen -= (n))

#ifdef	_POSIX2_RE_DUP_MAX
#define	DUPMAX	_POSIX2_RE_DUP_MAX
#else
#define	DUPMAX	255
#endif
#define REGINFINITY (DUPMAX + 1)

#ifndef NDEBUG
static int never = 0;		                                       
#else
#define	never	0		                                    
#endif

  
                                                      
   
int				                                        
llvh_regcomp(llvm_regex_t *preg, const char *pattern, int cflags)
{
	struct parse pa;
	struct re_guts *g;
	struct parse *p = &pa;
	int i;
	size_t len;
#ifdef REDEBUG
#	define	GOODFLAGS(f)	(f)
#else
#	define	GOODFLAGS(f)	((f)&~REG_DUMP)
#endif

	cflags = GOODFLAGS(cflags);
	if ((cflags&REG_EXTENDED) && (cflags&REG_NOSPEC))
		return(REG_INVARG);

	if (cflags&REG_PEND) {
		if (preg->re_endp < pattern)
			return(REG_INVARG);
		len = preg->re_endp - pattern;
	} else
		len = strlen((const char *)pattern);

	                                                      
	g = (struct re_guts *)malloc(sizeof(struct re_guts) +
							(NC-1)*sizeof(cat_t));
	if (g == NULL)
		return(REG_ESPACE);
	p->ssize = len/(size_t)2*(size_t)3 + (size_t)1;	         
	p->strip = (sop *)calloc(p->ssize, sizeof(sop));
	p->slen = 0;
	if (p->strip == NULL) {
		free((char *)g);
		return(REG_ESPACE);
	}

	                   
	p->g = g;
	p->next = (char *)pattern;	                                      
	p->end = p->next + len;
	p->error = 0;
	p->ncsalloc = 0;
	for (i = 0; i < NPAREN; i++) {
		p->pbegin[i] = 0;
		p->pend[i] = 0;
	}
	g->csetsize = NC;
	g->sets = NULL;
	g->setbits = NULL;
	g->ncsets = 0;
	g->cflags = cflags;
	g->iflags = 0;
	g->nbol = 0;
	g->neol = 0;
	g->must = NULL;
	g->mlen = 0;
	g->nsub = 0;
	g->ncategories = 1;	                                     
	g->categories = &g->catspace[-(CHAR_MIN)];
	(void) memset((char *)g->catspace, 0, NC*sizeof(cat_t));
	g->backrefs = 0;

	           
	EMIT(OEND, 0);
	g->firststate = THERE();
	if (cflags&REG_EXTENDED)
		p_ere(p, OUT);
	else if (cflags&REG_NOSPEC)
		p_str(p);
	else
		p_bre(p, OUT, OUT);
	EMIT(OEND, 0);
	g->laststate = THERE();

	                                           
	categorize(p, g);
	stripsnug(p, g);
	findmust(p, g);
	g->nplus = pluscount(p, g);
	g->magic = MAGIC2;
	preg->re_nsub = g->nsub;
	preg->re_g = g;
	preg->re_magic = MAGIC1;
#ifndef REDEBUG
	                                                                    
	if (g->iflags&REGEX_BAD)
		SETERROR(REG_ASSERT);
#endif

	                             
	if (p->error != 0)	          
		llvh_regfree(preg);
	return(p->error);
}

  
                                                              
   
static void
p_ere(struct parse *p, int stop)	                                      
{
	char c;
	sopno prevback = 0;
	sopno prevfwd = 0;
	sopno conc;
	int first = 1;		                                    

	for (;;) {
		                                            
		conc = HERE();
		while (MORE() && (c = PEEK()) != '|' && c != stop)
			p_ere_exp(p);
		REQUIRE(HERE() != conc, REG_EMPTY);	                      

		if (!EAT('|'))
			break;		                    

		if (first) {
			INSERT(OCH_, conc);	                     
			prevfwd = conc;
			prevback = conc;
			first = 0;
		}
		ASTERN(OOR1, prevback);
		prevback = THERE();
		AHEAD(prevfwd);			                         
		prevfwd = HERE();
		EMIT(OOR2, 0);			                          
	}

	if (!first) {		                     
		AHEAD(prevfwd);
		ASTERN(O_CH, prevback);
	}

	assert(!MORE() || SEE(stop));
}

  
                                                                             
   
static void
p_ere_exp(struct parse *p)
{
	char c;
	sopno pos;
	int count;
	int count2;
	int backrefnum;
	sopno subno;
	int wascaret = 0;

	assert(MORE());		                                     
	c = GETNEXT();

	pos = HERE();
	switch (c) {
	case '(':
		REQUIRE(MORE(), REG_EPAREN);
		p->g->nsub++;
		subno = p->g->nsub;
		if (subno < NPAREN)
			p->pbegin[subno] = HERE();
		EMIT(OLPAREN, subno);
		if (!SEE(')'))
			p_ere(p, ')');
		if (subno < NPAREN) {
			p->pend[subno] = HERE();
			assert(p->pend[subno] != 0);
		}
		EMIT(ORPAREN, subno);
		MUSTEAT(')', REG_EPAREN);
		break;
#ifndef POSIX_MISTAKE
	case ')':		                                            
		  
                                                          
                                                             
                                                            
                                                           
                         
     
		SETERROR(REG_EPAREN);
		break;
#endif
	case '^':
		EMIT(OBOL, 0);
		p->g->iflags |= USEBOL;
		p->g->nbol++;
		wascaret = 1;
		break;
	case '$':
		EMIT(OEOL, 0);
		p->g->iflags |= USEEOL;
		p->g->neol++;
		break;
	case '|':
		SETERROR(REG_EMPTY);
		break;
	case '*':
	case '+':
	case '?':
		SETERROR(REG_BADRPT);
		break;
	case '.':
		if (p->g->cflags&REG_NEWLINE)
			nonnewline(p);
		else
			EMIT(OANY, 0);
		break;
	case '[':
		p_bracket(p);
		break;
	case '\\':
		REQUIRE(MORE(), REG_EESCAPE);
		c = GETNEXT();
		if (c >= '1' && c <= '9') {
			                                                                   
                                                                   
                                                                   
                                                                   
      
			backrefnum = c - '0';
			if (p->pend[backrefnum] == 0) {
				SETERROR(REG_ESUBREG);
				break;
			}

			                                                        
                                                         
      
			assert(backrefnum <= p->g->nsub);
			EMIT(OBACK_, backrefnum);
			assert(p->pbegin[backrefnum] != 0);
			assert(OP(p->strip[p->pbegin[backrefnum]]) != OLPAREN);
			assert(OP(p->strip[p->pend[backrefnum]]) != ORPAREN);
			(void) dupl(p, p->pbegin[backrefnum]+1, p->pend[backrefnum]);
			EMIT(O_BACK, backrefnum);
			p->g->backrefs = 1;
		} else {
			                                                                   
      
			ordinary(p, c);
		}
		break;
	case '{':		                                              
		REQUIRE(!MORE() || !isdigit((uch)PEEK()), REG_BADRPT);
		FALLTHROUGH;
	default:
		ordinary(p, c);
		break;
	}

	if (!MORE())
		return;
	c = PEEK();
	                                                   
	if (!( c == '*' || c == '+' || c == '?' ||
				(c == '{' && MORE2() && isdigit((uch)PEEK2())) ))
		return;		                               
	NEXT();

	REQUIRE(!wascaret, REG_BADRPT);
	switch (c) {
	case '*':	                       
		                                                         
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		INSERT(OQUEST_, pos);
		ASTERN(O_QUEST, pos);
		break;
	case '+':
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		break;
	case '?':
		                                                         
		INSERT(OCH_, pos);		                           
		ASTERN(OOR1, pos);		                      
		AHEAD(pos);			                  
		EMIT(OOR2, 0);			                          
		AHEAD(THERE());			                  
		ASTERN(O_CH, THERETHERE());
		break;
	case '{':
		count = p_count(p);
		if (EAT(',')) {
			if (isdigit((uch)PEEK())) {
				count2 = p_count(p);
				REQUIRE(count <= count2, REG_BADBR);
			} else		                              
				count2 = REGINFINITY;
		} else		                          
			count2 = count;
		repeat(p, pos, count, count2);
		if (!EAT('}')) {	                      
			while (MORE() && PEEK() != '}')
				NEXT();
			REQUIRE(MORE(), REG_EBRACE);
			SETERROR(REG_BADBR);
		}
		break;
	}

	if (!MORE())
		return;
	c = PEEK();
	if (!( c == '*' || c == '+' || c == '?' ||
				(c == '{' && MORE2() && isdigit((uch)PEEK2())) ) )
		return;
	SETERROR(REG_BADRPT);
}

  
                                              
   
static void
p_str(struct parse *p)
{
	REQUIRE(MORE(), REG_EMPTY);
	while (MORE())
		ordinary(p, GETNEXT());
}

  
                                                            
                                                                 
  
                                                                          
                                                                        
                                                                        
                                                                      
                                                                    
   
static void
p_bre(struct parse *p,
    int end1,		                                 
    int end2)		                                  
{
	sopno start = HERE();
	int first = 1;			                          
	int wasdollar = 0;

	if (EAT('^')) {
		EMIT(OBOL, 0);
		p->g->iflags |= USEBOL;
		p->g->nbol++;
	}
	while (MORE() && !SEETWO(end1, end2)) {
		wasdollar = p_simp_re(p, first);
		first = 0;
	}
	if (wasdollar) {	                                      
		DROP(1);
		EMIT(OEOL, 0);
		p->g->iflags |= USEEOL;
		p->g->neol++;
	}

	REQUIRE(HERE() != start, REG_EMPTY);	                      
}

  
                                                                           
   
static int			                                           
p_simp_re(struct parse *p,
    int starordinary)		                                           
{
	int c;
	int count;
	int count2;
	sopno pos;
	int i;
	sopno subno;
#	define	BACKSL	(1<<CHAR_BIT)

        pos = HERE();                                              

        assert(MORE());                                      
        c = GETNEXT();
	if (c == '\\') {
		REQUIRE(MORE(), REG_EESCAPE);
		c = BACKSL | GETNEXT();
	}
	switch (c) {
	case '.':
		if (p->g->cflags&REG_NEWLINE)
			nonnewline(p);
		else
			EMIT(OANY, 0);
		break;
	case '[':
		p_bracket(p);
		break;
	case BACKSL|'{':
		SETERROR(REG_BADRPT);
		break;
	case BACKSL|'(':
		p->g->nsub++;
		subno = p->g->nsub;
		if (subno < NPAREN)
			p->pbegin[subno] = HERE();
		EMIT(OLPAREN, subno);
		                                         
		if (MORE() && !SEETWO('\\', ')'))
			p_bre(p, '\\', ')');
		if (subno < NPAREN) {
			p->pend[subno] = HERE();
			assert(p->pend[subno] != 0);
		}
		EMIT(ORPAREN, subno);
		REQUIRE(EATTWO('\\', ')'), REG_EPAREN);
		break;
	case BACKSL|')':	                                         
	case BACKSL|'}':
		SETERROR(REG_EPAREN);
		break;
	case BACKSL|'1':
	case BACKSL|'2':
	case BACKSL|'3':
	case BACKSL|'4':
	case BACKSL|'5':
	case BACKSL|'6':
	case BACKSL|'7':
	case BACKSL|'8':
	case BACKSL|'9':
		i = (c&~BACKSL) - '0';
		assert(i < NPAREN);
		if (p->pend[i] != 0) {
			assert(i <= p->g->nsub);
			EMIT(OBACK_, i);
			assert(p->pbegin[i] != 0);
			assert(OP(p->strip[p->pbegin[i]]) == OLPAREN);
			assert(OP(p->strip[p->pend[i]]) == ORPAREN);
			(void) dupl(p, p->pbegin[i]+1, p->pend[i]);
			EMIT(O_BACK, i);
		} else
			SETERROR(REG_ESUBREG);
		p->g->backrefs = 1;
		break;
	case '*':
		REQUIRE(starordinary, REG_BADRPT);
		FALLTHROUGH;
	default:
		ordinary(p, (char)c);
		break;
	}

	if (EAT('*')) {		                       
		                                                         
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		INSERT(OQUEST_, pos);
		ASTERN(O_QUEST, pos);
	} else if (EATTWO('\\', '{')) {
		count = p_count(p);
		if (EAT(',')) {
			if (MORE() && isdigit((uch)PEEK())) {
				count2 = p_count(p);
				REQUIRE(count <= count2, REG_BADBR);
			} else		                              
				count2 = REGINFINITY;
		} else		                          
			count2 = count;
		repeat(p, pos, count, count2);
		if (!EATTWO('\\', '}')) {	                      
			while (MORE() && !SEETWO('\\', '}'))
				NEXT();
			REQUIRE(MORE(), REG_EBRACE);
			SETERROR(REG_BADBR);
		}
	} else if (c == '$')	                            
		return(1);

	return(0);
}

  
                                     
   
static int			               
p_count(struct parse *p)
{
	int count = 0;
	int ndigits = 0;

	while (MORE() && isdigit((uch)PEEK()) && count <= DUPMAX) {
		count = count*10 + (GETNEXT() - '0');
		ndigits++;
	}

	REQUIRE(ndigits > 0 && count <= DUPMAX, REG_BADBR);
	return(count);
}

  
                                               
  
                                                                             
                              
   
static void
p_bracket(struct parse *p)
{
	cset *cs;
	int invert = 0;

	                                                  
	if (p->next + 5 < p->end && strncmp(p->next, "[:<:]]", 6) == 0) {
		EMIT(OBOW, 0);
		NEXTn(6);
		return;
	}
	if (p->next + 5 < p->end && strncmp(p->next, "[:>:]]", 6) == 0) {
		EMIT(OEOW, 0);
		NEXTn(6);
		return;
	}

	if ((cs = allocset(p)) == NULL) {
		                                        
		return;
	}

	if (EAT('^'))
		invert++;	                                    
	if (EAT(']'))
		CHadd(cs, ']');
	else if (EAT('-'))
		CHadd(cs, '-');
	while (MORE() && PEEK() != ']' && !SEETWO('-', ']'))
		p_b_term(p, cs);
	if (EAT('-'))
		CHadd(cs, '-');
	MUSTEAT(']', REG_EBRACK);

	if (p->error != 0) {	                                  
		freeset(p, cs);
		return;
	}

	if (p->g->cflags&REG_ICASE) {
		int i;
		int ci;

		for (i = p->g->csetsize - 1; i >= 0; i--)
			if (CHIN(cs, i) && isalpha(i)) {
				ci = othercase(i);
				if (ci != i)
					CHadd(cs, ci);
			}
		if (cs->multis != NULL)
			mccase(p, cs);
	}
	if (invert) {
		int i;

		for (i = p->g->csetsize - 1; i >= 0; i--)
			if (CHIN(cs, i))
				CHsub(cs, i);
			else
				CHadd(cs, i);
		if (p->g->cflags&REG_NEWLINE)
			CHsub(cs, '\n');
		if (cs->multis != NULL)
			mcinvert(p, cs);
	}

	assert(cs->multis == NULL);		         

	if (nch(p, cs) == 1) {		                             
		ordinary(p, firstch(p, cs));
		freeset(p, cs);
	} else
		EMIT(OANYOF, freezeset(p, cs));
}

  
                                                          
   
static void
p_b_term(struct parse *p, cset *cs)
{
	char c;
	char start, finish;
	int i;

	                             
	switch ((MORE()) ? PEEK() : '\0') {
	case '[':
		c = (MORE2()) ? PEEK2() : '\0';
		break;
	case '-':
		SETERROR(REG_ERANGE);
		return;			                 
		break;
	default:
		c = '\0';
		break;
	}

	switch (c) {
	case ':':		                     
		NEXT2();
		REQUIRE(MORE(), REG_EBRACK);
		c = PEEK();
		REQUIRE(c != '-' && c != ']', REG_ECTYPE);
		p_b_cclass(p, cs);
		REQUIRE(MORE(), REG_EBRACK);
		REQUIRE(EATTWO(':', ']'), REG_ECTYPE);
		break;
	case '=':		                       
		NEXT2();
		REQUIRE(MORE(), REG_EBRACK);
		c = PEEK();
		REQUIRE(c != '-' && c != ']', REG_ECOLLATE);
		p_b_eclass(p, cs);
		REQUIRE(MORE(), REG_EBRACK);
		REQUIRE(EATTWO('=', ']'), REG_ECOLLATE);
		break;
	default:		                                          
                                             
		start = p_b_symbol(p);
		if (SEE('-') && MORE2() && PEEK2() != ']') {
			           
			NEXT();
			if (EAT('-'))
				finish = '-';
			else
				finish = p_b_symbol(p);
		} else
			finish = start;
                                         
		REQUIRE(start <= finish, REG_ERANGE);
		for (i = start; i <= finish; i++)
			CHadd(cs, i);
		break;
	}
}

  
                                                             
   
static void
p_b_cclass(struct parse *p, cset *cs)
{
	char *sp = p->next;
	struct cclass *cp;
	size_t len;
	const char *u;
	char c;

	while (MORE() && isalpha((uch)PEEK()))
		NEXT();
	len = p->next - sp;
	for (cp = cclasses; cp->name != NULL; cp++)
		if (strncmp(cp->name, sp, len) == 0 && cp->name[len] == '\0')
			break;
	if (cp->name == NULL) {
		                          
		SETERROR(REG_ECTYPE);
		return;
	}

	u = cp->chars;
	while ((c = *u++) != '\0')
		CHadd(cs, c);
	for (u = cp->multis; *u != '\0'; u += strlen(u) + 1)
		MCadd(p, cs, u);
}

  
                                                                
  
                                         
   
static void
p_b_eclass(struct parse *p, cset *cs)
{
	char c;

	c = p_b_coll_elem(p, '=');
	CHadd(cs, c);
}

  
                                                                           
   
static char			                     
p_b_symbol(struct parse *p)
{
	char value;

	REQUIRE(MORE(), REG_EBRACK);
	if (!EATTWO('[', '.'))
		return(GETNEXT());

	                      
	value = p_b_coll_elem(p, '.');
	REQUIRE(EATTWO('.', ']'), REG_ECOLLATE);
	return(value);
}

  
                                                                
   
static char			                                
p_b_coll_elem(struct parse *p,
    int endc)			                            
{
	char *sp = p->next;
	struct cname *cp;
	size_t len;

	while (MORE() && !SEETWO(endc, ']'))
		NEXT();
	if (!MORE()) {
		SETERROR(REG_EBRACK);
		return(0);
	}
	len = p->next - sp;
	for (cp = cnames; cp->name != NULL; cp++)
		if (strncmp(cp->name, sp, len) == 0 && strlen(cp->name) == len)
			return(cp->code);	                
	if (len == 1)
		return(*sp);	                      
	SETERROR(REG_ECOLLATE);			             
	return(0);
}

  
                                                           
   
static char			                                  
othercase(int ch)
{
	ch = (uch)ch;
	assert(isalpha(ch));
	if (isupper(ch))
		return ((uch)tolower(ch));
	else if (islower(ch))
		return ((uch)toupper(ch));
	else			                                
		return(ch);
}

  
                                                              
  
                                               
   
static void
bothcases(struct parse *p, int ch)
{
	char *oldnext = p->next;
	char *oldend = p->end;
	char bracket[3];

	ch = (uch)ch;
	assert(othercase(ch) != ch);	                               
	p->next = bracket;
	p->end = bracket+2;
	bracket[0] = ch;
	bracket[1] = ']';
	bracket[2] = '\0';
	p_bracket(p);
	assert(p->next == bracket+2);
	p->next = oldnext;
	p->end = oldend;
}

  
                                        
   
static void
ordinary(struct parse *p, int ch)
{
	cat_t *cap = p->g->categories;

	if ((p->g->cflags&REG_ICASE) && isalpha((uch)ch) && othercase(ch) != ch)
		bothcases(p, ch);
	else {
		EMIT(OCHAR, (uch)ch);
		if (cap[ch] == 0)
			cap[ch] = p->g->ncategories++;
	}
}

  
                                                
  
                                               
   
static void
nonnewline(struct parse *p)
{
	char *oldnext = p->next;
	char *oldend = p->end;
	char bracket[4];

	p->next = bracket;
	p->end = bracket+3;
	bracket[0] = '^';
	bracket[1] = '\n';
	bracket[2] = ']';
	bracket[3] = '\0';
	p_bracket(p);
	assert(p->next == bracket+3);
	p->next = oldnext;
	p->end = oldend;
}

  
                                                                         
   
static void
repeat(struct parse *p,
    sopno start,		                                       
    int from,			                               
    int to)			                                              
{
	sopno finish = HERE();
#	define	N	2
#	define	INF	3
#	define	REP(f, t)	((f)*8 + (t))
#	define	MAP(n)	(((n) <= 1) ? (n) : ((n) == REGINFINITY) ? INF : N)
	sopno copy;

	if (p->error != 0)	                                         
		return;

	assert(from <= to);

	switch (REP(MAP(from), MAP(to))) {
	case REP(0, 0):			                             
		DROP(finish-start);	                      
		break;
	case REP(0, 1):			                
	case REP(0, N):			                
	case REP(0, INF):		               
		                                                         
		INSERT(OCH_, start);		                        
		repeat(p, start+1, 1, to);
		ASTERN(OOR1, start);
		AHEAD(start);			                
		EMIT(OOR2, 0);
		AHEAD(THERE());
		ASTERN(O_CH, THERETHERE());
		break;
	case REP(1, 1):			                  
		          
		break;
	case REP(1, N):			                   
		                                                         
		INSERT(OCH_, start);
		ASTERN(OOR1, start);
		AHEAD(start);
		EMIT(OOR2, 0);			                          
		AHEAD(THERE());			                  
		ASTERN(O_CH, THERETHERE());
		copy = dupl(p, start+1, finish+1);
		assert(copy == finish+4);
		repeat(p, copy, 1, to-1);
		break;
	case REP(1, INF):		           
		INSERT(OPLUS_, start);
		ASTERN(O_PLUS, start);
		break;
	case REP(N, N):			                    
		copy = dupl(p, start, finish);
		repeat(p, copy, from-1, to-1);
		break;
	case REP(N, INF):		                    
		copy = dupl(p, start, finish);
		repeat(p, copy, from-1, to);
		break;
	default:			                    
		SETERROR(REG_ASSERT);	                  
		break;
	}
}

  
                                  
   
static int			                                           
seterr(struct parse *p, int e)
{
	if (p->error == 0)	                                   
		p->error = e;
	p->next = nuls;		                                   
	p->end = nuls;
	return(0);		                                        
}

  
                                                 
   
static cset *
allocset(struct parse *p)
{
	int no = p->g->ncsets++;
	size_t nc;
	size_t nbytes;
	cset *cs;
	size_t css = (size_t)p->g->csetsize;
	int i;

	if (no >= p->ncsalloc) {	                                  
		void *ptr;

		p->ncsalloc += CHAR_BIT;
		nc = p->ncsalloc;
		if (nc > SIZE_MAX / sizeof(cset))
			goto nomem;
		assert(nc % CHAR_BIT == 0);
		nbytes = nc / CHAR_BIT * css;

		ptr = (cset *)realloc((char *)p->g->sets, nc * sizeof(cset));
		if (ptr == NULL)
			goto nomem;
		p->g->sets = ptr;

		ptr = (uch *)realloc((char *)p->g->setbits, nbytes);
		if (ptr == NULL)
			goto nomem;
		p->g->setbits = ptr;

		for (i = 0; i < no; i++)
			p->g->sets[i].ptr = p->g->setbits + css*(i/CHAR_BIT);

		(void) memset((char *)p->g->setbits + (nbytes - css), 0, css);
	}
	                           
	if (p->g->sets == NULL || p->g->setbits == NULL)
		goto nomem;

	cs = &p->g->sets[no];
	cs->ptr = p->g->setbits + css*((no)/CHAR_BIT);
	cs->mask = 1 << ((no) % CHAR_BIT);
	cs->hash = 0;
	cs->smultis = 0;
	cs->multis = NULL;

	return(cs);
nomem:
	free(p->g->sets);
	p->g->sets = NULL;
	free(p->g->setbits);
	p->g->setbits = NULL;

	SETERROR(REG_ESPACE);
	                                               
	return(NULL);
}

  
                                  
   
static void
freeset(struct parse *p, cset *cs)
{
	size_t i;
	cset *top = &p->g->sets[p->g->ncsets];
	size_t css = (size_t)p->g->csetsize;

	for (i = 0; i < css; i++)
		CHsub(cs, i);
	if (cs == top-1)	                                
		p->g->ncsets--;
}

  
                                                      
  
                                                                         
                                                                       
                                                                          
                                                                       
                  
   
static int			                
freezeset(struct parse *p, cset *cs)
{
	uch h = cs->hash;
	size_t i;
	cset *top = &p->g->sets[p->g->ncsets];
	cset *cs2;
	size_t css = (size_t)p->g->csetsize;

	                                               
	for (cs2 = &p->g->sets[0]; cs2 < top; cs2++)
		if (cs2->hash == h && cs2 != cs) {
			           
			for (i = 0; i < css; i++)
				if (!!CHIN(cs2, i) != !!CHIN(cs, i))
					break;		        
			if (i == css)
				break;			         
		}

	if (cs2 < top) {	               
		freeset(p, cs);
		cs = cs2;
	}

	return((int)(cs - p->g->sets));
}

  
                                                                           
   
static int			                                         
firstch(struct parse *p, cset *cs)
{
	size_t i;
	size_t css = (size_t)p->g->csetsize;

	for (i = 0; i < css; i++)
		if (CHIN(cs, i))
			return((char)i);
	assert(never);
	return(0);		               
}

  
                                      
   
static int
nch(struct parse *p, cset *cs)
{
	size_t i;
	size_t css = (size_t)p->g->csetsize;
	int n = 0;

	for (i = 0; i < css; i++)
		if (CHIN(cs, i))
			n++;
	return(n);
}

  
                                            
   
static void
mcadd( struct parse *p, cset *cs, const char *cp)
{
	size_t oldend = cs->smultis;
	void *np;

	cs->smultis += strlen(cp) + 1;
	np = realloc(cs->multis, cs->smultis);
	if (np == NULL) {
		if (cs->multis)
			free(cs->multis);
		cs->multis = NULL;
		SETERROR(REG_ESPACE);
		return;
	}
	cs->multis = np;

	llvh_strlcpy(cs->multis + oldend - 1, cp, cs->smultis - oldend + 1);
}

  
                                                             
  
                                                                    
               
   
              
static void
mcinvert(struct parse *p, cset *cs)
{
	assert(cs->multis == NULL);	         
}

  
                                                                             
  
                                                                    
               
   
              
static void
mccase(struct parse *p, cset *cs)
{
	assert(cs->multis == NULL);	         
}

  
                                            
   
static int			               
isinsets(struct re_guts *g, int c)
{
	uch *col;
	int i;
	int ncols = (g->ncsets+(CHAR_BIT-1)) / CHAR_BIT;
	unsigned uc = (uch)c;

	for (i = 0, col = g->setbits; i < ncols; i++, col += g->csetsize)
		if (col[uc] != 0)
			return(1);
	return(0);
}

  
                                                                
   
static int			               
samesets(struct re_guts *g, int c1, int c2)
{
	uch *col;
	int i;
	int ncols = (g->ncsets+(CHAR_BIT-1)) / CHAR_BIT;
	unsigned uc1 = (uch)c1;
	unsigned uc2 = (uch)c2;

	for (i = 0, col = g->setbits; i < ncols; i++, col += g->csetsize)
		if (col[uc1] != col[uc2])
			return(0);
	return(1);
}

  
                                             
   
static void
categorize(struct parse *p, struct re_guts *g)
{
	cat_t *cats = g->categories;
	int c;
	int c2;
	cat_t cat;

	                                         
	if (p->error != 0)
		return;

	for (c = CHAR_MIN; c <= CHAR_MAX; c++)
		if (cats[c] == 0 && isinsets(g, c)) {
			cat = g->ncategories++;
			cats[c] = cat;
			for (c2 = c+1; c2 <= CHAR_MAX; c2++)
				if (cats[c2] == 0 && samesets(g, c, c2))
					cats[c2] = cat;
		}
}

  
                                             
   
static sopno			                        
dupl(struct parse *p,
    sopno start,		               
    sopno finish)		                      
{
	sopno ret = HERE();
	sopno len = finish - start;

	assert(finish >= start);
	if (len == 0)
		return(ret);
	enlarge(p, p->ssize + len);	                                    
	assert(p->ssize >= p->slen + len);
	(void) memmove((char *)(p->strip + p->slen),
		(char *)(p->strip + start), (size_t)len*sizeof(sop));
	p->slen += len;
	return(ret);
}

  
                                 
  
                                                                       
                                                                     
                                                     
   
static void
doemit(struct parse *p, sop op, size_t opnd)
{
	                                         
	if (p->error != 0)
		return;

	                                                                
	assert(opnd < 1<<OPSHIFT);

	                                
	if (p->slen >= p->ssize)
		enlarge(p, (p->ssize+1) / 2 * 3);	          
	assert(p->slen < p->ssize);

	                                                
	p->strip[p->slen++] = SOP(op, opnd);
}

  
                                         
   
static void
doinsert(struct parse *p, sop op, size_t opnd, sopno pos)
{
	sopno sn;
	sop s;
	int i;

	                                         
	if (p->error != 0)
		return;

	sn = HERE();
	EMIT(op, opnd);		                             
	assert(HERE() == sn+1);
	s = p->strip[sn];

	                           
	assert(pos > 0);
	for (i = 1; i < NPAREN; i++) {
		if (p->pbegin[i] >= pos) {
			p->pbegin[i]++;
		}
		if (p->pend[i] >= pos) {
			p->pend[i]++;
		}
	}

	memmove((char *)&p->strip[pos+1], (char *)&p->strip[pos],
						(HERE()-pos-1)*sizeof(sop));
	p->strip[pos] = s;
}

  
                                       
   
static void
dofwd(struct parse *p, sopno pos, sop value)
{
	                                         
	if (p->error != 0)
		return;

	assert(value < 1<<OPSHIFT);
	p->strip[pos] = OP(p->strip[pos]) | value;
}

  
                              
   
static void
enlarge(struct parse *p, sopno size)
{
	sop *sp;

	if (p->ssize >= size)
		return;

	if ((uintptr_t)size > SIZE_MAX / sizeof(sop)) {
		SETERROR(REG_ESPACE);
		return;
	}

	sp = (sop *)realloc(p->strip, size*sizeof(sop));
	if (sp == NULL) {
		SETERROR(REG_ESPACE);
		return;
	}
	p->strip = sp;
	p->ssize = size;
}

  
                                
   
static void
stripsnug(struct parse *p, struct re_guts *g)
{
	g->nstates = p->slen;
	if ((uintptr_t)p->slen > SIZE_MAX / sizeof(sop)) {
		g->strip = p->strip;
		SETERROR(REG_ESPACE);
		return;
	}

	g->strip = (sop *)realloc((char *)p->strip, p->slen * sizeof(sop));
	if (g->strip == NULL) {
		SETERROR(REG_ESPACE);
		g->strip = p->strip;
	}
}

  
                                                                         
  
                                                                        
                                                                         
                            
  
                                                        
   
static void
findmust(struct parse *p, struct re_guts *g)
{
	sop *scan;
	sop *start = 0;                                                        
	sop *newstart = 0;                                                 
	sopno newlen;
	sop s;
	char *cp;
	sopno i;

	                                         
	if (p->error != 0)
		return;

	                                              
	newlen = 0;
	scan = g->strip + 1;
	do {
		s = *scan++;
		switch (OP(s)) {
		case OCHAR:		                     
			if (newlen == 0)		                  
				newstart = scan - 1;
			newlen++;
			break;
		case OPLUS_:		                                 
		case OLPAREN:
		case ORPAREN:
			break;
		case OQUEST_:		                                 
		case OCH_:
			scan--;
			do {
				scan += OPND(s);
				s = *scan;
				                                           
				if (OP(s) != O_QUEST && OP(s) != O_CH &&
							OP(s) != OOR2) {
					g->iflags |= REGEX_BAD;
					return;
				}
			} while (OP(s) != O_QUEST && OP(s) != O_CH);
			FALLTHROUGH;
		default:		                                  
			if (newlen > g->mlen) {		              
				start = newstart;
				g->mlen = newlen;
			}
			newlen = 0;
			break;
		}
	} while (OP(s) != OEND);

	if (g->mlen == 0)		                     
		return;

	                                     
	g->must = malloc((size_t)g->mlen + 1);
	if (g->must == NULL) {		                          
		g->mlen = 0;
		return;
	}
	cp = g->must;
	scan = start;
	for (i = g->mlen; i > 0; i--) {
		while (OP(s = *scan++) != OCHAR)
			continue;
		assert(cp < g->must + g->mlen);
		*cp++ = (char)OPND(s);
	}
	assert(cp == g->must + g->mlen);
	*cp++ = '\0';		                                
}

  
                              
   
static sopno			                   
pluscount(struct parse *p, struct re_guts *g)
{
	sop *scan;
	sop s;
	sopno plusnest = 0;
	sopno maxnest = 0;

	if (p->error != 0)
		return(0);	                              

	scan = g->strip + 1;
	do {
		s = *scan++;
		switch (OP(s)) {
		case OPLUS_:
			plusnest++;
			break;
		case O_PLUS:
			if (plusnest > maxnest)
				maxnest = plusnest;
			plusnest--;
			break;
		}
	} while (OP(s) != OEND);
	if (plusnest != 0)
		g->iflags |= REGEX_BAD;
	return(maxnest);
}
