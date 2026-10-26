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
 *	@(#)engine.c	8.5 (Berkeley) 3/20/94
 */

  
                                                                        
                                                                      
                                                                         
           
   

#ifdef SNAMES
#define	matcher	smatcher
#define	fast	sfast
#define	slow	sslow
#define	dissect	sdissect
#define	backref	sbackref
#define	step	sstep
#define	print	sprint
#define	at	sat
#define	match	smat
#define	nope	snope
#endif
#ifdef LNAMES
#define	matcher	lmatcher
#define	fast	lfast
#define	slow	lslow
#define	dissect	ldissect
#define	backref	lbackref
#define	step	lstep
#define	print	lprint
#define	at	lat
#define	match	lmat
#define	nope	lnope
#endif

                                                                          
struct match {
	struct re_guts *g;
	int eflags;
	llvm_regmatch_t *pmatch;	                                 
	const char *offp;		                            
	const char *beginp;		                                             
	const char *endp;		                                       
	const char *coldp;		                                          
	const char **lastpos;		               
	STATEVARS;
	states st;		                    
	states fresh;		                              
	states tmp;		               
	states empty;		                         
};

static int matcher(struct re_guts *, const char *, size_t,
                   llvm_regmatch_t[], int);
static const char *dissect(struct match *, const char *, const char *, sopno,
                           sopno);
static const char *backref(struct match *, const char *, const char *, sopno,
                           sopno, sopno, int);
static const char *fast(struct match *, const char *, const char *, sopno, sopno);
static const char *slow(struct match *, const char *, const char *, sopno, sopno);
static states step(struct re_guts *, sopno, sopno, states, int, states);
#define MAX_RECURSION	100
#define	BOL	(OUT+1)
#define	EOL	(BOL+1)
#define	BOLEOL	(BOL+2)
#define	NOTHING	(BOL+3)
#define	BOW	(BOL+4)
#define	EOW	(BOL+5)
#define	CODEMAX	(BOL+5)		                       
#define	NONCHAR(c)	((c) > CHAR_MAX)
#define	NNONCHAR	(CODEMAX-CHAR_MAX)
#ifdef REDEBUG
static void print(struct match *, char *, states, int, FILE *);
#endif
#ifdef REDEBUG
static void at(struct match *, char *, char *, char *, sopno, sopno);
#endif
#ifdef REDEBUG
static char *pchar(int);
#endif

#ifdef REDEBUG
#define	SP(t, s, c)	print(m, t, s, c, stdout)
#define	AT(t, p1, p2, s1, s2)	at(m, t, p1, p2, s1, s2)
#define	NOTE(str)	{ if (m->eflags&REG_TRACE) (void)printf("=%s\n", (str)); }
static int nope = 0;
#else
#define	SP(t, s, c)	             
#define	AT(t, p1, p2, s1, s2)	             
#define	NOTE(s)	             
#endif

  
                                       
   
static int			                                    
matcher(struct re_guts *g, const char *string, size_t nmatch,
        llvm_regmatch_t pmatch[],
    int eflags)
{
	const char *endp;
	size_t i;
	struct match mv;
	struct match *m = &mv;
	const char *dp;
	const sopno gf = g->firststate+1;	                 
	const sopno gl = g->laststate;
	const char *start;
	const char *stop;

	                                           
	if (g->cflags&REG_NOSUB)
		nmatch = 0;
	if (eflags&REG_STARTEND) {
		start = string + pmatch[0].rm_so;
		stop = string + pmatch[0].rm_eo;
	} else {
		start = string;
		stop = start + strlen(start);
	}
	if (stop < start)
		return(REG_INVARG);

	                                                               
	if (g->must != NULL) {
		for (dp = start; dp < stop; dp++)
			if (*dp == g->must[0] && stop - dp >= g->mlen &&
				memcmp(dp, g->must, (size_t)g->mlen) == 0)
				break;
		if (dp == stop)		                            
			return(REG_NOMATCH);
	}

	                        
	m->g = g;
	m->eflags = eflags;
	m->pmatch = NULL;
	m->lastpos = NULL;
	m->offp = string;
	m->beginp = start;
	m->endp = stop;
	STATESETUP(m, 4);
	SETUP(m->st);
	SETUP(m->fresh);
	SETUP(m->tmp);
	SETUP(m->empty);
	CLEAR(m->empty);

	                                                            
	for (;;) {
		endp = fast(m, start, stop, gf, gl);
		if (endp == NULL) {		            
			free(m->pmatch);
			free((void*)m->lastpos);
			STATETEARDOWN(m);
			return(REG_NOMATCH);
		}
		if (nmatch == 0 && !g->backrefs)
			break;		                            

		            
		assert(m->coldp != NULL);
		for (;;) {
			NOTE("finding start");
			endp = slow(m, m->coldp, stop, gf, gl);
			if (endp != NULL)
				break;
			assert(m->coldp < m->endp);
			m->coldp++;
		}
		if (nmatch == 1 && !g->backrefs)
			break;		                            

		                                            
		if (m->pmatch == NULL)
			m->pmatch = (llvm_regmatch_t *)malloc((m->g->nsub + 1) *
							sizeof(llvm_regmatch_t));
		if (m->pmatch == NULL) {
			STATETEARDOWN(m);
			return(REG_ESPACE);
		}
		for (i = 1; i <= m->g->nsub; i++)
			m->pmatch[i].rm_so = m->pmatch[i].rm_eo = -1;
		if (!g->backrefs && !(m->eflags&REG_BACKR)) {
			NOTE("dissecting");
			dp = dissect(m, m->coldp, endp, gf, gl);
		} else {
			if (g->nplus > 0 && m->lastpos == NULL)
				m->lastpos = (const char **)malloc((g->nplus+1) *
							sizeof(char *));
			if (g->nplus > 0 && m->lastpos == NULL) {
				free(m->pmatch);
				STATETEARDOWN(m);
				return(REG_ESPACE);
			}
			NOTE("backref dissect");
			dp = backref(m, m->coldp, endp, gf, gl, (sopno)0, 0);
		}
		if (dp != NULL)
			break;

		                                                           
		assert(g->backrefs);	                                      
		assert(g->nplus == 0 || m->lastpos != NULL);
		for (;;) {
			if (dp != NULL || endp <= m->coldp)
				break;		            
			NOTE("backoff");
			endp = slow(m, m->coldp, endp-1, gf, gl);
			if (endp == NULL)
				break;		            
			                                     
#ifndef NDEBUG
			for (i = 1; i <= m->g->nsub; i++) {
				assert(m->pmatch[i].rm_so == -1);
				assert(m->pmatch[i].rm_eo == -1);
			}
#endif
			NOTE("backoff dissect");
			dp = backref(m, m->coldp, endp, gf, gl, (sopno)0, 0);
		}
		assert(dp == NULL || dp == endp);
		if (dp != NULL)		                         
			break;

		                                                         
		NOTE("false alarm");
		if (m->coldp == stop)
			break;
		start = m->coldp + 1;	                            
	}

	                                      
	if (nmatch > 0) {
		pmatch[0].rm_so = m->coldp - m->offp;
		pmatch[0].rm_eo = endp - m->offp;
	}
	if (nmatch > 1) {
		assert(m->pmatch != NULL);
		for (i = 1; i < nmatch; i++)
			if (i <= m->g->nsub)
				pmatch[i] = m->pmatch[i];
			else {
				pmatch[i].rm_so = -1;
				pmatch[i].rm_eo = -1;
			}
	}

	if (m->pmatch != NULL)
		free((char *)m->pmatch);
	if (m->lastpos != NULL)
		free((char *)m->lastpos);
	STATETEARDOWN(m);
	return(0);
}

  
                                                             
   
static const char *			                              
dissect(struct match *m, const char *start, const char *stop, sopno startst,
        sopno stopst)
{
	int i;
	sopno ss;	                                
	sopno es;	                              
	const char *sp;	                                   
	const char *stp;	                                           
	const char *rest;	                             
	const char *tail;	                                    
	sopno ssub;	                           
	sopno esub;	                         
	const char *ssp;	                                         
	const char *sep;	                                       
	const char *oldssp;	                  

	AT("diss", start, stop, startst, stopst);
	sp = start;
	for (ss = startst; ss < stopst; ss = es) {
		                           
		es = ss;
		switch (OP(m->g->strip[es])) {
		case OPLUS_:
		case OQUEST_:
			es += OPND(m->g->strip[es]);
			break;
		case OCH_:
			while (OP(m->g->strip[es]) != O_CH)
				es += OPND(m->g->strip[es]);
			break;
		}
		es++;

		                                
		switch (OP(m->g->strip[ss])) {
		case OEND:
			assert(nope);
			break;
		case OCHAR:
			sp++;
			break;
		case OBOL:
		case OEOL:
		case OBOW:
		case OEOW:
			break;
		case OANY:
		case OANYOF:
			sp++;
			break;
		case OBACK_:
		case O_BACK:
			assert(nope);
			break;
		                                                 
		case OQUEST_:
			stp = stop;
			for (;;) {
				                                 
				rest = slow(m, sp, stp, ss, es);
				assert(rest != NULL);	                  
				                                    
				tail = slow(m, rest, stop, es, stopst);
				if (tail == stop)
					break;		          
				                                            
				stp = rest - 1;
				assert(stp >= sp);	                 
			}
			ssub = ss + 1;
			esub = es - 1;
			                        
			if (slow(m, sp, rest, ssub, esub) != NULL) {
				const char *dp = dissect(m, sp, rest, ssub, esub);
				(void)dp;                                      
				assert(dp == rest);
			} else		        
				assert(sp == rest);
			sp = rest;
			break;
		case OPLUS_:
			stp = stop;
			for (;;) {
				                                 
				rest = slow(m, sp, stp, ss, es);
				assert(rest != NULL);	                  
				                                    
				tail = slow(m, rest, stop, es, stopst);
				if (tail == stop)
					break;		          
				                                            
				stp = rest - 1;
				assert(stp >= sp);	                 
			}
			ssub = ss + 1;
			esub = es - 1;
			ssp = sp;
			oldssp = ssp;
			for (;;) {	                                
				sep = slow(m, ssp, rest, ssub, esub);
				if (sep == NULL || sep == ssp)
					break;	                            
				oldssp = ssp;	                    
				ssp = sep;
			}
			if (sep == NULL) {
				                           
				sep = ssp;
				ssp = oldssp;
			}
			assert(sep == rest);	                            
			assert(slow(m, ssp, sep, ssub, esub) == rest);
			{
				const char *dp = dissect(m, ssp, sep, ssub, esub);
				(void)dp;                                      
				assert(dp == sep);
			}
			sp = rest;
			break;
		case OCH_:
			stp = stop;
			for (;;) {
				                                 
				rest = slow(m, sp, stp, ss, es);
				assert(rest != NULL);	                  
				                                    
				tail = slow(m, rest, stop, es, stopst);
				if (tail == stop)
					break;		          
				                                            
				stp = rest - 1;
				assert(stp >= sp);	                 
			}
			ssub = ss + 1;
			esub = ss + OPND(m->g->strip[ss]) - 1;
			assert(OP(m->g->strip[esub]) == OOR1);
			for (;;) {	                                
				if (slow(m, sp, rest, ssub, esub) == rest)
					break;	                          
				                                   
				assert(OP(m->g->strip[esub]) == OOR1);
				esub++;
				assert(OP(m->g->strip[esub]) == OOR2);
				ssub = esub + 1;
				esub += OPND(m->g->strip[esub]);
				if (OP(m->g->strip[esub]) == OOR2)
					esub--;
				else
					assert(OP(m->g->strip[esub]) == O_CH);
			}
			{
				const char *dp = dissect(m, sp, rest, ssub, esub);
				(void)dp;                                      
				assert(dp == rest);
			}
			sp = rest;
			break;
		case O_PLUS:
		case O_QUEST:
		case OOR1:
		case OOR2:
		case O_CH:
			assert(nope);
			break;
		case OLPAREN:
			i = OPND(m->g->strip[ss]);
			assert(0 < i && i <= m->g->nsub);
			m->pmatch[i].rm_so = sp - m->offp;
			break;
		case ORPAREN:
			i = OPND(m->g->strip[ss]);
			assert(0 < i && i <= m->g->nsub);
			m->pmatch[i].rm_eo = sp - m->offp;
			break;
		default:		           
			assert(nope);
			break;
		}
	}

	assert(sp == stop);
	return(sp);
}

  
                                                                      
   
static const char *			                                         
backref(struct match *m, const char *start, const char *stop, sopno startst,
        sopno stopst, sopno lev, int rec)			                        
{
	int i;
	sopno ss;	                                
	const char *sp;	                                   
	sopno ssub;	                           
	sopno esub;	                         
	const char *ssp;	                                         
	const char *dp;
	size_t len;
	int hard;
	sop s;
	llvm_regoff_t offsave;
	cset *cs;

	AT("back", start, stop, startst, stopst);
	sp = start;

	                                          
	hard = 0;
	for (ss = startst; !hard && ss < stopst; ss++)
		switch (OP(s = m->g->strip[ss])) {
		case OCHAR:
			if (sp == stop || *sp++ != (char)OPND(s))
				return(NULL);
			break;
		case OANY:
			if (sp == stop)
				return(NULL);
			sp++;
			break;
		case OANYOF:
			cs = &m->g->sets[OPND(s)];
			if (sp == stop || !CHIN(cs, *sp++))
				return(NULL);
			break;
		case OBOL:
			if ( (sp == m->beginp && !(m->eflags&REG_NOTBOL)) ||
					(sp < m->endp && *(sp-1) == '\n' &&
						(m->g->cflags&REG_NEWLINE)) )
				{           }
			else
				return(NULL);
			break;
		case OEOL:
			if ( (sp == m->endp && !(m->eflags&REG_NOTEOL)) ||
					(sp < m->endp && *sp == '\n' &&
						(m->g->cflags&REG_NEWLINE)) )
				{           }
			else
				return(NULL);
			break;
		case OBOW:
			if (( (sp == m->beginp && !(m->eflags&REG_NOTBOL)) ||
					(sp < m->endp && *(sp-1) == '\n' &&
						(m->g->cflags&REG_NEWLINE)) ||
					(sp > m->beginp &&
							!ISWORD(*(sp-1))) ) &&
					(sp < m->endp && ISWORD(*sp)) )
				{           }
			else
				return(NULL);
			break;
		case OEOW:
			if (( (sp == m->endp && !(m->eflags&REG_NOTEOL)) ||
					(sp < m->endp && *sp == '\n' &&
						(m->g->cflags&REG_NEWLINE)) ||
					(sp < m->endp && !ISWORD(*sp)) ) &&
					(sp > m->beginp && ISWORD(*(sp-1))) )
				{           }
			else
				return(NULL);
			break;
		case O_QUEST:
			break;
		case OOR1:	                                    
			ss++;
			s = m->g->strip[ss];
			do {
				assert(OP(s) == OOR2);
				ss += OPND(s);
			} while (OP(s = m->g->strip[ss]) != O_CH);
			                                              
			break;
		default:	                           
			hard = 1;
			break;
		}
	if (!hard) {		                  
		if (sp != stop)
			return(NULL);
		return(sp);
	}
	ss--;			                                          

	                    
	AT("hard", sp, stop, ss, stopst);
	s = m->g->strip[ss];
	switch (OP(s)) {
	case OBACK_:		                       
		i = OPND(s);
		assert(0 < i && i <= m->g->nsub);
		if (m->pmatch[i].rm_eo == -1)
			return(NULL);
		assert(m->pmatch[i].rm_so != -1);
		len = m->pmatch[i].rm_eo - m->pmatch[i].rm_so;
		if (len == 0 && rec++ > MAX_RECURSION)
			return(NULL);
		assert(stop - m->beginp >= len);
		if (sp > stop - len)
			return(NULL);	                              
		ssp = m->offp + m->pmatch[i].rm_so;
		if (memcmp(sp, ssp, len) != 0)
			return(NULL);
		while (m->g->strip[ss] != SOP(O_BACK, i))
			ss++;
		return(backref(m, sp+len, stop, ss+1, stopst, lev, rec));
		break;
	case OQUEST_:		                    
		dp = backref(m, sp, stop, ss+1, stopst, lev, rec);
		if (dp != NULL)
			return(dp);	         
		return(backref(m, sp, stop, ss+OPND(s)+1, stopst, lev, rec));
		break;
	case OPLUS_:
		assert(m->lastpos != NULL);
		assert(lev+1 <= m->g->nplus);
		m->lastpos[lev+1] = sp;
		return(backref(m, sp, stop, ss+1, stopst, lev+1, rec));
		break;
	case O_PLUS:
		if (sp == m->lastpos[lev])	                            
			return(backref(m, sp, stop, ss+1, stopst, lev-1, rec));
		                      
		m->lastpos[lev] = sp;
		dp = backref(m, sp, stop, ss-OPND(s)+1, stopst, lev, rec);
		if (dp == NULL)
			return(backref(m, sp, stop, ss+1, stopst, lev-1, rec));
		else
			return(dp);
		break;
	case OCH_:		                                
		ssub = ss + 1;
		esub = ss + OPND(s) - 1;
		assert(OP(m->g->strip[esub]) == OOR1);
		for (;;) {	                                
			dp = backref(m, sp, stop, ssub, esub, lev, rec);
			if (dp != NULL)
				return(dp);
			                                   
			if (OP(m->g->strip[esub]) == O_CH)
				return(NULL);	                   
			esub++;
			assert(OP(m->g->strip[esub]) == OOR2);
			ssub = esub + 1;
			esub += OPND(m->g->strip[esub]);
			if (OP(m->g->strip[esub]) == OOR2)
				esub--;
			else
				assert(OP(m->g->strip[esub]) == O_CH);
		}
		break;
	case OLPAREN:		                                        
		i = OPND(s);
		assert(0 < i && i <= m->g->nsub);
		offsave = m->pmatch[i].rm_so;
		m->pmatch[i].rm_so = sp - m->offp;
		dp = backref(m, sp, stop, ss+1, stopst, lev, rec);
		if (dp != NULL)
			return(dp);
		m->pmatch[i].rm_so = offsave;
		return(NULL);
		break;
	case ORPAREN:		                                        
		i = OPND(s);
		assert(0 < i && i <= m->g->nsub);
		offsave = m->pmatch[i].rm_eo;
		m->pmatch[i].rm_eo = sp - m->offp;
		dp = backref(m, sp, stop, ss+1, stopst, lev, rec);
		if (dp != NULL)
			return(dp);
		m->pmatch[i].rm_eo = offsave;
		return(NULL);
		break;
	default:		           
		assert(nope);
		break;
	}

	                    
	assert(nope);
	                
        return NULL;
}

  
                                              
   
static const char *			                                          
fast(struct match *m, const char *start, const char *stop, sopno startst,
     sopno stopst)
{
	states st = m->st;
	states fresh = m->fresh;
	states tmp = m->tmp;
	const char *p = start;
	int c = (start == m->beginp) ? OUT : *(start-1);
	int lastc;	                
	int flagch;
	int i;
	const char *coldp;	                                              

	CLEAR(st);
	SET1(st, startst);
	st = step(m->g, startst, stopst, st, NOTHING, st);
	ASSIGN(fresh, st);
	SP("start", st, *p);
	coldp = NULL;
	for (;;) {
		                    
		lastc = c;
		c = (p == m->endp) ? OUT : *p;
		if (EQ(st, fresh))
			coldp = p;

		                                                     
		flagch = '\0';
		i = 0;
		if ( (lastc == '\n' && m->g->cflags&REG_NEWLINE) ||
				(lastc == OUT && !(m->eflags&REG_NOTBOL)) ) {
			flagch = BOL;
			i = m->g->nbol;
		}
		if ( (c == '\n' && m->g->cflags&REG_NEWLINE) ||
				(c == OUT && !(m->eflags&REG_NOTEOL)) ) {
			flagch = (flagch == BOL) ? BOLEOL : EOL;
			i += m->g->neol;
		}
		if (i != 0) {
			for (; i > 0; i--)
				st = step(m->g, startst, stopst, st, flagch, st);
			SP("boleol", st, c);
		}

		                                
		if ( (flagch == BOL || (lastc != OUT && !ISWORD(lastc))) &&
					(c != OUT && ISWORD(c)) ) {
			flagch = BOW;
		}
		if ( (lastc != OUT && ISWORD(lastc)) &&
				(flagch == EOL || (c != OUT && !ISWORD(c))) ) {
			flagch = EOW;
		}
		if (flagch == BOW || flagch == EOW) {
			st = step(m->g, startst, stopst, st, flagch, st);
			SP("boweow", st, c);
		}

		                  
		if (ISSET(st, stopst) || p == stop)
			break;		                    

		                                          
		ASSIGN(tmp, st);
		ASSIGN(st, fresh);
		assert(c != OUT);
		st = step(m->g, startst, stopst, tmp, c, st);
		SP("aft", st, c);
		assert(EQ(step(m->g, startst, stopst, st, NOTHING, st), st));
		p++;
	}

	assert(coldp != NULL);
	m->coldp = coldp;
	if (ISSET(st, stopst))
		return(p+1);
	else
		return(NULL);
}

  
                                                   
   
static const char *			                    
slow(struct match *m, const char *start, const char *stop, sopno startst,
     sopno stopst)
{
	states st = m->st;
	states empty = m->empty;
	states tmp = m->tmp;
	const char *p = start;
	int c = (start == m->beginp) ? OUT : *(start-1);
	int lastc;	                
	int flagch;
	int i;
	const char *matchp;	                                   

	AT("slow", start, stop, startst, stopst);
	CLEAR(st);
	SET1(st, startst);
	SP("sstart", st, *p);
	st = step(m->g, startst, stopst, st, NOTHING, st);
	matchp = NULL;
	for (;;) {
		                    
		lastc = c;
		c = (p == m->endp) ? OUT : *p;

		                                                     
		flagch = '\0';
		i = 0;
		if ( (lastc == '\n' && m->g->cflags&REG_NEWLINE) ||
				(lastc == OUT && !(m->eflags&REG_NOTBOL)) ) {
			flagch = BOL;
			i = m->g->nbol;
		}
		if ( (c == '\n' && m->g->cflags&REG_NEWLINE) ||
				(c == OUT && !(m->eflags&REG_NOTEOL)) ) {
			flagch = (flagch == BOL) ? BOLEOL : EOL;
			i += m->g->neol;
		}
		if (i != 0) {
			for (; i > 0; i--)
				st = step(m->g, startst, stopst, st, flagch, st);
			SP("sboleol", st, c);
		}

		                                
		if ( (flagch == BOL || (lastc != OUT && !ISWORD(lastc))) &&
					(c != OUT && ISWORD(c)) ) {
			flagch = BOW;
		}
		if ( (lastc != OUT && ISWORD(lastc)) &&
				(flagch == EOL || (c != OUT && !ISWORD(c))) ) {
			flagch = EOW;
		}
		if (flagch == BOW || flagch == EOW) {
			st = step(m->g, startst, stopst, st, flagch, st);
			SP("sboweow", st, c);
		}

		                  
		if (ISSET(st, stopst))
			matchp = p;
		if (EQ(st, empty) || p == stop)
			break;		                    

		                                          
		ASSIGN(tmp, st);
		ASSIGN(st, empty);
		assert(c != OUT);
		st = step(m->g, startst, stopst, tmp, c, st);
		SP("saft", st, c);
		assert(EQ(step(m->g, startst, stopst, st, NOTHING, st), st));
		p++;
	}

	return(matchp);
}


  
                                                                        
   
static states
step(struct re_guts *g,
    sopno start,		                              
    sopno stop,			                                         
    states bef,			                             
    int ch,			                               
    states aft)			                                          
{
	cset *cs;
	sop s;
	sopno pc;
	onestate here;		                                 
	sopno look;
	int i;

	for (pc = start, INIT(here, pc); pc != stop; pc++, INC(here)) {
		s = g->strip[pc];
		switch (OP(s)) {
		case OEND:
			assert(pc == stop-1);
			break;
		case OCHAR:
			                               
			assert(!NONCHAR(ch) || ch != (char)OPND(s));
			if (ch == (char)OPND(s))
				FWD(aft, bef, 1);
			break;
		case OBOL:
			if (ch == BOL || ch == BOLEOL)
				FWD(aft, bef, 1);
			break;
		case OEOL:
			if (ch == EOL || ch == BOLEOL)
				FWD(aft, bef, 1);
			break;
		case OBOW:
			if (ch == BOW)
				FWD(aft, bef, 1);
			break;
		case OEOW:
			if (ch == EOW)
				FWD(aft, bef, 1);
			break;
		case OANY:
			if (!NONCHAR(ch))
				FWD(aft, bef, 1);
			break;
		case OANYOF:
			cs = &g->sets[OPND(s)];
			if (!NONCHAR(ch) && CHIN(cs, ch))
				FWD(aft, bef, 1);
			break;
		case OBACK_:		                  
		case O_BACK:
			FWD(aft, aft, 1);
			break;
		case OPLUS_:		                                    
			FWD(aft, aft, 1);
			break;
		case O_PLUS:		                           
			FWD(aft, aft, 1);
			i = ISSETBACK(aft, OPND(s));
			BACK(aft, aft, OPND(s));
			if (!i && ISSETBACK(aft, OPND(s))) {
				                                    
				pc -= OPND(s) + 1;
				INIT(here, pc);
			}
			break;
		case OQUEST_:		                                
			FWD(aft, aft, 1);
			FWD(aft, aft, OPND(s));
			break;
		case O_QUEST:		                   
			FWD(aft, aft, 1);
			break;
		case OLPAREN:		                          
		case ORPAREN:
			FWD(aft, aft, 1);
			break;
		case OCH_:		                                 
			FWD(aft, aft, 1);
			assert(OP(g->strip[pc+OPND(s)]) == OOR2);
			FWD(aft, aft, OPND(s));
			break;
		case OOR1:		                                  
			if (ISSTATEIN(aft, here)) {
				for (look = 1;
						OP(s = g->strip[pc+look]) != O_CH;
						look += OPND(s))
					assert(OP(s) == OOR2);
				FWD(aft, aft, look);
			}
			break;
		case OOR2:		                              
			FWD(aft, aft, 1);
			if (OP(g->strip[pc+OPND(s)]) != O_CH) {
				assert(OP(g->strip[pc+OPND(s)]) == OOR2);
				FWD(aft, aft, OPND(s));
			}
			break;
		case O_CH:		                
			FWD(aft, aft, 1);
			break;
		default:		                
			assert(nope);
			break;
		}
	}

	return(aft);
}

#ifdef REDEBUG
  
                                
   
static void
print(struct match *m, char *caption, states st, int ch, FILE *d)
{
	struct re_guts *g = m->g;
	int i;
	int first = 1;

	if (!(m->eflags&REG_TRACE))
		return;

	(void)fprintf(d, "%s", caption);
	if (ch != '\0')
		(void)fprintf(d, " %s", pchar(ch));
	for (i = 0; i < g->nstates; i++)
		if (ISSET(st, i)) {
			(void)fprintf(d, "%s%d", (first) ? "\t" : ", ", i);
			first = 0;
		}
	(void)fprintf(d, "\n");
}

   
                               
   
static void
at(struct match *m, char *title, char *start, char *stop, sopno startst,
    sopno stopst)
{
	if (!(m->eflags&REG_TRACE))
		return;

	(void)printf("%s %s-", title, pchar(*start));
	(void)printf("%s ", pchar(*stop));
	(void)printf("%ld-%ld\n", (long)startst, (long)stopst);
}

#ifndef PCHARDONE
#define	PCHARDONE	                 
  
                                     
  
                                                                     
                                                                     
                                                                    
                                                               
   
static char *			                       
pchar(int ch)
{
	static char pbuf[10];

	if (isPrint(ch) || ch == ' ')
		(void)snprintf(pbuf, sizeof pbuf, "%c", ch);
	else
		(void)snprintf(pbuf, sizeof pbuf, "\\%o", ch);
	return(pbuf);
}
#endif
#endif

#undef	matcher
#undef	fast
#undef	slow
#undef	dissect
#undef	backref
#undef	step
#undef	print
#undef	at
#undef	match
#undef	nope
