                                                                  
  
                                                                  
                                                                            
  
                 
                                                                 
                                                          
                                                                   
                                                                   
                                                                 
                                                                  
                                                              
                                                              
                                                                   
                                                           
                                                                
                                                            
                 
                                                           
                 
                                                             
                                                            
                                     
                                                              
                                                            
                                                             
                                                             
                                                               
                                                       
                                                              
                  
   

#if defined __has_attribute
  #if __has_attribute(fallthrough)
    #define FALLTHROUGH __attribute__ ((fallthrough))
  #else
    #define FALLTHROUGH (void)0
  #endif
#else
  #define FALLTHROUGH (void)0
#endif


 char *
g_dtoa
#ifdef KR_headers
	(dalloc, dd, mode, ndigits, decpt, sign, rve)
	dtoa_alloc *dalloc; double dd; int mode, ndigits, *decpt, *sign; char **rve;
#else
	(dtoa_alloc *dalloc, double dd, int mode, int ndigits, int *decpt, int *sign, char **rve)
#endif
{
                                                       
                                                     
                                                        
                                                            
                            

      
                                                  
                          
                                                      
                                                
                                                  
                                                        
                                               
                                      
                                                     
                                                  
                                                 
                           
                                                   
                                                  
                                                     
                                            
                                                    
                                         
                                                         
                                                

                                                      

                                                   
                                        
   

	int bbits, b2, b5, be, dig, i, ieps, ilim, ilim0, ilim1,
		j, j1 = 0, k, k0, k_check, leftright, m2, m5, s2, s5,
		spec_case, try_quick;
	Long L;
#ifndef Sudden_Underflow
	int denorm;
	ULong x;
#endif
	Bigint *b, *b1, *delta, *mlo, *mhi, *S;
	U d2, eps, u;
	double ds;
	char *s, *s0;
#ifndef No_leftright
#ifdef IEEE_Arith
	U eps1;
#endif
#endif
#ifdef SET_INEXACT
	int inexact, oldinexact;
#endif
#ifdef Honor_FLT_ROUNDS      
	int Rounding;
#ifdef Trust_FLT_ROUNDS                                                     
	Rounding = Flt_Rounds;
#else       
	Rounding = 1;
	switch(fegetround()) {
	  case FE_TOWARDZERO:	Rounding = 0; break;
	  case FE_UPWARD:	Rounding = 2; break;
	  case FE_DOWNWARD:	Rounding = 3;
	  }
#endif       
#endif      

#ifndef MULTIPLE_THREADS
	if (dtoa_result) {
		g_freedtoa(dtoa_result);
		dtoa_result = 0;
		}
#endif

	u.d = dd;
	if (word0(&u) & Sign_bit) {
		                                                     
		*sign = 1;
		word0(&u) &= ~Sign_bit;	                    
		}
	else
		*sign = 0;

#if defined(IEEE_Arith) + defined(VAX)
#ifdef IEEE_Arith
	if ((word0(&u) & Exp_mask) == Exp_mask)
#else
	if (word0(&u)  == 0x8000)
#endif
		{
		                     
		*decpt = 9999;
#ifdef IEEE_Arith
		if (!word1(&u) && !(word0(&u) & 0xfffff))
			return nrv_alloc(dalloc, "Infinity", rve, 8);
#endif
		return nrv_alloc(dalloc, "NaN", rve, 3);
		}
#endif
#ifdef IBM
	dval(&u) += 0;                
#endif
	if (!dval(&u)) {
		*decpt = 1;
		return nrv_alloc(dalloc, "0", rve, 1);
		}

#ifdef SET_INEXACT
	try_quick = oldinexact = get_inexact();
	inexact = 1;
#endif
#ifdef Honor_FLT_ROUNDS
	if (Rounding >= 2) {
		if (*sign)
			Rounding = Rounding == 2 ? 0 : 2;
		else
			if (Rounding != 2)
				Rounding = 0;
		}
#endif

	b = d2b(dalloc, &u, &be, &bbits);
#ifdef Sudden_Underflow
	i = (int)(word0(&u) >> Exp_shift1 & (Exp_mask>>Exp_shift1));
#else
	if ((i = (int)(word0(&u) >> Exp_shift1 & (Exp_mask>>Exp_shift1)))) {
#endif
		dval(&d2) = dval(&u);
		word0(&d2) &= Frac_mask1;
		word0(&d2) |= Exp_11;
#ifdef IBM
		if (j = 11 - hi0bits(word0(&d2) & Frac_mask))
			dval(&d2) /= 1 << j;
#endif

		                                    
                                  
                                                  
                                                   
    
                                                              
    
                                     
                                                          
    
                                                     
                                                             
                                                             
                                                         
                                                               
                                            
                                                          
                                                          
                                                       
                                           
     

		i -= Bias;
#ifdef IBM
		i <<= 2;
		i += j;
#endif
#ifndef Sudden_Underflow
		denorm = 0;
		}
	else {
		                       

		i = bbits + be + (Bias + (P-1) - 1);
		x = i > 32  ? word0(&u) << (64 - i) | word1(&u) >> (i - 32)
			    : word1(&u) << (32 - i);
		dval(&d2) = x;
		word0(&d2) -= 31*Exp_msk1;                      
		i -= (Bias + (P-1) - 1) + 1;
		denorm = 1;
		}
#endif
	ds = (dval(&d2)-1.5)*0.289529654602168 + 0.1760912590558 + i*0.301029995663981;
	k = (int)ds;
	if (ds < 0. && ds != k)
		k--;	                        
	k_check = 1;
	if (k >= 0 && k <= Ten_pmax) {
		if (dval(&u) < tens[k])
			k--;
		k_check = 0;
		}
	j = bbits - i - 1;
	if (j >= 0) {
		b2 = 0;
		s2 = j;
		}
	else {
		b2 = -j;
		s2 = 0;
		}
	if (k >= 0) {
		b5 = 0;
		s5 = k;
		s2 += k;
		}
	else {
		b2 -= k;
		b5 = -k;
		s5 = 0;
		}
	if (mode < 0 || mode > 9)
		mode = 0;

#ifndef SET_INEXACT
#ifdef Check_FLT_ROUNDS
	try_quick = Rounding == 1;
#else
	try_quick = 1;
#endif
#endif                

	if (mode > 5) {
		mode -= 4;
		try_quick = 0;
		}
	leftright = 1;
	ilim = ilim1 = -1;	                                            
				                                            
	switch(mode) {
		case 0:
		case 1:
			i = 18;
			ndigits = 0;
			break;
		case 2:
			leftright = 0;
			FALLTHROUGH;
		case 4:
			if (ndigits <= 0)
				ndigits = 1;
			ilim = ilim1 = i = ndigits;
			break;
		case 3:
			leftright = 0;
			FALLTHROUGH;
		case 5:
			i = ndigits + k + 1;
			ilim = i;
			ilim1 = i - 1;
			if (i <= 0)
				i = 1;
		}
	s = s0 = rv_alloc(dalloc, i);

#ifdef Honor_FLT_ROUNDS
	if (mode > 1 && Rounding != 1)
		leftright = 0;
#endif

	if (ilim >= 0 && ilim <= Quick_max && try_quick) {

		                                                   

		i = 0;
		dval(&d2) = dval(&u);
		k0 = k;
		ilim0 = ilim;
		ieps = 2;                   
		if (k > 0) {
			ds = tens[k&0xf];
			j = k >> 4;
			if (j & Bletch) {
				                       
				j &= Bletch - 1;
				dval(&u) /= bigtens[n_bigtens-1];
				ieps++;
				}
			for(; j; j >>= 1, i++)
				if (j & 1) {
					ieps++;
					ds *= bigtens[i];
					}
			dval(&u) /= ds;
			}
		else if ((j1 = -k)) {
			dval(&u) *= tens[j1 & 0xf];
			for(j = j1 >> 4; j; j >>= 1, i++)
				if (j & 1) {
					ieps++;
					dval(&u) *= bigtens[i];
					}
			}
		if (k_check && dval(&u) < 1. && ilim > 0) {
			if (ilim1 <= 0)
				goto fast_failed;
			ilim = ilim1;
			k--;
			dval(&u) *= 10.;
			ieps++;
			}
		dval(&eps) = ieps*dval(&u) + 7.;
		word0(&eps) -= (P-1)*Exp_msk1;
		if (ilim == 0) {
			S = mhi = 0;
			dval(&u) -= 5.;
			if (dval(&u) > dval(&eps))
				goto one_digit;
			if (dval(&u) < -dval(&eps))
				goto no_digits;
			goto fast_failed;
			}
#ifndef No_leftright
		if (leftright) {
			                                    
                               
      
			dval(&eps) = 0.5/tens[ilim-1] - dval(&eps);
#ifdef IEEE_Arith
			if (k0 < 0 && j1 >= 307) {
				eps1.d = 1.01e256;                                                 
				word0(&eps1) -= Exp_msk1 * (Bias+P-1);
				dval(&eps1) *= tens[j1 & 0xf];
				for(i = 0, j = (j1-256) >> 4; j; j >>= 1, i++)
					if (j & 1)
						dval(&eps1) *= bigtens[i];
				if (eps.d < eps1.d)
					eps.d = eps1.d;
				}
#endif
			for(i = 0;;) {
				L = dval(&u);
				dval(&u) -= L;
				*s++ = '0' + (int)L;
				if (1. - dval(&u) < dval(&eps))
					goto bump_up;
				if (dval(&u) < dval(&eps))
					goto ret1;
				if (++i >= ilim)
					break;
				dval(&eps) *= 10.;
				dval(&u) *= 10.;
				}
			}
		else {
#endif
			                                             
			dval(&eps) *= tens[ilim-1];
			for(i = 1;; i++, dval(&u) *= 10.) {
				L = (Long)(dval(&u));
				if (!(dval(&u) -= L))
					ilim = i;
				*s++ = '0' + (int)L;
				if (i == ilim) {
					if (dval(&u) > 0.5 + dval(&eps))
						goto bump_up;
					else if (dval(&u) < 0.5 - dval(&eps)) {
						while(*--s == '0');
						s++;
						goto ret1;
						}
					break;
					}
				}
#ifndef No_leftright
			}
#endif
 fast_failed:
		s = s0;
		dval(&u) = dval(&d2);
		k = k0;
		ilim = ilim0;
		}

	                                   

	if (be >= 0 && k <= Int_max) {
		          
		ds = tens[k];
		if (ndigits < 0 && ilim <= 0) {
			S = mhi = 0;
			if (ilim < 0 || dval(&u) <= 5*ds)
				goto no_digits;
			goto one_digit;
			}
		for(i = 1;; i++, dval(&u) *= 10.) {
			L = (Long)(dval(&u) / ds);
			dval(&u) -= L*ds;
#ifdef Check_FLT_ROUNDS
			                                                     
			if (dval(&u) < 0) {
				L--;
				dval(&u) += ds;
				}
#endif
			*s++ = '0' + (int)L;
			if (!dval(&u)) {
#ifdef SET_INEXACT
				inexact = 0;
#endif
				break;
				}
			if (i == ilim) {
#ifdef Honor_FLT_ROUNDS
				if (mode > 1)
				switch(Rounding) {
				  case 0: goto ret1;
				  case 2: goto bump_up;
				  }
#endif
				dval(&u) += dval(&u);
#ifdef ROUND_BIASED
				if (dval(&u) >= ds)
#else
				if (dval(&u) > ds || (dval(&u) == ds && L & 1))
#endif
					{
 bump_up:
					while(*--s == '9')
						if (s == s0) {
							k++;
							*s = '0';
							break;
							}
					++*s++;
					}
				break;
				}
			}
		goto ret1;
		}

	m2 = b2;
	m5 = b5;
	mhi = mlo = 0;
	if (leftright) {
		i =
#ifndef Sudden_Underflow
			denorm ? be + (Bias + (P-1) - 1 + 1) :
#endif
#ifdef IBM
			1 + 4*P - 3 - bbits + ((bbits + be - 1) & 3);
#else
			1 + P - bbits;
#endif
		b2 += i;
		s2 += i;
		mhi = i2b(dalloc, 1);
		}
	if (m2 > 0 && s2 > 0) {
		i = m2 < s2 ? m2 : s2;
		b2 -= i;
		m2 -= i;
		s2 -= i;
		}
	if (b5 > 0) {
		if (leftright) {
			if (m5 > 0) {
				mhi = pow5mult(dalloc, mhi, m5);
				b1 = mult(dalloc, mhi, b);
				Bfree(dalloc, b);
				b = b1;
				}
			if ((j = b5 - m5))
				b = pow5mult(dalloc, b, j);
			}
		else
			b = pow5mult(dalloc, b, b5);
		}
	S = i2b(dalloc, 1);
	if (s5 > 0)
		S = pow5mult(dalloc, S, s5);

	                                                               

	spec_case = 0;
	if ((mode < 2 || leftright)
#ifdef Honor_FLT_ROUNDS
			&& Rounding == 1
#endif
				) {
		if (!word1(&u) && !(word0(&u) & Bndry_mask)
#ifndef Sudden_Underflow
		 && word0(&u) & (Exp_mask & ~Exp_msk1)
#endif
				) {
			                      
			b2 += Log2P;
			s2 += Log2P;
			spec_case = 1;
			}
		}

	                                                   
                                                            
   
                                                            
                                                          
                                                         
    
	i = dshift(S, s2);
	b2 += i;
	m2 += i;
	s2 += i;
	if (b2 > 0)
		b = lshift(dalloc, b, b2);
	if (s2 > 0)
		S = lshift(dalloc, S, s2);
	if (k_check) {
		if (cmp(b,S) < 0) {
			k--;
			b = multadd(dalloc, b, 10, 0);	                               
			if (leftright)
				mhi = multadd(dalloc, mhi, 10, 0);
			ilim = ilim1;
			}
		}
	if (ilim <= 0 && (mode == 3 || mode == 5)) {
#ifndef HERMES_FIXEDPOINT_HACK
		if (ilim < 0 || cmp(b,S = multadd(dalloc, S,5,0)) <= 0) {
#else
                                                                                    
                                                                               
                                                                             
                                                                                          
		if (ilim < 0 || cmp(b,S = multadd(dalloc, S,5,0)) < 0) {
#endif
			                           
 no_digits:
			k = -1 - ndigits;
			goto ret;
			}
 one_digit:
		*s++ = '1';
		k++;
		goto ret;
		}
	if (leftright) {
		if (m2 > 0)
			mhi = lshift(dalloc, mhi, m2);

		                                        
                                       
     

		mlo = mhi;
		if (spec_case) {
			mhi = Balloc(dalloc, mhi->k);
			Bcopy(mhi, mlo);
			mhi = lshift(dalloc, mhi, Log2P);
			}

		for(i = 1;;i++) {
			dig = quorem(b,S) + '0';
			                                             
                           
      
			j = cmp(b, mlo);
			delta = diff(dalloc, S, mhi);
			j1 = delta->sign ? 1 : cmp(b, delta);
			Bfree(dalloc, delta);
#ifndef ROUND_BIASED
			if (j1 == 0 && mode != 1 && !(word1(&u) & 1)
#ifdef Honor_FLT_ROUNDS
				&& Rounding >= 1
#endif
								   ) {
				if (dig == '9')
					goto round_9_up;
				if (j > 0)
					dig++;
#ifdef SET_INEXACT
				else if (!b->x[0] && b->wds <= 1)
					inexact = 0;
#endif
				*s++ = dig;
				goto ret;
				}
#endif
			if (j < 0 || (j == 0 && mode != 1
#ifndef ROUND_BIASED
							&& !(word1(&u) & 1)
#endif
					)) {
				if (!b->x[0] && b->wds <= 1) {
#ifdef SET_INEXACT
					inexact = 0;
#endif
					goto accept_dig;
					}
#ifdef Honor_FLT_ROUNDS
				if (mode > 1)
				 switch(Rounding) {
				  case 0: goto accept_dig;
				  case 2: goto keep_dig;
				  }
#endif                     
				if (j1 > 0) {
					b = lshift(dalloc, b, 1);
					j1 = cmp(b, S);
#ifdef ROUND_BIASED
					if (j1 >= 0      
#else
					if ((j1 > 0 || (j1 == 0 && dig & 1))
#endif
					&& dig++ == '9')
						goto round_9_up;
					}
 accept_dig:
				*s++ = dig;
				goto ret;
				}
			if (j1 > 0) {
#ifdef Honor_FLT_ROUNDS
				if (!Rounding)
					goto accept_dig;
#endif
				if (dig == '9') {                         
 round_9_up:
					*s++ = '9';
					goto roundoff;
					}
				*s++ = dig + 1;
				goto ret;
				}
#ifdef Honor_FLT_ROUNDS
 keep_dig:
#endif
			*s++ = dig;
			if (i == ilim)
				break;
			b = multadd(dalloc, b, 10, 0);
			if (mlo == mhi)
				mlo = mhi = multadd(dalloc, mhi, 10, 0);
			else {
				mlo = multadd(dalloc, mlo, 10, 0);
				mhi = multadd(dalloc, mhi, 10, 0);
				}
			}
		}
	else
		for(i = 1;; i++) {
			*s++ = dig = quorem(b,S) + '0';
			if (!b->x[0] && b->wds <= 1) {
#ifdef SET_INEXACT
				inexact = 0;
#endif
				goto ret;
				}
			if (i >= ilim)
				break;
			b = multadd(dalloc, b, 10, 0);
			}

	                          

#ifdef Honor_FLT_ROUNDS
	switch(Rounding) {
	  case 0: goto trimzeros;
	  case 2: goto roundoff;
	  }
#endif
	b = lshift(dalloc, b, 1);
	j = cmp(b, S);
#ifdef ROUND_BIASED
	if (j >= 0)
#else
	if (j > 0 || (j == 0 && dig & 1))
#endif
		{
 roundoff:
		while(*--s == '9')
			if (s == s0) {
				k++;
				*s++ = '1';
				goto ret;
				}
		++*s++;
		}
	else {
#ifdef Honor_FLT_ROUNDS
 trimzeros:
#endif
		while(*--s == '0');
		s++;
		}
 ret:
	Bfree(dalloc, S);
	if (mhi) {
		if (mlo && mlo != mhi)
			Bfree(dalloc, mlo);
		Bfree(dalloc, mhi);
		}
 ret1:
#ifdef SET_INEXACT
	if (inexact) {
		if (!oldinexact) {
			word0(&u) = Exp_1 + (70 << Exp_shift);
			word1(&u) = 0;
			dval(&u) += 1.;
			}
		}
	else if (!oldinexact)
		clear_inexact();
#endif
	Bfree(dalloc, b);
	*s = 0;
	*decpt = k + 1;
	if (rve)
		*rve = s;
	return s0;
	}
