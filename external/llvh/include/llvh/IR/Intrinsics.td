//===- Intrinsics.td - Defines all LLVM intrinsics ---------*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines properties of all LLVM intrinsics.
//
//===----------------------------------------------------------------------===//

include "llvm/CodeGen/ValueTypes.td"
include "llvm/CodeGen/SDNodeProperties.td"

                                                                                
                                               
                                                                                

class IntrinsicProperty;

                                                                       
                                                                               
                            

                                                                          
                                                  
def IntrNoMem : IntrinsicProperty;

                                                                            
                                                                             
                                                                              
                      
def IntrReadMem : IntrinsicProperty;

                                                                              
                                                                             
                                     
def IntrWriteMem : IntrinsicProperty;

                                                                              
                                                                          
                                                                               
def IntrArgMemOnly : IntrinsicProperty;

                                                                             
                                                                               
def IntrInaccessibleMemOnly : IntrinsicProperty;

                                                                              
                                                                        
                                                                         
def IntrInaccessibleMemOrArgMemOnly : IntrinsicProperty;

                                                                 
def Commutative : IntrinsicProperty;

                                     
def Throws : IntrinsicProperty;

                                                                               
class NoCapture<int argNo> : IntrinsicProperty {
  int ArgNo = argNo;
}

                                                                      
             
class Returned<int argNo> : IntrinsicProperty {
  int ArgNo = argNo;
}

                                                                          
                            
class ReadOnly<int argNo> : IntrinsicProperty {
  int ArgNo = argNo;
}

                                                                       
                    
class WriteOnly<int argNo> : IntrinsicProperty {
  int ArgNo = argNo;
}

                                                                       
             
class ReadNone<int argNo> : IntrinsicProperty {
  int ArgNo = argNo;
}

def IntrNoReturn : IntrinsicProperty;

                                                                  
                                                            
def IntrNoDuplicate : IntrinsicProperty;

                                                                              
                                              
                                                           
def IntrConvergent : IntrinsicProperty;

                                                                   
def IntrSpeculatable : IntrinsicProperty;

                                                                        
                                                                           
                                                                         
                                                                         
                                      
                                                                           
                                                                            
def IntrHasSideEffects : IntrinsicProperty;

                                                                                
                            
                                                                                

class LLVMType<ValueType vt> {
  ValueType VT = vt;
  int isAny = 0;
}

class LLVMQualPointerType<LLVMType elty, int addrspace>
  : LLVMType<iPTR>{
  LLVMType ElTy = elty;
  int AddrSpace = addrspace;
}

class LLVMPointerType<LLVMType elty>
  : LLVMQualPointerType<elty, 0>;

class LLVMAnyPointerType<LLVMType elty>
  : LLVMType<iPTRAny>{
  LLVMType ElTy = elty;

  let isAny = 1;
}

                                                                              
                                                                             
                                                                         
                                                                                
                                                                         
                                                                  
class LLVMMatchType<int num>
  : LLVMType<OtherVT>{
  int Number = num;
}

                                                                                
                                                                               
                                                                                
                                                                               
class LLVMExtendedType<int num> : LLVMMatchType<num>;
class LLVMTruncatedType<int num> : LLVMMatchType<num>;
class LLVMVectorSameWidth<int num, LLVMType elty>
  : LLVMMatchType<num> {
  ValueType ElTy = elty.VT;
}
class LLVMPointerTo<int num> : LLVMMatchType<num>;
class LLVMPointerToElt<int num> : LLVMMatchType<num>;
class LLVMVectorOfAnyPointersToElt<int num> : LLVMMatchType<num>;

                                                                         
                                                               
class LLVMHalfElementsVectorType<int num> : LLVMMatchType<num>;

def llvm_void_ty       : LLVMType<isVoid>;
let isAny = 1 in {
  def llvm_any_ty        : LLVMType<Any>;
  def llvm_anyint_ty     : LLVMType<iAny>;
  def llvm_anyfloat_ty   : LLVMType<fAny>;
  def llvm_anyvector_ty  : LLVMType<vAny>;
}
def llvm_i1_ty         : LLVMType<i1>;
def llvm_i8_ty         : LLVMType<i8>;
def llvm_i16_ty        : LLVMType<i16>;
def llvm_i32_ty        : LLVMType<i32>;
def llvm_i64_ty        : LLVMType<i64>;
def llvm_half_ty       : LLVMType<f16>;
def llvm_float_ty      : LLVMType<f32>;
def llvm_double_ty     : LLVMType<f64>;
def llvm_f80_ty        : LLVMType<f80>;
def llvm_f128_ty       : LLVMType<f128>;
def llvm_ppcf128_ty    : LLVMType<ppcf128>;
def llvm_ptr_ty        : LLVMPointerType<llvm_i8_ty>;                   
def llvm_ptrptr_ty     : LLVMPointerType<llvm_ptr_ty>;                   
def llvm_anyptr_ty     : LLVMAnyPointerType<llvm_i8_ty>;                       
def llvm_empty_ty      : LLVMType<OtherVT>;                             
def llvm_descriptor_ty : LLVMPointerType<llvm_empty_ty>;                 
def llvm_metadata_ty   : LLVMType<MetadataVT>;                             
def llvm_token_ty      : LLVMType<token>;                                 

def llvm_x86mmx_ty     : LLVMType<x86mmx>;
def llvm_ptrx86mmx_ty  : LLVMPointerType<llvm_x86mmx_ty>;                      

def llvm_v2i1_ty       : LLVMType<v2i1>;                
def llvm_v4i1_ty       : LLVMType<v4i1>;                
def llvm_v8i1_ty       : LLVMType<v8i1>;                
def llvm_v16i1_ty      : LLVMType<v16i1>;               
def llvm_v32i1_ty      : LLVMType<v32i1>;               
def llvm_v64i1_ty      : LLVMType<v64i1>;               
def llvm_v512i1_ty     : LLVMType<v512i1>;              
def llvm_v1024i1_ty    : LLVMType<v1024i1>;             

def llvm_v1i8_ty       : LLVMType<v1i8>;               
def llvm_v2i8_ty       : LLVMType<v2i8>;               
def llvm_v4i8_ty       : LLVMType<v4i8>;               
def llvm_v8i8_ty       : LLVMType<v8i8>;               
def llvm_v16i8_ty      : LLVMType<v16i8>;              
def llvm_v32i8_ty      : LLVMType<v32i8>;              
def llvm_v64i8_ty      : LLVMType<v64i8>;              
def llvm_v128i8_ty     : LLVMType<v128i8>;             
def llvm_v256i8_ty     : LLVMType<v256i8>;             

def llvm_v1i16_ty      : LLVMType<v1i16>;               
def llvm_v2i16_ty      : LLVMType<v2i16>;               
def llvm_v4i16_ty      : LLVMType<v4i16>;               
def llvm_v8i16_ty      : LLVMType<v8i16>;               
def llvm_v16i16_ty     : LLVMType<v16i16>;              
def llvm_v32i16_ty     : LLVMType<v32i16>;              
def llvm_v64i16_ty     : LLVMType<v64i16>;              
def llvm_v128i16_ty    : LLVMType<v128i16>;             

def llvm_v1i32_ty      : LLVMType<v1i32>;               
def llvm_v2i32_ty      : LLVMType<v2i32>;               
def llvm_v4i32_ty      : LLVMType<v4i32>;               
def llvm_v8i32_ty      : LLVMType<v8i32>;               
def llvm_v16i32_ty     : LLVMType<v16i32>;              
def llvm_v32i32_ty     : LLVMType<v32i32>;              
def llvm_v64i32_ty     : LLVMType<v64i32>;              

def llvm_v1i64_ty      : LLVMType<v1i64>;               
def llvm_v2i64_ty      : LLVMType<v2i64>;               
def llvm_v4i64_ty      : LLVMType<v4i64>;               
def llvm_v8i64_ty      : LLVMType<v8i64>;               
def llvm_v16i64_ty     : LLVMType<v16i64>;              
def llvm_v32i64_ty     : LLVMType<v32i64>;              

def llvm_v1i128_ty     : LLVMType<v1i128>;               

def llvm_v2f16_ty      : LLVMType<v2f16>;                         
def llvm_v4f16_ty      : LLVMType<v4f16>;                         
def llvm_v8f16_ty      : LLVMType<v8f16>;                         
def llvm_v1f32_ty      : LLVMType<v1f32>;                 
def llvm_v2f32_ty      : LLVMType<v2f32>;                 
def llvm_v4f32_ty      : LLVMType<v4f32>;                 
def llvm_v8f32_ty      : LLVMType<v8f32>;                 
def llvm_v16f32_ty     : LLVMType<v16f32>;                
def llvm_v1f64_ty      : LLVMType<v1f64>;                  
def llvm_v2f64_ty      : LLVMType<v2f64>;                  
def llvm_v4f64_ty      : LLVMType<v4f64>;                  
def llvm_v8f64_ty      : LLVMType<v8f64>;                  

def llvm_vararg_ty     : LLVMType<isVoid>;                            

                                                                                
                         
                                                                                

                                                                                
                                                                               
                                                                            
                                            
  
                                                                     
                
                                                                          
                
                                                                      
  
class Intrinsic<list<LLVMType> ret_types,
                list<LLVMType> param_types = [],
                list<IntrinsicProperty> intr_properties = [],
                string name = "",
                list<SDNodeProperty> sd_properties = []> : SDPatternOperator {
  string LLVMName = name;
  string TargetPrefix = "";                                                     
  list<LLVMType> RetTypes = ret_types;
  list<LLVMType> ParamTypes = param_types;
  list<IntrinsicProperty> IntrProperties = intr_properties;
  let Properties = sd_properties;

  bit isTarget = 0;
}

                                                                             
                                                                           
            
class GCCBuiltin<string name> {
  string GCCBuiltinName = name;
}

class MSBuiltin<string name> {
  string MSBuiltinName = name;
}


                                                                                
  

def int_vastart : Intrinsic<[], [llvm_ptr_ty], [], "llvm.va_start">;
def int_vacopy  : Intrinsic<[], [llvm_ptr_ty, llvm_ptr_ty], [],
                            "llvm.va_copy">;
def int_vaend   : Intrinsic<[], [llvm_ptr_ty], [], "llvm.va_end">;

                                                                                
  
def int_gcroot  : Intrinsic<[],
                            [llvm_ptrptr_ty, llvm_ptr_ty]>;
def int_gcread  : Intrinsic<[llvm_ptr_ty],
                            [llvm_ptr_ty, llvm_ptrptr_ty],
                            [IntrReadMem, IntrArgMemOnly]>;
def int_gcwrite : Intrinsic<[],
                            [llvm_ptr_ty, llvm_ptr_ty, llvm_ptrptr_ty],
                            [IntrArgMemOnly, NoCapture<1>, NoCapture<2>]>;

                                                                                
  
def int_returnaddress : Intrinsic<[llvm_ptr_ty], [llvm_i32_ty], [IntrNoMem]>;
def int_addressofreturnaddress : Intrinsic<[llvm_ptr_ty], [], [IntrNoMem]>;
def int_frameaddress  : Intrinsic<[llvm_ptr_ty], [llvm_i32_ty], [IntrNoMem]>;
def int_read_register  : Intrinsic<[llvm_anyint_ty], [llvm_metadata_ty],
                                   [IntrReadMem], "llvm.read_register">;
def int_write_register : Intrinsic<[], [llvm_metadata_ty, llvm_anyint_ty],
                                   [], "llvm.write_register">;

                                                                               
                                                                   
def int_localaddress : Intrinsic<[llvm_ptr_ty], [], [IntrNoMem]>;

                                                                
def int_localescape : Intrinsic<[], [llvm_vararg_ty]>;

                                                                             
                                                   
def int_localrecover : Intrinsic<[llvm_ptr_ty],
                                 [llvm_ptr_ty, llvm_ptr_ty, llvm_i32_ty],
                                 [IntrNoMem]>;
                                                                               
                                       
def int_stacksave     : Intrinsic<[llvm_ptr_ty]>,
                        GCCBuiltin<"__builtin_stack_save">;
def int_stackrestore  : Intrinsic<[], [llvm_ptr_ty]>,
                        GCCBuiltin<"__builtin_stack_restore">;

def int_get_dynamic_area_offset : Intrinsic<[llvm_anyint_ty]>;

def int_thread_pointer : Intrinsic<[llvm_ptr_ty], [], [IntrNoMem]>,
                         GCCBuiltin<"__builtin_thread_pointer">;

                                                                             
                                                                            
                                                                             
                                          
def int_prefetch
    : Intrinsic<[], [ llvm_ptr_ty, llvm_i32_ty, llvm_i32_ty, llvm_i32_ty ],
                [ IntrInaccessibleMemOrArgMemOnly, ReadOnly<0>, NoCapture<0> ]>;
def int_pcmarker      : Intrinsic<[], [llvm_i32_ty]>;

def int_readcyclecounter : Intrinsic<[llvm_i64_ty]>;

                                                                       
                                           
def int_assume        : Intrinsic<[], [llvm_i1_ty], []>;

                                                                            
                                                 
def int_stackprotector : Intrinsic<[], [llvm_ptr_ty, llvm_ptrptr_ty], []>;
def int_stackguard : Intrinsic<[llvm_ptr_ty], [], []>;

                                                           
def int_instrprof_increment : Intrinsic<[],
                                        [llvm_ptr_ty, llvm_i64_ty,
                                         llvm_i32_ty, llvm_i32_ty],
                                        []>;

                                                                     
def int_instrprof_increment_step : Intrinsic<[],
                                        [llvm_ptr_ty, llvm_i64_ty,
                                         llvm_i32_ty, llvm_i32_ty, llvm_i64_ty],
                                        []>;

                                                                      
                                           
def int_instrprof_value_profile : Intrinsic<[],
                                            [llvm_ptr_ty, llvm_i64_ty,
                                             llvm_i64_ty, llvm_i32_ty,
                                             llvm_i32_ty],
                                            []>;

                                                                                
  

def int_memcpy  : Intrinsic<[],
                             [llvm_anyptr_ty, llvm_anyptr_ty, llvm_anyint_ty,
                              llvm_i1_ty],
                            [IntrArgMemOnly, NoCapture<0>, NoCapture<1>,
                             WriteOnly<0>, ReadOnly<1>]>;
def int_memmove : Intrinsic<[],
                            [llvm_anyptr_ty, llvm_anyptr_ty, llvm_anyint_ty,
                             llvm_i1_ty],
                            [IntrArgMemOnly, NoCapture<0>, NoCapture<1>,
                             ReadOnly<1>]>;
def int_memset  : Intrinsic<[],
                            [llvm_anyptr_ty, llvm_i8_ty, llvm_anyint_ty,
                             llvm_i1_ty],
                            [IntrArgMemOnly, NoCapture<0>, WriteOnly<0>]>;

                                                                                
                                            

let IntrProperties = [IntrNoMem, IntrSpeculatable] in {
  def int_fma  : Intrinsic<[llvm_anyfloat_ty],
                           [LLVMMatchType<0>, LLVMMatchType<0>,
                            LLVMMatchType<0>]>;
  def int_fmuladd : Intrinsic<[llvm_anyfloat_ty],
                              [LLVMMatchType<0>, LLVMMatchType<0>,
                               LLVMMatchType<0>]>;

                                                                 
                                                                   
                                                    
  def int_sqrt : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_powi : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>, llvm_i32_ty]>;
  def int_sin  : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_cos  : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_pow  : Intrinsic<[llvm_anyfloat_ty],
                           [LLVMMatchType<0>, LLVMMatchType<0>]>;
  def int_log  : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_log10: Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_log2 : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_exp  : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_exp2 : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_fabs : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_copysign : Intrinsic<[llvm_anyfloat_ty],
                               [LLVMMatchType<0>, LLVMMatchType<0>]>;
  def int_floor : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_ceil  : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_trunc : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_rint  : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_nearbyint : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_round : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>]>;
  def int_canonicalize : Intrinsic<[llvm_anyfloat_ty], [LLVMMatchType<0>],
                                   [IntrNoMem]>;
}

def int_minnum : Intrinsic<[llvm_anyfloat_ty],
  [LLVMMatchType<0>, LLVMMatchType<0>],
  [IntrNoMem, IntrSpeculatable, Commutative]
>;
def int_maxnum : Intrinsic<[llvm_anyfloat_ty],
  [LLVMMatchType<0>, LLVMMatchType<0>],
  [IntrNoMem, IntrSpeculatable, Commutative]
>;

                                       
def int_setjmp     : Intrinsic<[llvm_i32_ty],  [llvm_ptr_ty]>;
def int_longjmp    : Intrinsic<[], [llvm_ptr_ty, llvm_i32_ty], [IntrNoReturn]>;
def int_sigsetjmp  : Intrinsic<[llvm_i32_ty] , [llvm_ptr_ty, llvm_i32_ty]>;
def int_siglongjmp : Intrinsic<[], [llvm_ptr_ty, llvm_i32_ty], [IntrNoReturn]>;

                                              
def int_objectsize : Intrinsic<[llvm_anyint_ty],
                               [llvm_anyptr_ty, llvm_i1_ty, llvm_i1_ty],
                               [IntrNoMem, IntrSpeculatable]>,
                               GCCBuiltin<"__builtin_object_size">;

                                                                                
  

let IntrProperties = [IntrInaccessibleMemOnly] in {
  def int_experimental_constrained_fadd : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_fsub : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_fmul : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_fdiv : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_frem : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;

  def int_experimental_constrained_fma : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;

                                                                               
                                                                              
                                                                            
          
  def int_experimental_constrained_sqrt : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_powi : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_i32_ty,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_sin  : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_cos  : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_pow  : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_log  : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_log10: Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_log2 : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_exp  : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_exp2 : Intrinsic<[ llvm_anyfloat_ty ],
                                                    [ LLVMMatchType<0>,
                                                      llvm_metadata_ty,
                                                      llvm_metadata_ty ]>;
  def int_experimental_constrained_rint  : Intrinsic<[ llvm_anyfloat_ty ],
                                                     [ LLVMMatchType<0>,
                                                       llvm_metadata_ty,
                                                       llvm_metadata_ty ]>;
  def int_experimental_constrained_nearbyint : Intrinsic<[ llvm_anyfloat_ty ],
                                                         [ LLVMMatchType<0>,
                                                           llvm_metadata_ty,
                                                           llvm_metadata_ty ]>;
}
                                                                     
                                                                          


                                                                                
  
def int_expect : Intrinsic<[llvm_anyint_ty], [LLVMMatchType<0>,
                                              LLVMMatchType<0>], [IntrNoMem]>;

                                                                                
  

                                                   
let IntrProperties = [IntrNoMem, IntrSpeculatable] in {
  def int_bswap: Intrinsic<[llvm_anyint_ty], [LLVMMatchType<0>]>;
  def int_ctpop: Intrinsic<[llvm_anyint_ty], [LLVMMatchType<0>]>;
  def int_ctlz : Intrinsic<[llvm_anyint_ty], [LLVMMatchType<0>, llvm_i1_ty]>;
  def int_cttz : Intrinsic<[llvm_anyint_ty], [LLVMMatchType<0>, llvm_i1_ty]>;
  def int_bitreverse : Intrinsic<[llvm_anyint_ty], [LLVMMatchType<0>]>;
  def int_fshl : Intrinsic<[llvm_anyint_ty],
      [LLVMMatchType<0>, LLVMMatchType<0>, LLVMMatchType<0>]>;
  def int_fshr : Intrinsic<[llvm_anyint_ty],
      [LLVMMatchType<0>, LLVMMatchType<0>, LLVMMatchType<0>]>;
}

                                                                                
  

                                                                     
                                                                      
                                                             
                                                               
let IntrProperties = [IntrNoMem, IntrSpeculatable] in {
  def int_dbg_declare      : Intrinsic<[],
                                       [llvm_metadata_ty,
                                        llvm_metadata_ty,
                                        llvm_metadata_ty]>;
  def int_dbg_value        : Intrinsic<[],
                                       [llvm_metadata_ty,
                                        llvm_metadata_ty,
                                        llvm_metadata_ty]>;
  def int_dbg_addr         : Intrinsic<[],
                                       [llvm_metadata_ty,
                                        llvm_metadata_ty,
                                        llvm_metadata_ty]>;
  def int_dbg_label        : Intrinsic<[],
                                       [llvm_metadata_ty]>;
}

                                                                                
  

                                                                              
                                                     
def int_eh_typeid_for : Intrinsic<[llvm_i32_ty], [llvm_ptr_ty], [IntrNoMem]>;

def int_eh_return_i32 : Intrinsic<[], [llvm_i32_ty, llvm_ptr_ty]>;
def int_eh_return_i64 : Intrinsic<[], [llvm_i64_ty, llvm_ptr_ty]>;

                                                                     
                        
def int_eh_exceptionpointer : Intrinsic<[llvm_anyptr_ty], [llvm_token_ty],
                                        [IntrNoMem]>;

                                                                              
def int_eh_exceptioncode : Intrinsic<[llvm_i32_ty], [llvm_token_ty], [IntrNoMem]>;

                                                                         
                                                                              
                                                              
def int_eh_unwind_init: Intrinsic<[]>,
                        GCCBuiltin<"__builtin_unwind_init">;

def int_eh_dwarf_cfa  : Intrinsic<[llvm_ptr_ty], [llvm_i32_ty]>;

let IntrProperties = [IntrNoMem] in {
  def int_eh_sjlj_lsda             : Intrinsic<[llvm_ptr_ty]>;
  def int_eh_sjlj_callsite         : Intrinsic<[], [llvm_i32_ty]>;
}
def int_eh_sjlj_functioncontext : Intrinsic<[], [llvm_ptr_ty]>;
def int_eh_sjlj_setjmp          : Intrinsic<[llvm_i32_ty], [llvm_ptr_ty]>;
def int_eh_sjlj_longjmp         : Intrinsic<[], [llvm_ptr_ty], [IntrNoReturn]>;
def int_eh_sjlj_setup_dispatch  : Intrinsic<[], []>;

                                                                                
  
def int_var_annotation : Intrinsic<[],
                                   [llvm_ptr_ty, llvm_ptr_ty,
                                    llvm_ptr_ty, llvm_i32_ty],
                                   [], "llvm.var.annotation">;
def int_ptr_annotation : Intrinsic<[LLVMAnyPointerType<llvm_anyint_ty>],
                                   [LLVMMatchType<0>, llvm_ptr_ty, llvm_ptr_ty,
                                    llvm_i32_ty],
                                   [], "llvm.ptr.annotation">;
def int_annotation : Intrinsic<[llvm_anyint_ty],
                               [LLVMMatchType<0>, llvm_ptr_ty,
                                llvm_ptr_ty, llvm_i32_ty],
                               [], "llvm.annotation">;

                                                                              
                                                                             
                                          
def int_codeview_annotation : Intrinsic<[], [llvm_metadata_ty],
                                        [IntrInaccessibleMemOnly, IntrNoDuplicate],
                                        "llvm.codeview.annotation">;

                                                                                
  
def int_init_trampoline : Intrinsic<[],
                                    [llvm_ptr_ty, llvm_ptr_ty, llvm_ptr_ty],
                                    [IntrArgMemOnly, NoCapture<0>]>,
                                   GCCBuiltin<"__builtin_init_trampoline">;

def int_adjust_trampoline : Intrinsic<[llvm_ptr_ty], [llvm_ptr_ty],
                                      [IntrReadMem, IntrArgMemOnly]>,
                                     GCCBuiltin<"__builtin_adjust_trampoline">;

                                                                                
  

                                                              
def int_sadd_with_overflow : Intrinsic<[llvm_anyint_ty, llvm_i1_ty],
                                       [LLVMMatchType<0>, LLVMMatchType<0>],
                                       [IntrNoMem, IntrSpeculatable]>;
def int_uadd_with_overflow : Intrinsic<[llvm_anyint_ty, llvm_i1_ty],
                                       [LLVMMatchType<0>, LLVMMatchType<0>],
                                       [IntrNoMem, IntrSpeculatable]>;

def int_ssub_with_overflow : Intrinsic<[llvm_anyint_ty, llvm_i1_ty],
                                       [LLVMMatchType<0>, LLVMMatchType<0>],
                                       [IntrNoMem, IntrSpeculatable]>;
def int_usub_with_overflow : Intrinsic<[llvm_anyint_ty, llvm_i1_ty],
                                       [LLVMMatchType<0>, LLVMMatchType<0>],
                                       [IntrNoMem, IntrSpeculatable]>;

def int_smul_with_overflow : Intrinsic<[llvm_anyint_ty, llvm_i1_ty],
                                       [LLVMMatchType<0>, LLVMMatchType<0>],
                                       [IntrNoMem, IntrSpeculatable]>;
def int_umul_with_overflow : Intrinsic<[llvm_anyint_ty, llvm_i1_ty],
                                       [LLVMMatchType<0>, LLVMMatchType<0>],
                                       [IntrNoMem, IntrSpeculatable]>;

                                                                                
  
def int_lifetime_start  : Intrinsic<[],
                                    [llvm_i64_ty, llvm_anyptr_ty],
                                    [IntrArgMemOnly, NoCapture<1>]>;
def int_lifetime_end    : Intrinsic<[],
                                    [llvm_i64_ty, llvm_anyptr_ty],
                                    [IntrArgMemOnly, NoCapture<1>]>;
def int_invariant_start : Intrinsic<[llvm_descriptor_ty],
                                    [llvm_i64_ty, llvm_anyptr_ty],
                                    [IntrArgMemOnly, NoCapture<1>]>;
def int_invariant_end   : Intrinsic<[],
                                    [llvm_descriptor_ty, llvm_i64_ty,
                                     llvm_anyptr_ty],
                                    [IntrArgMemOnly, NoCapture<2>]>;

                                                                       
                                                                     
                                                                       
                                                               
                                                                   
                                                                 
                                                               
                                        
                                                                       
                           
                                                                     
                              
def int_launder_invariant_group : Intrinsic<[llvm_anyptr_ty],
                                            [LLVMMatchType<0>],
                                            [IntrInaccessibleMemOnly, IntrSpeculatable]>;


def int_strip_invariant_group : Intrinsic<[llvm_anyptr_ty],
                                          [LLVMMatchType<0>],
                                          [IntrSpeculatable, IntrNoMem]>;

                                                                                
  
def int_experimental_stackmap : Intrinsic<[],
                                  [llvm_i64_ty, llvm_i32_ty, llvm_vararg_ty],
                                  [Throws]>;
def int_experimental_patchpoint_void : Intrinsic<[],
                                                 [llvm_i64_ty, llvm_i32_ty,
                                                  llvm_ptr_ty, llvm_i32_ty,
                                                  llvm_vararg_ty],
                                                  [Throws]>;
def int_experimental_patchpoint_i64 : Intrinsic<[llvm_i64_ty],
                                                [llvm_i64_ty, llvm_i32_ty,
                                                 llvm_ptr_ty, llvm_i32_ty,
                                                 llvm_vararg_ty],
                                                 [Throws]>;


                                                                                
                                              

def int_experimental_gc_statepoint : Intrinsic<[llvm_token_ty],
                               [llvm_i64_ty, llvm_i32_ty,
                                llvm_anyptr_ty, llvm_i32_ty,
                                llvm_i32_ty, llvm_vararg_ty],
                                [Throws]>;

def int_experimental_gc_result   : Intrinsic<[llvm_any_ty], [llvm_token_ty],
                                             [IntrReadMem]>;
def int_experimental_gc_relocate : Intrinsic<[llvm_any_ty],
                                [llvm_token_ty, llvm_i32_ty, llvm_i32_ty],
                                [IntrReadMem]>;

                                                                       
                                              

                                  

def int_coro_id : Intrinsic<[llvm_token_ty], [llvm_i32_ty, llvm_ptr_ty,
                             llvm_ptr_ty, llvm_ptr_ty],
                            [IntrArgMemOnly, IntrReadMem,
                             ReadNone<1>, ReadOnly<2>, NoCapture<2>]>;
def int_coro_alloc : Intrinsic<[llvm_i1_ty], [llvm_token_ty], []>;
def int_coro_begin : Intrinsic<[llvm_ptr_ty], [llvm_token_ty, llvm_ptr_ty],
                               [WriteOnly<1>]>;

def int_coro_free : Intrinsic<[llvm_ptr_ty], [llvm_token_ty, llvm_ptr_ty],
                              [IntrReadMem, IntrArgMemOnly, ReadOnly<1>,
                               NoCapture<1>]>;
def int_coro_end : Intrinsic<[llvm_i1_ty], [llvm_ptr_ty, llvm_i1_ty], []>;

def int_coro_frame : Intrinsic<[llvm_ptr_ty], [], [IntrNoMem]>;
def int_coro_noop : Intrinsic<[llvm_ptr_ty], [], [IntrNoMem]>;
def int_coro_size : Intrinsic<[llvm_anyint_ty], [], [IntrNoMem]>;

def int_coro_save : Intrinsic<[llvm_token_ty], [llvm_ptr_ty], []>;
def int_coro_suspend : Intrinsic<[llvm_i8_ty], [llvm_token_ty, llvm_i1_ty], []>;

def int_coro_param : Intrinsic<[llvm_i1_ty], [llvm_ptr_ty, llvm_ptr_ty],
                               [IntrNoMem, ReadNone<0>, ReadNone<1>]>;

                                     

def int_coro_resume : Intrinsic<[], [llvm_ptr_ty], [Throws]>;
def int_coro_destroy : Intrinsic<[], [llvm_ptr_ty], [Throws]>;
def int_coro_done : Intrinsic<[llvm_i1_ty], [llvm_ptr_ty],
                              [IntrArgMemOnly, ReadOnly<0>, NoCapture<0>]>;
def int_coro_promise : Intrinsic<[llvm_ptr_ty],
                                 [llvm_ptr_ty, llvm_i32_ty, llvm_i1_ty],
                                 [IntrNoMem, NoCapture<0>]>;

                                                                      

def int_coro_subfn_addr : Intrinsic<[llvm_ptr_ty], [llvm_ptr_ty, llvm_i8_ty],
                                    [IntrReadMem, IntrArgMemOnly, ReadOnly<0>,
                                     NoCapture<0>]>;

                                                                                 
  
def int_flt_rounds : Intrinsic<[llvm_i32_ty]>,
                     GCCBuiltin<"__builtin_flt_rounds">;
def int_trap : Intrinsic<[], [], [IntrNoReturn]>,
               GCCBuiltin<"__builtin_trap">;
def int_debugtrap : Intrinsic<[]>,
                    GCCBuiltin<"__builtin_debugtrap">;

                                                            
def int_experimental_deoptimize : Intrinsic<[llvm_any_ty], [llvm_vararg_ty],
                                            [Throws]>;

                                         
def int_experimental_guard : Intrinsic<[], [llvm_i1_ty, llvm_vararg_ty],
                                       [Throws]>;

                                                              
def int_donothing : Intrinsic<[], [], [IntrNoMem]>;

                                                                               
                                                                            
                                                                             
                                                       
def int_sideeffect : Intrinsic<[], [], [IntrInaccessibleMemOnly]>;

                                                            
let IntrProperties = [IntrNoMem] in {
def int_convert_to_fp16   : Intrinsic<[llvm_i16_ty], [llvm_anyfloat_ty]>;
def int_convert_from_fp16 : Intrinsic<[llvm_anyfloat_ty], [llvm_i16_ty]>;
}

                                                              
                                                       
def int_clear_cache : Intrinsic<[], [llvm_ptr_ty, llvm_ptr_ty],
                                [], "llvm.clear_cache">;

                                                                                
  
def int_masked_store : Intrinsic<[], [llvm_anyvector_ty,
                                      LLVMAnyPointerType<LLVMMatchType<0>>,
                                      llvm_i32_ty,
                                      LLVMVectorSameWidth<0, llvm_i1_ty>],
                                 [IntrArgMemOnly]>;

def int_masked_load  : Intrinsic<[llvm_anyvector_ty],
                                 [LLVMAnyPointerType<LLVMMatchType<0>>, llvm_i32_ty,
                                  LLVMVectorSameWidth<0, llvm_i1_ty>, LLVMMatchType<0>],
                                 [IntrReadMem, IntrArgMemOnly]>;

def int_masked_gather: Intrinsic<[llvm_anyvector_ty],
                                 [LLVMVectorOfAnyPointersToElt<0>, llvm_i32_ty,
                                  LLVMVectorSameWidth<0, llvm_i1_ty>,
                                  LLVMMatchType<0>],
                                 [IntrReadMem]>;

def int_masked_scatter: Intrinsic<[],
                                  [llvm_anyvector_ty,
                                   LLVMVectorOfAnyPointersToElt<0>, llvm_i32_ty,
                                   LLVMVectorSameWidth<0, llvm_i1_ty>]>;

def int_masked_expandload: Intrinsic<[llvm_anyvector_ty],
                                     [LLVMPointerToElt<0>,
                                      LLVMVectorSameWidth<0, llvm_i1_ty>,
                                      LLVMMatchType<0>],
                                     [IntrReadMem]>;

def int_masked_compressstore: Intrinsic<[],
                                     [llvm_anyvector_ty,
                                      LLVMPointerToElt<0>,
                                      LLVMVectorSameWidth<0, llvm_i1_ty>],
                                     [IntrArgMemOnly]>;

                                                                        
def int_type_test : Intrinsic<[llvm_i1_ty], [llvm_ptr_ty, llvm_metadata_ty],
                              [IntrNoMem]>;

                                                                                    
def int_type_checked_load : Intrinsic<[llvm_ptr_ty, llvm_i1_ty],
                                      [llvm_ptr_ty, llvm_i32_ty, llvm_metadata_ty],
                                      [IntrNoMem]>;

                                                                              
                                             
def int_icall_branch_funnel : Intrinsic<[], [llvm_vararg_ty], []>;

def int_load_relative: Intrinsic<[llvm_ptr_ty], [llvm_ptr_ty, llvm_anyint_ty],
                                 [IntrReadMem, IntrArgMemOnly]>;

                  
                                                                                
                                  
                                                            
def int_xray_customevent : Intrinsic<[], [llvm_ptr_ty, llvm_i32_ty],
                                     [NoCapture<0>, ReadOnly<0>, IntrWriteMem]>;
                                 
                                                                                
def int_xray_typedevent : Intrinsic<[], [llvm_i16_ty, llvm_ptr_ty, llvm_i32_ty],
                                        [NoCapture<1>, ReadOnly<1>, IntrWriteMem]>;
                                                                                

                                                                                
  

                                                                          
def int_memcpy_element_unordered_atomic
    : Intrinsic<[],
                [
                  llvm_anyptr_ty, llvm_anyptr_ty, llvm_anyint_ty, llvm_i32_ty
                ],
                [
                  IntrArgMemOnly, NoCapture<0>, NoCapture<1>, WriteOnly<0>,
                  ReadOnly<1>
                ]>;

                                                                           
def int_memmove_element_unordered_atomic
    : Intrinsic<[],
                [
                  llvm_anyptr_ty, llvm_anyptr_ty, llvm_anyint_ty, llvm_i32_ty
                ],
                [
                  IntrArgMemOnly, NoCapture<0>, NoCapture<1>, WriteOnly<0>,
                  ReadOnly<1>
                ]>;

                                                                            
def int_memset_element_unordered_atomic
    : Intrinsic<[], [ llvm_anyptr_ty, llvm_i8_ty, llvm_anyint_ty, llvm_i32_ty ],
                [ IntrArgMemOnly, NoCapture<0>, WriteOnly<0> ]>;

                                                                                
  
def int_experimental_vector_reduce_fadd : Intrinsic<[llvm_anyfloat_ty],
                                                    [llvm_anyfloat_ty,
                                                     llvm_anyvector_ty],
                                                    [IntrNoMem]>;
def int_experimental_vector_reduce_fmul : Intrinsic<[llvm_anyfloat_ty],
                                                    [llvm_anyfloat_ty,
                                                     llvm_anyvector_ty],
                                                    [IntrNoMem]>;
def int_experimental_vector_reduce_add : Intrinsic<[llvm_anyint_ty],
                                                   [llvm_anyvector_ty],
                                                   [IntrNoMem]>;
def int_experimental_vector_reduce_mul : Intrinsic<[llvm_anyint_ty],
                                                   [llvm_anyvector_ty],
                                                   [IntrNoMem]>;
def int_experimental_vector_reduce_and : Intrinsic<[llvm_anyint_ty],
                                                   [llvm_anyvector_ty],
                                                   [IntrNoMem]>;
def int_experimental_vector_reduce_or : Intrinsic<[llvm_anyint_ty],
                                                  [llvm_anyvector_ty],
                                                  [IntrNoMem]>;
def int_experimental_vector_reduce_xor : Intrinsic<[llvm_anyint_ty],
                                                   [llvm_anyvector_ty],
                                                   [IntrNoMem]>;
def int_experimental_vector_reduce_smax : Intrinsic<[llvm_anyint_ty],
                                                    [llvm_anyvector_ty],
                                                    [IntrNoMem]>;
def int_experimental_vector_reduce_smin : Intrinsic<[llvm_anyint_ty],
                                                    [llvm_anyvector_ty],
                                                    [IntrNoMem]>;
def int_experimental_vector_reduce_umax : Intrinsic<[llvm_anyint_ty],
                                                    [llvm_anyvector_ty],
                                                    [IntrNoMem]>;
def int_experimental_vector_reduce_umin : Intrinsic<[llvm_anyint_ty],
                                                    [llvm_anyvector_ty],
                                                    [IntrNoMem]>;
def int_experimental_vector_reduce_fmax : Intrinsic<[llvm_anyfloat_ty],
                                                    [llvm_anyvector_ty],
                                                    [IntrNoMem]>;
def int_experimental_vector_reduce_fmin : Intrinsic<[llvm_anyfloat_ty],
                                                    [llvm_anyvector_ty],
                                                    [IntrNoMem]>;

                                                                               

def int_ssa_copy : Intrinsic<[llvm_any_ty], [LLVMMatchType<0>],
                             [IntrNoMem, Returned<0>]>;
                                                                                
                             
                                                                                

include "llvm/IR/IntrinsicsPowerPC.td"
include "llvm/IR/IntrinsicsX86.td"
include "llvm/IR/IntrinsicsARM.td"
include "llvm/IR/IntrinsicsAArch64.td"
include "llvm/IR/IntrinsicsXCore.td"
include "llvm/IR/IntrinsicsHexagon.td"
include "llvm/IR/IntrinsicsNVVM.td"
include "llvm/IR/IntrinsicsMips.td"
include "llvm/IR/IntrinsicsAMDGPU.td"
include "llvm/IR/IntrinsicsBPF.td"
include "llvm/IR/IntrinsicsSystemZ.td"
include "llvm/IR/IntrinsicsWebAssembly.td"
include "llvm/IR/IntrinsicsRISCV.td"
