//===- IntrinsicsHexagon.td - Defines Hexagon intrinsics ---*- tablegen -*-===//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines all of the Hexagon-specific intrinsics.
//
//===----------------------------------------------------------------------===//

                                                                                
                                          
  
                                                     
let TargetPrefix = "hexagon" in {
                                                                
  class Hexagon_Intrinsic<string GCCIntSuffix, list<LLVMType> ret_types,
                              list<LLVMType> param_types,
                              list<IntrinsicProperty> properties>
    : GCCBuiltin<!strconcat("__builtin_", GCCIntSuffix)>,
      Intrinsic<ret_types, param_types, properties>;

                                                                           
                 
  class Hexagon_NonGCC_Intrinsic<list<LLVMType> ret_types,
                                 list<LLVMType> param_types,
                                 list<IntrinsicProperty> properties>
    : Intrinsic<ret_types, param_types, properties>;
}

                                                                                
  
                                                      
                                                
  
class Hexagon_qi_mem_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_ptr_ty],
                          [IntrNoMem]>;
  
                                                    
                                               
  
class Hexagon_hi_si_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i16_ty], [llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                    
                                               
  
class Hexagon_si_si_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                         
                                               
  
class Hexagon_di_si_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                         
                                               
  
class Hexagon_si_di_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                              
                                               
  
class Hexagon_di_di_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                      
                                               
  
class Hexagon_qi_qi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                     
                                               
  
class Hexagon_qi_si_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                          
                                               
  
class Hexagon_di_qi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                     
                                               
  
class Hexagon_si_qi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                              
                                                 
  
class Hexagon_qi_sisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                
                                                   
  
class Hexagon_void_sisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_void_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                             
                                                 
  
class Hexagon_si_sisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                               
                                                  
  
class Hexagon_usi_sisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                  
                                                 
  
class Hexagon_di_sisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                    
                                                  
  
class Hexagon_udi_sisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                       
                                                 
  
class Hexagon_di_sidi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty, llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                       
                                                 
  
class Hexagon_di_disi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                  
                                                 
  
class Hexagon_si_sidi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                       
                                                 
  
class Hexagon_si_didi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i64_ty, llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                            
                                                 
  
class Hexagon_di_didi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                              
                                                  
  
class Hexagon_udi_didi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                  
                                                 
  
class Hexagon_si_disi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i64_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                        
                                                 
  
class Hexagon_qi_didi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i64_ty, llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                   
                                                 
  
class Hexagon_qi_sidi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i32_ty, llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                   
                                                 
  
class Hexagon_qi_disi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i64_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                
                                                 
  
class Hexagon_qi_qiqi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                  
                                                   
  
class Hexagon_qi_qiqiqi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_i1_ty, llvm_i1_ty, llvm_i1_ty],
                          [IntrNoMem]>;
  
                                                               
                                                 
  
class Hexagon_si_qiqi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                              
                                                 
  
class Hexagon_si_qisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i1_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                         
                                                     
  
class Hexagon_void_sisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_void_ty], [llvm_i32_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                      
                                                   
  
class Hexagon_si_sisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                           
                                                   
  
class Hexagon_di_sisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                           
                                                   
  
class Hexagon_si_disisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i64_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                                
                                                   
  
class Hexagon_di_disisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                           
                                                   
  
class Hexagon_si_sidisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i64_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                               
                                             
                                                   
  
class Hexagon_di_didisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i64_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                                
                                                   
  
class Hexagon_si_sididi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i64_ty,
                           llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                           
                                      
                                                   
  
class Hexagon_di_dididi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i64_ty,
                           llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                           
                                                   
  
class Hexagon_si_sisidi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty,
                           llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                       
                                                   
  
class Hexagon_si_qisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                            
                                                   
  
class Hexagon_di_qisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i1_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                       
                                      
                                                   
  
class Hexagon_di_qididi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty, llvm_i64_ty,
                           llvm_i64_ty],
                          [IntrNoMem]>;
  
                                                                           
                                  
                                                   
  
class Hexagon_di_didiqi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i64_ty,
                           llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                               
                                                     
  
class Hexagon_si_sisisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty,
                           llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                                 
                                                    
                                                     
  
class Hexagon_di_didisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i64_ty,
                           llvm_i32_ty, llvm_i32_ty],
                          [IntrNoMem]>;

class Hexagon_mem_memmemsi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_ptr_ty], [llvm_ptr_ty, llvm_ptr_ty,
                           llvm_i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_mem_memsisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_ptr_ty], [llvm_ptr_ty, llvm_i32_ty,
                           llvm_i32_ty],
                          [IntrWriteMem]>;

class Hexagon_mem_memdisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_ptr_ty], [llvm_ptr_ty, llvm_i64_ty,
                           llvm_i32_ty],
                          [IntrWriteMem]>;

class Hexagon_mem_memmemsisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_ptr_ty], [llvm_ptr_ty, llvm_ptr_ty,
                           llvm_i32_ty, llvm_i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_mem_memsisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_ptr_ty], [llvm_ptr_ty, llvm_i32_ty,
                           llvm_i32_ty, llvm_i32_ty],
                          [IntrWriteMem]>;

class Hexagon_mem_memdisisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_ptr_ty], [llvm_ptr_ty, llvm_i64_ty,
                           llvm_i32_ty, llvm_i32_ty],
                          [IntrWriteMem]>;

class Hexagon_v256_v256v256_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v8i32_ty], [llvm_v8i32_ty, llvm_v8i32_ty],
                          [IntrArgMemOnly]>;

  
                                               
  
class Hexagon_sf_si_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_float_ty], [llvm_i32_ty],
                          [IntrNoMem, Throws]>;
  
                                               
  
class Hexagon_sf_df_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_float_ty], [llvm_double_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_sf_di_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_float_ty], [llvm_i64_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_df_sf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_double_ty], [llvm_float_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_di_sf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_float_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_sf_sf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_float_ty], [llvm_float_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_si_sf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_float_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_si_df_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_double_ty],
                          [IntrNoMem]>;
  
                                                 
  
class Hexagon_sf_sfsf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_float_ty], [llvm_float_ty, llvm_float_ty],
                          [IntrNoMem, Throws]>;
  
                                                 
  
class Hexagon_si_sfsf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_float_ty, llvm_float_ty],
                          [IntrNoMem, Throws]>;
  
                                                 
  
class Hexagon_si_sfsi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_float_ty, llvm_i32_ty],
                          [IntrNoMem, Throws]>;
  
                                                 
  
class Hexagon_qi_sfqi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i1_ty], [llvm_float_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                                   
  
class Hexagon_sf_sfsfsf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_float_ty], [llvm_float_ty, llvm_float_ty,
                                            llvm_float_ty],
                          [IntrNoMem, Throws]>;
  
                                                     
  
class Hexagon_sf_sfsfsfqi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_float_ty], [llvm_float_ty, llvm_float_ty,
                                            llvm_float_ty,
                           llvm_i32_ty],
                          [IntrNoMem, Throws]>;
  
                                                   
  
class Hexagon_di_dididisi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty, llvm_i64_ty,
                           llvm_i64_ty, llvm_i32_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_df_si_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_double_ty], [llvm_i32_ty],
                          [IntrNoMem, Throws]>;
  
                                               
  
class Hexagon_df_di_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_double_ty], [llvm_i64_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_di_df_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_double_ty],
                          [IntrNoMem]>;
  
                                               
  
class Hexagon_df_df_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_double_ty], [llvm_double_ty],
                          [IntrNoMem]>;
  
                                                 
  
class Hexagon_df_dfdf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_double_ty], [llvm_double_ty, llvm_double_ty],
                          [IntrNoMem, Throws]>;
  
                                                 
  
class Hexagon_si_dfdf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_double_ty, llvm_double_ty],
                          [IntrNoMem, Throws]>;
  
                                                 
  
class Hexagon_si_dfsi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_double_ty, llvm_i32_ty],
                          [IntrNoMem, Throws]>;
  
  
                                                   
  
class Hexagon_df_dfdfdf_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_double_ty], [llvm_double_ty, llvm_double_ty,
                                             llvm_double_ty],
                          [IntrNoMem, Throws]>;
  
                                                   
  
class Hexagon_df_dfdfdfqi_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_double_ty], [llvm_double_ty, llvm_double_ty,
                                             llvm_double_ty,
                          llvm_i32_ty],
                          [IntrNoMem, Throws]>;


                                             
                                              
  
                                                         
  
def int_hexagon_circ_ldd :
Hexagon_mem_memmemsisi_Intrinsic<"circ_ldd">;
  
                                                         
  
def int_hexagon_circ_ldw :
Hexagon_mem_memmemsisi_Intrinsic<"circ_ldw">;
  
                                                         
  
def int_hexagon_circ_ldh :
Hexagon_mem_memmemsisi_Intrinsic<"circ_ldh">;
  
                                                          
  
def int_hexagon_circ_lduh :
Hexagon_mem_memmemsisi_Intrinsic<"circ_lduh">;
  
                                                         
  
def int_hexagon_circ_ldb :
Hexagon_mem_memmemsisi_Intrinsic<"circ_ldb">;
  
                                                          
  
def int_hexagon_circ_ldub :
Hexagon_mem_memmemsisi_Intrinsic<"circ_ldub">;

  
                                                        
  
def int_hexagon_circ_std :
Hexagon_mem_memdisisi_Intrinsic<"circ_std">;
  
                                                        
  
def int_hexagon_circ_stw :
Hexagon_mem_memsisisi_Intrinsic<"circ_stw">;
  
                                                        
  
def int_hexagon_circ_sth :
Hexagon_mem_memsisisi_Intrinsic<"circ_sth">;
  
                                                          
  
def int_hexagon_circ_sthhi :
Hexagon_mem_memsisisi_Intrinsic<"circ_sthhi">;
  
                                                        
  
def int_hexagon_circ_stb :
Hexagon_mem_memsisisi_Intrinsic<"circ_stb">;


def int_hexagon_mm256i_vaddw :
Hexagon_v256_v256v256_Intrinsic<"_mm256i_vaddw">;


                                             
                                              
  
                                                 
  
def int_hexagon_C2_cmpeq :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpeq">;
  
                                                 
  
def int_hexagon_C2_cmpgt :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpgt">;
  
                                                  
  
def int_hexagon_C2_cmpgtu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpgtu">;
  
                                                  
  
def int_hexagon_C2_cmpeqp :
Hexagon_si_didi_Intrinsic<"HEXAGON_C2_cmpeqp">;
  
                                                  
  
def int_hexagon_C2_cmpgtp :
Hexagon_si_didi_Intrinsic<"HEXAGON_C2_cmpgtp">;
  
                                                   
  
def int_hexagon_C2_cmpgtup :
Hexagon_si_didi_Intrinsic<"HEXAGON_C2_cmpgtup">;
  
                                                   
  
def int_hexagon_A4_rcmpeqi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_rcmpeqi">;
  
                                                    
  
def int_hexagon_A4_rcmpneqi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_rcmpneqi">;
  
                                                  
  
def int_hexagon_A4_rcmpeq :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_rcmpeq">;
  
                                                   
  
def int_hexagon_A4_rcmpneq :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_rcmpneq">;
  
                                                   
  
def int_hexagon_C2_bitsset :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_bitsset">;
  
                                                   
  
def int_hexagon_C2_bitsclr :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_bitsclr">;
  
                                                    
  
def int_hexagon_C4_nbitsset :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_nbitsset">;
  
                                                    
  
def int_hexagon_C4_nbitsclr :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_nbitsclr">;
  
                                                  
  
def int_hexagon_C2_cmpeqi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpeqi">;
  
                                                  
  
def int_hexagon_C2_cmpgti :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpgti">;
  
                                                   
  
def int_hexagon_C2_cmpgtui :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpgtui">;
  
                                                  
  
def int_hexagon_C2_cmpgei :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpgei">;
  
                                                   
  
def int_hexagon_C2_cmpgeui :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpgeui">;
  
                                                 
  
def int_hexagon_C2_cmplt :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmplt">;
  
                                                  
  
def int_hexagon_C2_cmpltu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_cmpltu">;
  
                                                    
  
def int_hexagon_C2_bitsclri :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_bitsclri">;
  
                                                     
  
def int_hexagon_C4_nbitsclri :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_nbitsclri">;
  
                                                   
  
def int_hexagon_C4_cmpneqi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_cmpneqi">;
  
                                                   
  
def int_hexagon_C4_cmpltei :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_cmpltei">;
  
                                                    
  
def int_hexagon_C4_cmplteui :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_cmplteui">;
  
                                                  
  
def int_hexagon_C4_cmpneq :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_cmpneq">;
  
                                                  
  
def int_hexagon_C4_cmplte :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_cmplte">;
  
                                                   
  
def int_hexagon_C4_cmplteu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C4_cmplteu">;
  
                                               
  
def int_hexagon_C2_and :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_and">;
  
                                              
  
def int_hexagon_C2_or :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_or">;
  
                                               
  
def int_hexagon_C2_xor :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_xor">;
  
                                                
  
def int_hexagon_C2_andn :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_andn">;
  
                                             
  
def int_hexagon_C2_not :
Hexagon_si_si_Intrinsic<"HEXAGON_C2_not">;
  
                                               
  
def int_hexagon_C2_orn :
Hexagon_si_sisi_Intrinsic<"HEXAGON_C2_orn">;
  
                                                     
  
def int_hexagon_C4_and_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_and_and">;
  
                                                    
  
def int_hexagon_C4_and_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_and_or">;
  
                                                    
  
def int_hexagon_C4_or_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_or_and">;
  
                                                   
  
def int_hexagon_C4_or_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_or_or">;
  
                                                      
  
def int_hexagon_C4_and_andn :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_and_andn">;
  
                                                     
  
def int_hexagon_C4_and_orn :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_and_orn">;
  
                                                     
  
def int_hexagon_C4_or_andn :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_or_andn">;
  
                                                    
  
def int_hexagon_C4_or_orn :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_C4_or_orn">;
  
                                                   
  
def int_hexagon_C2_pxfer_map :
Hexagon_si_qi_Intrinsic<"HEXAGON_C2_pxfer_map">;
  
                                              
  
def int_hexagon_C2_any8 :
Hexagon_si_qi_Intrinsic<"HEXAGON_C2_any8">;
  
                                              
  
def int_hexagon_C2_all8 :
Hexagon_si_qi_Intrinsic<"HEXAGON_C2_all8">;
  
                                                   
  
def int_hexagon_C2_vitpack :
Hexagon_si_qiqi_Intrinsic<"HEXAGON_C2_vitpack">;
  
                                                 
  
def int_hexagon_C2_mux :
Hexagon_si_qisisi_Intrinsic<"HEXAGON_C2_mux">;
  
                                                   
  
def int_hexagon_C2_muxii :
Hexagon_si_qisisi_Intrinsic<"HEXAGON_C2_muxii">;
  
                                                   
  
def int_hexagon_C2_muxir :
Hexagon_si_qisisi_Intrinsic<"HEXAGON_C2_muxir">;
  
                                                   
  
def int_hexagon_C2_muxri :
Hexagon_si_qisisi_Intrinsic<"HEXAGON_C2_muxri">;
  
                                                  
  
def int_hexagon_C2_vmux :
Hexagon_di_qididi_Intrinsic<"HEXAGON_C2_vmux">;
  
                                              
  
def int_hexagon_C2_mask :
Hexagon_di_qi_Intrinsic<"HEXAGON_C2_mask">;
  
                                                   
  
def int_hexagon_A2_vcmpbeq :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmpbeq">;
  
                                                    
  
def int_hexagon_A4_vcmpbeqi :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmpbeqi">;
  
                                                       
  
def int_hexagon_A4_vcmpbeq_any :
Hexagon_si_didi_Intrinsic<"HEXAGON_A4_vcmpbeq_any">;
  
                                                    
  
def int_hexagon_A2_vcmpbgtu :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmpbgtu">;
  
                                                     
  
def int_hexagon_A4_vcmpbgtui :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmpbgtui">;
  
                                                   
  
def int_hexagon_A4_vcmpbgt :
Hexagon_si_didi_Intrinsic<"HEXAGON_A4_vcmpbgt">;
  
                                                    
  
def int_hexagon_A4_vcmpbgti :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmpbgti">;
  
                                                  
  
def int_hexagon_A4_cmpbeq :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpbeq">;
  
                                                   
  
def int_hexagon_A4_cmpbeqi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpbeqi">;
  
                                                   
  
def int_hexagon_A4_cmpbgtu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpbgtu">;
  
                                                    
  
def int_hexagon_A4_cmpbgtui :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpbgtui">;
  
                                                  
  
def int_hexagon_A4_cmpbgt :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpbgt">;
  
                                                   
  
def int_hexagon_A4_cmpbgti :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpbgti">;
  
                                                   
  
def int_hexagon_A2_vcmpheq :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmpheq">;
  
                                                   
  
def int_hexagon_A2_vcmphgt :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmphgt">;
  
                                                    
  
def int_hexagon_A2_vcmphgtu :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmphgtu">;
  
                                                    
  
def int_hexagon_A4_vcmpheqi :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmpheqi">;
  
                                                    
  
def int_hexagon_A4_vcmphgti :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmphgti">;
  
                                                     
  
def int_hexagon_A4_vcmphgtui :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmphgtui">;
  
                                                  
  
def int_hexagon_A4_cmpheq :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpheq">;
  
                                                  
  
def int_hexagon_A4_cmphgt :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmphgt">;
  
                                                   
  
def int_hexagon_A4_cmphgtu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmphgtu">;
  
                                                   
  
def int_hexagon_A4_cmpheqi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmpheqi">;
  
                                                   
  
def int_hexagon_A4_cmphgti :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmphgti">;
  
                                                    
  
def int_hexagon_A4_cmphgtui :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cmphgtui">;
  
                                                   
  
def int_hexagon_A2_vcmpweq :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmpweq">;
  
                                                   
  
def int_hexagon_A2_vcmpwgt :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmpwgt">;
  
                                                    
  
def int_hexagon_A2_vcmpwgtu :
Hexagon_si_didi_Intrinsic<"HEXAGON_A2_vcmpwgtu">;
  
                                                    
  
def int_hexagon_A4_vcmpweqi :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmpweqi">;
  
                                                    
  
def int_hexagon_A4_vcmpwgti :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmpwgti">;
  
                                                     
  
def int_hexagon_A4_vcmpwgtui :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_vcmpwgtui">;
  
                                                       
  
def int_hexagon_A4_boundscheck :
Hexagon_si_sidi_Intrinsic<"HEXAGON_A4_boundscheck">;
  
                                                    
  
def int_hexagon_A4_tlbmatch :
Hexagon_si_disi_Intrinsic<"HEXAGON_A4_tlbmatch">;
  
                                               
  
def int_hexagon_C2_tfrpr :
Hexagon_si_qi_Intrinsic<"HEXAGON_C2_tfrpr">;
  
                                               
  
def int_hexagon_C2_tfrrp :
Hexagon_si_si_Intrinsic<"HEXAGON_C2_tfrrp">;
  
                                                       
  
def int_hexagon_C4_fastcorner9 :
Hexagon_si_qiqi_Intrinsic<"HEXAGON_C4_fastcorner9">;
  
                                                           
  
def int_hexagon_C4_fastcorner9_not :
Hexagon_si_qiqi_Intrinsic<"HEXAGON_C4_fastcorner9_not">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_hh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_hh_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_hh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_hh_s1">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_hl_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_hl_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_hl_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_hl_s1">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_lh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_lh_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_lh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_lh_s1">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_ll_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_ll_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_acc_ll_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_ll_s1">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_hh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_hh_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_hh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_hh_s1">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_hl_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_hl_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_hl_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_hl_s1">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_lh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_lh_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_lh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_lh_s1">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_ll_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_ll_s0">;
  
                                                           
  
def int_hexagon_M2_mpy_nac_ll_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_ll_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_hh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_hh_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_hh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_hh_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_hl_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_hl_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_hl_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_hl_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_lh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_lh_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_lh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_lh_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_ll_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_ll_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_acc_sat_ll_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_acc_sat_ll_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_hh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_hh_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_hh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_hh_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_hl_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_hl_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_hl_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_hl_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_lh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_lh_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_lh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_lh_s1">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_ll_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_ll_s0">;
  
                                                               
  
def int_hexagon_M2_mpy_nac_sat_ll_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpy_nac_sat_ll_s1">;
  
                                                     
  
def int_hexagon_M2_mpy_hh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_hh_s0">;
  
                                                     
  
def int_hexagon_M2_mpy_hh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_hh_s1">;
  
                                                     
  
def int_hexagon_M2_mpy_hl_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_hl_s0">;
  
                                                     
  
def int_hexagon_M2_mpy_hl_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_hl_s1">;
  
                                                     
  
def int_hexagon_M2_mpy_lh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_lh_s0">;
  
                                                     
  
def int_hexagon_M2_mpy_lh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_lh_s1">;
  
                                                     
  
def int_hexagon_M2_mpy_ll_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_ll_s0">;
  
                                                     
  
def int_hexagon_M2_mpy_ll_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_ll_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_hh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_hh_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_hh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_hh_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_hl_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_hl_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_hl_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_hl_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_lh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_lh_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_lh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_lh_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_ll_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_ll_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_sat_ll_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_ll_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_hh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_hh_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_hh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_hh_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_hl_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_hl_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_hl_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_hl_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_lh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_lh_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_lh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_lh_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_ll_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_ll_s0">;
  
                                                         
  
def int_hexagon_M2_mpy_rnd_ll_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_rnd_ll_s1">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_hh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_hh_s0">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_hh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_hh_s1">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_hl_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_hl_s0">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_hl_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_hl_s1">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_lh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_lh_s0">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_lh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_lh_s1">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_ll_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_ll_s0">;
  
                                                             
  
def int_hexagon_M2_mpy_sat_rnd_ll_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_sat_rnd_ll_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_hh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_hh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_hh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_hh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_hl_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_hl_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_hl_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_hl_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_lh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_lh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_lh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_lh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_ll_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_ll_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_acc_ll_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_acc_ll_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_hh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_hh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_hh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_hh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_hl_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_hl_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_hl_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_hl_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_lh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_lh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_lh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_lh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_ll_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_ll_s0">;
  
                                                            
  
def int_hexagon_M2_mpyd_nac_ll_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyd_nac_ll_s1">;
  
                                                      
  
def int_hexagon_M2_mpyd_hh_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_hh_s0">;
  
                                                      
  
def int_hexagon_M2_mpyd_hh_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_hh_s1">;
  
                                                      
  
def int_hexagon_M2_mpyd_hl_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_hl_s0">;
  
                                                      
  
def int_hexagon_M2_mpyd_hl_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_hl_s1">;
  
                                                      
  
def int_hexagon_M2_mpyd_lh_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_lh_s0">;
  
                                                      
  
def int_hexagon_M2_mpyd_lh_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_lh_s1">;
  
                                                      
  
def int_hexagon_M2_mpyd_ll_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_ll_s0">;
  
                                                      
  
def int_hexagon_M2_mpyd_ll_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_ll_s1">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_hh_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_hh_s0">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_hh_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_hh_s1">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_hl_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_hl_s0">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_hl_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_hl_s1">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_lh_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_lh_s0">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_lh_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_lh_s1">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_ll_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_ll_s0">;
  
                                                          
  
def int_hexagon_M2_mpyd_rnd_ll_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyd_rnd_ll_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_hh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_hh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_hh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_hh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_hl_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_hl_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_hl_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_hl_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_lh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_lh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_lh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_lh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_ll_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_ll_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_acc_ll_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_acc_ll_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_hh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_hh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_hh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_hh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_hl_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_hl_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_hl_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_hl_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_lh_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_lh_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_lh_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_lh_s1">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_ll_s0 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_ll_s0">;
  
                                                            
  
def int_hexagon_M2_mpyu_nac_ll_s1 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_mpyu_nac_ll_s1">;
  
                                                       
  
def int_hexagon_M2_mpyu_hh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_hh_s0">;
  
                                                       
  
def int_hexagon_M2_mpyu_hh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_hh_s1">;
  
                                                       
  
def int_hexagon_M2_mpyu_hl_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_hl_s0">;
  
                                                       
  
def int_hexagon_M2_mpyu_hl_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_hl_s1">;
  
                                                       
  
def int_hexagon_M2_mpyu_lh_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_lh_s0">;
  
                                                       
  
def int_hexagon_M2_mpyu_lh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_lh_s1">;
  
                                                       
  
def int_hexagon_M2_mpyu_ll_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_ll_s0">;
  
                                                       
  
def int_hexagon_M2_mpyu_ll_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_ll_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_hh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_hh_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_hh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_hh_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_hl_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_hl_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_hl_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_hl_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_lh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_lh_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_lh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_lh_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_ll_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_ll_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_acc_ll_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_acc_ll_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_hh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_hh_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_hh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_hh_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_hl_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_hl_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_hl_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_hl_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_lh_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_lh_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_lh_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_lh_s1">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_ll_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_ll_s0">;
  
                                                             
  
def int_hexagon_M2_mpyud_nac_ll_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_mpyud_nac_ll_s1">;
  
                                                        
  
def int_hexagon_M2_mpyud_hh_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_hh_s0">;
  
                                                        
  
def int_hexagon_M2_mpyud_hh_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_hh_s1">;
  
                                                        
  
def int_hexagon_M2_mpyud_hl_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_hl_s0">;
  
                                                        
  
def int_hexagon_M2_mpyud_hl_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_hl_s1">;
  
                                                        
  
def int_hexagon_M2_mpyud_lh_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_lh_s0">;
  
                                                        
  
def int_hexagon_M2_mpyud_lh_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_lh_s1">;
  
                                                        
  
def int_hexagon_M2_mpyud_ll_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_ll_s0">;
  
                                                        
  
def int_hexagon_M2_mpyud_ll_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_mpyud_ll_s1">;
  
                                                  
  
def int_hexagon_M2_mpysmi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpysmi">;
  
                                                    
  
def int_hexagon_M2_macsip :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_macsip">;
  
                                                    
  
def int_hexagon_M2_macsin :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_macsin">;
  
                                                      
  
def int_hexagon_M2_dpmpyss_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_dpmpyss_s0">;
  
                                                            
  
def int_hexagon_M2_dpmpyss_acc_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_dpmpyss_acc_s0">;
  
                                                            
  
def int_hexagon_M2_dpmpyss_nac_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_dpmpyss_nac_s0">;
  
                                                       
  
def int_hexagon_M2_dpmpyuu_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_dpmpyuu_s0">;
  
                                                            
  
def int_hexagon_M2_dpmpyuu_acc_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_dpmpyuu_acc_s0">;
  
                                                            
  
def int_hexagon_M2_dpmpyuu_nac_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_dpmpyuu_nac_s0">;
  
                                                  
  
def int_hexagon_M2_mpy_up :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_up">;
  
                                                     
  
def int_hexagon_M2_mpy_up_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_up_s1">;
  
                                                         
  
def int_hexagon_M2_mpy_up_s1_sat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpy_up_s1_sat">;
  
                                                    
  
def int_hexagon_M2_mpyu_up :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyu_up">;
  
                                                    
  
def int_hexagon_M2_mpysu_up :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpysu_up">;
  
                                                          
  
def int_hexagon_M2_dpmpyss_rnd_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_dpmpyss_rnd_s0">;
  
                                                           
  
def int_hexagon_M4_mac_up_s1_sat :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_mac_up_s1_sat">;
  
                                                           
  
def int_hexagon_M4_nac_up_s1_sat :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_nac_up_s1_sat">;
  
                                                
  
def int_hexagon_M2_mpyi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyi">;
  
                                                 
  
def int_hexagon_M2_mpyui :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_mpyui">;
  
                                                  
  
def int_hexagon_M2_maci :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_maci">;
  
                                                  
  
def int_hexagon_M2_acci :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_acci">;
  
                                                   
  
def int_hexagon_M2_accii :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_accii">;
  
                                                   
  
def int_hexagon_M2_nacci :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_nacci">;
  
                                                    
  
def int_hexagon_M2_naccii :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_naccii">;
  
                                                    
  
def int_hexagon_M2_subacc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_subacc">;
  
                                                        
  
def int_hexagon_M4_mpyrr_addr :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_mpyrr_addr">;
  
                                                           
  
def int_hexagon_M4_mpyri_addr_u2 :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_mpyri_addr_u2">;
  
                                                        
  
def int_hexagon_M4_mpyri_addr :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_mpyri_addr">;
  
                                                        
  
def int_hexagon_M4_mpyri_addi :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_mpyri_addi">;
  
                                                        
  
def int_hexagon_M4_mpyrr_addi :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_mpyrr_addi">;
  
                                                     
  
def int_hexagon_M2_vmpy2s_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_vmpy2s_s0">;
  
                                                     
  
def int_hexagon_M2_vmpy2s_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_vmpy2s_s1">;
  
                                                       
  
def int_hexagon_M2_vmac2s_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_vmac2s_s0">;
  
                                                       
  
def int_hexagon_M2_vmac2s_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_vmac2s_s1">;
  
                                                      
  
def int_hexagon_M2_vmpy2su_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_vmpy2su_s0">;
  
                                                      
  
def int_hexagon_M2_vmpy2su_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_vmpy2su_s1">;
  
                                                        
  
def int_hexagon_M2_vmac2su_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_vmac2su_s0">;
  
                                                        
  
def int_hexagon_M2_vmac2su_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_vmac2su_s1">;
  
                                                         
  
def int_hexagon_M2_vmpy2s_s0pack :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_vmpy2s_s0pack">;
  
                                                         
  
def int_hexagon_M2_vmpy2s_s1pack :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_vmpy2s_s1pack">;
  
                                                   
  
def int_hexagon_M2_vmac2 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_vmac2">;
  
                                                      
  
def int_hexagon_M2_vmpy2es_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vmpy2es_s0">;
  
                                                      
  
def int_hexagon_M2_vmpy2es_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vmpy2es_s1">;
  
                                                        
  
def int_hexagon_M2_vmac2es_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vmac2es_s0">;
  
                                                        
  
def int_hexagon_M2_vmac2es_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vmac2es_s1">;
  
                                                     
  
def int_hexagon_M2_vmac2es :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vmac2es">;
  
                                                      
  
def int_hexagon_M2_vrmac_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vrmac_s0">;
  
                                                    
  
def int_hexagon_M2_vrmpy_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vrmpy_s0">;
  
                                                      
  
def int_hexagon_M2_vdmpyrs_s0 :
Hexagon_si_didi_Intrinsic<"HEXAGON_M2_vdmpyrs_s0">;
  
                                                      
  
def int_hexagon_M2_vdmpyrs_s1 :
Hexagon_si_didi_Intrinsic<"HEXAGON_M2_vdmpyrs_s1">;
  
                                                    
  
def int_hexagon_M5_vrmpybuu :
Hexagon_di_didi_Intrinsic<"HEXAGON_M5_vrmpybuu">;
  
                                                      
  
def int_hexagon_M5_vrmacbuu :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M5_vrmacbuu">;
  
                                                    
  
def int_hexagon_M5_vrmpybsu :
Hexagon_di_didi_Intrinsic<"HEXAGON_M5_vrmpybsu">;
  
                                                      
  
def int_hexagon_M5_vrmacbsu :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M5_vrmacbsu">;
  
                                                   
  
def int_hexagon_M5_vmpybuu :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M5_vmpybuu">;
  
                                                   
  
def int_hexagon_M5_vmpybsu :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M5_vmpybsu">;
  
                                                     
  
def int_hexagon_M5_vmacbuu :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M5_vmacbuu">;
  
                                                     
  
def int_hexagon_M5_vmacbsu :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M5_vmacbsu">;
  
                                                    
  
def int_hexagon_M5_vdmpybsu :
Hexagon_di_didi_Intrinsic<"HEXAGON_M5_vdmpybsu">;
  
                                                      
  
def int_hexagon_M5_vdmacbsu :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M5_vdmacbsu">;
  
                                                       
  
def int_hexagon_M2_vdmacs_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vdmacs_s0">;
  
                                                       
  
def int_hexagon_M2_vdmacs_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vdmacs_s1">;
  
                                                     
  
def int_hexagon_M2_vdmpys_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vdmpys_s0">;
  
                                                     
  
def int_hexagon_M2_vdmpys_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vdmpys_s1">;
  
                                                     
  
def int_hexagon_M2_cmpyrs_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_cmpyrs_s0">;
  
                                                     
  
def int_hexagon_M2_cmpyrs_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_cmpyrs_s1">;
  
                                                      
  
def int_hexagon_M2_cmpyrsc_s0 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_cmpyrsc_s0">;
  
                                                      
  
def int_hexagon_M2_cmpyrsc_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_cmpyrsc_s1">;
  
                                                      
  
def int_hexagon_M2_cmacs_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cmacs_s0">;
  
                                                      
  
def int_hexagon_M2_cmacs_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cmacs_s1">;
  
                                                       
  
def int_hexagon_M2_cmacsc_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cmacsc_s0">;
  
                                                       
  
def int_hexagon_M2_cmacsc_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cmacsc_s1">;
  
                                                    
  
def int_hexagon_M2_cmpys_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_cmpys_s0">;
  
                                                    
  
def int_hexagon_M2_cmpys_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_cmpys_s1">;
  
                                                     
  
def int_hexagon_M2_cmpysc_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_cmpysc_s0">;
  
                                                     
  
def int_hexagon_M2_cmpysc_s1 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_cmpysc_s1">;
  
                                                      
  
def int_hexagon_M2_cnacs_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cnacs_s0">;
  
                                                      
  
def int_hexagon_M2_cnacs_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cnacs_s1">;
  
                                                       
  
def int_hexagon_M2_cnacsc_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cnacsc_s0">;
  
                                                       
  
def int_hexagon_M2_cnacsc_s1 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cnacsc_s1">;
  
                                                      
  
def int_hexagon_M2_vrcmpys_s1 :
Hexagon_di_disi_Intrinsic<"HEXAGON_M2_vrcmpys_s1">;
  
                                                            
  
def int_hexagon_M2_vrcmpys_acc_s1 :
Hexagon_di_didisi_Intrinsic<"HEXAGON_M2_vrcmpys_acc_s1">;
  
                                                        
  
def int_hexagon_M2_vrcmpys_s1rp :
Hexagon_si_disi_Intrinsic<"HEXAGON_M2_vrcmpys_s1rp">;
  
                                                       
  
def int_hexagon_M2_mmacls_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacls_s0">;
  
                                                       
  
def int_hexagon_M2_mmacls_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacls_s1">;
  
                                                       
  
def int_hexagon_M2_mmachs_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmachs_s0">;
  
                                                       
  
def int_hexagon_M2_mmachs_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmachs_s1">;
  
                                                    
  
def int_hexagon_M2_mmpyl_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyl_s0">;
  
                                                    
  
def int_hexagon_M2_mmpyl_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyl_s1">;
  
                                                    
  
def int_hexagon_M2_mmpyh_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyh_s0">;
  
                                                    
  
def int_hexagon_M2_mmpyh_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyh_s1">;
  
                                                        
  
def int_hexagon_M2_mmacls_rs0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacls_rs0">;
  
                                                        
  
def int_hexagon_M2_mmacls_rs1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacls_rs1">;
  
                                                        
  
def int_hexagon_M2_mmachs_rs0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmachs_rs0">;
  
                                                        
  
def int_hexagon_M2_mmachs_rs1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmachs_rs1">;
  
                                                     
  
def int_hexagon_M2_mmpyl_rs0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyl_rs0">;
  
                                                     
  
def int_hexagon_M2_mmpyl_rs1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyl_rs1">;
  
                                                     
  
def int_hexagon_M2_mmpyh_rs0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyh_rs0">;
  
                                                     
  
def int_hexagon_M2_mmpyh_rs1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyh_rs1">;
  
                                                      
  
def int_hexagon_M4_vrmpyeh_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M4_vrmpyeh_s0">;
  
                                                      
  
def int_hexagon_M4_vrmpyeh_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M4_vrmpyeh_s1">;
  
                                                            
  
def int_hexagon_M4_vrmpyeh_acc_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M4_vrmpyeh_acc_s0">;
  
                                                            
  
def int_hexagon_M4_vrmpyeh_acc_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M4_vrmpyeh_acc_s1">;
  
                                                      
  
def int_hexagon_M4_vrmpyoh_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M4_vrmpyoh_s0">;
  
                                                      
  
def int_hexagon_M4_vrmpyoh_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M4_vrmpyoh_s1">;
  
                                                            
  
def int_hexagon_M4_vrmpyoh_acc_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M4_vrmpyoh_acc_s0">;
  
                                                            
  
def int_hexagon_M4_vrmpyoh_acc_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M4_vrmpyoh_acc_s1">;
  
                                                      
  
def int_hexagon_M2_hmmpyl_rs1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_hmmpyl_rs1">;
  
                                                      
  
def int_hexagon_M2_hmmpyh_rs1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_hmmpyh_rs1">;
  
                                                     
  
def int_hexagon_M2_hmmpyl_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_hmmpyl_s1">;
  
                                                     
  
def int_hexagon_M2_hmmpyh_s1 :
Hexagon_si_sisi_Intrinsic<"HEXAGON_M2_hmmpyh_s1">;
  
                                                        
  
def int_hexagon_M2_mmaculs_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmaculs_s0">;
  
                                                        
  
def int_hexagon_M2_mmaculs_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmaculs_s1">;
  
                                                        
  
def int_hexagon_M2_mmacuhs_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacuhs_s0">;
  
                                                        
  
def int_hexagon_M2_mmacuhs_s1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacuhs_s1">;
  
                                                     
  
def int_hexagon_M2_mmpyul_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyul_s0">;
  
                                                     
  
def int_hexagon_M2_mmpyul_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyul_s1">;
  
                                                     
  
def int_hexagon_M2_mmpyuh_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyuh_s0">;
  
                                                     
  
def int_hexagon_M2_mmpyuh_s1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyuh_s1">;
  
                                                         
  
def int_hexagon_M2_mmaculs_rs0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmaculs_rs0">;
  
                                                         
  
def int_hexagon_M2_mmaculs_rs1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmaculs_rs1">;
  
                                                         
  
def int_hexagon_M2_mmacuhs_rs0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacuhs_rs0">;
  
                                                         
  
def int_hexagon_M2_mmacuhs_rs1 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_mmacuhs_rs1">;
  
                                                      
  
def int_hexagon_M2_mmpyul_rs0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyul_rs0">;
  
                                                      
  
def int_hexagon_M2_mmpyul_rs1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyul_rs1">;
  
                                                      
  
def int_hexagon_M2_mmpyuh_rs0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyuh_rs0">;
  
                                                      
  
def int_hexagon_M2_mmpyuh_rs1 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_mmpyuh_rs1">;
  
                                                        
  
def int_hexagon_M2_vrcmaci_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vrcmaci_s0">;
  
                                                        
  
def int_hexagon_M2_vrcmacr_s0 :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vrcmacr_s0">;
  
                                                         
  
def int_hexagon_M2_vrcmaci_s0c :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vrcmaci_s0c">;
  
                                                         
  
def int_hexagon_M2_vrcmacr_s0c :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vrcmacr_s0c">;
  
                                                      
  
def int_hexagon_M2_cmaci_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cmaci_s0">;
  
                                                      
  
def int_hexagon_M2_cmacr_s0 :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M2_cmacr_s0">;
  
                                                      
  
def int_hexagon_M2_vrcmpyi_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vrcmpyi_s0">;
  
                                                      
  
def int_hexagon_M2_vrcmpyr_s0 :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vrcmpyr_s0">;
  
                                                       
  
def int_hexagon_M2_vrcmpyi_s0c :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vrcmpyi_s0c">;
  
                                                       
  
def int_hexagon_M2_vrcmpyr_s0c :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vrcmpyr_s0c">;
  
                                                    
  
def int_hexagon_M2_cmpyi_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_cmpyi_s0">;
  
                                                    
  
def int_hexagon_M2_cmpyr_s0 :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M2_cmpyr_s0">;
  
                                                    
  
def int_hexagon_M4_cmpyi_wh :
Hexagon_si_disi_Intrinsic<"HEXAGON_M4_cmpyi_wh">;
  
                                                    
  
def int_hexagon_M4_cmpyr_wh :
Hexagon_si_disi_Intrinsic<"HEXAGON_M4_cmpyr_wh">;
  
                                                     
  
def int_hexagon_M4_cmpyi_whc :
Hexagon_si_disi_Intrinsic<"HEXAGON_M4_cmpyi_whc">;
  
                                                     
  
def int_hexagon_M4_cmpyr_whc :
Hexagon_si_disi_Intrinsic<"HEXAGON_M4_cmpyr_whc">;
  
                                                          
  
def int_hexagon_M2_vcmpy_s0_sat_i :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vcmpy_s0_sat_i">;
  
                                                          
  
def int_hexagon_M2_vcmpy_s0_sat_r :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vcmpy_s0_sat_r">;
  
                                                          
  
def int_hexagon_M2_vcmpy_s1_sat_i :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vcmpy_s1_sat_i">;
  
                                                          
  
def int_hexagon_M2_vcmpy_s1_sat_r :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vcmpy_s1_sat_r">;
  
                                                            
  
def int_hexagon_M2_vcmac_s0_sat_i :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vcmac_s0_sat_i">;
  
                                                            
  
def int_hexagon_M2_vcmac_s0_sat_r :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M2_vcmac_s0_sat_r">;
  
                                                    
  
def int_hexagon_S2_vcrotate :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_vcrotate">;
  
                                                             
  
def int_hexagon_S4_vrcrotate_acc :
Hexagon_di_didisisi_Intrinsic<"HEXAGON_S4_vrcrotate_acc">;
  
                                                       
  
def int_hexagon_S4_vrcrotate :
Hexagon_di_disisi_Intrinsic<"HEXAGON_S4_vrcrotate">;
  
                                                  
  
def int_hexagon_S2_vcnegh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_vcnegh">;
  
                                                     
  
def int_hexagon_S2_vrcnegh :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_vrcnegh">;
  
                                                 
  
def int_hexagon_M4_pmpyw :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M4_pmpyw">;
  
                                                  
  
def int_hexagon_M4_vpmpyh :
Hexagon_di_sisi_Intrinsic<"HEXAGON_M4_vpmpyh">;
  
                                                       
  
def int_hexagon_M4_pmpyw_acc :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M4_pmpyw_acc">;
  
                                                        
  
def int_hexagon_M4_vpmpyh_acc :
Hexagon_di_disisi_Intrinsic<"HEXAGON_M4_vpmpyh_acc">;
  
                                               
  
def int_hexagon_A2_add :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_add">;
  
                                               
  
def int_hexagon_A2_sub :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_sub">;
  
                                                  
  
def int_hexagon_A2_addsat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addsat">;
  
                                                  
  
def int_hexagon_A2_subsat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subsat">;
  
                                                
  
def int_hexagon_A2_addi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addi">;
  
                                                       
  
def int_hexagon_A2_addh_l16_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_l16_ll">;
  
                                                       
  
def int_hexagon_A2_addh_l16_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_l16_hl">;
  
                                                           
  
def int_hexagon_A2_addh_l16_sat_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_l16_sat_ll">;
  
                                                           
  
def int_hexagon_A2_addh_l16_sat_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_l16_sat_hl">;
  
                                                       
  
def int_hexagon_A2_subh_l16_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_l16_ll">;
  
                                                       
  
def int_hexagon_A2_subh_l16_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_l16_hl">;
  
                                                           
  
def int_hexagon_A2_subh_l16_sat_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_l16_sat_ll">;
  
                                                           
  
def int_hexagon_A2_subh_l16_sat_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_l16_sat_hl">;
  
                                                       
  
def int_hexagon_A2_addh_h16_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_ll">;
  
                                                       
  
def int_hexagon_A2_addh_h16_lh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_lh">;
  
                                                       
  
def int_hexagon_A2_addh_h16_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_hl">;
  
                                                       
  
def int_hexagon_A2_addh_h16_hh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_hh">;
  
                                                           
  
def int_hexagon_A2_addh_h16_sat_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_sat_ll">;
  
                                                           
  
def int_hexagon_A2_addh_h16_sat_lh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_sat_lh">;
  
                                                           
  
def int_hexagon_A2_addh_h16_sat_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_sat_hl">;
  
                                                           
  
def int_hexagon_A2_addh_h16_sat_hh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_addh_h16_sat_hh">;
  
                                                       
  
def int_hexagon_A2_subh_h16_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_ll">;
  
                                                       
  
def int_hexagon_A2_subh_h16_lh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_lh">;
  
                                                       
  
def int_hexagon_A2_subh_h16_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_hl">;
  
                                                       
  
def int_hexagon_A2_subh_h16_hh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_hh">;
  
                                                           
  
def int_hexagon_A2_subh_h16_sat_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_sat_ll">;
  
                                                           
  
def int_hexagon_A2_subh_h16_sat_lh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_sat_lh">;
  
                                                           
  
def int_hexagon_A2_subh_h16_sat_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_sat_hl">;
  
                                                           
  
def int_hexagon_A2_subh_h16_sat_hh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subh_h16_sat_hh">;
  
                                              
  
def int_hexagon_A2_aslh :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_aslh">;
  
                                              
  
def int_hexagon_A2_asrh :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_asrh">;
  
                                                
  
def int_hexagon_A2_addp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_addp">;
  
                                                   
  
def int_hexagon_A2_addpsat :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_addpsat">;
  
                                                 
  
def int_hexagon_A2_addsp :
Hexagon_di_sidi_Intrinsic<"HEXAGON_A2_addsp">;
  
                                                
  
def int_hexagon_A2_subp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_subp">;
  
                                             
  
def int_hexagon_A2_neg :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_neg">;
  
                                                
  
def int_hexagon_A2_negsat :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_negsat">;
  
                                             
  
def int_hexagon_A2_abs :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_abs">;
  
                                                
  
def int_hexagon_A2_abssat :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_abssat">;
  
                                               
  
def int_hexagon_A2_vconj :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_vconj">;
  
                                              
  
def int_hexagon_A2_negp :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_negp">;
  
                                              
  
def int_hexagon_A2_absp :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_absp">;
  
                                               
  
def int_hexagon_A2_max :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_max">;
  
                                                 
  
def int_hexagon_A2_maxu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_maxu">;
  
                                               
  
def int_hexagon_A2_min :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_min">;
  
                                                 
  
def int_hexagon_A2_minu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_minu">;
  
                                                
  
def int_hexagon_A2_maxp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_maxp">;
  
                                                  
  
def int_hexagon_A2_maxup :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_maxup">;
  
                                                
  
def int_hexagon_A2_minp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_minp">;
  
                                                  
  
def int_hexagon_A2_minup :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_minup">;
  
                                             
  
def int_hexagon_A2_tfr :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_tfr">;
  
                                               
  
def int_hexagon_A2_tfrsi :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_tfrsi">;
  
                                              
  
def int_hexagon_A2_tfrp :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_tfrp">;
  
                                               
  
def int_hexagon_A2_tfrpi :
Hexagon_di_si_Intrinsic<"HEXAGON_A2_tfrpi">;
  
                                              
  
def int_hexagon_A2_zxtb :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_zxtb">;
  
                                              
  
def int_hexagon_A2_sxtb :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_sxtb">;
  
                                              
  
def int_hexagon_A2_zxth :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_zxth">;
  
                                              
  
def int_hexagon_A2_sxth :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_sxth">;
  
                                                    
  
def int_hexagon_A2_combinew :
Hexagon_di_sisi_Intrinsic<"HEXAGON_A2_combinew">;
  
                                                     
  
def int_hexagon_A4_combineri :
Hexagon_di_sisi_Intrinsic<"HEXAGON_A4_combineri">;
  
                                                     
  
def int_hexagon_A4_combineir :
Hexagon_di_sisi_Intrinsic<"HEXAGON_A4_combineir">;
  
                                                     
  
def int_hexagon_A2_combineii :
Hexagon_di_sisi_Intrinsic<"HEXAGON_A2_combineii">;
  
                                                      
  
def int_hexagon_A2_combine_hh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_combine_hh">;
  
                                                      
  
def int_hexagon_A2_combine_hl :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_combine_hl">;
  
                                                      
  
def int_hexagon_A2_combine_lh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_combine_lh">;
  
                                                      
  
def int_hexagon_A2_combine_ll :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_combine_ll">;
  
                                                 
  
def int_hexagon_A2_tfril :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_tfril">;
  
                                                 
  
def int_hexagon_A2_tfrih :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_tfrih">;
  
                                               
  
def int_hexagon_A2_and :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_and">;
  
                                              
  
def int_hexagon_A2_or :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_or">;
  
                                               
  
def int_hexagon_A2_xor :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_xor">;
  
                                             
  
def int_hexagon_A2_not :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_not">;
  
                                                      
  
def int_hexagon_M2_xor_xacc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M2_xor_xacc">;
  
                                                      
  
def int_hexagon_M4_xor_xacc :
Hexagon_di_dididi_Intrinsic<"HEXAGON_M4_xor_xacc">;
  
                                                
  
def int_hexagon_A4_andn :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_andn">;
  
                                               
  
def int_hexagon_A4_orn :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_orn">;
  
                                                 
  
def int_hexagon_A4_andnp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A4_andnp">;
  
                                                
  
def int_hexagon_A4_ornp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A4_ornp">;
  
                                                     
  
def int_hexagon_S4_addaddi :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_addaddi">;
  
                                                     
  
def int_hexagon_S4_subaddi :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_subaddi">;
  
                                                     
  
def int_hexagon_M4_and_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_and_and">;
  
                                                      
  
def int_hexagon_M4_and_andn :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_and_andn">;
  
                                                    
  
def int_hexagon_M4_and_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_and_or">;
  
                                                     
  
def int_hexagon_M4_and_xor :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_and_xor">;
  
                                                    
  
def int_hexagon_M4_or_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_or_and">;
  
                                                     
  
def int_hexagon_M4_or_andn :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_or_andn">;
  
                                                   
  
def int_hexagon_M4_or_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_or_or">;
  
                                                    
  
def int_hexagon_M4_or_xor :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_or_xor">;
  
                                                      
  
def int_hexagon_S4_or_andix :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_or_andix">;
  
                                                     
  
def int_hexagon_S4_or_andi :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_or_andi">;
  
                                                    
  
def int_hexagon_S4_or_ori :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_or_ori">;
  
                                                     
  
def int_hexagon_M4_xor_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_xor_and">;
  
                                                    
  
def int_hexagon_M4_xor_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_xor_or">;
  
                                                      
  
def int_hexagon_M4_xor_andn :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_M4_xor_andn">;
  
                                                 
  
def int_hexagon_A2_subri :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_subri">;
  
                                                 
  
def int_hexagon_A2_andir :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_andir">;
  
                                                
  
def int_hexagon_A2_orir :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_orir">;
  
                                                
  
def int_hexagon_A2_andp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_andp">;
  
                                               
  
def int_hexagon_A2_orp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_orp">;
  
                                                
  
def int_hexagon_A2_xorp :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_xorp">;
  
                                              
  
def int_hexagon_A2_notp :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_notp">;
  
                                              
  
def int_hexagon_A2_sxtw :
Hexagon_di_si_Intrinsic<"HEXAGON_A2_sxtw">;
  
                                             
  
def int_hexagon_A2_sat :
Hexagon_si_di_Intrinsic<"HEXAGON_A2_sat">;
  
                                                  
  
def int_hexagon_A2_roundsat :
Hexagon_si_di_Intrinsic<"HEXAGON_A2_roundsat">;
  
                                              
  
def int_hexagon_A2_sath :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_sath">;
  
                                               
  
def int_hexagon_A2_satuh :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_satuh">;
  
                                               
  
def int_hexagon_A2_satub :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_satub">;
  
                                              
  
def int_hexagon_A2_satb :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_satb">;
  
                                                  
  
def int_hexagon_A2_vaddub :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vaddub">;
  
                                                     
  
def int_hexagon_A2_vaddb_map :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vaddb_map">;
  
                                                   
  
def int_hexagon_A2_vaddubs :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vaddubs">;
  
                                                 
  
def int_hexagon_A2_vaddh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vaddh">;
  
                                                  
  
def int_hexagon_A2_vaddhs :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vaddhs">;
  
                                                   
  
def int_hexagon_A2_vadduhs :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vadduhs">;
  
                                                    
  
def int_hexagon_A5_vaddhubs :
Hexagon_si_didi_Intrinsic<"HEXAGON_A5_vaddhubs">;
  
                                                 
  
def int_hexagon_A2_vaddw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vaddw">;
  
                                                  
  
def int_hexagon_A2_vaddws :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vaddws">;
  
                                                     
  
def int_hexagon_S4_vxaddsubw :
Hexagon_di_didi_Intrinsic<"HEXAGON_S4_vxaddsubw">;
  
                                                     
  
def int_hexagon_S4_vxsubaddw :
Hexagon_di_didi_Intrinsic<"HEXAGON_S4_vxsubaddw">;
  
                                                     
  
def int_hexagon_S4_vxaddsubh :
Hexagon_di_didi_Intrinsic<"HEXAGON_S4_vxaddsubh">;
  
                                                     
  
def int_hexagon_S4_vxsubaddh :
Hexagon_di_didi_Intrinsic<"HEXAGON_S4_vxsubaddh">;
  
                                                      
  
def int_hexagon_S4_vxaddsubhr :
Hexagon_di_didi_Intrinsic<"HEXAGON_S4_vxaddsubhr">;
  
                                                      
  
def int_hexagon_S4_vxsubaddhr :
Hexagon_di_didi_Intrinsic<"HEXAGON_S4_vxsubaddhr">;
  
                                                  
  
def int_hexagon_A2_svavgh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svavgh">;
  
                                                   
  
def int_hexagon_A2_svavghs :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svavghs">;
  
                                                   
  
def int_hexagon_A2_svnavgh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svnavgh">;
  
                                                  
  
def int_hexagon_A2_svaddh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svaddh">;
  
                                                   
  
def int_hexagon_A2_svaddhs :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svaddhs">;
  
                                                    
  
def int_hexagon_A2_svadduhs :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svadduhs">;
  
                                                  
  
def int_hexagon_A2_svsubh :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svsubh">;
  
                                                   
  
def int_hexagon_A2_svsubhs :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svsubhs">;
  
                                                    
  
def int_hexagon_A2_svsubuhs :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A2_svsubuhs">;
  
                                                   
  
def int_hexagon_A2_vraddub :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vraddub">;
  
                                                         
  
def int_hexagon_A2_vraddub_acc :
Hexagon_di_dididi_Intrinsic<"HEXAGON_A2_vraddub_acc">;
  
                                                  
  
def int_hexagon_M2_vraddh :
Hexagon_si_didi_Intrinsic<"HEXAGON_M2_vraddh">;
  
                                                   
  
def int_hexagon_M2_vradduh :
Hexagon_si_didi_Intrinsic<"HEXAGON_M2_vradduh">;
  
                                                  
  
def int_hexagon_A2_vsubub :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsubub">;
  
                                                     
  
def int_hexagon_A2_vsubb_map :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsubb_map">;
  
                                                   
  
def int_hexagon_A2_vsububs :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsububs">;
  
                                                 
  
def int_hexagon_A2_vsubh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsubh">;
  
                                                  
  
def int_hexagon_A2_vsubhs :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsubhs">;
  
                                                   
  
def int_hexagon_A2_vsubuhs :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsubuhs">;
  
                                                 
  
def int_hexagon_A2_vsubw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsubw">;
  
                                                  
  
def int_hexagon_A2_vsubws :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vsubws">;
  
                                               
  
def int_hexagon_A2_vabsh :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_vabsh">;
  
                                                  
  
def int_hexagon_A2_vabshsat :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_vabshsat">;
  
                                               
  
def int_hexagon_A2_vabsw :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_vabsw">;
  
                                                  
  
def int_hexagon_A2_vabswsat :
Hexagon_di_di_Intrinsic<"HEXAGON_A2_vabswsat">;
  
                                                     
  
def int_hexagon_M2_vabsdiffw :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vabsdiffw">;
  
                                                     
  
def int_hexagon_M2_vabsdiffh :
Hexagon_di_didi_Intrinsic<"HEXAGON_M2_vabsdiffh">;
  
                                                   
  
def int_hexagon_A2_vrsadub :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vrsadub">;
  
                                                         
  
def int_hexagon_A2_vrsadub_acc :
Hexagon_di_dididi_Intrinsic<"HEXAGON_A2_vrsadub_acc">;
  
                                                  
  
def int_hexagon_A2_vavgub :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavgub">;
  
                                                  
  
def int_hexagon_A2_vavguh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavguh">;
  
                                                 
  
def int_hexagon_A2_vavgh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavgh">;
  
                                                  
  
def int_hexagon_A2_vnavgh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vnavgh">;
  
                                                 
  
def int_hexagon_A2_vavgw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavgw">;
  
                                                  
  
def int_hexagon_A2_vnavgw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vnavgw">;
  
                                                  
  
def int_hexagon_A2_vavgwr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavgwr">;
  
                                                   
  
def int_hexagon_A2_vnavgwr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vnavgwr">;
  
                                                   
  
def int_hexagon_A2_vavgwcr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavgwcr">;
  
                                                    
  
def int_hexagon_A2_vnavgwcr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vnavgwcr">;
  
                                                   
  
def int_hexagon_A2_vavghcr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavghcr">;
  
                                                    
  
def int_hexagon_A2_vnavghcr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vnavghcr">;
  
                                                  
  
def int_hexagon_A2_vavguw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavguw">;
  
                                                   
  
def int_hexagon_A2_vavguwr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavguwr">;
  
                                                   
  
def int_hexagon_A2_vavgubr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavgubr">;
  
                                                   
  
def int_hexagon_A2_vavguhr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavguhr">;
  
                                                  
  
def int_hexagon_A2_vavghr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vavghr">;
  
                                                   
  
def int_hexagon_A2_vnavghr :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vnavghr">;
  
                                                    
  
def int_hexagon_A4_round_ri :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_round_ri">;
  
                                                    
  
def int_hexagon_A4_round_rr :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_round_rr">;
  
                                                        
  
def int_hexagon_A4_round_ri_sat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_round_ri_sat">;
  
                                                        
  
def int_hexagon_A4_round_rr_sat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_round_rr_sat">;
  
                                                     
  
def int_hexagon_A4_cround_ri :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cround_ri">;
  
                                                     
  
def int_hexagon_A4_cround_rr :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_cround_rr">;
  
                                                    
  
def int_hexagon_A4_vrminh :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrminh">;
  
                                                    
  
def int_hexagon_A4_vrmaxh :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrmaxh">;
  
                                                     
  
def int_hexagon_A4_vrminuh :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrminuh">;
  
                                                     
  
def int_hexagon_A4_vrmaxuh :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrmaxuh">;
  
                                                    
  
def int_hexagon_A4_vrminw :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrminw">;
  
                                                    
  
def int_hexagon_A4_vrmaxw :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrmaxw">;
  
                                                     
  
def int_hexagon_A4_vrminuw :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrminuw">;
  
                                                     
  
def int_hexagon_A4_vrmaxuw :
Hexagon_di_didisi_Intrinsic<"HEXAGON_A4_vrmaxuw">;
  
                                                 
  
def int_hexagon_A2_vminb :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vminb">;
  
                                                 
  
def int_hexagon_A2_vmaxb :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vmaxb">;
  
                                                  
  
def int_hexagon_A2_vminub :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vminub">;
  
                                                  
  
def int_hexagon_A2_vmaxub :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vmaxub">;
  
                                                 
  
def int_hexagon_A2_vminh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vminh">;
  
                                                 
  
def int_hexagon_A2_vmaxh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vmaxh">;
  
                                                  
  
def int_hexagon_A2_vminuh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vminuh">;
  
                                                  
  
def int_hexagon_A2_vmaxuh :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vmaxuh">;
  
                                                 
  
def int_hexagon_A2_vminw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vminw">;
  
                                                 
  
def int_hexagon_A2_vmaxw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vmaxw">;
  
                                                  
  
def int_hexagon_A2_vminuw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vminuw">;
  
                                                  
  
def int_hexagon_A2_vmaxuw :
Hexagon_di_didi_Intrinsic<"HEXAGON_A2_vmaxuw">;
  
                                                    
  
def int_hexagon_A4_modwrapu :
Hexagon_si_sisi_Intrinsic<"HEXAGON_A4_modwrapu">;
  
                                                 
  
def int_hexagon_F2_sfadd :
Hexagon_sf_sfsf_Intrinsic<"HEXAGON_F2_sfadd">;
  
                                                 
  
def int_hexagon_F2_sfsub :
Hexagon_sf_sfsf_Intrinsic<"HEXAGON_F2_sfsub">;
  
                                                 
  
def int_hexagon_F2_sfmpy :
Hexagon_sf_sfsf_Intrinsic<"HEXAGON_F2_sfmpy">;
  
                                                   
  
def int_hexagon_F2_sffma :
Hexagon_sf_sfsfsf_Intrinsic<"HEXAGON_F2_sffma">;
  
                                                        
  
def int_hexagon_F2_sffma_sc :
Hexagon_sf_sfsfsfqi_Intrinsic<"HEXAGON_F2_sffma_sc">;
  
                                                   
  
def int_hexagon_F2_sffms :
Hexagon_sf_sfsfsf_Intrinsic<"HEXAGON_F2_sffms">;
  
                                                       
  
def int_hexagon_F2_sffma_lib :
Hexagon_sf_sfsfsf_Intrinsic<"HEXAGON_F2_sffma_lib">;
  
                                                       
  
def int_hexagon_F2_sffms_lib :
Hexagon_sf_sfsfsf_Intrinsic<"HEXAGON_F2_sffms_lib">;
  
                                                   
  
def int_hexagon_F2_sfcmpeq :
Hexagon_si_sfsf_Intrinsic<"HEXAGON_F2_sfcmpeq">;
  
                                                   
  
def int_hexagon_F2_sfcmpgt :
Hexagon_si_sfsf_Intrinsic<"HEXAGON_F2_sfcmpgt">;
  
                                                   
  
def int_hexagon_F2_sfcmpge :
Hexagon_si_sfsf_Intrinsic<"HEXAGON_F2_sfcmpge">;
  
                                                   
  
def int_hexagon_F2_sfcmpuo :
Hexagon_si_sfsf_Intrinsic<"HEXAGON_F2_sfcmpuo">;
  
                                                 
  
def int_hexagon_F2_sfmax :
Hexagon_sf_sfsf_Intrinsic<"HEXAGON_F2_sfmax">;
  
                                                 
  
def int_hexagon_F2_sfmin :
Hexagon_sf_sfsf_Intrinsic<"HEXAGON_F2_sfmin">;
  
                                                   
  
def int_hexagon_F2_sfclass :
Hexagon_si_sfsi_Intrinsic<"HEXAGON_F2_sfclass">;
  
                                                 
  
def int_hexagon_F2_sfimm_p :
Hexagon_sf_si_Intrinsic<"HEXAGON_F2_sfimm_p">;
  
                                                 
  
def int_hexagon_F2_sfimm_n :
Hexagon_sf_si_Intrinsic<"HEXAGON_F2_sfimm_n">;
  
                                                    
  
def int_hexagon_F2_sffixupn :
Hexagon_sf_sfsf_Intrinsic<"HEXAGON_F2_sffixupn">;
  
                                                    
  
def int_hexagon_F2_sffixupd :
Hexagon_sf_sfsf_Intrinsic<"HEXAGON_F2_sffixupd">;
  
                                                  
  
def int_hexagon_F2_sffixupr :
Hexagon_sf_sf_Intrinsic<"HEXAGON_F2_sffixupr">;
  
                                                   
  
def int_hexagon_F2_dfcmpeq :
Hexagon_si_dfdf_Intrinsic<"HEXAGON_F2_dfcmpeq">;
  
                                                   
  
def int_hexagon_F2_dfcmpgt :
Hexagon_si_dfdf_Intrinsic<"HEXAGON_F2_dfcmpgt">;
  
                                                   
  
def int_hexagon_F2_dfcmpge :
Hexagon_si_dfdf_Intrinsic<"HEXAGON_F2_dfcmpge">;
  
                                                   
  
def int_hexagon_F2_dfcmpuo :
Hexagon_si_dfdf_Intrinsic<"HEXAGON_F2_dfcmpuo">;
  
                                                   
  
def int_hexagon_F2_dfclass :
Hexagon_si_dfsi_Intrinsic<"HEXAGON_F2_dfclass">;
  
                                                 
  
def int_hexagon_F2_dfimm_p :
Hexagon_df_si_Intrinsic<"HEXAGON_F2_dfimm_p">;
  
                                                 
  
def int_hexagon_F2_dfimm_n :
Hexagon_df_si_Intrinsic<"HEXAGON_F2_dfimm_n">;
  
                                                    
  
def int_hexagon_F2_conv_sf2df :
Hexagon_df_sf_Intrinsic<"HEXAGON_F2_conv_sf2df">;
  
                                                    
  
def int_hexagon_F2_conv_df2sf :
Hexagon_sf_df_Intrinsic<"HEXAGON_F2_conv_df2sf">;
  
                                                    
  
def int_hexagon_F2_conv_uw2sf :
Hexagon_sf_si_Intrinsic<"HEXAGON_F2_conv_uw2sf">;
  
                                                    
  
def int_hexagon_F2_conv_uw2df :
Hexagon_df_si_Intrinsic<"HEXAGON_F2_conv_uw2df">;
  
                                                   
  
def int_hexagon_F2_conv_w2sf :
Hexagon_sf_si_Intrinsic<"HEXAGON_F2_conv_w2sf">;
  
                                                   
  
def int_hexagon_F2_conv_w2df :
Hexagon_df_si_Intrinsic<"HEXAGON_F2_conv_w2df">;
  
                                                    
  
def int_hexagon_F2_conv_ud2sf :
Hexagon_sf_di_Intrinsic<"HEXAGON_F2_conv_ud2sf">;
  
                                                    
  
def int_hexagon_F2_conv_ud2df :
Hexagon_df_di_Intrinsic<"HEXAGON_F2_conv_ud2df">;
  
                                                   
  
def int_hexagon_F2_conv_d2sf :
Hexagon_sf_di_Intrinsic<"HEXAGON_F2_conv_d2sf">;
  
                                                   
  
def int_hexagon_F2_conv_d2df :
Hexagon_df_di_Intrinsic<"HEXAGON_F2_conv_d2df">;
  
                                                    
  
def int_hexagon_F2_conv_sf2uw :
Hexagon_si_sf_Intrinsic<"HEXAGON_F2_conv_sf2uw">;
  
                                                   
  
def int_hexagon_F2_conv_sf2w :
Hexagon_si_sf_Intrinsic<"HEXAGON_F2_conv_sf2w">;
  
                                                    
  
def int_hexagon_F2_conv_sf2ud :
Hexagon_di_sf_Intrinsic<"HEXAGON_F2_conv_sf2ud">;
  
                                                   
  
def int_hexagon_F2_conv_sf2d :
Hexagon_di_sf_Intrinsic<"HEXAGON_F2_conv_sf2d">;
  
                                                    
  
def int_hexagon_F2_conv_df2uw :
Hexagon_si_df_Intrinsic<"HEXAGON_F2_conv_df2uw">;
  
                                                   
  
def int_hexagon_F2_conv_df2w :
Hexagon_si_df_Intrinsic<"HEXAGON_F2_conv_df2w">;
  
                                                    
  
def int_hexagon_F2_conv_df2ud :
Hexagon_di_df_Intrinsic<"HEXAGON_F2_conv_df2ud">;
  
                                                   
  
def int_hexagon_F2_conv_df2d :
Hexagon_di_df_Intrinsic<"HEXAGON_F2_conv_df2d">;
  
                                                         
  
def int_hexagon_F2_conv_sf2uw_chop :
Hexagon_si_sf_Intrinsic<"HEXAGON_F2_conv_sf2uw_chop">;
  
                                                        
  
def int_hexagon_F2_conv_sf2w_chop :
Hexagon_si_sf_Intrinsic<"HEXAGON_F2_conv_sf2w_chop">;
  
                                                         
  
def int_hexagon_F2_conv_sf2ud_chop :
Hexagon_di_sf_Intrinsic<"HEXAGON_F2_conv_sf2ud_chop">;
  
                                                        
  
def int_hexagon_F2_conv_sf2d_chop :
Hexagon_di_sf_Intrinsic<"HEXAGON_F2_conv_sf2d_chop">;
  
                                                         
  
def int_hexagon_F2_conv_df2uw_chop :
Hexagon_si_df_Intrinsic<"HEXAGON_F2_conv_df2uw_chop">;
  
                                                        
  
def int_hexagon_F2_conv_df2w_chop :
Hexagon_si_df_Intrinsic<"HEXAGON_F2_conv_df2w_chop">;
  
                                                         
  
def int_hexagon_F2_conv_df2ud_chop :
Hexagon_di_df_Intrinsic<"HEXAGON_F2_conv_df2ud_chop">;
  
                                                        
  
def int_hexagon_F2_conv_df2d_chop :
Hexagon_di_df_Intrinsic<"HEXAGON_F2_conv_df2d_chop">;
  
                                                   
  
def int_hexagon_S2_asr_r_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asr_r_r">;
  
                                                   
  
def int_hexagon_S2_asl_r_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asl_r_r">;
  
                                                   
  
def int_hexagon_S2_lsr_r_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_lsr_r_r">;
  
                                                   
  
def int_hexagon_S2_lsl_r_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_lsl_r_r">;
  
                                                   
  
def int_hexagon_S2_asr_r_p :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_r_p">;
  
                                                   
  
def int_hexagon_S2_asl_r_p :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asl_r_p">;
  
                                                   
  
def int_hexagon_S2_lsr_r_p :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsr_r_p">;
  
                                                   
  
def int_hexagon_S2_lsl_r_p :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsl_r_p">;
  
                                                         
  
def int_hexagon_S2_asr_r_r_acc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_r_r_acc">;
  
                                                         
  
def int_hexagon_S2_asl_r_r_acc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_r_r_acc">;
  
                                                         
  
def int_hexagon_S2_lsr_r_r_acc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_r_r_acc">;
  
                                                         
  
def int_hexagon_S2_lsl_r_r_acc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsl_r_r_acc">;
  
                                                         
  
def int_hexagon_S2_asr_r_p_acc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_r_p_acc">;
  
                                                         
  
def int_hexagon_S2_asl_r_p_acc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_r_p_acc">;
  
                                                         
  
def int_hexagon_S2_lsr_r_p_acc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_r_p_acc">;
  
                                                         
  
def int_hexagon_S2_lsl_r_p_acc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsl_r_p_acc">;
  
                                                         
  
def int_hexagon_S2_asr_r_r_nac :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_r_r_nac">;
  
                                                         
  
def int_hexagon_S2_asl_r_r_nac :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_r_r_nac">;
  
                                                         
  
def int_hexagon_S2_lsr_r_r_nac :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_r_r_nac">;
  
                                                         
  
def int_hexagon_S2_lsl_r_r_nac :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsl_r_r_nac">;
  
                                                         
  
def int_hexagon_S2_asr_r_p_nac :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_r_p_nac">;
  
                                                         
  
def int_hexagon_S2_asl_r_p_nac :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_r_p_nac">;
  
                                                         
  
def int_hexagon_S2_lsr_r_p_nac :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_r_p_nac">;
  
                                                         
  
def int_hexagon_S2_lsl_r_p_nac :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsl_r_p_nac">;
  
                                                         
  
def int_hexagon_S2_asr_r_r_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_r_r_and">;
  
                                                         
  
def int_hexagon_S2_asl_r_r_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_r_r_and">;
  
                                                         
  
def int_hexagon_S2_lsr_r_r_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_r_r_and">;
  
                                                         
  
def int_hexagon_S2_lsl_r_r_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsl_r_r_and">;
  
                                                        
  
def int_hexagon_S2_asr_r_r_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_r_r_or">;
  
                                                        
  
def int_hexagon_S2_asl_r_r_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_r_r_or">;
  
                                                        
  
def int_hexagon_S2_lsr_r_r_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_r_r_or">;
  
                                                        
  
def int_hexagon_S2_lsl_r_r_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsl_r_r_or">;
  
                                                         
  
def int_hexagon_S2_asr_r_p_and :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_r_p_and">;
  
                                                         
  
def int_hexagon_S2_asl_r_p_and :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_r_p_and">;
  
                                                         
  
def int_hexagon_S2_lsr_r_p_and :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_r_p_and">;
  
                                                         
  
def int_hexagon_S2_lsl_r_p_and :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsl_r_p_and">;
  
                                                        
  
def int_hexagon_S2_asr_r_p_or :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_r_p_or">;
  
                                                        
  
def int_hexagon_S2_asl_r_p_or :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_r_p_or">;
  
                                                        
  
def int_hexagon_S2_lsr_r_p_or :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_r_p_or">;
  
                                                        
  
def int_hexagon_S2_lsl_r_p_or :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsl_r_p_or">;
  
                                                         
  
def int_hexagon_S2_asr_r_p_xor :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_r_p_xor">;
  
                                                         
  
def int_hexagon_S2_asl_r_p_xor :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_r_p_xor">;
  
                                                         
  
def int_hexagon_S2_lsr_r_p_xor :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_r_p_xor">;
  
                                                         
  
def int_hexagon_S2_lsl_r_p_xor :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsl_r_p_xor">;
  
                                                       
  
def int_hexagon_S2_asr_r_r_sat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asr_r_r_sat">;
  
                                                       
  
def int_hexagon_S2_asl_r_r_sat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asl_r_r_sat">;
  
                                                   
  
def int_hexagon_S2_asr_i_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asr_i_r">;
  
                                                   
  
def int_hexagon_S2_lsr_i_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_lsr_i_r">;
  
                                                   
  
def int_hexagon_S2_asl_i_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asl_i_r">;
  
                                                   
  
def int_hexagon_S2_asr_i_p :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_i_p">;
  
                                                   
  
def int_hexagon_S2_lsr_i_p :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsr_i_p">;
  
                                                   
  
def int_hexagon_S2_asl_i_p :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asl_i_p">;
  
                                                         
  
def int_hexagon_S2_asr_i_r_acc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_i_r_acc">;
  
                                                         
  
def int_hexagon_S2_lsr_i_r_acc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_i_r_acc">;
  
                                                         
  
def int_hexagon_S2_asl_i_r_acc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_i_r_acc">;
  
                                                         
  
def int_hexagon_S2_asr_i_p_acc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_i_p_acc">;
  
                                                         
  
def int_hexagon_S2_lsr_i_p_acc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_i_p_acc">;
  
                                                         
  
def int_hexagon_S2_asl_i_p_acc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_i_p_acc">;
  
                                                         
  
def int_hexagon_S2_asr_i_r_nac :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_i_r_nac">;
  
                                                         
  
def int_hexagon_S2_lsr_i_r_nac :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_i_r_nac">;
  
                                                         
  
def int_hexagon_S2_asl_i_r_nac :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_i_r_nac">;
  
                                                         
  
def int_hexagon_S2_asr_i_p_nac :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_i_p_nac">;
  
                                                         
  
def int_hexagon_S2_lsr_i_p_nac :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_i_p_nac">;
  
                                                         
  
def int_hexagon_S2_asl_i_p_nac :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_i_p_nac">;
  
                                                          
  
def int_hexagon_S2_lsr_i_r_xacc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_i_r_xacc">;
  
                                                          
  
def int_hexagon_S2_asl_i_r_xacc :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_i_r_xacc">;
  
                                                          
  
def int_hexagon_S2_lsr_i_p_xacc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_i_p_xacc">;
  
                                                          
  
def int_hexagon_S2_asl_i_p_xacc :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_i_p_xacc">;
  
                                                         
  
def int_hexagon_S2_asr_i_r_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_i_r_and">;
  
                                                         
  
def int_hexagon_S2_lsr_i_r_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_i_r_and">;
  
                                                         
  
def int_hexagon_S2_asl_i_r_and :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_i_r_and">;
  
                                                        
  
def int_hexagon_S2_asr_i_r_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asr_i_r_or">;
  
                                                        
  
def int_hexagon_S2_lsr_i_r_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_lsr_i_r_or">;
  
                                                        
  
def int_hexagon_S2_asl_i_r_or :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_asl_i_r_or">;
  
                                                         
  
def int_hexagon_S2_asr_i_p_and :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_i_p_and">;
  
                                                         
  
def int_hexagon_S2_lsr_i_p_and :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_i_p_and">;
  
                                                         
  
def int_hexagon_S2_asl_i_p_and :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_i_p_and">;
  
                                                        
  
def int_hexagon_S2_asr_i_p_or :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asr_i_p_or">;
  
                                                        
  
def int_hexagon_S2_lsr_i_p_or :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_lsr_i_p_or">;
  
                                                        
  
def int_hexagon_S2_asl_i_p_or :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_asl_i_p_or">;
  
                                                       
  
def int_hexagon_S2_asl_i_r_sat :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asl_i_r_sat">;
  
                                                       
  
def int_hexagon_S2_asr_i_r_rnd :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asr_i_r_rnd">;
  
                                                                  
  
def int_hexagon_S2_asr_i_r_rnd_goodsyntax :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_asr_i_r_rnd_goodsyntax">;
  
                                                       
  
def int_hexagon_S2_asr_i_p_rnd :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_i_p_rnd">;
  
                                                                  
  
def int_hexagon_S2_asr_i_p_rnd_goodsyntax :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_i_p_rnd_goodsyntax">;
  
                                                
  
def int_hexagon_S4_lsli :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S4_lsli">;
  
                                                         
  
def int_hexagon_S2_addasl_rrri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_addasl_rrri">;
  
                                                         
  
def int_hexagon_S4_andi_asl_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_andi_asl_ri">;
  
                                                        
  
def int_hexagon_S4_ori_asl_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_ori_asl_ri">;
  
                                                         
  
def int_hexagon_S4_addi_asl_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_addi_asl_ri">;
  
                                                         
  
def int_hexagon_S4_subi_asl_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_subi_asl_ri">;
  
                                                         
  
def int_hexagon_S4_andi_lsr_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_andi_lsr_ri">;
  
                                                        
  
def int_hexagon_S4_ori_lsr_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_ori_lsr_ri">;
  
                                                         
  
def int_hexagon_S4_addi_lsr_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_addi_lsr_ri">;
  
                                                         
  
def int_hexagon_S4_subi_lsr_ri :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_subi_lsr_ri">;
  
                                                      
  
def int_hexagon_S2_valignib :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_valignib">;
  
                                                      
  
def int_hexagon_S2_valignrb :
Hexagon_di_didiqi_Intrinsic<"HEXAGON_S2_valignrb">;
  
                                                       
  
def int_hexagon_S2_vspliceib :
Hexagon_di_didisi_Intrinsic<"HEXAGON_S2_vspliceib">;
  
                                                       
  
def int_hexagon_S2_vsplicerb :
Hexagon_di_didiqi_Intrinsic<"HEXAGON_S2_vsplicerb">;
  
                                                  
  
def int_hexagon_S2_vsplatrh :
Hexagon_di_si_Intrinsic<"HEXAGON_S2_vsplatrh">;
  
                                                  
  
def int_hexagon_S2_vsplatrb :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_vsplatrb">;
  
                                                      
  
def int_hexagon_S2_insert :
Hexagon_si_sisisisi_Intrinsic<"HEXAGON_S2_insert">;
  
                                                                    
  
def int_hexagon_S2_tableidxb_goodsyntax :
Hexagon_si_sisisisi_Intrinsic<"HEXAGON_S2_tableidxb_goodsyntax">;
  
                                                                    
  
def int_hexagon_S2_tableidxh_goodsyntax :
Hexagon_si_sisisisi_Intrinsic<"HEXAGON_S2_tableidxh_goodsyntax">;
  
                                                                    
  
def int_hexagon_S2_tableidxw_goodsyntax :
Hexagon_si_sisisisi_Intrinsic<"HEXAGON_S2_tableidxw_goodsyntax">;
  
                                                                    
  
def int_hexagon_S2_tableidxd_goodsyntax :
Hexagon_si_sisisisi_Intrinsic<"HEXAGON_S2_tableidxd_goodsyntax">;
  
                                                     
  
def int_hexagon_A4_bitspliti :
Hexagon_di_sisi_Intrinsic<"HEXAGON_A4_bitspliti">;
  
                                                    
  
def int_hexagon_A4_bitsplit :
Hexagon_di_sisi_Intrinsic<"HEXAGON_A4_bitsplit">;
  
                                                     
  
def int_hexagon_S4_extract :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S4_extract">;
  
                                                      
  
def int_hexagon_S2_extractu :
Hexagon_si_sisisi_Intrinsic<"HEXAGON_S2_extractu">;
  
                                                       
  
def int_hexagon_S2_insertp :
Hexagon_di_didisisi_Intrinsic<"HEXAGON_S2_insertp">;
  
                                                      
  
def int_hexagon_S4_extractp :
Hexagon_di_disisi_Intrinsic<"HEXAGON_S4_extractp">;
  
                                                       
  
def int_hexagon_S2_extractup :
Hexagon_di_disisi_Intrinsic<"HEXAGON_S2_extractup">;
  
                                                       
  
def int_hexagon_S2_insert_rp :
Hexagon_si_sisidi_Intrinsic<"HEXAGON_S2_insert_rp">;
  
                                                      
  
def int_hexagon_S4_extract_rp :
Hexagon_si_sidi_Intrinsic<"HEXAGON_S4_extract_rp">;
  
                                                       
  
def int_hexagon_S2_extractu_rp :
Hexagon_si_sidi_Intrinsic<"HEXAGON_S2_extractu_rp">;
  
                                                        
  
def int_hexagon_S2_insertp_rp :
Hexagon_di_dididi_Intrinsic<"HEXAGON_S2_insertp_rp">;
  
                                                       
  
def int_hexagon_S4_extractp_rp :
Hexagon_di_didi_Intrinsic<"HEXAGON_S4_extractp_rp">;
  
                                                        
  
def int_hexagon_S2_extractup_rp :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_extractup_rp">;
  
                                                    
  
def int_hexagon_S2_tstbit_i :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_tstbit_i">;
  
                                                     
  
def int_hexagon_S4_ntstbit_i :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S4_ntstbit_i">;
  
                                                    
  
def int_hexagon_S2_setbit_i :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_setbit_i">;
  
                                                       
  
def int_hexagon_S2_togglebit_i :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_togglebit_i">;
  
                                                    
  
def int_hexagon_S2_clrbit_i :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_clrbit_i">;
  
                                                    
  
def int_hexagon_S2_tstbit_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_tstbit_r">;
  
                                                     
  
def int_hexagon_S4_ntstbit_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S4_ntstbit_r">;
  
                                                    
  
def int_hexagon_S2_setbit_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_setbit_r">;
  
                                                       
  
def int_hexagon_S2_togglebit_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_togglebit_r">;
  
                                                    
  
def int_hexagon_S2_clrbit_r :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S2_clrbit_r">;
  
                                                    
  
def int_hexagon_S2_asr_i_vh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_i_vh">;
  
                                                    
  
def int_hexagon_S2_lsr_i_vh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsr_i_vh">;
  
                                                    
  
def int_hexagon_S2_asl_i_vh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asl_i_vh">;
  
                                                    
  
def int_hexagon_S2_asr_r_vh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_r_vh">;
  
                                                                     
  
def int_hexagon_S5_asrhub_rnd_sat_goodsyntax :
Hexagon_si_disi_Intrinsic<"HEXAGON_S5_asrhub_rnd_sat_goodsyntax">;
  
                                                      
  
def int_hexagon_S5_asrhub_sat :
Hexagon_si_disi_Intrinsic<"HEXAGON_S5_asrhub_sat">;
  
                                                               
  
def int_hexagon_S5_vasrhrnd_goodsyntax :
Hexagon_di_disi_Intrinsic<"HEXAGON_S5_vasrhrnd_goodsyntax">;
  
                                                    
  
def int_hexagon_S2_asl_r_vh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asl_r_vh">;
  
                                                    
  
def int_hexagon_S2_lsr_r_vh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsr_r_vh">;
  
                                                    
  
def int_hexagon_S2_lsl_r_vh :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsl_r_vh">;
  
                                                    
  
def int_hexagon_S2_asr_i_vw :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_i_vw">;
  
                                                          
  
def int_hexagon_S2_asr_i_svw_trun :
Hexagon_si_disi_Intrinsic<"HEXAGON_S2_asr_i_svw_trun">;
  
                                                          
  
def int_hexagon_S2_asr_r_svw_trun :
Hexagon_si_disi_Intrinsic<"HEXAGON_S2_asr_r_svw_trun">;
  
                                                    
  
def int_hexagon_S2_lsr_i_vw :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsr_i_vw">;
  
                                                    
  
def int_hexagon_S2_asl_i_vw :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asl_i_vw">;
  
                                                    
  
def int_hexagon_S2_asr_r_vw :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asr_r_vw">;
  
                                                    
  
def int_hexagon_S2_asl_r_vw :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_asl_r_vw">;
  
                                                    
  
def int_hexagon_S2_lsr_r_vw :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsr_r_vw">;
  
                                                    
  
def int_hexagon_S2_lsl_r_vw :
Hexagon_di_disi_Intrinsic<"HEXAGON_S2_lsl_r_vw">;
  
                                                    
  
def int_hexagon_S2_vrndpackwh :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vrndpackwh">;
  
                                                     
  
def int_hexagon_S2_vrndpackwhs :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vrndpackwhs">;
  
                                                
  
def int_hexagon_S2_vsxtbh :
Hexagon_di_si_Intrinsic<"HEXAGON_S2_vsxtbh">;
  
                                                
  
def int_hexagon_S2_vzxtbh :
Hexagon_di_si_Intrinsic<"HEXAGON_S2_vzxtbh">;
  
                                                 
  
def int_hexagon_S2_vsathub :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vsathub">;
  
                                                  
  
def int_hexagon_S2_svsathub :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_svsathub">;
  
                                                 
  
def int_hexagon_S2_svsathb :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_svsathb">;
  
                                                
  
def int_hexagon_S2_vsathb :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vsathb">;
  
                                                  
  
def int_hexagon_S2_vtrunohb :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vtrunohb">;
  
                                                    
  
def int_hexagon_S2_vtrunewh :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_vtrunewh">;
  
                                                    
  
def int_hexagon_S2_vtrunowh :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_vtrunowh">;
  
                                                  
  
def int_hexagon_S2_vtrunehb :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vtrunehb">;
  
                                                
  
def int_hexagon_S2_vsxthw :
Hexagon_di_si_Intrinsic<"HEXAGON_S2_vsxthw">;
  
                                                
  
def int_hexagon_S2_vzxthw :
Hexagon_di_si_Intrinsic<"HEXAGON_S2_vzxthw">;
  
                                                
  
def int_hexagon_S2_vsatwh :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vsatwh">;
  
                                                 
  
def int_hexagon_S2_vsatwuh :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_vsatwuh">;
  
                                                  
  
def int_hexagon_S2_packhl :
Hexagon_di_sisi_Intrinsic<"HEXAGON_S2_packhl">;
  
                                              
  
def int_hexagon_A2_swiz :
Hexagon_si_si_Intrinsic<"HEXAGON_A2_swiz">;
  
                                                        
  
def int_hexagon_S2_vsathub_nopack :
Hexagon_di_di_Intrinsic<"HEXAGON_S2_vsathub_nopack">;
  
                                                       
  
def int_hexagon_S2_vsathb_nopack :
Hexagon_di_di_Intrinsic<"HEXAGON_S2_vsathb_nopack">;
  
                                                       
  
def int_hexagon_S2_vsatwh_nopack :
Hexagon_di_di_Intrinsic<"HEXAGON_S2_vsatwh_nopack">;
  
                                                        
  
def int_hexagon_S2_vsatwuh_nopack :
Hexagon_di_di_Intrinsic<"HEXAGON_S2_vsatwuh_nopack">;
  
                                                   
  
def int_hexagon_S2_shuffob :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_shuffob">;
  
                                                   
  
def int_hexagon_S2_shuffeb :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_shuffeb">;
  
                                                   
  
def int_hexagon_S2_shuffoh :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_shuffoh">;
  
                                                   
  
def int_hexagon_S2_shuffeh :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_shuffeh">;
  
                                                   
  
def int_hexagon_S5_popcountp :
Hexagon_si_di_Intrinsic<"HEXAGON_S5_popcountp">;
  
                                                  
  
def int_hexagon_S4_parity :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S4_parity">;
  
                                                   
  
def int_hexagon_S2_parityp :
Hexagon_si_didi_Intrinsic<"HEXAGON_S2_parityp">;
  
                                                
  
def int_hexagon_S2_lfsp :
Hexagon_di_didi_Intrinsic<"HEXAGON_S2_lfsp">;
  
                                                 
  
def int_hexagon_S2_clbnorm :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_clbnorm">;
  
                                                   
  
def int_hexagon_S4_clbaddi :
Hexagon_si_sisi_Intrinsic<"HEXAGON_S4_clbaddi">;
  
                                                  
  
def int_hexagon_S4_clbpnorm :
Hexagon_si_di_Intrinsic<"HEXAGON_S4_clbpnorm">;
  
                                                    
  
def int_hexagon_S4_clbpaddi :
Hexagon_si_disi_Intrinsic<"HEXAGON_S4_clbpaddi">;
  
                                             
  
def int_hexagon_S2_clb :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_clb">;
  
                                             
  
def int_hexagon_S2_cl0 :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_cl0">;
  
                                             
  
def int_hexagon_S2_cl1 :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_cl1">;
  
                                              
  
def int_hexagon_S2_clbp :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_clbp">;
  
                                              
  
def int_hexagon_S2_cl0p :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_cl0p">;
  
                                              
  
def int_hexagon_S2_cl1p :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_cl1p">;
  
                                              
  
def int_hexagon_S2_brev :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_brev">;
  
                                               
  
def int_hexagon_S2_brevp :
Hexagon_di_di_Intrinsic<"HEXAGON_S2_brevp">;
  
                                             
  
def int_hexagon_S2_ct0 :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_ct0">;
  
                                             
  
def int_hexagon_S2_ct1 :
Hexagon_si_si_Intrinsic<"HEXAGON_S2_ct1">;
  
                                              
  
def int_hexagon_S2_ct0p :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_ct0p">;
  
                                              
  
def int_hexagon_S2_ct1p :
Hexagon_si_di_Intrinsic<"HEXAGON_S2_ct1p">;
  
                                                    
  
def int_hexagon_S2_interleave :
Hexagon_di_di_Intrinsic<"HEXAGON_S2_interleave">;
  
                                                      
  
def int_hexagon_S2_deinterleave :
Hexagon_di_di_Intrinsic<"HEXAGON_S2_deinterleave">;

  
                                                
  
def int_hexagon_prefetch :
Hexagon_Intrinsic<"HEXAGON_prefetch", [], [llvm_ptr_ty], []>;
def int_hexagon_Y2_dccleana :
Hexagon_Intrinsic<"HEXAGON_Y2_dccleana", [], [llvm_ptr_ty], []>;
def int_hexagon_Y2_dccleaninva :
Hexagon_Intrinsic<"HEXAGON_Y2_dccleaninva", [], [llvm_ptr_ty], []>;
def int_hexagon_Y2_dcinva :
Hexagon_Intrinsic<"HEXAGON_Y2_dcinva", [], [llvm_ptr_ty], []>;
def int_hexagon_Y2_dczeroa :
Hexagon_Intrinsic<"HEXAGON_Y2_dczeroa", [], [llvm_ptr_ty],
      [IntrWriteMem, IntrArgMemOnly, IntrHasSideEffects]>;
def int_hexagon_Y4_l2fetch :
Hexagon_Intrinsic<"HEXAGON_Y4_l2fetch", [], [llvm_ptr_ty, llvm_i32_ty], []>;
def int_hexagon_Y5_l2fetch :
Hexagon_Intrinsic<"HEXAGON_Y5_l2fetch", [], [llvm_ptr_ty, llvm_i64_ty], []>;

def llvm_ptr32_ty : LLVMPointerType<llvm_i32_ty>;
def llvm_ptr64_ty : LLVMPointerType<llvm_i64_ty>;

                                                                        
def int_hexagon_L2_loadw_locked :
Hexagon_Intrinsic<"HEXAGON_L2_loadw_locked", [llvm_i32_ty], [llvm_ptr32_ty],
      [IntrArgMemOnly, NoCapture<0>]>;
def int_hexagon_L4_loadd_locked :
Hexagon_Intrinsic<"HEXAGON_L4_loadd_locked", [llvm_i64_ty], [llvm_ptr64_ty],
      [IntrArgMemOnly, NoCapture<0>]>;

def int_hexagon_S2_storew_locked :
Hexagon_Intrinsic<"HEXAGON_S2_storew_locked", [llvm_i32_ty],
      [llvm_ptr32_ty, llvm_i32_ty], [IntrArgMemOnly, NoCapture<0>]>;
def int_hexagon_S4_stored_locked :
Hexagon_Intrinsic<"HEXAGON_S4_stored_locked", [llvm_i32_ty],
      [llvm_ptr64_ty, llvm_i64_ty], [IntrArgMemOnly, NoCapture<0>]>;

      

class Hexagon_v2048v2048_Intrinsic_T<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty],
                          [IntrNoMem]>;

                
                
class Hexagon_v512v1024_Intrinsic_T<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v32i32_ty],
                          [IntrNoMem]>;

                     
                     
class Hexagon_v1024v2048_Intrinsic_T<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v64i32_ty],
                          [IntrNoMem]>;

class Hexagon_v1024v1024_Intrinsic_T<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty],
                          [IntrNoMem]>;

                                              
              
def int_hexagon_V6_hi :
Hexagon_v512v1024_Intrinsic_T<"HEXAGON_V6_hi">;

                                              
              
def int_hexagon_V6_lo :
Hexagon_v512v1024_Intrinsic_T<"HEXAGON_V6_lo">;

                                              
                   
def int_hexagon_V6_hi_128B :
Hexagon_v1024v2048_Intrinsic_T<"HEXAGON_V6_hi_128B">;

                                              
                   
def int_hexagon_V6_lo_128B :
Hexagon_v1024v2048_Intrinsic_T<"HEXAGON_V6_lo_128B">;

                                                  
                    
def int_hexagon_V6_vassignp :
Hexagon_v1024v1024_Intrinsic_T<"HEXAGON_V6_vassignp">;

                                                  
                         
def int_hexagon_V6_vassignp_128B :
Hexagon_v2048v2048_Intrinsic_T<"HEXAGON_V6_vassignp_128B">;


  
                                             
                   
class Hexagon_iii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                 
                   
class Hexagon_LLiLLii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                              
                       
class Hexagon_iiii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i32_ty,llvm_i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                    
                       
class Hexagon_LLiLLiLLii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty,llvm_i64_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                       
                   
class Hexagon_v512v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                        
class Hexagon_v1024v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                   
                
class Hexagon_v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                     
                     
class Hexagon_v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                   
                     
class Hexagon_v1024v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                    
                          
class Hexagon_v2048v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                        
                     
class Hexagon_v1024v1024v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                         
                          
class Hexagon_v2048v2048v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                      
                   
class Hexagon_v512v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                         
                        
class Hexagon_v1024v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                     
                            
class Hexagon_v2048v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                                
class Hexagon_v2048v2048v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                          
class Hexagon_v512v512v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                              
                               
class Hexagon_v1024v1024v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                    
                      
class Hexagon_v512v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                     
                           
class Hexagon_v1024v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                        
                          
class Hexagon_v512v512v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                               
class Hexagon_v1024v1024v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                      
                    
class Hexagon_v1024v1024ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                      
                         
class Hexagon_v2048v2048ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                           
                        
class Hexagon_v1024v1024v1024ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                           
                             
class Hexagon_v2048v2048v2048ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v64i32_ty,llvm_i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                         
                         
class Hexagon_v2048v2048v2048_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v64i32_ty],
                          [IntrNoMem]>;

  
                                                       
                   
class Hexagon_v1024v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                         
                        
class Hexagon_v2048v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                              
               
class Hexagon_v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [],
                          [IntrNoMem]>;

  
                                               
                    
class Hexagon_v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [],
                          [IntrNoMem]>;

  
                                                          
                  
class Hexagon_v512v64iv512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v512i1_ty,llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                              
                       
class Hexagon_v1024v128iv1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v1024i1_ty,llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                  
                 
class Hexagon_v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                    
                      
class Hexagon_v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                            
                      
class Hexagon_v1024v1024v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                              
                           
class Hexagon_v2048v2048v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                    
                  
class Hexagon_v1024v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                     
                       
class Hexagon_v2048v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                         
                      
class Hexagon_v1024v1024v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                           
class Hexagon_v2048v2048v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                   
                   
class Hexagon_v512v64ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v512i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                     
                        
class Hexagon_v1024v128ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v1024i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                       
                       
class Hexagon_v512v512v64ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v512i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                            
class Hexagon_v1024v1024v128ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v1024i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                   
                   
class Hexagon_v64iv512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                     
                        
class Hexagon_v128iv1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                       
                       
class Hexagon_v64iv64iv512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_v512i1_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                            
class Hexagon_v128iv128iv1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_v1024i1_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                      
                
class Hexagon_v64iv512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                         
                     
class Hexagon_v128iv1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                          
                    
class Hexagon_v64iv64iv512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_v512i1_ty,llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                              
                         
class Hexagon_v128iv128iv1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_v1024i1_ty,llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                      
                   
class Hexagon_v64iv64iv64i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_v512i1_ty,llvm_v512i1_ty],
                          [IntrNoMem]>;

  
                                                         
                        
class Hexagon_v128iv128iv128i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_v1024i1_ty,llvm_v1024i1_ty],
                          [IntrNoMem]>;

  
                                                  
                    
class Hexagon_v64iv64i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_v512i1_ty],
                          [IntrNoMem]>;

  
                                                    
                         
class Hexagon_v128iv128i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_v1024i1_ty],
                          [IntrNoMem]>;

  
                                               
                        
class Hexagon_v64ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                
                             
class Hexagon_v128ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                           
                 
class Hexagon_v1024v64iv512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v512i1_ty,llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                              
                      
class Hexagon_v2048v128iv1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v1024i1_ty,llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                        
                     
class Hexagon_v1024v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                          
class Hexagon_v2048v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;


  
                                                
                    
class Hexagon_iv512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                 
                         
class Hexagon_iv1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                               
                    
class Hexagon_v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                
                         
class Hexagon_v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                           
                         
class Hexagon_v512v512v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                               
                              
class Hexagon_v1024v1024v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                             
                         
class Hexagon_v1024v1024v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                               
                              
class Hexagon_v2048v2048v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                       
                         
class Hexagon_vv64ivmemv512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_v512i1_ty,llvm_ptr_ty,llvm_v16i32_ty],
                          [IntrArgMemOnly]>;

  
                                                         
                              
class Hexagon_vv128ivmemv1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_v1024i1_ty,llvm_ptr_ty,llvm_v32i32_ty],
                          [IntrArgMemOnly]>;

  
                                                   
                   
def int_hexagon_S6_rol_i_r :
Hexagon_iii_Intrinsic<"HEXAGON_S6_rol_i_r">;

  
                                                   
                   
def int_hexagon_S6_rol_i_p :
Hexagon_LLiLLii_Intrinsic<"HEXAGON_S6_rol_i_p">;

  
                                                         
                       
def int_hexagon_S6_rol_i_r_acc :
Hexagon_iiii_Intrinsic<"HEXAGON_S6_rol_i_r_acc">;

  
                                                         
                       
def int_hexagon_S6_rol_i_p_acc :
Hexagon_LLiLLiLLii_Intrinsic<"HEXAGON_S6_rol_i_p_acc">;

  
                                                         
                       
def int_hexagon_S6_rol_i_r_nac :
Hexagon_iiii_Intrinsic<"HEXAGON_S6_rol_i_r_nac">;

  
                                                         
                       
def int_hexagon_S6_rol_i_p_nac :
Hexagon_LLiLLiLLii_Intrinsic<"HEXAGON_S6_rol_i_p_nac">;

  
                                                          
                        
def int_hexagon_S6_rol_i_r_xacc :
Hexagon_iiii_Intrinsic<"HEXAGON_S6_rol_i_r_xacc">;

  
                                                          
                        
def int_hexagon_S6_rol_i_p_xacc :
Hexagon_LLiLLiLLii_Intrinsic<"HEXAGON_S6_rol_i_p_xacc">;

  
                                                         
                       
def int_hexagon_S6_rol_i_r_and :
Hexagon_iiii_Intrinsic<"HEXAGON_S6_rol_i_r_and">;

  
                                                        
                      
def int_hexagon_S6_rol_i_r_or :
Hexagon_iiii_Intrinsic<"HEXAGON_S6_rol_i_r_or">;

  
                                                         
                       
def int_hexagon_S6_rol_i_p_and :
Hexagon_LLiLLiLLii_Intrinsic<"HEXAGON_S6_rol_i_p_and">;

  
                                                        
                      
def int_hexagon_S6_rol_i_p_or :
Hexagon_LLiLLiLLii_Intrinsic<"HEXAGON_S6_rol_i_p_or">;

  
                                                         
                       
def int_hexagon_S2_cabacencbin :
Hexagon_LLiLLiLLii_Intrinsic<"HEXAGON_S2_cabacencbin">;

  
                                                     
                   
def int_hexagon_V6_valignb :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_valignb">;

  
                                                          
                        
def int_hexagon_V6_valignb_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_valignb_128B">;

  
                                                      
                    
def int_hexagon_V6_vlalignb :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vlalignb">;

  
                                                           
                         
def int_hexagon_V6_vlalignb_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vlalignb_128B">;

  
                                                      
                    
def int_hexagon_V6_valignbi :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_valignbi">;

  
                                                           
                         
def int_hexagon_V6_valignbi_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_valignbi_128B">;

  
                                                       
                     
def int_hexagon_V6_vlalignbi :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vlalignbi">;

  
                                                            
                          
def int_hexagon_V6_vlalignbi_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vlalignbi_128B">;

  
                                                
                
def int_hexagon_V6_vror :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vror">;

  
                                                     
                     
def int_hexagon_V6_vror_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vror_128B">;

  
                                                   
                     
def int_hexagon_V6_vunpackub :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vunpackub">;

  
                                                        
                          
def int_hexagon_V6_vunpackub_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vunpackub_128B">;

  
                                                  
                    
def int_hexagon_V6_vunpackb :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vunpackb">;

  
                                                       
                         
def int_hexagon_V6_vunpackb_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vunpackb_128B">;

  
                                                   
                     
def int_hexagon_V6_vunpackuh :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vunpackuh">;

  
                                                        
                          
def int_hexagon_V6_vunpackuh_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vunpackuh_128B">;

  
                                                  
                    
def int_hexagon_V6_vunpackh :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vunpackh">;

  
                                                       
                         
def int_hexagon_V6_vunpackh_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vunpackh_128B">;

  
                                                     
                     
def int_hexagon_V6_vunpackob :
Hexagon_v1024v1024v512_Intrinsic<"HEXAGON_V6_vunpackob">;

  
                                                          
                          
def int_hexagon_V6_vunpackob_128B :
Hexagon_v2048v2048v1024_Intrinsic<"HEXAGON_V6_vunpackob_128B">;

  
                                                     
                     
def int_hexagon_V6_vunpackoh :
Hexagon_v1024v1024v512_Intrinsic<"HEXAGON_V6_vunpackoh">;

  
                                                          
                          
def int_hexagon_V6_vunpackoh_128B :
Hexagon_v2048v2048v1024_Intrinsic<"HEXAGON_V6_vunpackoh_128B">;

  
                                                   
                   
def int_hexagon_V6_vpackeb :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackeb">;

  
                                                        
                        
def int_hexagon_V6_vpackeb_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackeb_128B">;

  
                                                   
                   
def int_hexagon_V6_vpackeh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackeh">;

  
                                                        
                        
def int_hexagon_V6_vpackeh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackeh_128B">;

  
                                                   
                   
def int_hexagon_V6_vpackob :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackob">;

  
                                                        
                        
def int_hexagon_V6_vpackob_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackob_128B">;

  
                                                   
                   
def int_hexagon_V6_vpackoh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackoh">;

  
                                                        
                        
def int_hexagon_V6_vpackoh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackoh_128B">;

  
                                                        
                        
def int_hexagon_V6_vpackhub_sat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackhub_sat">;

  
                                                             
                             
def int_hexagon_V6_vpackhub_sat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackhub_sat_128B">;

  
                                                       
                       
def int_hexagon_V6_vpackhb_sat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackhb_sat">;

  
                                                            
                            
def int_hexagon_V6_vpackhb_sat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackhb_sat_128B">;

  
                                                        
                        
def int_hexagon_V6_vpackwuh_sat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackwuh_sat">;

  
                                                             
                             
def int_hexagon_V6_vpackwuh_sat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackwuh_sat_128B">;

  
                                                       
                       
def int_hexagon_V6_vpackwh_sat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vpackwh_sat">;

  
                                                            
                            
def int_hexagon_V6_vpackwh_sat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vpackwh_sat_128B">;

  
                                             
               
def int_hexagon_V6_vzb :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vzb">;

  
                                                  
                    
def int_hexagon_V6_vzb_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vzb_128B">;

  
                                             
               
def int_hexagon_V6_vsb :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vsb">;

  
                                                  
                    
def int_hexagon_V6_vsb_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vsb_128B">;

  
                                             
               
def int_hexagon_V6_vzh :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vzh">;

  
                                                  
                    
def int_hexagon_V6_vzh_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vzh_128B">;

  
                                             
               
def int_hexagon_V6_vsh :
Hexagon_v1024v512_Intrinsic<"HEXAGON_V6_vsh">;

  
                                                  
                    
def int_hexagon_V6_vsh_128B :
Hexagon_v2048v1024_Intrinsic<"HEXAGON_V6_vsh_128B">;

  
                                                    
                    
def int_hexagon_V6_vdmpybus :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vdmpybus">;

  
                                                         
                         
def int_hexagon_V6_vdmpybus_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpybus_128B">;

  
                                                          
                        
def int_hexagon_V6_vdmpybus_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vdmpybus_acc">;

  
                                                               
                             
def int_hexagon_V6_vdmpybus_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpybus_acc_128B">;

  
                                                       
                       
def int_hexagon_V6_vdmpybus_dv :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpybus_dv">;

  
                                                            
                            
def int_hexagon_V6_vdmpybus_dv_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vdmpybus_dv_128B">;

  
                                                             
                           
def int_hexagon_V6_vdmpybus_dv_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpybus_dv_acc">;

  
                                                                  
                                
def int_hexagon_V6_vdmpybus_dv_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vdmpybus_dv_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vdmpyhb :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vdmpyhb">;

  
                                                        
                        
def int_hexagon_V6_vdmpyhb_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhb_128B">;

  
                                                         
                       
def int_hexagon_V6_vdmpyhb_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vdmpyhb_acc">;

  
                                                              
                            
def int_hexagon_V6_vdmpyhb_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhb_acc_128B">;

  
                                                      
                      
def int_hexagon_V6_vdmpyhb_dv :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhb_dv">;

  
                                                           
                           
def int_hexagon_V6_vdmpyhb_dv_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vdmpyhb_dv_128B">;

  
                                                            
                          
def int_hexagon_V6_vdmpyhb_dv_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhb_dv_acc">;

  
                                                                 
                               
def int_hexagon_V6_vdmpyhb_dv_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vdmpyhb_dv_acc_128B">;

  
                                                      
                      
def int_hexagon_V6_vdmpyhvsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vdmpyhvsat">;

  
                                                           
                           
def int_hexagon_V6_vdmpyhvsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vdmpyhvsat_128B">;

  
                                                            
                          
def int_hexagon_V6_vdmpyhvsat_acc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vdmpyhvsat_acc">;

  
                                                                 
                               
def int_hexagon_V6_vdmpyhvsat_acc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vdmpyhvsat_acc_128B">;

  
                                                     
                     
def int_hexagon_V6_vdmpyhsat :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vdmpyhsat">;

  
                                                          
                          
def int_hexagon_V6_vdmpyhsat_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhsat_128B">;

  
                                                           
                         
def int_hexagon_V6_vdmpyhsat_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vdmpyhsat_acc">;

  
                                                                
                              
def int_hexagon_V6_vdmpyhsat_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhsat_acc_128B">;

  
                                                      
                      
def int_hexagon_V6_vdmpyhisat :
Hexagon_v512v1024i_Intrinsic<"HEXAGON_V6_vdmpyhisat">;

  
                                                           
                           
def int_hexagon_V6_vdmpyhisat_128B :
Hexagon_v1024v2048i_Intrinsic<"HEXAGON_V6_vdmpyhisat_128B">;

  
                                                            
                          
def int_hexagon_V6_vdmpyhisat_acc :
Hexagon_v512v512v1024i_Intrinsic<"HEXAGON_V6_vdmpyhisat_acc">;

  
                                                                 
                               
def int_hexagon_V6_vdmpyhisat_acc_128B :
Hexagon_v1024v1024v2048i_Intrinsic<"HEXAGON_V6_vdmpyhisat_acc_128B">;

  
                                                       
                       
def int_hexagon_V6_vdmpyhsusat :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vdmpyhsusat">;

  
                                                            
                            
def int_hexagon_V6_vdmpyhsusat_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhsusat_128B">;

  
                                                             
                           
def int_hexagon_V6_vdmpyhsusat_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vdmpyhsusat_acc">;

  
                                                                  
                                
def int_hexagon_V6_vdmpyhsusat_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vdmpyhsusat_acc_128B">;

  
                                                        
                        
def int_hexagon_V6_vdmpyhsuisat :
Hexagon_v512v1024i_Intrinsic<"HEXAGON_V6_vdmpyhsuisat">;

  
                                                             
                             
def int_hexagon_V6_vdmpyhsuisat_128B :
Hexagon_v1024v2048i_Intrinsic<"HEXAGON_V6_vdmpyhsuisat_128B">;

  
                                                              
                            
def int_hexagon_V6_vdmpyhsuisat_acc :
Hexagon_v512v512v1024i_Intrinsic<"HEXAGON_V6_vdmpyhsuisat_acc">;

  
                                                                   
                                 
def int_hexagon_V6_vdmpyhsuisat_acc_128B :
Hexagon_v1024v1024v2048i_Intrinsic<"HEXAGON_V6_vdmpyhsuisat_acc_128B">;

  
                                                  
                  
def int_hexagon_V6_vtmpyb :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vtmpyb">;

  
                                                       
                       
def int_hexagon_V6_vtmpyb_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vtmpyb_128B">;

  
                                                        
                      
def int_hexagon_V6_vtmpyb_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vtmpyb_acc">;

  
                                                             
                           
def int_hexagon_V6_vtmpyb_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vtmpyb_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vtmpybus :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vtmpybus">;

  
                                                         
                         
def int_hexagon_V6_vtmpybus_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vtmpybus_128B">;

  
                                                          
                        
def int_hexagon_V6_vtmpybus_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vtmpybus_acc">;

  
                                                               
                             
def int_hexagon_V6_vtmpybus_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vtmpybus_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vtmpyhb :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vtmpyhb">;

  
                                                        
                        
def int_hexagon_V6_vtmpyhb_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vtmpyhb_128B">;

  
                                                         
                       
def int_hexagon_V6_vtmpyhb_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vtmpyhb_acc">;

  
                                                              
                            
def int_hexagon_V6_vtmpyhb_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vtmpyhb_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vrmpyub :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vrmpyub">;

  
                                                        
                        
def int_hexagon_V6_vrmpyub_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vrmpyub_128B">;

  
                                                         
                       
def int_hexagon_V6_vrmpyub_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vrmpyub_acc">;

  
                                                              
                            
def int_hexagon_V6_vrmpyub_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vrmpyub_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vrmpyubv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vrmpyubv">;

  
                                                         
                         
def int_hexagon_V6_vrmpyubv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrmpyubv_128B">;

  
                                                          
                        
def int_hexagon_V6_vrmpyubv_acc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vrmpyubv_acc">;

  
                                                               
                             
def int_hexagon_V6_vrmpyubv_acc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrmpyubv_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vrmpybv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vrmpybv">;

  
                                                        
                        
def int_hexagon_V6_vrmpybv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrmpybv_128B">;

  
                                                         
                       
def int_hexagon_V6_vrmpybv_acc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vrmpybv_acc">;

  
                                                              
                            
def int_hexagon_V6_vrmpybv_acc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrmpybv_acc_128B">;

  
                                                      
                    
def int_hexagon_V6_vrmpyubi :
Hexagon_v1024v1024ii_Intrinsic<"HEXAGON_V6_vrmpyubi">;

  
                                                           
                         
def int_hexagon_V6_vrmpyubi_128B :
Hexagon_v2048v2048ii_Intrinsic<"HEXAGON_V6_vrmpyubi_128B">;

  
                                                            
                        
def int_hexagon_V6_vrmpyubi_acc :
Hexagon_v1024v1024v1024ii_Intrinsic<"HEXAGON_V6_vrmpyubi_acc">;

  
                                                                 
                             
def int_hexagon_V6_vrmpyubi_acc_128B :
Hexagon_v2048v2048v2048ii_Intrinsic<"HEXAGON_V6_vrmpyubi_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vrmpybus :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vrmpybus">;

  
                                                         
                         
def int_hexagon_V6_vrmpybus_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vrmpybus_128B">;

  
                                                          
                        
def int_hexagon_V6_vrmpybus_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vrmpybus_acc">;

  
                                                               
                             
def int_hexagon_V6_vrmpybus_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vrmpybus_acc_128B">;

  
                                                       
                     
def int_hexagon_V6_vrmpybusi :
Hexagon_v1024v1024ii_Intrinsic<"HEXAGON_V6_vrmpybusi">;

  
                                                            
                          
def int_hexagon_V6_vrmpybusi_128B :
Hexagon_v2048v2048ii_Intrinsic<"HEXAGON_V6_vrmpybusi_128B">;

  
                                                             
                         
def int_hexagon_V6_vrmpybusi_acc :
Hexagon_v1024v1024v1024ii_Intrinsic<"HEXAGON_V6_vrmpybusi_acc">;

  
                                                                  
                              
def int_hexagon_V6_vrmpybusi_acc_128B :
Hexagon_v2048v2048v2048ii_Intrinsic<"HEXAGON_V6_vrmpybusi_acc_128B">;

  
                                                     
                     
def int_hexagon_V6_vrmpybusv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vrmpybusv">;

  
                                                          
                          
def int_hexagon_V6_vrmpybusv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrmpybusv_128B">;

  
                                                           
                         
def int_hexagon_V6_vrmpybusv_acc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vrmpybusv_acc">;

  
                                                                
                              
def int_hexagon_V6_vrmpybusv_acc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrmpybusv_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vdsaduh :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vdsaduh">;

  
                                                        
                        
def int_hexagon_V6_vdsaduh_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vdsaduh_128B">;

  
                                                         
                       
def int_hexagon_V6_vdsaduh_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vdsaduh_acc">;

  
                                                              
                            
def int_hexagon_V6_vdsaduh_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vdsaduh_acc_128B">;

  
                                                      
                    
def int_hexagon_V6_vrsadubi :
Hexagon_v1024v1024ii_Intrinsic<"HEXAGON_V6_vrsadubi">;

  
                                                           
                         
def int_hexagon_V6_vrsadubi_128B :
Hexagon_v2048v2048ii_Intrinsic<"HEXAGON_V6_vrsadubi_128B">;

  
                                                            
                        
def int_hexagon_V6_vrsadubi_acc :
Hexagon_v1024v1024v1024ii_Intrinsic<"HEXAGON_V6_vrsadubi_acc">;

  
                                                                 
                             
def int_hexagon_V6_vrsadubi_acc_128B :
Hexagon_v2048v2048v2048ii_Intrinsic<"HEXAGON_V6_vrsadubi_acc_128B">;

  
                                                 
                 
def int_hexagon_V6_vasrw :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vasrw">;

  
                                                      
                      
def int_hexagon_V6_vasrw_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vasrw_128B">;


  
                                                 
                 
def int_hexagon_V6_vaslw :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vaslw">;

  
                                                      
                      
def int_hexagon_V6_vaslw_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vaslw_128B">;

  
                                                 
                 
def int_hexagon_V6_vlsrw :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vlsrw">;

  
                                                      
                      
def int_hexagon_V6_vlsrw_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vlsrw_128B">;

  
                                                  
                  
def int_hexagon_V6_vasrwv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vasrwv">;

  
                                                       
                       
def int_hexagon_V6_vasrwv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vasrwv_128B">;

  
                                                  
                  
def int_hexagon_V6_vaslwv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaslwv">;

  
                                                       
                       
def int_hexagon_V6_vaslwv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaslwv_128B">;

  
                                                  
                  
def int_hexagon_V6_vlsrwv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vlsrwv">;

  
                                                       
                       
def int_hexagon_V6_vlsrwv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vlsrwv_128B">;

  
                                                 
                 
def int_hexagon_V6_vasrh :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vasrh">;

  
                                                      
                      
def int_hexagon_V6_vasrh_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vasrh_128B">;

  
                                                 
                 
def int_hexagon_V6_vaslh :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vaslh">;

  
                                                      
                      
def int_hexagon_V6_vaslh_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vaslh_128B">;

  
                                                 
                 
def int_hexagon_V6_vlsrh :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vlsrh">;

  
                                                      
                      
def int_hexagon_V6_vlsrh_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vlsrh_128B">;

  
                                                  
                  
def int_hexagon_V6_vasrhv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vasrhv">;

  
                                                       
                       
def int_hexagon_V6_vasrhv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vasrhv_128B">;

  
                                                  
                  
def int_hexagon_V6_vaslhv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaslhv">;

  
                                                       
                       
def int_hexagon_V6_vaslhv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaslhv_128B">;

  
                                                  
                  
def int_hexagon_V6_vlsrhv :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vlsrhv">;

  
                                                       
                       
def int_hexagon_V6_vlsrhv_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vlsrhv_128B">;

  
                                                    
                  
def int_hexagon_V6_vasrwh :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrwh">;

  
                                                         
                       
def int_hexagon_V6_vasrwh_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrwh_128B">;

  
                                                       
                     
def int_hexagon_V6_vasrwhsat :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrwhsat">;

  
                                                            
                          
def int_hexagon_V6_vasrwhsat_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrwhsat_128B">;

  
                                                          
                        
def int_hexagon_V6_vasrwhrndsat :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrwhrndsat">;

  
                                                               
                             
def int_hexagon_V6_vasrwhrndsat_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrwhrndsat_128B">;

  
                                                        
                      
def int_hexagon_V6_vasrwuhsat :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrwuhsat">;

  
                                                             
                           
def int_hexagon_V6_vasrwuhsat_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrwuhsat_128B">;

  
                                                    
                    
def int_hexagon_V6_vroundwh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vroundwh">;

  
                                                         
                         
def int_hexagon_V6_vroundwh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vroundwh_128B">;

  
                                                     
                     
def int_hexagon_V6_vroundwuh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vroundwuh">;

  
                                                          
                          
def int_hexagon_V6_vroundwuh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vroundwuh_128B">;

  
                                                        
                      
def int_hexagon_V6_vasrhubsat :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrhubsat">;

  
                                                             
                           
def int_hexagon_V6_vasrhubsat_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrhubsat_128B">;

  
                                                           
                         
def int_hexagon_V6_vasrhubrndsat :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrhubrndsat">;

  
                                                                
                              
def int_hexagon_V6_vasrhubrndsat_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrhubrndsat_128B">;

  
                                                          
                        
def int_hexagon_V6_vasrhbrndsat :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrhbrndsat">;

  
                                                               
                             
def int_hexagon_V6_vasrhbrndsat_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrhbrndsat_128B">;

  
                                                    
                    
def int_hexagon_V6_vroundhb :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vroundhb">;

  
                                                         
                         
def int_hexagon_V6_vroundhb_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vroundhb_128B">;

  
                                                     
                     
def int_hexagon_V6_vroundhub :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vroundhub">;

  
                                                          
                          
def int_hexagon_V6_vroundhub_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vroundhub_128B">;

  
                                                       
                     
def int_hexagon_V6_vaslw_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vaslw_acc">;

  
                                                            
                          
def int_hexagon_V6_vaslw_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vaslw_acc_128B">;

  
                                                       
                     
def int_hexagon_V6_vasrw_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrw_acc">;

  
                                                            
                          
def int_hexagon_V6_vasrw_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrw_acc_128B">;

  
                                                 
                 
def int_hexagon_V6_vaddb :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaddb">;

  
                                                      
                      
def int_hexagon_V6_vaddb_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddb_128B">;

  
                                                 
                 
def int_hexagon_V6_vsubb :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsubb">;

  
                                                      
                      
def int_hexagon_V6_vsubb_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubb_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddb_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddb_dv">;

  
                                                         
                         
def int_hexagon_V6_vaddb_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vaddb_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vsubb_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubb_dv">;

  
                                                         
                         
def int_hexagon_V6_vsubb_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubb_dv_128B">;

  
                                                 
                 
def int_hexagon_V6_vaddh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaddh">;

  
                                                      
                      
def int_hexagon_V6_vaddh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddh_128B">;

  
                                                 
                 
def int_hexagon_V6_vsubh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsubh">;

  
                                                      
                      
def int_hexagon_V6_vsubh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubh_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddh_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddh_dv">;

  
                                                         
                         
def int_hexagon_V6_vaddh_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vaddh_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vsubh_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubh_dv">;

  
                                                         
                         
def int_hexagon_V6_vsubh_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubh_dv_128B">;

  
                                                 
                 
def int_hexagon_V6_vaddw :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaddw">;

  
                                                      
                      
def int_hexagon_V6_vaddw_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddw_128B">;

  
                                                 
                 
def int_hexagon_V6_vsubw :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsubw">;

  
                                                      
                      
def int_hexagon_V6_vsubw_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubw_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddw_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddw_dv">;

  
                                                         
                         
def int_hexagon_V6_vaddw_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vaddw_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vsubw_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubw_dv">;

  
                                                         
                         
def int_hexagon_V6_vsubw_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubw_dv_128B">;

  
                                                     
                     
def int_hexagon_V6_vaddubsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaddubsat">;

  
                                                          
                          
def int_hexagon_V6_vaddubsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddubsat_128B">;

  
                                                        
                        
def int_hexagon_V6_vaddubsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddubsat_dv">;

  
                                                             
                             
def int_hexagon_V6_vaddubsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vaddubsat_dv_128B">;

  
                                                     
                     
def int_hexagon_V6_vsububsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsububsat">;

  
                                                          
                          
def int_hexagon_V6_vsububsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsububsat_128B">;

  
                                                        
                        
def int_hexagon_V6_vsububsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsububsat_dv">;

  
                                                             
                             
def int_hexagon_V6_vsububsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsububsat_dv_128B">;

  
                                                     
                     
def int_hexagon_V6_vadduhsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vadduhsat">;

  
                                                          
                          
def int_hexagon_V6_vadduhsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vadduhsat_128B">;

  
                                                        
                        
def int_hexagon_V6_vadduhsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vadduhsat_dv">;

  
                                                             
                             
def int_hexagon_V6_vadduhsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vadduhsat_dv_128B">;

  
                                                     
                     
def int_hexagon_V6_vsubuhsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsubuhsat">;

  
                                                          
                          
def int_hexagon_V6_vsubuhsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubuhsat_128B">;

  
                                                        
                        
def int_hexagon_V6_vsubuhsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubuhsat_dv">;

  
                                                             
                             
def int_hexagon_V6_vsubuhsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubuhsat_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddhsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaddhsat">;

  
                                                         
                         
def int_hexagon_V6_vaddhsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddhsat_128B">;

  
                                                       
                       
def int_hexagon_V6_vaddhsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddhsat_dv">;

  
                                                            
                            
def int_hexagon_V6_vaddhsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vaddhsat_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vsubhsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsubhsat">;

  
                                                         
                         
def int_hexagon_V6_vsubhsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubhsat_128B">;

  
                                                       
                       
def int_hexagon_V6_vsubhsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubhsat_dv">;

  
                                                            
                            
def int_hexagon_V6_vsubhsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubhsat_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddwsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vaddwsat">;

  
                                                         
                         
def int_hexagon_V6_vaddwsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddwsat_128B">;

  
                                                       
                       
def int_hexagon_V6_vaddwsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddwsat_dv">;

  
                                                            
                            
def int_hexagon_V6_vaddwsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vaddwsat_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vsubwsat :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsubwsat">;

  
                                                         
                         
def int_hexagon_V6_vsubwsat_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubwsat_128B">;

  
                                                       
                       
def int_hexagon_V6_vsubwsat_dv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubwsat_dv">;

  
                                                            
                            
def int_hexagon_V6_vsubwsat_dv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubwsat_dv_128B">;

  
                                                  
                  
def int_hexagon_V6_vavgub :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavgub">;

  
                                                       
                       
def int_hexagon_V6_vavgub_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavgub_128B">;

  
                                                     
                     
def int_hexagon_V6_vavgubrnd :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavgubrnd">;

  
                                                          
                          
def int_hexagon_V6_vavgubrnd_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavgubrnd_128B">;

  
                                                  
                  
def int_hexagon_V6_vavguh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavguh">;

  
                                                       
                       
def int_hexagon_V6_vavguh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavguh_128B">;

  
                                                     
                     
def int_hexagon_V6_vavguhrnd :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavguhrnd">;

  
                                                          
                          
def int_hexagon_V6_vavguhrnd_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavguhrnd_128B">;

  
                                                 
                 
def int_hexagon_V6_vavgh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavgh">;

  
                                                      
                      
def int_hexagon_V6_vavgh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavgh_128B">;

  
                                                    
                    
def int_hexagon_V6_vavghrnd :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavghrnd">;

  
                                                         
                         
def int_hexagon_V6_vavghrnd_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavghrnd_128B">;

  
                                                  
                  
def int_hexagon_V6_vnavgh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vnavgh">;

  
                                                       
                       
def int_hexagon_V6_vnavgh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vnavgh_128B">;

  
                                                 
                 
def int_hexagon_V6_vavgw :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavgw">;

  
                                                      
                      
def int_hexagon_V6_vavgw_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavgw_128B">;

  
                                                    
                    
def int_hexagon_V6_vavgwrnd :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vavgwrnd">;

  
                                                         
                         
def int_hexagon_V6_vavgwrnd_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavgwrnd_128B">;

  
                                                  
                  
def int_hexagon_V6_vnavgw :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vnavgw">;

  
                                                       
                       
def int_hexagon_V6_vnavgw_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vnavgw_128B">;

  
                                                      
                      
def int_hexagon_V6_vabsdiffub :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vabsdiffub">;

  
                                                           
                           
def int_hexagon_V6_vabsdiffub_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vabsdiffub_128B">;

  
                                                      
                      
def int_hexagon_V6_vabsdiffuh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vabsdiffuh">;

  
                                                           
                           
def int_hexagon_V6_vabsdiffuh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vabsdiffuh_128B">;

  
                                                     
                     
def int_hexagon_V6_vabsdiffh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vabsdiffh">;

  
                                                          
                          
def int_hexagon_V6_vabsdiffh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vabsdiffh_128B">;

  
                                                     
                     
def int_hexagon_V6_vabsdiffw :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vabsdiffw">;

  
                                                          
                          
def int_hexagon_V6_vabsdiffw_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vabsdiffw_128B">;

  
                                                   
                   
def int_hexagon_V6_vnavgub :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vnavgub">;

  
                                                        
                        
def int_hexagon_V6_vnavgub_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vnavgub_128B">;

  
                                                   
                   
def int_hexagon_V6_vaddubh :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vaddubh">;

  
                                                        
                        
def int_hexagon_V6_vaddubh_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vaddubh_128B">;

  
                                                   
                   
def int_hexagon_V6_vsububh :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vsububh">;

  
                                                        
                        
def int_hexagon_V6_vsububh_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vsububh_128B">;

  
                                                  
                  
def int_hexagon_V6_vaddhw :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vaddhw">;

  
                                                       
                       
def int_hexagon_V6_vaddhw_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vaddhw_128B">;

  
                                                  
                  
def int_hexagon_V6_vsubhw :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vsubhw">;

  
                                                       
                       
def int_hexagon_V6_vsubhw_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vsubhw_128B">;

  
                                                   
                   
def int_hexagon_V6_vadduhw :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vadduhw">;

  
                                                        
                        
def int_hexagon_V6_vadduhw_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vadduhw_128B">;

  
                                                   
                   
def int_hexagon_V6_vsubuhw :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vsubuhw">;

  
                                                        
                        
def int_hexagon_V6_vsubuhw_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vsubuhw_128B">;

  
                                           
               
def int_hexagon_V6_vd0 :
Hexagon_v512_Intrinsic<"HEXAGON_V6_vd0">;

  
                                                
                    
def int_hexagon_V6_vd0_128B :
Hexagon_v1024_Intrinsic<"HEXAGON_V6_vd0_128B">;

  
                                                    
                  
def int_hexagon_V6_vaddbq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vaddbq">;

  
                                                         
                       
def int_hexagon_V6_vaddbq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vaddbq_128B">;


  
                                                    
                  
def int_hexagon_V6_vsubbq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vsubbq">;

  
                                                         
                       
def int_hexagon_V6_vsubbq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vsubbq_128B">;

  
                                                     
                   
def int_hexagon_V6_vaddbnq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vaddbnq">;

  
                                                          
                        
def int_hexagon_V6_vaddbnq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vaddbnq_128B">;

  
                                                     
                   
def int_hexagon_V6_vsubbnq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vsubbnq">;

  
                                                          
                        
def int_hexagon_V6_vsubbnq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vsubbnq_128B">;

  
                                                    
                  
def int_hexagon_V6_vaddhq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vaddhq">;

  
                                                         
                       
def int_hexagon_V6_vaddhq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vaddhq_128B">;

  
                                                    
                  
def int_hexagon_V6_vsubhq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vsubhq">;

  
                                                         
                       
def int_hexagon_V6_vsubhq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vsubhq_128B">;

  
                                                     
                   
def int_hexagon_V6_vaddhnq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vaddhnq">;

  
                                                          
                        
def int_hexagon_V6_vaddhnq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vaddhnq_128B">;

  
                                                     
                   
def int_hexagon_V6_vsubhnq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vsubhnq">;

  
                                                          
                        
def int_hexagon_V6_vsubhnq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vsubhnq_128B">;

  
                                                    
                  
def int_hexagon_V6_vaddwq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vaddwq">;

  
                                                         
                       
def int_hexagon_V6_vaddwq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vaddwq_128B">;

  
                                                    
                  
def int_hexagon_V6_vsubwq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vsubwq">;

  
                                                         
                       
def int_hexagon_V6_vsubwq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vsubwq_128B">;

  
                                                     
                   
def int_hexagon_V6_vaddwnq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vaddwnq">;

  
                                                          
                        
def int_hexagon_V6_vaddwnq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vaddwnq_128B">;

  
                                                     
                   
def int_hexagon_V6_vsubwnq :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vsubwnq">;

  
                                                          
                        
def int_hexagon_V6_vsubwnq_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vsubwnq_128B">;

  
                                               
                 
def int_hexagon_V6_vabsh :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vabsh">;

  
                                                    
                      
def int_hexagon_V6_vabsh_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vabsh_128B">;

  
                                                   
                     
def int_hexagon_V6_vabsh_sat :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vabsh_sat">;

  
                                                        
                          
def int_hexagon_V6_vabsh_sat_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vabsh_sat_128B">;

  
                                               
                 
def int_hexagon_V6_vabsw :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vabsw">;

  
                                                    
                      
def int_hexagon_V6_vabsw_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vabsw_128B">;

  
                                                   
                     
def int_hexagon_V6_vabsw_sat :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vabsw_sat">;

  
                                                        
                          
def int_hexagon_V6_vabsw_sat_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vabsw_sat_128B">;

  
                                                  
                  
def int_hexagon_V6_vmpybv :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vmpybv">;

  
                                                       
                       
def int_hexagon_V6_vmpybv_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpybv_128B">;

  
                                                        
                      
def int_hexagon_V6_vmpybv_acc :
Hexagon_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vmpybv_acc">;

  
                                                             
                           
def int_hexagon_V6_vmpybv_acc_128B :
Hexagon_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpybv_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyubv :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyubv">;

  
                                                        
                        
def int_hexagon_V6_vmpyubv_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyubv_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpyubv_acc :
Hexagon_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyubv_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpyubv_acc_128B :
Hexagon_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyubv_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpybusv :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vmpybusv">;

  
                                                         
                         
def int_hexagon_V6_vmpybusv_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpybusv_128B">;

  
                                                          
                        
def int_hexagon_V6_vmpybusv_acc :
Hexagon_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vmpybusv_acc">;

  
                                                               
                             
def int_hexagon_V6_vmpybusv_acc_128B :
Hexagon_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpybusv_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpabusv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpabusv">;

  
                                                         
                         
def int_hexagon_V6_vmpabusv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vmpabusv_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpabuuv :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpabuuv">;

  
                                                         
                         
def int_hexagon_V6_vmpabuuv_128B :
Hexagon_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vmpabuuv_128B">;

  
                                                  
                  
def int_hexagon_V6_vmpyhv :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyhv">;

  
                                                       
                       
def int_hexagon_V6_vmpyhv_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyhv_128B">;

  
                                                        
                      
def int_hexagon_V6_vmpyhv_acc :
Hexagon_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyhv_acc">;

  
                                                             
                           
def int_hexagon_V6_vmpyhv_acc_128B :
Hexagon_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyhv_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyuhv :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyuhv">;

  
                                                        
                        
def int_hexagon_V6_vmpyuhv_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyuhv_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpyuhv_acc :
Hexagon_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyuhv_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpyuhv_acc_128B :
Hexagon_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyuhv_acc_128B">;

  
                                                     
                     
def int_hexagon_V6_vmpyhvsrs :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyhvsrs">;

  
                                                          
                          
def int_hexagon_V6_vmpyhvsrs_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyhvsrs_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyhus :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyhus">;

  
                                                        
                        
def int_hexagon_V6_vmpyhus_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyhus_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpyhus_acc :
Hexagon_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyhus_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpyhus_acc_128B :
Hexagon_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyhus_acc_128B">;

  
                                                  
                  
def int_hexagon_V6_vmpyih :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyih">;

  
                                                       
                       
def int_hexagon_V6_vmpyih_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyih_128B">;

  
                                                        
                      
def int_hexagon_V6_vmpyih_acc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vmpyih_acc">;

  
                                                             
                           
def int_hexagon_V6_vmpyih_acc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyih_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpyewuh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyewuh">;

  
                                                         
                         
def int_hexagon_V6_vmpyewuh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyewuh_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyowh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyowh">;

  
                                                        
                        
def int_hexagon_V6_vmpyowh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyowh_128B">;

  
                                                       
                       
def int_hexagon_V6_vmpyowh_rnd :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyowh_rnd">;

  
                                                            
                            
def int_hexagon_V6_vmpyowh_rnd_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyowh_rnd_128B">;

  
                                                          
                        
def int_hexagon_V6_vmpyowh_sacc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vmpyowh_sacc">;

  
                                                               
                             
def int_hexagon_V6_vmpyowh_sacc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyowh_sacc_128B">;

  
                                                              
                            
def int_hexagon_V6_vmpyowh_rnd_sacc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vmpyowh_rnd_sacc">;

  
                                                                   
                                 
def int_hexagon_V6_vmpyowh_rnd_sacc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyowh_rnd_sacc_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpyieoh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyieoh">;

  
                                                         
                         
def int_hexagon_V6_vmpyieoh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyieoh_128B">;

  
                                                     
                     
def int_hexagon_V6_vmpyiewuh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyiewuh">;

  
                                                          
                          
def int_hexagon_V6_vmpyiewuh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyiewuh_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpyiowh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmpyiowh">;

  
                                                         
                         
def int_hexagon_V6_vmpyiowh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyiowh_128B">;

  
                                                          
                        
def int_hexagon_V6_vmpyiewh_acc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vmpyiewh_acc">;

  
                                                               
                             
def int_hexagon_V6_vmpyiewh_acc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyiewh_acc_128B">;

  
                                                           
                         
def int_hexagon_V6_vmpyiewuh_acc :
Hexagon_v512v512v512v512_Intrinsic<"HEXAGON_V6_vmpyiewuh_acc">;

  
                                                                
                              
def int_hexagon_V6_vmpyiewuh_acc_128B :
Hexagon_v1024v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmpyiewuh_acc_128B">;

  
                                                  
                  
def int_hexagon_V6_vmpyub :
Hexagon_v1024v512i_Intrinsic<"HEXAGON_V6_vmpyub">;

  
                                                       
                       
def int_hexagon_V6_vmpyub_128B :
Hexagon_v2048v1024i_Intrinsic<"HEXAGON_V6_vmpyub_128B">;

  
                                                        
                      
def int_hexagon_V6_vmpyub_acc :
Hexagon_v1024v1024v512i_Intrinsic<"HEXAGON_V6_vmpyub_acc">;

  
                                                             
                           
def int_hexagon_V6_vmpyub_acc_128B :
Hexagon_v2048v2048v1024i_Intrinsic<"HEXAGON_V6_vmpyub_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpybus :
Hexagon_v1024v512i_Intrinsic<"HEXAGON_V6_vmpybus">;

  
                                                        
                        
def int_hexagon_V6_vmpybus_128B :
Hexagon_v2048v1024i_Intrinsic<"HEXAGON_V6_vmpybus_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpybus_acc :
Hexagon_v1024v1024v512i_Intrinsic<"HEXAGON_V6_vmpybus_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpybus_acc_128B :
Hexagon_v2048v2048v1024i_Intrinsic<"HEXAGON_V6_vmpybus_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpabus :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpabus">;

  
                                                        
                        
def int_hexagon_V6_vmpabus_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vmpabus_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpabus_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpabus_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpabus_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vmpabus_acc_128B">;

  
                                                  
                  
def int_hexagon_V6_vmpahb :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpahb">;

  
                                                       
                       
def int_hexagon_V6_vmpahb_128B :
Hexagon_v2048v2048i_Intrinsic<"HEXAGON_V6_vmpahb_128B">;

  
                                                        
                      
def int_hexagon_V6_vmpahb_acc :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpahb_acc">;

  
                                                             
                           
def int_hexagon_V6_vmpahb_acc_128B :
Hexagon_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vmpahb_acc_128B">;

  
                                                 
                 
def int_hexagon_V6_vmpyh :
Hexagon_v1024v512i_Intrinsic<"HEXAGON_V6_vmpyh">;

  
                                                      
                      
def int_hexagon_V6_vmpyh_128B :
Hexagon_v2048v1024i_Intrinsic<"HEXAGON_V6_vmpyh_128B">;

  
                                                          
                        
def int_hexagon_V6_vmpyhsat_acc :
Hexagon_v1024v1024v512i_Intrinsic<"HEXAGON_V6_vmpyhsat_acc">;

  
                                                               
                             
def int_hexagon_V6_vmpyhsat_acc_128B :
Hexagon_v2048v2048v1024i_Intrinsic<"HEXAGON_V6_vmpyhsat_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyhss :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vmpyhss">;

  
                                                        
                        
def int_hexagon_V6_vmpyhss_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyhss_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpyhsrs :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vmpyhsrs">;

  
                                                         
                         
def int_hexagon_V6_vmpyhsrs_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyhsrs_128B">;

  
                                                  
                  
def int_hexagon_V6_vmpyuh :
Hexagon_v1024v512i_Intrinsic<"HEXAGON_V6_vmpyuh">;

  
                                                       
                       
def int_hexagon_V6_vmpyuh_128B :
Hexagon_v2048v1024i_Intrinsic<"HEXAGON_V6_vmpyuh_128B">;

  
                                                        
                      
def int_hexagon_V6_vmpyuh_acc :
Hexagon_v1024v1024v512i_Intrinsic<"HEXAGON_V6_vmpyuh_acc">;

  
                                                             
                           
def int_hexagon_V6_vmpyuh_acc_128B :
Hexagon_v2048v2048v1024i_Intrinsic<"HEXAGON_V6_vmpyuh_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyihb :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vmpyihb">;

  
                                                        
                        
def int_hexagon_V6_vmpyihb_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyihb_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpyihb_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vmpyihb_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpyihb_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyihb_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyiwb :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vmpyiwb">;

  
                                                        
                        
def int_hexagon_V6_vmpyiwb_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyiwb_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpyiwb_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vmpyiwb_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpyiwb_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyiwb_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyiwh :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vmpyiwh">;

  
                                                        
                        
def int_hexagon_V6_vmpyiwh_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyiwh_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpyiwh_acc :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vmpyiwh_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpyiwh_acc_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyiwh_acc_128B">;

  
                                                
                
def int_hexagon_V6_vand :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vand">;

  
                                                     
                     
def int_hexagon_V6_vand_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vand_128B">;

  
                                               
               
def int_hexagon_V6_vor :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vor">;

  
                                                    
                    
def int_hexagon_V6_vor_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vor_128B">;

  
                                                
                
def int_hexagon_V6_vxor :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vxor">;

  
                                                     
                     
def int_hexagon_V6_vxor_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vxor_128B">;

  
                                              
                
def int_hexagon_V6_vnot :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vnot">;

  
                                                   
                     
def int_hexagon_V6_vnot_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vnot_128B">;

  
                                                   
                   
def int_hexagon_V6_vandqrt :
Hexagon_v512v64ii_Intrinsic<"HEXAGON_V6_vandqrt">;

  
                                                        
                        
def int_hexagon_V6_vandqrt_128B :
Hexagon_v1024v128ii_Intrinsic<"HEXAGON_V6_vandqrt_128B">;

  
                                                         
                       
def int_hexagon_V6_vandqrt_acc :
Hexagon_v512v512v64ii_Intrinsic<"HEXAGON_V6_vandqrt_acc">;

  
                                                              
                            
def int_hexagon_V6_vandqrt_acc_128B :
Hexagon_v1024v1024v128ii_Intrinsic<"HEXAGON_V6_vandqrt_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vandvrt :
Hexagon_v64iv512i_Intrinsic<"HEXAGON_V6_vandvrt">;

  
                                                        
                        
def int_hexagon_V6_vandvrt_128B :
Hexagon_v128iv1024i_Intrinsic<"HEXAGON_V6_vandvrt_128B">;

  
                                                         
                       
def int_hexagon_V6_vandvrt_acc :
Hexagon_v64iv64iv512i_Intrinsic<"HEXAGON_V6_vandvrt_acc">;

  
                                                              
                            
def int_hexagon_V6_vandvrt_acc_128B :
Hexagon_v128iv128iv1024i_Intrinsic<"HEXAGON_V6_vandvrt_acc_128B">;

  
                                                
                
def int_hexagon_V6_vgtw :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_vgtw">;

  
                                                     
                     
def int_hexagon_V6_vgtw_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtw_128B">;

  
                                                      
                    
def int_hexagon_V6_vgtw_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtw_and">;

  
                                                           
                         
def int_hexagon_V6_vgtw_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtw_and_128B">;

  
                                                     
                   
def int_hexagon_V6_vgtw_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtw_or">;

  
                                                          
                        
def int_hexagon_V6_vgtw_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtw_or_128B">;

  
                                                      
                    
def int_hexagon_V6_vgtw_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtw_xor">;

  
                                                           
                         
def int_hexagon_V6_vgtw_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtw_xor_128B">;

  
                                                
                
def int_hexagon_V6_veqw :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_veqw">;

  
                                                     
                     
def int_hexagon_V6_veqw_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_veqw_128B">;

  
                                                      
                    
def int_hexagon_V6_veqw_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqw_and">;

  
                                                           
                         
def int_hexagon_V6_veqw_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqw_and_128B">;

  
                                                     
                   
def int_hexagon_V6_veqw_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqw_or">;

  
                                                          
                        
def int_hexagon_V6_veqw_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqw_or_128B">;

  
                                                      
                    
def int_hexagon_V6_veqw_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqw_xor">;

  
                                                           
                         
def int_hexagon_V6_veqw_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqw_xor_128B">;

  
                                                
                
def int_hexagon_V6_vgth :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_vgth">;

  
                                                     
                     
def int_hexagon_V6_vgth_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_vgth_128B">;

  
                                                      
                    
def int_hexagon_V6_vgth_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgth_and">;

  
                                                           
                         
def int_hexagon_V6_vgth_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgth_and_128B">;

  
                                                     
                   
def int_hexagon_V6_vgth_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgth_or">;

  
                                                          
                        
def int_hexagon_V6_vgth_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgth_or_128B">;

  
                                                      
                    
def int_hexagon_V6_vgth_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgth_xor">;

  
                                                           
                         
def int_hexagon_V6_vgth_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgth_xor_128B">;

  
                                                
                
def int_hexagon_V6_veqh :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_veqh">;

  
                                                     
                     
def int_hexagon_V6_veqh_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_veqh_128B">;

  
                                                      
                    
def int_hexagon_V6_veqh_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqh_and">;

  
                                                           
                         
def int_hexagon_V6_veqh_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqh_and_128B">;

  
                                                     
                   
def int_hexagon_V6_veqh_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqh_or">;

  
                                                          
                        
def int_hexagon_V6_veqh_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqh_or_128B">;

  
                                                      
                    
def int_hexagon_V6_veqh_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqh_xor">;

  
                                                           
                         
def int_hexagon_V6_veqh_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqh_xor_128B">;

  
                                                
                
def int_hexagon_V6_vgtb :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_vgtb">;

  
                                                     
                     
def int_hexagon_V6_vgtb_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtb_128B">;

  
                                                      
                    
def int_hexagon_V6_vgtb_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtb_and">;

  
                                                           
                         
def int_hexagon_V6_vgtb_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtb_and_128B">;

  
                                                     
                   
def int_hexagon_V6_vgtb_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtb_or">;

  
                                                          
                        
def int_hexagon_V6_vgtb_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtb_or_128B">;

  
                                                      
                    
def int_hexagon_V6_vgtb_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtb_xor">;

  
                                                           
                         
def int_hexagon_V6_vgtb_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtb_xor_128B">;

  
                                                
                
def int_hexagon_V6_veqb :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_veqb">;

  
                                                     
                     
def int_hexagon_V6_veqb_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_veqb_128B">;

  
                                                      
                    
def int_hexagon_V6_veqb_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqb_and">;

  
                                                           
                         
def int_hexagon_V6_veqb_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqb_and_128B">;

  
                                                     
                   
def int_hexagon_V6_veqb_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqb_or">;

  
                                                          
                        
def int_hexagon_V6_veqb_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqb_or_128B">;

  
                                                      
                    
def int_hexagon_V6_veqb_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_veqb_xor">;

  
                                                           
                         
def int_hexagon_V6_veqb_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_veqb_xor_128B">;

  
                                                 
                 
def int_hexagon_V6_vgtuw :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_vgtuw">;

  
                                                      
                      
def int_hexagon_V6_vgtuw_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuw_128B">;

  
                                                       
                     
def int_hexagon_V6_vgtuw_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtuw_and">;

  
                                                            
                          
def int_hexagon_V6_vgtuw_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuw_and_128B">;

  
                                                      
                    
def int_hexagon_V6_vgtuw_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtuw_or">;

  
                                                           
                         
def int_hexagon_V6_vgtuw_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuw_or_128B">;

  
                                                       
                     
def int_hexagon_V6_vgtuw_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtuw_xor">;

  
                                                            
                          
def int_hexagon_V6_vgtuw_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuw_xor_128B">;

  
                                                 
                 
def int_hexagon_V6_vgtuh :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_vgtuh">;

  
                                                      
                      
def int_hexagon_V6_vgtuh_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuh_128B">;

  
                                                       
                     
def int_hexagon_V6_vgtuh_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtuh_and">;

  
                                                            
                          
def int_hexagon_V6_vgtuh_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuh_and_128B">;

  
                                                      
                    
def int_hexagon_V6_vgtuh_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtuh_or">;

  
                                                           
                         
def int_hexagon_V6_vgtuh_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuh_or_128B">;

  
                                                       
                     
def int_hexagon_V6_vgtuh_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtuh_xor">;

  
                                                            
                          
def int_hexagon_V6_vgtuh_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtuh_xor_128B">;

  
                                                 
                 
def int_hexagon_V6_vgtub :
Hexagon_v64iv512v512_Intrinsic<"HEXAGON_V6_vgtub">;

  
                                                      
                      
def int_hexagon_V6_vgtub_128B :
Hexagon_v128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtub_128B">;

  
                                                       
                     
def int_hexagon_V6_vgtub_and :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtub_and">;

  
                                                            
                          
def int_hexagon_V6_vgtub_and_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtub_and_128B">;

  
                                                      
                    
def int_hexagon_V6_vgtub_or :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtub_or">;

  
                                                           
                         
def int_hexagon_V6_vgtub_or_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtub_or_128B">;

  
                                                       
                     
def int_hexagon_V6_vgtub_xor :
Hexagon_v64iv64iv512v512_Intrinsic<"HEXAGON_V6_vgtub_xor">;

  
                                                            
                          
def int_hexagon_V6_vgtub_xor_128B :
Hexagon_v128iv128iv1024v1024_Intrinsic<"HEXAGON_V6_vgtub_xor_128B">;

  
                                                   
                   
def int_hexagon_V6_pred_or :
Hexagon_v64iv64iv64i_Intrinsic<"HEXAGON_V6_pred_or">;

  
                                                        
                        
def int_hexagon_V6_pred_or_128B :
Hexagon_v128iv128iv128i_Intrinsic<"HEXAGON_V6_pred_or_128B">;

  
                                                    
                    
def int_hexagon_V6_pred_and :
Hexagon_v64iv64iv64i_Intrinsic<"HEXAGON_V6_pred_and">;

  
                                                         
                         
def int_hexagon_V6_pred_and_128B :
Hexagon_v128iv128iv128i_Intrinsic<"HEXAGON_V6_pred_and_128B">;

  
                                                  
                    
def int_hexagon_V6_pred_not :
Hexagon_v64iv64i_Intrinsic<"HEXAGON_V6_pred_not">;

  
                                                       
                         
def int_hexagon_V6_pred_not_128B :
Hexagon_v128iv128i_Intrinsic<"HEXAGON_V6_pred_not_128B">;

  
                                                    
                    
def int_hexagon_V6_pred_xor :
Hexagon_v64iv64iv64i_Intrinsic<"HEXAGON_V6_pred_xor">;

  
                                                         
                         
def int_hexagon_V6_pred_xor_128B :
Hexagon_v128iv128iv128i_Intrinsic<"HEXAGON_V6_pred_xor_128B">;

  
                                                      
                      
def int_hexagon_V6_pred_and_n :
Hexagon_v64iv64iv64i_Intrinsic<"HEXAGON_V6_pred_and_n">;

  
                                                           
                           
def int_hexagon_V6_pred_and_n_128B :
Hexagon_v128iv128iv128i_Intrinsic<"HEXAGON_V6_pred_and_n_128B">;

  
                                                     
                     
def int_hexagon_V6_pred_or_n :
Hexagon_v64iv64iv64i_Intrinsic<"HEXAGON_V6_pred_or_n">;

  
                                                          
                          
def int_hexagon_V6_pred_or_n_128B :
Hexagon_v128iv128iv128i_Intrinsic<"HEXAGON_V6_pred_or_n_128B">;

  
                                                      
                        
def int_hexagon_V6_pred_scalar2 :
Hexagon_v64ii_Intrinsic<"HEXAGON_V6_pred_scalar2">;

  
                                                           
                             
def int_hexagon_V6_pred_scalar2_128B :
Hexagon_v128ii_Intrinsic<"HEXAGON_V6_pred_scalar2_128B">;

  
                                                  
                
def int_hexagon_V6_vmux :
Hexagon_v512v64iv512v512_Intrinsic<"HEXAGON_V6_vmux">;

  
                                                       
                     
def int_hexagon_V6_vmux_128B :
Hexagon_v1024v128iv1024v1024_Intrinsic<"HEXAGON_V6_vmux_128B">;

  
                                                   
                 
def int_hexagon_V6_vswap :
Hexagon_v1024v64iv512v512_Intrinsic<"HEXAGON_V6_vswap">;

  
                                                        
                      
def int_hexagon_V6_vswap_128B :
Hexagon_v2048v128iv1024v1024_Intrinsic<"HEXAGON_V6_vswap_128B">;

  
                                                  
                  
def int_hexagon_V6_vmaxub :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmaxub">;

  
                                                       
                       
def int_hexagon_V6_vmaxub_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmaxub_128B">;

  
                                                  
                  
def int_hexagon_V6_vminub :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vminub">;

  
                                                       
                       
def int_hexagon_V6_vminub_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vminub_128B">;

  
                                                  
                  
def int_hexagon_V6_vmaxuh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmaxuh">;

  
                                                       
                       
def int_hexagon_V6_vmaxuh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmaxuh_128B">;

  
                                                  
                  
def int_hexagon_V6_vminuh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vminuh">;

  
                                                       
                       
def int_hexagon_V6_vminuh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vminuh_128B">;

  
                                                 
                 
def int_hexagon_V6_vmaxh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmaxh">;

  
                                                      
                      
def int_hexagon_V6_vmaxh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmaxh_128B">;

  
                                                 
                 
def int_hexagon_V6_vminh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vminh">;

  
                                                      
                      
def int_hexagon_V6_vminh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vminh_128B">;

  
                                                 
                 
def int_hexagon_V6_vmaxw :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vmaxw">;

  
                                                      
                      
def int_hexagon_V6_vmaxw_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmaxw_128B">;

  
                                                 
                 
def int_hexagon_V6_vminw :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vminw">;

  
                                                      
                      
def int_hexagon_V6_vminw_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vminw_128B">;

  
                                                   
                   
def int_hexagon_V6_vsathub :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsathub">;

  
                                                        
                        
def int_hexagon_V6_vsathub_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsathub_128B">;

  
                                                  
                  
def int_hexagon_V6_vsatwh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vsatwh">;

  
                                                       
                       
def int_hexagon_V6_vsatwh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsatwh_128B">;

  
                                                    
                    
def int_hexagon_V6_vshuffeb :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vshuffeb">;

  
                                                         
                         
def int_hexagon_V6_vshuffeb_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vshuffeb_128B">;

  
                                                    
                    
def int_hexagon_V6_vshuffob :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vshuffob">;

  
                                                         
                         
def int_hexagon_V6_vshuffob_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vshuffob_128B">;

  
                                                   
                   
def int_hexagon_V6_vshufeh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vshufeh">;

  
                                                        
                        
def int_hexagon_V6_vshufeh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vshufeh_128B">;

  
                                                   
                   
def int_hexagon_V6_vshufoh :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vshufoh">;

  
                                                        
                        
def int_hexagon_V6_vshufoh_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vshufoh_128B">;

  
                                                       
                     
def int_hexagon_V6_vshuffvdd :
Hexagon_v1024v512v512i_Intrinsic<"HEXAGON_V6_vshuffvdd">;

  
                                                            
                          
def int_hexagon_V6_vshuffvdd_128B :
Hexagon_v2048v1024v1024i_Intrinsic<"HEXAGON_V6_vshuffvdd_128B">;

  
                                                      
                    
def int_hexagon_V6_vdealvdd :
Hexagon_v1024v512v512i_Intrinsic<"HEXAGON_V6_vdealvdd">;

  
                                                           
                         
def int_hexagon_V6_vdealvdd_128B :
Hexagon_v2048v1024v1024i_Intrinsic<"HEXAGON_V6_vdealvdd_128B">;

  
                                                    
                    
def int_hexagon_V6_vshufoeh :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vshufoeh">;

  
                                                         
                         
def int_hexagon_V6_vshufoeh_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vshufoeh_128B">;

  
                                                    
                    
def int_hexagon_V6_vshufoeb :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vshufoeb">;

  
                                                         
                         
def int_hexagon_V6_vshufoeb_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vshufoeb_128B">;

  
                                                
                  
def int_hexagon_V6_vdealh :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vdealh">;

  
                                                     
                       
def int_hexagon_V6_vdealh_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vdealh_128B">;

  
                                                
                  
def int_hexagon_V6_vdealb :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vdealb">;

  
                                                     
                       
def int_hexagon_V6_vdealb_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vdealb_128B">;

  
                                                    
                    
def int_hexagon_V6_vdealb4w :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vdealb4w">;

  
                                                         
                         
def int_hexagon_V6_vdealb4w_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vdealb4w_128B">;

  
                                                 
                   
def int_hexagon_V6_vshuffh :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vshuffh">;

  
                                                      
                        
def int_hexagon_V6_vshuffh_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vshuffh_128B">;

  
                                                 
                   
def int_hexagon_V6_vshuffb :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vshuffb">;

  
                                                      
                        
def int_hexagon_V6_vshuffb_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vshuffb_128B">;

  
                                                    
                    
def int_hexagon_V6_extractw :
Hexagon_iv512i_Intrinsic<"HEXAGON_V6_extractw">;

  
                                                         
                         
def int_hexagon_V6_extractw_128B :
Hexagon_iv1024i_Intrinsic<"HEXAGON_V6_extractw_128B">;

  
                                                     
                     
def int_hexagon_V6_vinsertwr :
Hexagon_v512v512i_Intrinsic<"HEXAGON_V6_vinsertwr">;

  
                                                          
                          
def int_hexagon_V6_vinsertwr_128B :
Hexagon_v1024v1024i_Intrinsic<"HEXAGON_V6_vinsertwr_128B">;

  
                                                  
                    
def int_hexagon_V6_lvsplatw :
Hexagon_v512i_Intrinsic<"HEXAGON_V6_lvsplatw">;

  
                                                       
                         
def int_hexagon_V6_lvsplatw_128B :
Hexagon_v1024i_Intrinsic<"HEXAGON_V6_lvsplatw_128B">;

  
                                                 
                   
def int_hexagon_V6_vassign :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vassign">;

  
                                                      
                        
def int_hexagon_V6_vassign_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vassign_128B">;

  
                                                    
                    
def int_hexagon_V6_vcombine :
Hexagon_v1024v512v512_Intrinsic<"HEXAGON_V6_vcombine">;

  
                                                         
                         
def int_hexagon_V6_vcombine_128B :
Hexagon_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vcombine_128B">;

  
                                                  
                  
def int_hexagon_V6_vdelta :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vdelta">;

  
                                                       
                       
def int_hexagon_V6_vdelta_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vdelta_128B">;

  
                                                   
                   
def int_hexagon_V6_vrdelta :
Hexagon_v512v512v512_Intrinsic<"HEXAGON_V6_vrdelta">;

  
                                                        
                        
def int_hexagon_V6_vrdelta_128B :
Hexagon_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrdelta_128B">;

  
                                               
                 
def int_hexagon_V6_vcl0w :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vcl0w">;

  
                                                    
                      
def int_hexagon_V6_vcl0w_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vcl0w_128B">;

  
                                               
                 
def int_hexagon_V6_vcl0h :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vcl0h">;

  
                                                    
                      
def int_hexagon_V6_vcl0h_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vcl0h_128B">;

  
                                                   
                     
def int_hexagon_V6_vnormamtw :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vnormamtw">;

  
                                                        
                          
def int_hexagon_V6_vnormamtw_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vnormamtw_128B">;

  
                                                   
                     
def int_hexagon_V6_vnormamth :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vnormamth">;

  
                                                        
                          
def int_hexagon_V6_vnormamth_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vnormamth_128B">;

  
                                                    
                      
def int_hexagon_V6_vpopcounth :
Hexagon_v512v512_Intrinsic<"HEXAGON_V6_vpopcounth">;

  
                                                         
                           
def int_hexagon_V6_vpopcounth_128B :
Hexagon_v1024v1024_Intrinsic<"HEXAGON_V6_vpopcounth_128B">;

  
                                                     
                   
def int_hexagon_V6_vlutvvb :
Hexagon_v512v512v512i_Intrinsic<"HEXAGON_V6_vlutvvb">;

  
                                                          
                        
def int_hexagon_V6_vlutvvb_128B :
Hexagon_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvvb_128B">;

  
                                                             
                         
def int_hexagon_V6_vlutvvb_oracc :
Hexagon_v512v512v512v512i_Intrinsic<"HEXAGON_V6_vlutvvb_oracc">;

  
                                                                  
                              
def int_hexagon_V6_vlutvvb_oracc_128B :
Hexagon_v1024v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvvb_oracc_128B">;

  
                                                     
                   
def int_hexagon_V6_vlutvwh :
Hexagon_v1024v512v512i_Intrinsic<"HEXAGON_V6_vlutvwh">;

  
                                                          
                        
def int_hexagon_V6_vlutvwh_128B :
Hexagon_v2048v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvwh_128B">;

  
                                                             
                         
def int_hexagon_V6_vlutvwh_oracc :
Hexagon_v1024v1024v512v512i_Intrinsic<"HEXAGON_V6_vlutvwh_oracc">;

  
                                                                  
                              
def int_hexagon_V6_vlutvwh_oracc_128B :
Hexagon_v2048v2048v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvwh_oracc_128B">;

  
                       
  
def int_hexagon_V6_vS32b_qpred_ai :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vS32b_qpred_ai">;

def int_hexagon_V6_vS32b_nqpred_ai :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vS32b_nqpred_ai">;

def int_hexagon_V6_vS32b_nt_qpred_ai :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vS32b_nt_qpred_ai">;

def int_hexagon_V6_vS32b_nt_nqpred_ai :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vS32b_nt_nqpred_ai">;

def int_hexagon_V6_vS32b_qpred_ai_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vS32b_qpred_ai_128B">;

def int_hexagon_V6_vS32b_nqpred_ai_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vS32b_nqpred_ai_128B">;

def int_hexagon_V6_vS32b_nt_qpred_ai_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vS32b_nt_qpred_ai_128B">;

def int_hexagon_V6_vS32b_nt_nqpred_ai_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vS32b_nt_nqpred_ai_128B">;

def int_hexagon_V6_vmaskedstoreq :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vmaskedstoreq">;

def int_hexagon_V6_vmaskedstorenq :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vmaskedstorenq">;

def int_hexagon_V6_vmaskedstorentq :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vmaskedstorentq">;

def int_hexagon_V6_vmaskedstorentnq :
Hexagon_vv64ivmemv512_Intrinsic<"HEXAGON_V6_vmaskedstorentnq">;

def int_hexagon_V6_vmaskedstoreq_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vmaskedstoreq_128B">;

def int_hexagon_V6_vmaskedstorenq_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vmaskedstorenq_128B">;

def int_hexagon_V6_vmaskedstorentq_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vmaskedstorentq_128B">;

def int_hexagon_V6_vmaskedstorentnq_128B :
Hexagon_vv128ivmemv1024_Intrinsic<"HEXAGON_V6_vmaskedstorentnq_128B">;

multiclass Hexagon_custom_circ_ld_Intrinsic<LLVMType ElTy> {
  def NAME#_pci : Hexagon_NonGCC_Intrinsic<
    [ElTy, llvm_ptr_ty],
    [llvm_ptr_ty, llvm_i32_ty, llvm_i32_ty, llvm_ptr_ty],
    [IntrArgMemOnly, NoCapture<3>]>;
  def NAME#_pcr : Hexagon_NonGCC_Intrinsic<
    [ElTy, llvm_ptr_ty], [llvm_ptr_ty, llvm_i32_ty, llvm_ptr_ty],
    [IntrArgMemOnly, NoCapture<2>]>;
}

defm int_hexagon_L2_loadrub : Hexagon_custom_circ_ld_Intrinsic<llvm_i32_ty>;
defm int_hexagon_L2_loadrb : Hexagon_custom_circ_ld_Intrinsic<llvm_i32_ty>;
defm int_hexagon_L2_loadruh : Hexagon_custom_circ_ld_Intrinsic<llvm_i32_ty>;
defm int_hexagon_L2_loadrh : Hexagon_custom_circ_ld_Intrinsic<llvm_i32_ty>;
defm int_hexagon_L2_loadri : Hexagon_custom_circ_ld_Intrinsic<llvm_i32_ty>;
defm int_hexagon_L2_loadrd : Hexagon_custom_circ_ld_Intrinsic<llvm_i64_ty>;

multiclass Hexagon_custom_circ_st_Intrinsic<LLVMType ElTy> {
  def NAME#_pci : Hexagon_NonGCC_Intrinsic<
    [llvm_ptr_ty],
    [llvm_ptr_ty, llvm_i32_ty, llvm_i32_ty, ElTy, llvm_ptr_ty],
    [IntrArgMemOnly, NoCapture<4>]>;
  def NAME#_pcr : Hexagon_NonGCC_Intrinsic<
    [llvm_ptr_ty], [llvm_ptr_ty, llvm_i32_ty, ElTy, llvm_ptr_ty],
    [IntrArgMemOnly, NoCapture<3>]>;
}

defm int_hexagon_S2_storerb : Hexagon_custom_circ_st_Intrinsic<llvm_i32_ty>;
defm int_hexagon_S2_storerh : Hexagon_custom_circ_st_Intrinsic<llvm_i32_ty>;
defm int_hexagon_S2_storerf : Hexagon_custom_circ_st_Intrinsic<llvm_i32_ty>;
defm int_hexagon_S2_storeri : Hexagon_custom_circ_st_Intrinsic<llvm_i32_ty>;
defm int_hexagon_S2_storerd : Hexagon_custom_circ_st_Intrinsic<llvm_i64_ty>;

                                                                            
                                                                            
                         
class Hexagon_custom_brev_ld_Intrinsic<LLVMType ElTy>
 : Hexagon_NonGCC_Intrinsic<
    [ElTy, llvm_ptr_ty], [llvm_ptr_ty, llvm_i32_ty],
    [IntrReadMem]>;

def int_hexagon_L2_loadrub_pbr : Hexagon_custom_brev_ld_Intrinsic<llvm_i32_ty>;
def int_hexagon_L2_loadrb_pbr : Hexagon_custom_brev_ld_Intrinsic<llvm_i32_ty>;
def int_hexagon_L2_loadruh_pbr : Hexagon_custom_brev_ld_Intrinsic<llvm_i32_ty>;
def int_hexagon_L2_loadrh_pbr : Hexagon_custom_brev_ld_Intrinsic<llvm_i32_ty>;
def int_hexagon_L2_loadri_pbr : Hexagon_custom_brev_ld_Intrinsic<llvm_i32_ty>;
def int_hexagon_L2_loadrd_pbr : Hexagon_custom_brev_ld_Intrinsic<llvm_i64_ty>;

def int_hexagon_S2_storerb_pbr : Hexagon_mem_memsisi_Intrinsic<"brev_stb">;
def int_hexagon_S2_storerh_pbr : Hexagon_mem_memsisi_Intrinsic<"brev_sth">;
def int_hexagon_S2_storerf_pbr : Hexagon_mem_memsisi_Intrinsic<"brev_sthhi">;
def int_hexagon_S2_storeri_pbr : Hexagon_mem_memsisi_Intrinsic<"brev_stw">;
def int_hexagon_S2_storerd_pbr : Hexagon_mem_memdisi_Intrinsic<"brev_std">;


   
                         
   

  
                                                   
                     
class Hexagon_LLiLLiLLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i64_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                              
                     
class Hexagon_LLii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i64_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                       
                 
class Hexagon_V62_v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                         
                      
class Hexagon_V62_v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                           
                         
class Hexagon_V62_v512v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                              
                              
class Hexagon_V62_v1024v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                      
class Hexagon_V62_v512v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                             
                           
class Hexagon_V62_v1024v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                             
                             
class Hexagon_V62_v2048v2048v2048_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v64i32_ty],
                          [IntrNoMem]>;

  
                                                                
                      
class Hexagon_V62_v1024v1024v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                                  
                           
class Hexagon_V62_v2048v2048v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                           
                       
class Hexagon_V62_v1024v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                             
                            
class Hexagon_V62_v2048v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                         
                        
class Hexagon_V62_v2048v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                              
                            
class Hexagon_V62_v2048v2048v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                       
                    
class Hexagon_V62_v512v64ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v512i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                         
                         
class Hexagon_V62_v1024v128ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v1024i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                           
                        
class Hexagon_V62_v512v512v64ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v512i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                              
                             
class Hexagon_V62_v1024v1024v128ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v1024i1_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                   
class Hexagon_V62_v512v64iv512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v512i1_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                             
                        
class Hexagon_V62_v1024v128iv1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v1024i1_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                   
                          
class Hexagon_V62_v64ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                    
                               
class Hexagon_V62_v128ii_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                    
class Hexagon_V62_v64iv64iv64i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v512i1_ty], [llvm_v512i1_ty,llvm_v512i1_ty],
                          [IntrNoMem]>;

  
                                                             
                         
class Hexagon_V62_v128iv128iv128i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v1024i1_ty], [llvm_v1024i1_ty,llvm_v1024i1_ty],
                          [IntrNoMem]>;

  
                                                   
                    
class Hexagon_V62_v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                    
                         
class Hexagon_V62_v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                               
                          
class Hexagon_V62_v512v512v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                                   
                               
class Hexagon_V62_v1024v1024v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                            
                    
class Hexagon_V62_v1024v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                              
                         
class Hexagon_V62_v2048v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                                 
                          
class Hexagon_V62_v1024v1024v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                                   
                               
class Hexagon_V62_v2048v2048v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

                                                              
                    
class Hexagon_v512v64iv512v512v64i_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty, llvm_v512i1_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_v512i1_ty],
                          [IntrNoMem]>;

                                                                   
                         
class Hexagon_v1024v128iv1024v1024v128i_Intrinsic<string GCCIntSuffix>
  : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty, llvm_v1024i1_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_v1024i1_ty],
                          [IntrNoMem]>;


  
                                                     
                     
def int_hexagon_M6_vabsdiffb :
Hexagon_LLiLLiLLi_Intrinsic<"HEXAGON_M6_vabsdiffb">;

  
                                                      
                      
def int_hexagon_M6_vabsdiffub :
Hexagon_LLiLLiLLi_Intrinsic<"HEXAGON_M6_vabsdiffub">;

  
                                                        
                        
def int_hexagon_S6_vtrunehb_ppp :
Hexagon_LLiLLiLLi_Intrinsic<"HEXAGON_S6_vtrunehb_ppp">;

  
                                                        
                        
def int_hexagon_S6_vtrunohb_ppp :
Hexagon_LLiLLiLLi_Intrinsic<"HEXAGON_S6_vtrunohb_ppp">;

  
                                                   
                     
def int_hexagon_S6_vsplatrbp :
Hexagon_LLii_Intrinsic<"HEXAGON_S6_vsplatrbp">;

  
                                                 
                 
def int_hexagon_V6_vlsrb :
Hexagon_V62_v512v512i_Intrinsic<"HEXAGON_V6_vlsrb">;

  
                                                      
                      
def int_hexagon_V6_vlsrb_128B :
Hexagon_V62_v1024v1024i_Intrinsic<"HEXAGON_V6_vlsrb_128B">;

  
                                                           
                         
def int_hexagon_V6_vasrwuhrndsat :
Hexagon_V62_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrwuhrndsat">;

  
                                                                
                              
def int_hexagon_V6_vasrwuhrndsat_128B :
Hexagon_V62_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrwuhrndsat_128B">;

  
                                                            
                          
def int_hexagon_V6_vasruwuhrndsat :
Hexagon_V62_v512v512v512i_Intrinsic<"HEXAGON_V6_vasruwuhrndsat">;

  
                                                                 
                               
def int_hexagon_V6_vasruwuhrndsat_128B :
Hexagon_V62_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasruwuhrndsat_128B">;

  
                                                       
                     
def int_hexagon_V6_vasrhbsat :
Hexagon_V62_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrhbsat">;

  
                                                            
                          
def int_hexagon_V6_vasrhbsat_128B :
Hexagon_V62_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrhbsat_128B">;

  
                                                      
                      
def int_hexagon_V6_vrounduwuh :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vrounduwuh">;

  
                                                           
                           
def int_hexagon_V6_vrounduwuh_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrounduwuh_128B">;

  
                                                      
                      
def int_hexagon_V6_vrounduhub :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vrounduhub">;

  
                                                           
                           
def int_hexagon_V6_vrounduhub_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vrounduhub_128B">;

  
                                                     
                     
def int_hexagon_V6_vadduwsat :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vadduwsat">;

  
                                                          
                          
def int_hexagon_V6_vadduwsat_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vadduwsat_128B">;

  
                                                        
                        
def int_hexagon_V6_vadduwsat_dv :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vadduwsat_dv">;

  
                                                             
                             
def int_hexagon_V6_vadduwsat_dv_128B :
Hexagon_V62_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vadduwsat_dv_128B">;

  
                                                     
                     
def int_hexagon_V6_vsubuwsat :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vsubuwsat">;

  
                                                          
                          
def int_hexagon_V6_vsubuwsat_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubuwsat_128B">;

  
                                                        
                        
def int_hexagon_V6_vsubuwsat_dv :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubuwsat_dv">;

  
                                                             
                             
def int_hexagon_V6_vsubuwsat_dv_128B :
Hexagon_V62_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubuwsat_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddbsat :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vaddbsat">;

  
                                                         
                         
def int_hexagon_V6_vaddbsat_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddbsat_128B">;

  
                                                       
                       
def int_hexagon_V6_vaddbsat_dv :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddbsat_dv">;

  
                                                            
                            
def int_hexagon_V6_vaddbsat_dv_128B :
Hexagon_V62_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vaddbsat_dv_128B">;

  
                                                    
                    
def int_hexagon_V6_vsubbsat :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vsubbsat">;

  
                                                         
                         
def int_hexagon_V6_vsubbsat_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubbsat_128B">;

  
                                                       
                       
def int_hexagon_V6_vsubbsat_dv :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubbsat_dv">;

  
                                                            
                            
def int_hexagon_V6_vsubbsat_dv_128B :
Hexagon_V62_v2048v2048v2048_Intrinsic<"HEXAGON_V6_vsubbsat_dv_128B">;

  
                                                         
                         
def int_hexagon_V6_vaddububb_sat :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vaddububb_sat">;

  
                                                              
                              
def int_hexagon_V6_vaddububb_sat_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddububb_sat_128B">;

  
                                                         
                         
def int_hexagon_V6_vsubububb_sat :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vsubububb_sat">;

  
                                                              
                              
def int_hexagon_V6_vsubububb_sat_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsubububb_sat_128B">;

  
                                                        
                      
def int_hexagon_V6_vaddhw_acc :
Hexagon_V62_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vaddhw_acc">;

  
                                                             
                           
def int_hexagon_V6_vaddhw_acc_128B :
Hexagon_V62_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vaddhw_acc_128B">;

  
                                                         
                       
def int_hexagon_V6_vadduhw_acc :
Hexagon_V62_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vadduhw_acc">;

  
                                                              
                            
def int_hexagon_V6_vadduhw_acc_128B :
Hexagon_V62_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vadduhw_acc_128B">;

  
                                                         
                       
def int_hexagon_V6_vaddubh_acc :
Hexagon_V62_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vaddubh_acc">;

  
                                                              
                            
def int_hexagon_V6_vaddubh_acc_128B :
Hexagon_V62_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vaddubh_acc_128B">;

  
                                                       
                       
def int_hexagon_V6_vmpyewuh_64 :
Hexagon_V62_v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyewuh_64">;

  
                                                            
                            
def int_hexagon_V6_vmpyewuh_64_128B :
Hexagon_V62_v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyewuh_64_128B">;

  
                                                            
                          
def int_hexagon_V6_vmpyowh_64_acc :
Hexagon_V62_v1024v1024v512v512_Intrinsic<"HEXAGON_V6_vmpyowh_64_acc">;

  
                                                                 
                               
def int_hexagon_V6_vmpyowh_64_acc_128B :
Hexagon_V62_v2048v2048v1024v1024_Intrinsic<"HEXAGON_V6_vmpyowh_64_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpauhb :
Hexagon_V62_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpauhb">;

  
                                                        
                        
def int_hexagon_V6_vmpauhb_128B :
Hexagon_V62_v2048v2048i_Intrinsic<"HEXAGON_V6_vmpauhb_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpauhb_acc :
Hexagon_V62_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpauhb_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpauhb_acc_128B :
Hexagon_V62_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vmpauhb_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vmpyiwub :
Hexagon_V62_v512v512i_Intrinsic<"HEXAGON_V6_vmpyiwub">;

  
                                                         
                         
def int_hexagon_V6_vmpyiwub_128B :
Hexagon_V62_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyiwub_128B">;

  
                                                          
                        
def int_hexagon_V6_vmpyiwub_acc :
Hexagon_V62_v512v512v512i_Intrinsic<"HEXAGON_V6_vmpyiwub_acc">;

  
                                                               
                             
def int_hexagon_V6_vmpyiwub_acc_128B :
Hexagon_V62_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyiwub_acc_128B">;

  
                                                    
                    
def int_hexagon_V6_vandnqrt :
Hexagon_V62_v512v64ii_Intrinsic<"HEXAGON_V6_vandnqrt">;

  
                                                         
                         
def int_hexagon_V6_vandnqrt_128B :
Hexagon_V62_v1024v128ii_Intrinsic<"HEXAGON_V6_vandnqrt_128B">;

  
                                                          
                        
def int_hexagon_V6_vandnqrt_acc :
Hexagon_V62_v512v512v64ii_Intrinsic<"HEXAGON_V6_vandnqrt_acc">;

  
                                                               
                             
def int_hexagon_V6_vandnqrt_acc_128B :
Hexagon_V62_v1024v1024v128ii_Intrinsic<"HEXAGON_V6_vandnqrt_acc_128B">;

  
                                                   
                   
def int_hexagon_V6_vandvqv :
Hexagon_V62_v512v64iv512_Intrinsic<"HEXAGON_V6_vandvqv">;

  
                                                        
                        
def int_hexagon_V6_vandvqv_128B :
Hexagon_V62_v1024v128iv1024_Intrinsic<"HEXAGON_V6_vandvqv_128B">;

  
                                                    
                    
def int_hexagon_V6_vandvnqv :
Hexagon_V62_v512v64iv512_Intrinsic<"HEXAGON_V6_vandvnqv">;

  
                                                         
                         
def int_hexagon_V6_vandvnqv_128B :
Hexagon_V62_v1024v128iv1024_Intrinsic<"HEXAGON_V6_vandvnqv_128B">;

  
                                                        
                          
def int_hexagon_V6_pred_scalar2v2 :
Hexagon_V62_v64ii_Intrinsic<"HEXAGON_V6_pred_scalar2v2">;

  
                                                             
                               
def int_hexagon_V6_pred_scalar2v2_128B :
Hexagon_V62_v128ii_Intrinsic<"HEXAGON_V6_pred_scalar2v2_128B">;

  
                                                    
                    
def int_hexagon_V6_shuffeqw :
Hexagon_V62_v64iv64iv64i_Intrinsic<"HEXAGON_V6_shuffeqw">;

  
                                                         
                         
def int_hexagon_V6_shuffeqw_128B :
Hexagon_V62_v128iv128iv128i_Intrinsic<"HEXAGON_V6_shuffeqw_128B">;

  
                                                    
                    
def int_hexagon_V6_shuffeqh :
Hexagon_V62_v64iv64iv64i_Intrinsic<"HEXAGON_V6_shuffeqh">;

  
                                                         
                         
def int_hexagon_V6_shuffeqh_128B :
Hexagon_V62_v128iv128iv128i_Intrinsic<"HEXAGON_V6_shuffeqh_128B">;

  
                                                 
                 
def int_hexagon_V6_vmaxb :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vmaxb">;

  
                                                      
                      
def int_hexagon_V6_vmaxb_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vmaxb_128B">;

  
                                                 
                 
def int_hexagon_V6_vminb :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vminb">;

  
                                                      
                      
def int_hexagon_V6_vminb_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vminb_128B">;

  
                                                    
                    
def int_hexagon_V6_vsatuwuh :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vsatuwuh">;

  
                                                         
                         
def int_hexagon_V6_vsatuwuh_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vsatuwuh_128B">;

  
                                                  
                    
def int_hexagon_V6_lvsplath :
Hexagon_V62_v512i_Intrinsic<"HEXAGON_V6_lvsplath">;

  
                                                       
                         
def int_hexagon_V6_lvsplath_128B :
Hexagon_V62_v1024i_Intrinsic<"HEXAGON_V6_lvsplath_128B">;

  
                                                  
                    
def int_hexagon_V6_lvsplatb :
Hexagon_V62_v512i_Intrinsic<"HEXAGON_V6_lvsplatb">;

  
                                                       
                         
def int_hexagon_V6_lvsplatb_128B :
Hexagon_V62_v1024i_Intrinsic<"HEXAGON_V6_lvsplatb_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddclbw :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vaddclbw">;

  
                                                         
                         
def int_hexagon_V6_vaddclbw_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddclbw_128B">;

  
                                                    
                    
def int_hexagon_V6_vaddclbh :
Hexagon_V62_v512v512v512_Intrinsic<"HEXAGON_V6_vaddclbh">;

  
                                                         
                         
def int_hexagon_V6_vaddclbh_128B :
Hexagon_V62_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vaddclbh_128B">;

  
                                                      
                    
def int_hexagon_V6_vlutvvbi :
Hexagon_V62_v512v512v512i_Intrinsic<"HEXAGON_V6_vlutvvbi">;

  
                                                           
                         
def int_hexagon_V6_vlutvvbi_128B :
Hexagon_V62_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvvbi_128B">;

  
                                                              
                          
def int_hexagon_V6_vlutvvb_oracci :
Hexagon_V62_v512v512v512v512i_Intrinsic<"HEXAGON_V6_vlutvvb_oracci">;

  
                                                                   
                               
def int_hexagon_V6_vlutvvb_oracci_128B :
Hexagon_V62_v1024v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvvb_oracci_128B">;

  
                                                      
                    
def int_hexagon_V6_vlutvwhi :
Hexagon_V62_v1024v512v512i_Intrinsic<"HEXAGON_V6_vlutvwhi">;

  
                                                           
                         
def int_hexagon_V6_vlutvwhi_128B :
Hexagon_V62_v2048v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvwhi_128B">;

  
                                                              
                          
def int_hexagon_V6_vlutvwh_oracci :
Hexagon_V62_v1024v1024v512v512i_Intrinsic<"HEXAGON_V6_vlutvwh_oracci">;

  
                                                                   
                               
def int_hexagon_V6_vlutvwh_oracci_128B :
Hexagon_V62_v2048v2048v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvwh_oracci_128B">;

  
                                                        
                      
def int_hexagon_V6_vlutvvb_nm :
Hexagon_V62_v512v512v512i_Intrinsic<"HEXAGON_V6_vlutvvb_nm">;

  
                                                             
                           
def int_hexagon_V6_vlutvvb_nm_128B :
Hexagon_V62_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvvb_nm_128B">;

  
                                                        
                      
def int_hexagon_V6_vlutvwh_nm :
Hexagon_V62_v1024v512v512i_Intrinsic<"HEXAGON_V6_vlutvwh_nm">;

  
                                                             
                           
def int_hexagon_V6_vlutvwh_nm_128B :
Hexagon_V62_v2048v1024v1024i_Intrinsic<"HEXAGON_V6_vlutvwh_nm_128B">;

  
                                                       
                    
def int_hexagon_V6_vaddcarry :
Hexagon_v512v64iv512v512v64i_Intrinsic<"HEXAGON_v6_vaddcarry">;

  
                                                            
                         
def int_hexagon_V6_vaddcarry_128B :
Hexagon_v1024v128iv1024v1024v128i_Intrinsic<"HEXAGON_v6_vaddcarry_128B">;

  
                                                       
                    
def int_hexagon_V6_vsubcarry :
Hexagon_v512v64iv512v512v64i_Intrinsic<"HEXAGON_v6_vsubcarry">;

  
                                                            
                         
def int_hexagon_V6_vsubcarry_128B :
Hexagon_v1024v128iv1024v1024v128i_Intrinsic<"HEXAGON_v6_vsubcarry_128B">;


   
                         
   

  
                                                     
                          
class Hexagon_V65_iLLiLLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_i32_ty], [llvm_i64_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                          
                       
class Hexagon_V65_v1024v512LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v16i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                           
                            
class Hexagon_V65_v2048v1024LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v32i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                               
                           
class Hexagon_V65_v1024v1024v512LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                                
                                
class Hexagon_V65_v2048v2048v1024LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                           
                       
class Hexagon_V65_v512v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                              
                            
class Hexagon_V65_v1024v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                          
                  
class Hexagon_V65_v512v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                             
                       
class Hexagon_V65_v1024v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                      
                 
class Hexagon_V65_v512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty],
                          [IntrNoMem]>;

  
                                                        
                      
class Hexagon_V65_v1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty],
                          [IntrNoMem]>;

  
                                                         
                   
class Hexagon_V65_v1024v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                         
                        
class Hexagon_V65_v2048v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                              
                            
class Hexagon_V65_v2048v2048v2048i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v64i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                             
                     
class Hexagon_V65_v1024v1024v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                              
                          
class Hexagon_V65_v2048v2048v1024i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [llvm_v64i32_ty,llvm_v32i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                             
                     
class Hexagon_V65_v512v512v512LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_v16i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                                
                          
class Hexagon_V65_v1024v1024v1024LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_v32i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                         
                 
class Hexagon_V65_v512v512LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                           
                      
class Hexagon_V65_v1024v1024LLi_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v32i32_ty,llvm_i64_ty],
                          [IntrNoMem]>;

  
                                                       
                   
class Hexagon_V65_v512v512i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v16i32_ty,llvm_i32_ty],
                          [IntrNoMem]>;

  
                                                      
                     
class Hexagon_V65_v512v64i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v16i32_ty], [llvm_v512i1_ty],
                          [IntrNoMem]>;

  
                                                        
                          
class Hexagon_V65_v1024v128i_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v32i32_ty], [llvm_v1024i1_ty],
                          [IntrNoMem]>;

  
                                                          
                          
def int_hexagon_A6_vcmpbeq_notany :
Hexagon_V65_iLLiLLi_Intrinsic<"HEXAGON_A6_vcmpbeq_notany">;

  
                                                               
                               
def int_hexagon_A6_vcmpbeq_notany_128B :
Hexagon_V65_iLLiLLi_Intrinsic<"HEXAGON_A6_vcmpbeq_notany_128B">;

  
                                                       
                       
def int_hexagon_V6_vrmpyub_rtt :
Hexagon_V65_v1024v512LLi_Intrinsic<"HEXAGON_V6_vrmpyub_rtt">;

  
                                                            
                            
def int_hexagon_V6_vrmpyub_rtt_128B :
Hexagon_V65_v2048v1024LLi_Intrinsic<"HEXAGON_V6_vrmpyub_rtt_128B">;

  
                                                             
                           
def int_hexagon_V6_vrmpyub_rtt_acc :
Hexagon_V65_v1024v1024v512LLi_Intrinsic<"HEXAGON_V6_vrmpyub_rtt_acc">;

  
                                                                  
                                
def int_hexagon_V6_vrmpyub_rtt_acc_128B :
Hexagon_V65_v2048v2048v1024LLi_Intrinsic<"HEXAGON_V6_vrmpyub_rtt_acc_128B">;

  
                                                        
                        
def int_hexagon_V6_vrmpybub_rtt :
Hexagon_V65_v1024v512LLi_Intrinsic<"HEXAGON_V6_vrmpybub_rtt">;

  
                                                             
                             
def int_hexagon_V6_vrmpybub_rtt_128B :
Hexagon_V65_v2048v1024LLi_Intrinsic<"HEXAGON_V6_vrmpybub_rtt_128B">;

  
                                                              
                            
def int_hexagon_V6_vrmpybub_rtt_acc :
Hexagon_V65_v1024v1024v512LLi_Intrinsic<"HEXAGON_V6_vrmpybub_rtt_acc">;

  
                                                                   
                                 
def int_hexagon_V6_vrmpybub_rtt_acc_128B :
Hexagon_V65_v2048v2048v1024LLi_Intrinsic<"HEXAGON_V6_vrmpybub_rtt_acc_128B">;

  
                                                         
                       
def int_hexagon_V6_vasruwuhsat :
Hexagon_V65_v512v512v512i_Intrinsic<"HEXAGON_V6_vasruwuhsat">;

  
                                                              
                            
def int_hexagon_V6_vasruwuhsat_128B :
Hexagon_V65_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasruwuhsat_128B">;

  
                                                         
                       
def int_hexagon_V6_vasruhubsat :
Hexagon_V65_v512v512v512i_Intrinsic<"HEXAGON_V6_vasruhubsat">;

  
                                                              
                            
def int_hexagon_V6_vasruhubsat_128B :
Hexagon_V65_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasruhubsat_128B">;

  
                                                            
                          
def int_hexagon_V6_vasruhubrndsat :
Hexagon_V65_v512v512v512i_Intrinsic<"HEXAGON_V6_vasruhubrndsat">;

  
                                                                 
                               
def int_hexagon_V6_vasruhubrndsat_128B :
Hexagon_V65_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasruhubrndsat_128B">;

  
                                                       
                     
def int_hexagon_V6_vaslh_acc :
Hexagon_V65_v512v512v512i_Intrinsic<"HEXAGON_V6_vaslh_acc">;

  
                                                            
                          
def int_hexagon_V6_vaslh_acc_128B :
Hexagon_V65_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vaslh_acc_128B">;

  
                                                       
                     
def int_hexagon_V6_vasrh_acc :
Hexagon_V65_v512v512v512i_Intrinsic<"HEXAGON_V6_vasrh_acc">;

  
                                                            
                          
def int_hexagon_V6_vasrh_acc_128B :
Hexagon_V65_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vasrh_acc_128B">;

  
                                                  
                  
def int_hexagon_V6_vavguw :
Hexagon_V65_v512v512v512_Intrinsic<"HEXAGON_V6_vavguw">;

  
                                                       
                       
def int_hexagon_V6_vavguw_128B :
Hexagon_V65_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavguw_128B">;

  
                                                     
                     
def int_hexagon_V6_vavguwrnd :
Hexagon_V65_v512v512v512_Intrinsic<"HEXAGON_V6_vavguwrnd">;

  
                                                          
                          
def int_hexagon_V6_vavguwrnd_128B :
Hexagon_V65_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavguwrnd_128B">;

  
                                                 
                 
def int_hexagon_V6_vavgb :
Hexagon_V65_v512v512v512_Intrinsic<"HEXAGON_V6_vavgb">;

  
                                                      
                      
def int_hexagon_V6_vavgb_128B :
Hexagon_V65_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavgb_128B">;

  
                                                    
                    
def int_hexagon_V6_vavgbrnd :
Hexagon_V65_v512v512v512_Intrinsic<"HEXAGON_V6_vavgbrnd">;

  
                                                         
                         
def int_hexagon_V6_vavgbrnd_128B :
Hexagon_V65_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vavgbrnd_128B">;

  
                                                  
                  
def int_hexagon_V6_vnavgb :
Hexagon_V65_v512v512v512_Intrinsic<"HEXAGON_V6_vnavgb">;

  
                                                       
                       
def int_hexagon_V6_vnavgb_128B :
Hexagon_V65_v1024v1024v1024_Intrinsic<"HEXAGON_V6_vnavgb_128B">;

  
                                               
                 
def int_hexagon_V6_vabsb :
Hexagon_V65_v512v512_Intrinsic<"HEXAGON_V6_vabsb">;

  
                                                    
                      
def int_hexagon_V6_vabsb_128B :
Hexagon_V65_v1024v1024_Intrinsic<"HEXAGON_V6_vabsb_128B">;

  
                                                   
                     
def int_hexagon_V6_vabsb_sat :
Hexagon_V65_v512v512_Intrinsic<"HEXAGON_V6_vabsb_sat">;

  
                                                        
                          
def int_hexagon_V6_vabsb_sat_128B :
Hexagon_V65_v1024v1024_Intrinsic<"HEXAGON_V6_vabsb_sat_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpabuu :
Hexagon_V65_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpabuu">;

  
                                                        
                        
def int_hexagon_V6_vmpabuu_128B :
Hexagon_V65_v2048v2048i_Intrinsic<"HEXAGON_V6_vmpabuu_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpabuu_acc :
Hexagon_V65_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpabuu_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpabuu_acc_128B :
Hexagon_V65_v2048v2048v2048i_Intrinsic<"HEXAGON_V6_vmpabuu_acc_128B">;

  
                                                       
                     
def int_hexagon_V6_vmpyh_acc :
Hexagon_V65_v1024v1024v512i_Intrinsic<"HEXAGON_V6_vmpyh_acc">;

  
                                                            
                          
def int_hexagon_V6_vmpyh_acc_128B :
Hexagon_V65_v2048v2048v1024i_Intrinsic<"HEXAGON_V6_vmpyh_acc_128B">;

  
                                                       
                     
def int_hexagon_V6_vmpahhsat :
Hexagon_V65_v512v512v512LLi_Intrinsic<"HEXAGON_V6_vmpahhsat">;

  
                                                            
                          
def int_hexagon_V6_vmpahhsat_128B :
Hexagon_V65_v1024v1024v1024LLi_Intrinsic<"HEXAGON_V6_vmpahhsat_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpauhuhsat :
Hexagon_V65_v512v512v512LLi_Intrinsic<"HEXAGON_V6_vmpauhuhsat">;

  
                                                              
                            
def int_hexagon_V6_vmpauhuhsat_128B :
Hexagon_V65_v1024v1024v1024LLi_Intrinsic<"HEXAGON_V6_vmpauhuhsat_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpsuhuhsat :
Hexagon_V65_v512v512v512LLi_Intrinsic<"HEXAGON_V6_vmpsuhuhsat">;

  
                                                              
                            
def int_hexagon_V6_vmpsuhuhsat_128B :
Hexagon_V65_v1024v1024v1024LLi_Intrinsic<"HEXAGON_V6_vmpsuhuhsat_128B">;

  
                                                 
                 
def int_hexagon_V6_vlut4 :
Hexagon_V65_v512v512LLi_Intrinsic<"HEXAGON_V6_vlut4">;

  
                                                      
                      
def int_hexagon_V6_vlut4_128B :
Hexagon_V65_v1024v1024LLi_Intrinsic<"HEXAGON_V6_vlut4_128B">;

  
                                                   
                   
def int_hexagon_V6_vmpyuhe :
Hexagon_V65_v512v512i_Intrinsic<"HEXAGON_V6_vmpyuhe">;

  
                                                        
                        
def int_hexagon_V6_vmpyuhe_128B :
Hexagon_V65_v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyuhe_128B">;

  
                                                         
                       
def int_hexagon_V6_vmpyuhe_acc :
Hexagon_V65_v512v512v512i_Intrinsic<"HEXAGON_V6_vmpyuhe_acc">;

  
                                                              
                            
def int_hexagon_V6_vmpyuhe_acc_128B :
Hexagon_V65_v1024v1024v1024i_Intrinsic<"HEXAGON_V6_vmpyuhe_acc_128B">;

  
                                                   
                     
def int_hexagon_V6_vprefixqb :
Hexagon_V65_v512v64i_Intrinsic<"HEXAGON_V6_vprefixqb">;

  
                                                        
                          
def int_hexagon_V6_vprefixqb_128B :
Hexagon_V65_v1024v128i_Intrinsic<"HEXAGON_V6_vprefixqb_128B">;

  
                                                   
                     
def int_hexagon_V6_vprefixqh :
Hexagon_V65_v512v64i_Intrinsic<"HEXAGON_V6_vprefixqh">;

  
                                                        
                          
def int_hexagon_V6_vprefixqh_128B :
Hexagon_V65_v1024v128i_Intrinsic<"HEXAGON_V6_vprefixqh_128B">;

  
                                                   
                     
def int_hexagon_V6_vprefixqw :
Hexagon_V65_v512v64i_Intrinsic<"HEXAGON_V6_vprefixqw">;

  
                                                        
                          
def int_hexagon_V6_vprefixqw_128B :
Hexagon_V65_v1024v128i_Intrinsic<"HEXAGON_V6_vprefixqw_128B">;


                                                                              
                             
class Hexagon_V65_vvmemiiv512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_ptr_ty,llvm_i32_ty,llvm_i32_ty,
                               llvm_v16i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_V65_vvmemiiv1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_ptr_ty,llvm_i32_ty,llvm_i32_ty,
                               llvm_v32i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_V65_vvmemiiv2048_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_ptr_ty,llvm_i32_ty,llvm_i32_ty,
                               llvm_v64i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_V65_vvmemv64iiiv512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_ptr_ty,llvm_v512i1_ty,llvm_i32_ty,
                               llvm_i32_ty,llvm_v16i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_V65_vvmemv128iiiv1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_ptr_ty,llvm_v1024i1_ty,llvm_i32_ty,
                               llvm_i32_ty,llvm_v32i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_V65_vvmemv64iiiv1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_ptr_ty,llvm_v512i1_ty,llvm_i32_ty,
                               llvm_i32_ty,llvm_v32i32_ty],
                          [IntrArgMemOnly]>;

class Hexagon_V65_vvmemv128iiiv2048_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_ptr_ty,llvm_v1024i1_ty,llvm_i32_ty,
                               llvm_i32_ty,llvm_v64i32_ty],
                          [IntrArgMemOnly]>;

def int_hexagon_V6_vgathermw :
Hexagon_V65_vvmemiiv512_Intrinsic<"HEXAGON_V6_vgathermw">;

def int_hexagon_V6_vgathermw_128B :
Hexagon_V65_vvmemiiv1024_Intrinsic<"HEXAGON_V6_vgathermw_128B">;

def int_hexagon_V6_vgathermh :
Hexagon_V65_vvmemiiv512_Intrinsic<"HEXAGON_V6_vgathermh">;

def int_hexagon_V6_vgathermh_128B :
Hexagon_V65_vvmemiiv1024_Intrinsic<"HEXAGON_V6_vgathermh_128B">;

def int_hexagon_V6_vgathermhw :
Hexagon_V65_vvmemiiv1024_Intrinsic<"HEXAGON_V6_vgathermhw">;

def int_hexagon_V6_vgathermhw_128B :
Hexagon_V65_vvmemiiv2048_Intrinsic<"HEXAGON_V6_vgathermhw_128B">;

def int_hexagon_V6_vgathermwq :
Hexagon_V65_vvmemv64iiiv512_Intrinsic<"HEXAGON_V6_vgathermwq">;

def int_hexagon_V6_vgathermwq_128B :
Hexagon_V65_vvmemv128iiiv1024_Intrinsic<"HEXAGON_V6_vgathermwq_128B">;

def int_hexagon_V6_vgathermhq :
Hexagon_V65_vvmemv64iiiv512_Intrinsic<"HEXAGON_V6_vgathermhq">;

def int_hexagon_V6_vgathermhq_128B :
Hexagon_V65_vvmemv128iiiv1024_Intrinsic<"HEXAGON_V6_vgathermhq_128B">;

def int_hexagon_V6_vgathermhwq :
Hexagon_V65_vvmemv64iiiv1024_Intrinsic<"HEXAGON_V6_vgathermhwq">;

def int_hexagon_V6_vgathermhwq_128B :
Hexagon_V65_vvmemv128iiiv2048_Intrinsic<"HEXAGON_V6_vgathermhwq_128B">;

class Hexagon_V65_viiv512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_i32_ty,llvm_i32_ty,
                                           llvm_v16i32_ty,llvm_v16i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_viiv1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_i32_ty,llvm_i32_ty,
                                           llvm_v32i32_ty,llvm_v32i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_vv64iiiv512v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_v512i1_ty,llvm_i32_ty,
                                           llvm_i32_ty,llvm_v16i32_ty,
                                           llvm_v16i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_vv128iiiv1024v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_v1024i1_ty,llvm_i32_ty,
                                           llvm_i32_ty,llvm_v32i32_ty,
                                           llvm_v32i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_viiv1024v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_i32_ty,llvm_i32_ty,
                                           llvm_v32i32_ty,llvm_v16i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_viiv2048v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_i32_ty,llvm_i32_ty,
                                           llvm_v64i32_ty,llvm_v32i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_vv64iiiv1024v512_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_v512i1_ty,llvm_i32_ty,
                                           llvm_i32_ty,llvm_v32i32_ty,
                                           llvm_v16i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_vv128iiiv2048v1024_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [], [llvm_v1024i1_ty,llvm_i32_ty,
                                           llvm_i32_ty,llvm_v64i32_ty,
                                           llvm_v32i32_ty],
                          [IntrWriteMem]>;

class Hexagon_V65_v2048_Intrinsic<string GCCIntSuffix>
 : Hexagon_Intrinsic<GCCIntSuffix,
                          [llvm_v64i32_ty], [],
                          [IntrNoMem]>;

  
                                                         
                      
def int_hexagon_V6_vscattermw :
Hexagon_V65_viiv512v512_Intrinsic<"HEXAGON_V6_vscattermw">;

  
                                                              
                           
def int_hexagon_V6_vscattermw_128B :
Hexagon_V65_viiv1024v1024_Intrinsic<"HEXAGON_V6_vscattermw_128B">;

  
                                                         
                      
def int_hexagon_V6_vscattermh :
Hexagon_V65_viiv512v512_Intrinsic<"HEXAGON_V6_vscattermh">;

  
                                                              
                           
def int_hexagon_V6_vscattermh_128B :
Hexagon_V65_viiv1024v1024_Intrinsic<"HEXAGON_V6_vscattermh_128B">;

  
                                                             
                          
def int_hexagon_V6_vscattermw_add :
Hexagon_V65_viiv512v512_Intrinsic<"HEXAGON_V6_vscattermw_add">;

  
                                                                  
                               
def int_hexagon_V6_vscattermw_add_128B :
Hexagon_V65_viiv1024v1024_Intrinsic<"HEXAGON_V6_vscattermw_add_128B">;

  
                                                             
                          
def int_hexagon_V6_vscattermh_add :
Hexagon_V65_viiv512v512_Intrinsic<"HEXAGON_V6_vscattermh_add">;

  
                                                                  
                               
def int_hexagon_V6_vscattermh_add_128B :
Hexagon_V65_viiv1024v1024_Intrinsic<"HEXAGON_V6_vscattermh_add_128B">;

  
                                                            
                       
def int_hexagon_V6_vscattermwq :
Hexagon_V65_vv64iiiv512v512_Intrinsic<"HEXAGON_V6_vscattermwq">;

  
                                                                 
                            
def int_hexagon_V6_vscattermwq_128B :
Hexagon_V65_vv128iiiv1024v1024_Intrinsic<"HEXAGON_V6_vscattermwq_128B">;

  
                                                            
                       
def int_hexagon_V6_vscattermhq :
Hexagon_V65_vv64iiiv512v512_Intrinsic<"HEXAGON_V6_vscattermhq">;

  
                                                                 
                            
def int_hexagon_V6_vscattermhq_128B :
Hexagon_V65_vv128iiiv1024v1024_Intrinsic<"HEXAGON_V6_vscattermhq_128B">;

  
                                                          
                       
def int_hexagon_V6_vscattermhw :
Hexagon_V65_viiv1024v512_Intrinsic<"HEXAGON_V6_vscattermhw">;

  
                                                               
                            
def int_hexagon_V6_vscattermhw_128B :
Hexagon_V65_viiv2048v1024_Intrinsic<"HEXAGON_V6_vscattermhw_128B">;

  
                                                             
                        
def int_hexagon_V6_vscattermhwq :
Hexagon_V65_vv64iiiv1024v512_Intrinsic<"HEXAGON_V6_vscattermhwq">;

  
                                                                  
                             
def int_hexagon_V6_vscattermhwq_128B :
Hexagon_V65_vv128iiiv2048v1024_Intrinsic<"HEXAGON_V6_vscattermhwq_128B">;

  
                                                              
                           
def int_hexagon_V6_vscattermhw_add :
Hexagon_V65_viiv1024v512_Intrinsic<"HEXAGON_V6_vscattermhw_add">;

  
                                                                   
                                
def int_hexagon_V6_vscattermhw_add_128B :
Hexagon_V65_viiv2048v1024_Intrinsic<"HEXAGON_V6_vscattermhw_add_128B">;

  
                                            
                
def int_hexagon_V6_vdd0 :
Hexagon_v1024_Intrinsic<"HEXAGON_V6_vdd0">;

  
                                                 
                     
def int_hexagon_V6_vdd0_128B :
Hexagon_V65_v2048_Intrinsic<"HEXAGON_V6_vdd0_128B">;
