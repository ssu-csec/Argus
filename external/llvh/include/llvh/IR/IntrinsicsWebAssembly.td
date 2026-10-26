//===- IntrinsicsWebAssembly.td - Defines wasm intrinsics --*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file defines all of the WebAssembly-specific intrinsics.
///
//===----------------------------------------------------------------------===//

let TargetPrefix = "wasm" in {                                            

                                                                       
                                                                           
                                
def int_wasm_memory_size : Intrinsic<[llvm_anyint_ty],
                                     [llvm_i32_ty],
                                     [IntrReadMem]>;
def int_wasm_memory_grow : Intrinsic<[llvm_anyint_ty],
                                     [llvm_i32_ty, LLVMMatchType<0>],
                                     []>;

                           
def int_wasm_mem_size : Intrinsic<[llvm_anyint_ty],
                                  [llvm_i32_ty],
                                  [IntrReadMem]>;
def int_wasm_mem_grow : Intrinsic<[llvm_anyint_ty],
                                  [llvm_i32_ty, LLVMMatchType<0>],
                                  []>;

                                                                   
def int_wasm_current_memory : Intrinsic<[llvm_anyint_ty], [], [IntrReadMem]>;
def int_wasm_grow_memory : Intrinsic<[llvm_anyint_ty], [LLVMMatchType<0>], []>;

                                                                                
                                
                                                                                

                  
def int_wasm_throw : Intrinsic<[], [llvm_i32_ty, llvm_ptr_ty],
                               [Throws, IntrNoReturn]>;
def int_wasm_rethrow : Intrinsic<[], [], [Throws, IntrNoReturn]>;

                                                                             
                                                                              
def int_wasm_get_exception : Intrinsic<[llvm_ptr_ty], [llvm_token_ty],
                                       [IntrHasSideEffects]>;
def int_wasm_get_ehselector : Intrinsic<[llvm_i32_ty], [llvm_token_ty],
                                        [IntrHasSideEffects]>;

                                                                                
               
def int_wasm_catch : Intrinsic<[llvm_ptr_ty], [llvm_i32_ty],
                               [IntrHasSideEffects]>;

                                                                             
                                                                            
                                                           
def int_wasm_landingpad_index: Intrinsic<[], [llvm_i32_ty], [IntrNoMem]>;

                                                
def int_wasm_lsda : Intrinsic<[llvm_ptr_ty], [], [IntrNoMem]>;

                                                                                
                    
                                                                                

                
def int_wasm_atomic_wait_i32 :
  Intrinsic<[llvm_i32_ty],
            [LLVMPointerType<llvm_i32_ty>, llvm_i32_ty, llvm_i64_ty],
            [IntrInaccessibleMemOrArgMemOnly, ReadOnly<0>, NoCapture<0>,
             IntrHasSideEffects],
             "", [SDNPMemOperand]>;
def int_wasm_atomic_wait_i64 :
  Intrinsic<[llvm_i32_ty],
            [LLVMPointerType<llvm_i64_ty>, llvm_i64_ty, llvm_i64_ty],
            [IntrInaccessibleMemOrArgMemOnly, ReadOnly<0>, NoCapture<0>,
             IntrHasSideEffects],
             "", [SDNPMemOperand]>;
def int_wasm_atomic_notify:
  Intrinsic<[llvm_i32_ty], [LLVMPointerType<llvm_i32_ty>, llvm_i32_ty],
            [IntrInaccessibleMemOnly, NoCapture<0>, IntrHasSideEffects], "",
            [SDNPMemOperand]>;

                                                                                
                  
                                                                                

def int_wasm_add_saturate_signed :
  Intrinsic<[llvm_anyvector_ty],
            [LLVMMatchType<0>, LLVMMatchType<0>],
            [IntrNoMem, IntrSpeculatable]>;
def int_wasm_add_saturate_unsigned :
  Intrinsic<[llvm_anyvector_ty],
            [LLVMMatchType<0>, LLVMMatchType<0>],
            [IntrNoMem, IntrSpeculatable]>;
def int_wasm_sub_saturate_signed :
  Intrinsic<[llvm_anyvector_ty],
            [LLVMMatchType<0>, LLVMMatchType<0>],
            [IntrNoMem, IntrSpeculatable]>;
def int_wasm_sub_saturate_unsigned :
  Intrinsic<[llvm_anyvector_ty],
            [LLVMMatchType<0>, LLVMMatchType<0>],
            [IntrNoMem, IntrSpeculatable]>;
def int_wasm_bitselect :
  Intrinsic<[llvm_anyvector_ty],
            [LLVMMatchType<0>, LLVMMatchType<0>, LLVMMatchType<0>],
            [IntrNoMem, IntrSpeculatable]>;
def int_wasm_anytrue :
  Intrinsic<[llvm_i32_ty],
            [llvm_anyvector_ty],
            [IntrNoMem, IntrSpeculatable]>;
def int_wasm_alltrue :
  Intrinsic<[llvm_i32_ty],
            [llvm_anyvector_ty],
            [IntrNoMem, IntrSpeculatable]>;

}                         
