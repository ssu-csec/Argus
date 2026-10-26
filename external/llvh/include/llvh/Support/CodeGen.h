//===-- llvm/Support/CodeGen.h - CodeGen Concepts ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file define some types which define code generation concepts. For
// example, relocation model.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_CODEGEN_H
#define LLVM_SUPPORT_CODEGEN_H

namespace llvh {

                            
  namespace Reloc {
  enum Model { Static, PIC_, DynamicNoPIC, ROPI, RWPI, ROPI_RWPI };
  }

                      
  namespace CodeModel {
                                            
  enum Model { Tiny, Small, Kernel, Medium, Large };
  }

  namespace PICLevel {
                                       
    enum Level { NotPIC=0, SmallPIC=1, BigPIC=2 };
  }

  namespace PIELevel {
    enum Level { Default=0, Small=1, Large=2 };
  }

                
  namespace TLSModel {
    enum Model {
      GeneralDynamic,
      LocalDynamic,
      InitialExec,
      LocalExec
    };
  }

                                        
  namespace CodeGenOpt {
    enum Level {
      None,              
      Less,              
      Default,                
      Aggressive         
    };
  }

}                       

#endif
