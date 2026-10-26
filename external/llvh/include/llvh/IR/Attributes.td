                         
class Attr<string S> {
                                                       
  string AttrString = S;
}

                   
class EnumAttr<string S> : Attr<S>;

                         
class StrBoolAttr<string S> : Attr<S>;

                                       

                                                                             
                                                
def Alignment : EnumAttr<"align">;

                                                                               
                                                                      
def AllocSize : EnumAttr<"allocsize">;

                  
def AlwaysInline : EnumAttr<"alwaysinline">;

                                                                          
def ArgMemOnly : EnumAttr<"argmemonly">;

                                                                         
                
def Builtin : EnumAttr<"builtin">;

                            
def ByVal : EnumAttr<"byval">;

                                           
def Cold : EnumAttr<"cold">;

                                                   
def Convergent : EnumAttr<"convergent">;

                                           
def Dereferenceable : EnumAttr<"dereferenceable">;

                                              
def DereferenceableOrNull : EnumAttr<"dereferenceable_or_null">;

                                                                 
def InaccessibleMemOnly : EnumAttr<"inaccessiblememonly">;

                                                                            
                                           
def InaccessibleMemOrArgMemOnly : EnumAttr<"inaccessiblemem_or_argmemonly">;

                                
def InAlloca : EnumAttr<"inalloca">;

                                       
def InlineHint : EnumAttr<"inlinehint">;

                                            
def InReg : EnumAttr<"inreg">;

                                                   
def JumpTable : EnumAttr<"jumptable">;

                                              
def MinSize : EnumAttr<"minsize">;

                   
def Naked : EnumAttr<"naked">;

                                 
def Nest : EnumAttr<"nest">;

                                       
def NoAlias : EnumAttr<"noalias">;

                                         
def NoBuiltin : EnumAttr<"nobuiltin">;

                                           
def NoCapture : EnumAttr<"nocapture">;

                              
def NoDuplicate : EnumAttr<"noduplicate">;

                                          
def NoImplicitFloat : EnumAttr<"noimplicitfloat">;

                 
def NoInline : EnumAttr<"noinline">;

                                                                            
def NonLazyBind : EnumAttr<"nonlazybind">;

                                    
def NonNull : EnumAttr<"nonnull">;

                                  
def NoRecurse : EnumAttr<"norecurse">;

                    
def NoRedZone : EnumAttr<"noredzone">;

                                       
def NoReturn : EnumAttr<"noreturn">;

                                     
def NoCfCheck : EnumAttr<"nocf_check">;

                                  
def NoUnwind : EnumAttr<"nounwind">;

                                                 
def OptForFuzzing : EnumAttr<"optforfuzzing">;

             
def OptimizeForSize : EnumAttr<"optsize">;

                                   
def OptimizeNone : EnumAttr<"optnone">;

                                    
def ReadNone : EnumAttr<"readnone">;

                                    
def ReadOnly : EnumAttr<"readonly">;

                                                  
def Returned : EnumAttr<"returned">;

                              
def ReturnsTwice : EnumAttr<"returns_twice">;

                          
def SafeStack : EnumAttr<"safestack">;

                                 
def ShadowCallStack : EnumAttr<"shadowcallstack">;

                                    
def SExt : EnumAttr<"signext">;

                                                                              
                                                              
def StackAlignment : EnumAttr<"alignstack">;

                               
def Speculatable : EnumAttr<"speculatable">;

                     
def StackProtect : EnumAttr<"ssp">;

                              
def StackProtectReq : EnumAttr<"sspreq">;

                            
def StackProtectStrong : EnumAttr<"sspstrong">;

                                                                             
def StrictFP : EnumAttr<"strictfp">;

                                          
def StructRet : EnumAttr<"sret">;

                           
def SanitizeAddress : EnumAttr<"sanitize_address">;

                          
def SanitizeThread : EnumAttr<"sanitize_thread">;

                          
def SanitizeMemory : EnumAttr<"sanitize_memory">;

                             
def SanitizeHWAddress : EnumAttr<"sanitize_hwaddress">;

                                          
   
                                                                           
                                                                            
                                                                              
                                                                 
def SpeculativeLoadHardening : EnumAttr<"speculative_load_hardening">;

                            
def SwiftError : EnumAttr<"swifterror">;

                                   
def SwiftSelf : EnumAttr<"swiftself">;

                                       
def UWTable : EnumAttr<"uwtable">;

                                   
def WriteOnly : EnumAttr<"writeonly">;

                                    
def ZExt : EnumAttr<"zeroext">;

                                         
def LessPreciseFPMAD : StrBoolAttr<"less-precise-fpmad">;
def NoInfsFPMath : StrBoolAttr<"no-infs-fp-math">;
def NoNansFPMath : StrBoolAttr<"no-nans-fp-math">;
def UnsafeFPMath : StrBoolAttr<"unsafe-fp-math">;
def NoJumpTables : StrBoolAttr<"no-jump-tables">;
def ProfileSampleAccurate : StrBoolAttr<"profile-sample-accurate">;

class CompatRule<string F> {
                                                                             
                                                                         
                                                                              
                                                                               
                                                                               
                                                            
  string CompatFunc = F;
}

def : CompatRule<"isEqual<SanitizeAddressAttr>">;
def : CompatRule<"isEqual<SanitizeThreadAttr>">;
def : CompatRule<"isEqual<SanitizeMemoryAttr>">;
def : CompatRule<"isEqual<SanitizeHWAddressAttr>">;
def : CompatRule<"isEqual<SafeStackAttr>">;
def : CompatRule<"isEqual<ShadowCallStackAttr>">;

class MergeRule<string F> {
                                                                              
                                                
                                                                          
                                                                             
            
  string MergeFunc = F;
}

def : MergeRule<"setAND<LessPreciseFPMADAttr>">;
def : MergeRule<"setAND<NoInfsFPMathAttr>">;
def : MergeRule<"setAND<NoNansFPMathAttr>">;
def : MergeRule<"setAND<UnsafeFPMathAttr>">;
def : MergeRule<"setOR<NoImplicitFloatAttr>">;
def : MergeRule<"setOR<NoJumpTablesAttr>">;
def : MergeRule<"setOR<ProfileSampleAccurateAttr>">;
def : MergeRule<"setOR<SpeculativeLoadHardeningAttr>">;
def : MergeRule<"adjustCallerSSPLevel">;
def : MergeRule<"adjustCallerStackProbes">;
def : MergeRule<"adjustCallerStackProbeSize">;
def : MergeRule<"adjustMinLegalVectorWidth">;
def : MergeRule<"adjustNullPointerValidAttr">;
