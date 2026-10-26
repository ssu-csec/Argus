from .ir import header_body
"""Body-verified summaries for bounded, non-escaping direct local closures.

Never dispatch by a helper's name. Only exact CreateFunctionInst references
are eligible. This verifier intentionally rejects Date/object mutation, outer
frames, arbitrary properties/getters, recursion, callbacks and unknown calls.
"""
import re
from .engine import Slice,val,choice,walk_values
from .ir import untype,literal

class Unsupported(ValueError):pass

def kind(v):
    if v.incomplete:return None
    if v.kind=='number':return 'number'
    if v.kind=='timestamp':
        return 'string' if v.data in ('toUTCString','toGMTString','toISOString','toString') else 'number'
    if v.kind=='literal' and v.data in ('true','false'):return 'boolean'
    if v.kind in ('string','concat','encoded','helper_string'):return 'string'
    if v.kind=='helper_array':return 'array'
    if v.kind=='helper_number':return 'number'
    if v.kind=='choice':
        ks={kind(a) for a in v.args}
        return next(iter(ks)) if len(ks)==1 else None
    return None

class VerifiedSlice(Slice):
    def __init__(self,fn,parent,bindings,allow_date_reads=False):
        super().__init__(fn,parent.source_fn,parent.source)
        self.bindings=bindings
        self.allow_date_reads=allow_date_reads
        self.local_envs={i.id for i in fn.insts.values() if i.op=='CreateScopeInst'}

    def operand(self,a):
        a=untype(a)
        if a in self.bindings:return self.bindings[a]
        return super().operand(a)

    def transfer(self,i):
        a=i.args;op=i.op
        if op=='CreateScopeInst':return val('object',self.fn.header+':'+i.id)
        if op in ('LoadFrameInst','StoreFrameInst'):
            env=a[1] if op=='LoadFrameInst' else a[2]
            slot=untype(a[0] if op=='LoadFrameInst' else a[1])
            if untype(env) not in self.local_envs or slot not in self.fn.local_slots:raise Unsupported('captured frame read/write')
            return super().transfer(i)
        if op=='TryLoadGlobalPropertyInst':
            if untype(a[0])!='globalObject' or literal(a[1]) not in ('window','self'):raise Unsupported('unverified global')
            return val('helper_window',literal(a[1]))
        if op=='AllocArrayInst':
            xs=tuple(self.operand(x) for x in a[1:])
            if not all(kind(x)=='string' for x in xs):raise Unsupported('non-string array')
            return val('helper_array','literal',xs)
        if op=='LoadPropertyInst':
            obj=self.operand(a[0]);prop=literal(a[1]);k=kind(obj)
            if self.allow_date_reads and obj.kind=='date' and prop in ('getTime','toUTCString','toGMTString'):
                return val('property',prop,(obj,))
            if obj.kind=='helper_window' and prop=='location':return val('helper_location')
            if obj.kind=='helper_location' and prop=='hostname':return val('helper_string','browser hostname')
            if k in ('string','array'):
                if prop=='length':return val('helper_number','length',(obj,))
                if prop in ('split','slice','join','indexOf','concat'):return val('property',prop,(obj,))
                index=self.operand(a[1])
                if k=='array' and kind(index)=='number':return val('helper_string','array index',(obj,index))
            raise Unsupported('unverified property/getter')
        if op=='CallInst':
            callee=self.operand(a[0]);recv=self.operand(a[2]);xs=tuple(self.operand(x) for x in a[3:]);k=kind(recv)
            if callee.kind!='property' or callee.args!=(recv,):raise Unsupported('dynamic/callback/nested call')
            m=callee.data
            if self.allow_date_reads and recv.kind=='date' and not xs and m in ('getTime','toUTCString','toGMTString'):
                return val('timestamp',m,(recv,),status='TIMESTAMP_EXPRESSION')
            if m=='split' and k=='string' and len(xs)==1 and kind(xs[0])=='string':return val('helper_array','split',(recv,)+xs)
            if m=='slice' and k in ('array','string') and all(kind(x)=='number' for x in xs):return val('helper_array' if k=='array' else 'helper_string','slice',(recv,)+xs)
            if m=='join' and k=='array' and all(kind(x)=='string' for x in xs):return val('helper_string','join',(recv,)+xs)
            if m=='indexOf' and k in ('array','string') and all(kind(x) in ('string','number') for x in xs):return val('helper_number','indexOf',(recv,)+xs)
            if m=='concat' and k=='string' and all(kind(x) in ('string','number','boolean') for x in xs):
                for x in xs:recv=val('concat',args=(recv,x))
                return recv
            raise Unsupported('call contract not proven')
        if op=='BinaryOperatorInst':
            operator=literal(a[0]);x,y=self.operand(a[1]),self.operand(a[2]);kx,ky=kind(x),kind(y)
            if kx not in ('string','number','boolean') or ky not in ('string','number','boolean'):raise Unsupported('implicit conversion may call user code')
            if operator=='+' and 'string' in (kx,ky):return val('concat',args=(x,y))
            if operator in ('+','-','*','/','%','>','<','<=','>=','===','!==','==','!='):
                return val('helper_number',operator,(x,y))
            raise Unsupported('operator')
        if op=='UnaryOperatorInst':
            x=self.operand(a[1])
            if kind(x) not in ('number','boolean','string'):raise Unsupported('unverified unary conversion')
            return val('helper_number',literal(a[0]),(x,))
        if op in ('PhiInst','ReturnInst','MovInst'):return super().transfer(i)
        if op in ('BranchInst','CondBranchInst'):
            if op=='CondBranchInst':
                x=self.operand(a[0])
                if kind(x) is None or x.dep:raise Unsupported('unverified/source-dependent control')
            return val('literal','undefined')
        raise Unsupported('effect or unsupported instruction: '+op)

def summarize(parent,call,callee,args,allow_date_reads=False):
    """Return a summary only when the entire reachable helper is validated."""
    if callee.kind!='object':return None
    prefix=parent.fn.header+':'
    if not callee.data.startswith(prefix):return None
    create=parent.fn.insts.get(callee.data[len(prefix):])
    if not create or create.op!='CreateFunctionInst':return None
    ref=untype(create.args[0])[1:]
                                                                           
                                                                           
    normalized=lambda s:re.sub(r'\([^()]*\)(#\d+)$',r'()\1',s)
    targets=[f for f in parent.functions if normalized(header_body(f.header))==normalized(ref)]
    if len(targets)!=1:return None
    fn=targets[0]
    def rejected(why):
        parent.record(call,'HELPER_SUMMARY_REJECTED')
        parent.evidence[(call.id,'HELPER_SUMMARY_REJECTED')].update(helper_function=fn.header,why=why)
        return None
    if len(fn.insts)>256:return rejected('helper instruction budget 256')
    if any(i.op=='StorePropertyInst' and untype(i.args[1])=='globalObject' and
           literal(i.args[2]) in (None,'window','self') for i in parent.fn.insts.values()):
        return rejected('caller reassigns browser global')
    if any(fn.reachable(t,b) for b in fn.live_blocks for t in fn.succ.get(b,[])):return rejected('loop/recursive CFG')
                                                                                    
    m=re.search(r'\(([^()]*)\)#\d+$',fn.header)
    if not m:return rejected('parameter header unsupported')
    params=[x.strip() for x in m[1].split(',') if x.strip()]
    if len(params)!=len(args):return rejected('arity/default/arguments unsupported')
    if any(kind(a) not in ('string','number','boolean') and not (allow_date_reads and a.kind=='date' and not a.incomplete) for a in args):return rejected('object/opaque argument may mutate or coerce')
    if allow_date_reads:
                                                                            
        transformed=[]
        for a in args:
            if a.kind=='date':
                state=parent.date_state(a,call)
                if state.incomplete or state.status!='TIMESTAMP_EXPRESSION':return rejected('Date state not proven at call')
                a=val('date',a.data,(state,))
            transformed.append(a)
        args=tuple(transformed)
    child=VerifiedSlice(fn,parent,dict(zip(('%'+x for x in params),args)),allow_date_reads)
    returns=[]
    try:
        for i in fn.insts.values():
            if i.block not in fn.live_blocks:continue
            v=child.eval(i.id)
            if v.incomplete:raise Unsupported('unknown value/effect: '+i.text)
            if i.op=='ReturnInst':
                if kind(v) not in ('string','number','boolean'):raise Unsupported('nonprimitive return')
                returns.append(v)
        if not returns:raise Unsupported('no reachable return')
    except Unsupported as exc:return rejected(str(exc))
    result=choice(returns)
    parent.record(call,'VERIFIED_DIRECT_HELPER_SUMMARY')
    parent.evidence[(call.id,'VERIFIED_DIRECT_HELPER_SUMMARY')].update(
        helper_function=fn.header,create_instruction=create.text,create_location=create.loc,
        argument_dependency=[a.dep for a in args],return_dependency=result.dep,
        external_writes=False,argument_mutation=False,receiver_mutation=False,
        cookie_write=False,unknown_calls=False,depth=1,instruction_count=len(fn.insts),
        assumptions=['standard browser hostname getter and unmodified string/array built-ins'],
        body=[{'instruction':i.text,'block':i.block,'location':i.loc} for i in fn.insts.values() if i.block in fn.live_blocks])
    return result
