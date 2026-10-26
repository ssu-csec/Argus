from .ir import header_body
"""Conditional normal-return facts, never replacement Values or purity facts.

Only direct global JSON.stringify(x), exact local transport and primitive
String.concat use. The old opaque dependency/content Value stays untouched.
No site, identifier spelling, label, or external JavaScript execution.
"""
from .ir import untype, literal
from .arguments import slot, reaching
from .contexts import fact, function_ref
from .engine import Slice

ASSUMPTIONS = [
    'global JSON and JSON.stringify are standard at their exact lookup times',
    'String.prototype.concat is standard at its later lookup time, including after prior user effects',
    'explicit relevant writes in available IR reject the contract; absence is not runtime attestation',
    'unresolved global-key writes must not replace these intrinsics at the lookups; listed candidates are not proven harmless',
    'no hidden reflective frame access, dynamic code or unmodeled alias/prototype replacement',
    'normal completion is conditional, not execution, finite Date or browser storage proof',
]

def pool(sl):
    inv=getattr(sl.functions,'argument_inventory',None)
    return inv.functions if inv else sl.functions or [sl.fn]

def before(fn,a,b):
                                                                           
                                                                         
    return a.block==b.block and fn.positions[a.id]<fn.positions[b.id]

def _target(v):
    if v.kind=='global' or (v.kind=='symbol' and v.data in ('window','self','globalThis')):return 'global'
    if v.kind=='symbol' and v.data in ('JSON','String'):return v.data
    if v.kind=='property' and v.args:
        base=_target(v.args[0])
        if base=='global' and v.data in ('JSON','String'):return v.data
        if base=='String' and v.data=='prototype':return 'String.prototype'
    return None

def write_scan(sl):
    """Bounded explicit-write veto, NOT a complete interprocedural effect proof.

    Reuse Slice for alias/receiver values. Fresh unrelated own-property writes
    are not intrinsic overwrites just because their keys have the same name.
    """
    fs=pool(sl)
    cached=getattr(fs,'standard_return_write_scan',None)
    if cached is not None:return cached
    blocks=[];unresolved=[];checked=0
    for fn in fs:
        query=None
        def value(a):
            nonlocal query
            if query is None:
                query=Slice(fn,sl.source_fn,sl.source,())
                query.standard_return_queries_disabled=True
            return query.operand(a)
        for i in fn.insts.values():
            checked+=1
            if checked>250000:
                blocks.append(dict(intrinsic='ALL',reason='WRITE_SCAN_BUDGET'));break
            a=i.args;key=None;target=None
            if ('Property' in i.op and i.op.startswith(('Store','TryStore')) and len(a)>2) or (i.op=='DeletePropertyInst' and len(a)>=2):
                target_operand,key_operand=(a[0],a[1]) if i.op=='DeletePropertyInst' else (a[1],a[2])
                key=literal(key_operand)
                                                                         
                                                                         
                if key not in (None,'JSON','String','prototype','stringify','concat'):continue
                receiver=value(target_operand);target=_target(receiver)
                if key is None:
                    key_value=value(key_operand)
                    if key_value.kind=='string':key=key_value.data
                if target is None and key in ('stringify','concat'):
                    definition=fn.insts.get(receiver.data.rsplit(':',1)[-1]) if receiver.kind=='object' else None
                    if definition and definition.op in ('AllocObjectInst','AllocArrayInst','CreateFunctionInst'):continue
                    blocks.append(dict(**fact(fn,i),intrinsic='JSON' if key=='stringify' else 'concat',reason='POSSIBLE_ALIAS_WRITE'));continue
            elif i.op=='CallInst' and len(a)>=5:
                callee=fn.insts.get(untype(a[0]))
                if not callee or callee.op!='LoadPropertyInst' or literal(callee.args[1]) not in ('defineProperty','defineProperties','assign','set','setPrototypeOf'):continue
                                                                            
                                                                             
                                                                             
                target=_target(value(a[3]));key=literal(a[4])
                if key is None:
                    key_value=value(a[4])
                    if key_value.kind=='string':key=key_value.data
            else:continue
            affected=None
            if target=='global' and key is None:
                                                                           
                                                                            
                                                                           
                unresolved.append(dict(**fact(fn,i),target=target,resolved_key=None,
                    reason='GLOBAL_KEY_UNRESOLVED_NONMUTATION_REQUIRES_LOOKUP_ASSUMPTION'))
            if target=='global' and key=='JSON':affected='JSON'
            if target=='global' and key=='String':affected='concat'
            if target=='JSON' and key in (None,'stringify'):affected='JSON'
            if target=='String' and key in (None,'prototype'):affected='concat'
            if target=='String.prototype':affected='concat'
            if affected:blocks.append(dict(**fact(fn,i),intrinsic=affected,target=target,resolved_key=key,
                reason='POSSIBLE_DYNAMIC_INTRINSIC_WRITE' if key is None else 'EXPLICIT_RELEVANT_WRITE_OR_MUTATOR'))
        if checked>250000:break
    out=dict(functions=len(fs),instructions=checked,blockers=blocks,unresolved_write_candidates=unresolved,
             scope='available IR, scope-qualified Slice targets; not hidden/dynamic alias completeness')
    if hasattr(fs,'__dict__'):fs.standard_return_write_scan=out
    return out

def normal_return(sl,i):
    if getattr(sl,'standard_return_queries_disabled',False):return None
    if i.id in sl.standard_returns:return sl.standard_returns[i.id]
                                                                
    c=sl.fn.insts.get(untype(i.args[0])) if i.op=='CallInst' and i.args else None
    if not c or c.op!='LoadPropertyInst' or literal(c.args[1])!='stringify':return None
    ev=dict(rule='STANDARD_NORMAL_RETURN',scope=sl.fn.header,instruction=i.id,
            instruction_text=i.text,location=i.loc,block=i.block,supported=False,
            assumptions=ASSUMPTIONS,execution_success='NOT_PROVEN')
    sl.standard_returns[i.id]=ev
    def reject(reason):
        ev['reason']=reason;sl.evidence[i.id,'STANDARD_NORMAL_RETURN']=ev;return ev
    g=sl.fn.insts.get(untype(c.args[0]))
    if not (g and g.op=='TryLoadGlobalPropertyInst' and untype(g.args[0])=='globalObject' and literal(g.args[1])=='JSON'):
        return reject('NOT_DIRECT_GLOBAL_JSON_LOOKUP')
    if len(i.args)!=4 or untype(i.args[2])!=g.id:return reject('ARITY_OR_RECEIVER_UNSUPPORTED')
    if not (before(sl.fn,g,c) and before(sl.fn,c,i)):return reject('LOOKUP_ORDER_UNPROVEN')
    scan=write_scan(sl);ev['write_scan']=scan
    if any(b['intrinsic'] in ('JSON','ALL') for b in scan['blockers']):return reject('EXPLICIT_OR_POSSIBLE_JSON_REPLACEMENT')
    ev.update(supported=True,result_identity=sl.fn.header+':'+i.id,
        normal_types=['String','undefined'],condition='this exact call completes normally',
        global_lookup=fact(sl.fn,g),method_lookup=fact(sl.fn,c),actual=i.args[3],
        content='UNKNOWN_MAY_CONTAIN_COOKIE_DELIMITERS',dependency='ORIGINAL_OPAQUE_VALUE_PRESERVED',
        call_effects='MAY_INVOKE_GETTERS_TOJSON_AND_CHANGE_GLOBALS',call_exceptions='MAY_THROW',
        pure=False,primitive_reuse='NO_ORIGINAL_OBJECT_RETRAVERSAL',reason='CONDITIONAL_STANDARD_CONTRACT')
    if i.args[3].endswith(' : bigint'):
                                                                             
                                                                             
                                                                           
        ev['completion_obstacle']='BIGINT_INPUT_REQUIRES_CUSTOM_TOJSON_OR_TYPEERROR'
    sl.evidence[i.id,'STANDARD_NORMAL_RETURN']=ev
    return ev

class UseProof:
    """Identity walk, not a second value/taint engine. No heap/Phi transport."""
    def __init__(self,sl):
        self.sl=sl;self.fn=sl.fn;self.nodes=0;self.edges=[];self.returns={};self.reason=None
    def fail(self,why):self.reason=why;return None
    def primitive(self,a,use,depth=0):
        self.nodes+=1
        if self.nodes>64 or depth>16:return self.fail('RETURN_USE_BUDGET')
        a=untype(a)
        if literal(a) is not None:return ['String']
        if a=='undefined':return ['undefined']
        i=self.fn.insts.get(a)
        if not i or not before(self.fn,i,use):return self.fail('NO_SAME_BLOCK_EARLIER_DEFINITION')
        if i.op=='MovInst':return self.primitive(i.args[0],i,depth+1)
        if i.op in ('LoadFrameInst','LoadStackInst'):
            if i.op=='LoadFrameInst':
                binding=slot(i.args[0])
                if binding not in self.fn.local_slots:return self.fail('NONLOCAL_RETURN_TRANSPORT')
                fs=pool(self.sl)
                for f in fs:
                    if f.header==self.fn.header:continue
                    if any(k.op in ('LoadFrameInst','StoreFrameInst') and slot(k.args[0] if k.op=='LoadFrameInst' else k.args[1])==binding for k in f.insts.values()):
                        return self.fail('CAPTURED_RETURN_SLOT')
                                                                          
                known={function_ref(header_body(f.header)) for f in fs}
                for c in self.fn.insts.values():
                    if c.op=='CreateFunctionInst' and function_ref(untype(c.args[0])[1:]) not in known:
                        return self.fail('MISSING_NESTED_BODY')
                defs=reaching(self.fn,i,binding)
            else:
                                                                               
                defs=[k for k in self.fn.blocks[i.block][:self.fn.positions[i.id]] if k.op=='StoreStackInst' and untype(k.args[1])==untype(i.args[0])][-1:]
                addr=untype(i.args[0]);definition=self.fn.insts.get(addr)
                if not definition or definition.op!='AllocStackInst':return self.fail('NONLOCAL_STACK')
                if any(k.op not in ('StoreStackInst','LoadStackInst') and any(untype(x)==addr for x in k.args) for k in self.fn.insts.values()):return self.fail('STACK_ESCAPE')
            if len(defs)!=1 or defs[0] is None or not before(self.fn,defs[0],i):return self.fail('RETURN_REACHING_DEFINITION_AMBIGUOUS')
            store=defs[0]
            for k in self.fn.blocks[i.block][self.fn.positions[store.id]+1:self.fn.positions[i.id]]:
                if k.op!='CallInst':continue
                c=self.sl.operand(k.args[0]);r=self.sl.operand(k.args[2])
                if not (c.kind=='property' and c.data in ('getTime','valueOf','setTime','toUTCString','toGMTString') and r.kind=='date'):
                    return self.fail('RETURN_TRANSPORT_INTERVENING_CALL')
            self.edges.append(dict(scope=self.fn.header,load=i.id,store=store.id,load_instruction=i.text,store_instruction=store.text))
            return self.primitive(store.args[0],store,depth+1)
        if i.op=='CallInst':
            p=normal_return(self.sl,i)
            if p and p['supported']:
                self.returns[p['result_identity']]=p
                if p.get('completion_obstacle'):return self.fail('PRODUCER_ABRUPT_COMPLETION_NOT_DISCHARGED')
                return p['normal_types']
        return self.fail('NOT_EXACT_SUPPORTED_RETURN_OR_LITERAL')

def concat_effect(sl,i):
    """Only suppress *this* concat's conversion effect, never its producer's."""
    if i.id in sl.standard_uses:return sl.standard_uses[i.id]['supported']
    c=sl.fn.insts.get(untype(i.args[0])) if i.op=='CallInst' else None
    if not c or c.op!='LoadPropertyInst' or literal(c.args[1])!='concat':return False
    ev=dict(rule='STANDARD_PRIMITIVE_CONCAT_USE',scope=sl.fn.header,instruction=i.id,
            instruction_text=i.text,supported=False,assumptions=ASSUMPTIONS)
    sl.standard_uses[i.id]=ev
    def finish(ok,reason):
        ev.update(supported=ok,reason=reason);sl.evidence[i.id,'STANDARD_PRIMITIVE_CONCAT_USE']=ev;return ok
    if len(i.args)<3 or untype(c.args[0])!=untype(i.args[2]) or not before(sl.fn,c,i):return finish(False,'METHOD_RECEIVER_OR_LOOKUP_UNPROVEN')
    proof=UseProof(sl)
    receiver=proof.primitive(i.args[2],c)
    if receiver!=['String']:return finish(False,'PRIMITIVE_STRING_RECEIVER_UNPROVEN')
    scan=write_scan(sl);ev['write_scan']=scan
    if any(b['intrinsic'] in ('concat','ALL') for b in scan['blockers']):return finish(False,'EXPLICIT_OR_POSSIBLE_CONCAT_REPLACEMENT')
    args=[proof.primitive(a,i) for a in i.args[3:]]
    ev.update(receiver_types=receiver,actual_types=args,reaching_edges=proof.edges,normal_returns=list(proof.returns.values()),
              method_lookup=fact(sl.fn,c),value_content_and_dependency='UNCHANGED',prior_effects='NOT_DISCHARGED')
    if any(x is None for x in args):return finish(False,proof.reason or 'ACTUAL_CONVERSION_UNPROVEN')
                                                                            
    ev['current_conversion_effect']='NO_USER_OBJECT_COERCION_UNDER_STANDARD_CONTRACT'
    return finish(True,'EXACT_PRIMITIVE_ACTUALS')
