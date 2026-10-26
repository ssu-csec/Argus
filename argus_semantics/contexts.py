from .ir import header_body
"""Bounded, fail-closed call-context and local prototype proofs.

No method names, site keys or audit labels select an implementation. Escaping
closures, open-world receivers and uncertain callsites are never generalized
from a single observed window call.
"""
import re
from .ir import untype,literal

def function_ref(s):
    return re.sub(r'\([^()]*\)(#\d+)$',r'()\1',s)

def target(functions,create):
    ref=function_ref(untype(create.args[0])[1:])
    fs=[f for f in functions if function_ref(header_body(f.header))==ref]
    return fs[0] if len(fs)==1 else None

def fact(fn,i):
    return {'function':fn.header,'instruction':i.text,'value_id':i.id,'block':i.block,'location':i.loc}

def object_instruction(sl,v):
    prefix=sl.fn.header+':'
    return sl.fn.insts.get(v.data[len(prefix):]) if v.data.startswith(prefix) else None

def creation_sites(functions,fn):
    wanted=function_ref(header_body(fn.header))
    index=getattr(functions,'creation_index',None)
    if index is not None:return index.get(wanted,[])
    if not getattr(functions,'complete',False):return None
    return [dict(fact(f,i),id=i.id) for f in functions for i in f.insts.values()
            if i.op=='CreateFunctionInst' and function_ref(untype(i.args[0])[1:])==wanted]

def bind_document_parameter(sl,param):
    """All uses of one local, nonescaping closure must be direct same-window calls."""
    inventory=getattr(sl.functions,'argument_inventory',None)
    if inventory is not None:
        from .arguments import bind
        return bind(sl,param,inventory)
    from .engine import Slice,val
    fn=sl.fn;ev={'rule':'ARGUMENT_CONTEXT_PROOF','function':fn.header,'parameter':param,'supported':False}
    sl.evidence[('context:'+param,'ARGUMENT_CONTEXT_PROOF')]=ev
    def fail(why):ev['obstacle']=why;return None
    m=re.search(r'\(([^()]*)\)#\d+$',fn.header)
    ps=['%'+x.strip() for x in m[1].split(',') if x.strip()] if m else []
    if param not in ps:return fail('NOT_A_FORMAL_PARAMETER')
    ev['parameter_index']=ps.index(param)
    sites=creation_sites(sl.functions,fn)
    if sites is None:return fail('CREATION_UNIVERSE_NOT_AVAILABLE')
    ev['creation_sites']=sites
    if len(sites)!=1:return fail('MULTIPLE_OR_MISSING_CREATION_SITES')
    site=sites[0];owners=[f for f in sl.functions if f.header==site['function']]
    if len(owners)!=1:return fail('OWNER_BODY_NOT_AVAILABLE')
    owner=owners[0]
    other_creates=[i for i in owner.insts.values() if i.op=='CreateFunctionInst' and i.id!=site.get('id',site.get('value_id'))]
    if other_creates:
        ev['sibling_creation_count']=len(other_creates)
        ev['representative_sibling_creations']=[fact(owner,i) for i in other_creates[:3]]
        return fail('SIBLING_CLOSURE_CAPTURE_UNSUPPORTED')
    if len(owner.insts)>3000:return fail('OWNER_INSTRUCTION_BUDGET_3000')
    create=owner.insts[site.get('id',site.get('value_id'))]
    os=Slice(owner,sl.source_fn,sl.source,sl.functions)
    cv=os.eval(create.id)
    uses=[];slots=set();ids={create.id}
                                                                           
    for i in owner.insts.values():
        if i.op=='StoreFrameInst' and untype(i.args[0]) in ids:
            slot=untype(i.args[1])
            if slot not in owner.local_slots:return fail('CLOSURE_STORED_IN_OUTER_FRAME')
            slots.add(slot)
    for i in owner.insts.values():
        if i.op=='LoadFrameInst' and untype(i.args[0]) in slots:ids.add(i.id)
    for i in owner.insts.values():
        if i.op=='StoreFrameInst' and untype(i.args[1]) in slots and untype(i.args[0]) not in ids:
            if not (untype(i.args[0])=='undefined' and i.block==create.block and owner.positions[i.id]<owner.positions[create.id]):return fail('CLOSURE_REASSIGNED')
        if i.op=='CreateFunctionInst' and i.id!=create.id:return fail('SIBLING_CLOSURE_CAPTURE_UNSUPPORTED')
        referenced=[k for k,a in enumerate(i.args) if untype(a) in ids]
        if not referenced:continue
        if i.op=='StoreFrameInst' and referenced==[0] and untype(i.args[1]) in slots:continue
        if i.op=='CallInst' and referenced==[0]:uses.append(i);continue
        return fail('CLOSURE_ESCAPES_OR_INDIRECT_USE')
    if not uses:return fail('NO_DIRECT_CALL_CONTEXT')
    if len(uses)>8:return fail('CALLSITE_BUDGET_8')
                                                                             
                                                                   
    if any(i.op=='LoadFrameInst' and '@' in untype(i.args[0]) for i in fn.insts.values()):return fail('TARGET_OUTER_FRAME_READ_UNSUPPORTED')
    if any(i.op in ('StorePropertyInst','StoreNewOwnPropertyInst') and literal(i.args[2]) in (None,'document','window','self') for i in fn.insts.values()):return fail('TARGET_IDENTITY_PROPERTY_WRITE')
    if any(i.op=='StoreGetterSetterInst' or ('Property' in i.op and i.op.startswith('Store') and (i.op not in ('StorePropertyInst','StoreNewOwnPropertyInst') or literal(i.args[2])!='cookie')) for i in fn.insts.values()):return fail('TARGET_PROPERTY_EFFECT_UNSUPPORTED')
    for i in owner.insts.values():
        if i.op=='CallInst' and i not in uses:return fail('OWNER_UNKNOWN_CALL_OR_WRAPPER')
        if i.op in ('StorePropertyInst','StoreNewOwnPropertyInst','DeletePropertyInst'):return fail('OWNER_PROPERTY_WRITE_OR_EXPORT')
        if i.op in ('ThrowInst','TryStartInst','GetPNamesInst','GetNextPNameInst'):return fail('OWNER_CONTROL_OR_EXCEPTION_UNSUPPORTED')
    calls=[]
    for call in uses:
        if os.operand(call.args[0])!=cv:return fail('CALL_CALLEE_REACHING_DEFINITION_DIFFERS')
        index=3+ps.index(param)
        if len(call.args)<=index:return fail('MISSING_ACTUAL_ARGUMENT')
        actual=os.operand(call.args[index]);calls.append(dict(fact(owner,call),actual_operand=call.args[index],actual_kind=actual.kind,actual_value=actual.data))
        if actual.kind!='symbol' or actual.data not in ('window','self'):
            ev['callsites']=calls;return fail('ACTUALS_NOT_ALL_BROWSER_GLOBAL')
    check=Slice(fn,sl.source_fn,sl.source,sl.functions);check.bindings[param]=val('symbol','window')
    for i in fn.insts.values():
        if i.op=='CallInst':
            v=check.eval(i.id)
            if v.kind=='unknown' or v.incomplete:
                ev['callsites']=calls;return fail('TARGET_UNKNOWN_EFFECT_CONTEXT')
    ev.update(supported=True,callsites=calls,closed_use_count=len(uses),obstacle=None,
              assumptions=['standard unmodified browser globals','one local closure allocation; no escape or wrappers'])
    return val('symbol','window')

def local_instance(sl,i,callee):
    """Only a directly allocated instance of an empty local constructor."""
    from .engine import val
    create=object_instruction(sl,callee)
    if not create or create.op!='CreateFunctionInst' or len(i.args)>3:return None
    fn=target(sl.functions,create)
    if not fn or len(fn.insts)>32:return None
    for x in fn.insts.values():
        if x.block not in fn.live_blocks:continue
        if x.op=='CreateScopeInst':continue
        if x.op=='ReturnInst' and untype(x.args[0])=='undefined':continue
        return None
    sl.record(i,'LOCAL_EMPTY_CONSTRUCTOR_IDENTITY')
    return val('instance',sl.fn.header+':'+i.id,(callee,))

def method(sl,call,callee,recv,args):
    """Exact local allocation + unique prototype store + no escape/effect proof."""
    from .engine import val
    if callee.kind!='property' or recv.kind!='instance' or callee.args!=(recv,):return None
    ev=dict(fact(sl.fn,call),rule='PROTOTYPE_METHOD_PROOF',supported=False)
    sl.evidence[(call.id,'PROTOTYPE_METHOD_PROOF')]=ev
    def fail(why):ev['obstacle']=why;return None
    ctor=recv.args[0];proto=val('property','prototype',(ctor,))
    ctor_create=object_instruction(sl,ctor);allocation=object_instruction(sl,recv)
    if not ctor_create or not allocation:return fail('ALLOCATION_UNAVAILABLE')
    if len(sl.fn.insts)>3000:return fail('OWNER_INSTRUCTION_BUDGET_3000')
    writes=[]
    for i in sl.fn.insts.values():
        if i.op=='StoreFrameInst' and untype(i.args[1]) not in sl.fn.local_slots and sl.operand(i.args[0]) in (recv,ctor,proto):return fail('OUTER_FRAME_ALIAS_ESCAPE')
        if i.op not in ('StorePropertyInst','StoreNewOwnPropertyInst'):continue
        obj=sl.operand(i.args[1]);name=literal(i.args[2]);stored=sl.operand(i.args[0])
        if stored in (recv,ctor,proto):return fail('OBJECT_OR_CONSTRUCTOR_ESCAPE')
        if obj==ctor and name in (None,'prototype'):return fail('PROTOTYPE_REPLACED')
        if obj==recv:return fail('OWN_PROPERTY_SHADOW_OR_MUTATION')
        if obj==proto:
            if name is None:return fail('DYNAMIC_PROTOTYPE_WRITE')
            if name==callee.data:writes.append(i)
    if len(writes)!=1:return fail('MULTIPLE_OR_MISSING_METHOD_WRITES')
    write=writes[0]
    if not (write.block==allocation.block==call.block and sl.fn.positions[write.id]<sl.fn.positions[allocation.id]<sl.fn.positions[call.id]):return fail('METHOD_ORDER_OR_BRANCH_UNPROVEN')
    definition=sl.operand(write.args[0]);body_create=object_instruction(sl,definition)
    if not body_create or body_create.op!='CreateFunctionInst':return fail('METHOD_BODY_NOT_EXACT_LOCAL_CLOSURE')
    body=target(sl.functions,body_create)
    if body is None:return fail('METHOD_BODY_UNAVAILABLE')
                                                                           
                                                                             
    for i in sl.fn.insts.values():
        if i.id==call.id:continue
        if i.op in ('DeletePropertyInst','StoreGetterSetterInst') or ('Property' in i.op and i.op.startswith('Store') and i.op not in ('StorePropertyInst','StoreNewOwnPropertyInst')):return fail('UNMODELLED_PROPERTY_EFFECT')
        if i.op=='CallInst' and sl.fn.reachable(i.block,call.block):
            if i.block==call.block and sl.fn.positions[i.id]>sl.fn.positions[call.id]:continue
            if any(sl.operand(a) in (recv,ctor,proto) for a in i.args):return fail('ALIAS_ESCAPE_OR_RECEIVER_CALL')
            v=sl.eval(i.id)
            if v.kind=='unknown' or v.incomplete:return fail('UNKNOWN_CALL_OR_CALLBACK')
    from .helpers import summarize
                                                                              
                                                                            
    result=summarize(sl,call,definition,args,allow_date_reads=True)
    if result is None:return fail('METHOD_EFFECT_OR_RETURN_UNSUPPORTED')
    ev.update(supported=True,obstacle=None,allocation=fact(sl.fn,allocation),constructor=fact(sl.fn,ctor_create),prototype_store=fact(sl.fn,write),callee_function=body.header,this_identity=recv.data,argument_dependency=[a.dep for a in args],return_dependency=result.dep)
    return result
