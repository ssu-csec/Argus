"""Closed fresh-object own-data-property calls, never name-based dispatch.

An exact property read at one call is not an exhaustive caller set for a public
function. This certificate requires both target identity and closed uses.
"""
from .ir import untype,literal
from .arguments import slot
from .contexts import fact

def resolve(inv,owner,create,callee):
    cache=getattr(inv,'property_call_cache',None)
    if cache is None:cache={};inv.property_call_cache=cache
    key=(owner.header,create.id,callee.header)
    if key not in cache:cache[key]=_resolve(inv,owner,create,callee)
    return cache[key]

def _resolve(inv,owner,create,callee):
    ev=dict(rule='CLOSED_OWN_DATA_PROPERTY_CALL',supported=False,target=callee.header,
            owner=owner.header,creation=fact(owner,create),edges=[],
            budgets=dict(uses=256,aliases=32,calls=1),callset_complete=False,
            assumptions=['faithful complete IR', 'ordinary lexical semantics without dynamic frame reflection'])
    def fail(reason):ev['obstacle']=reason;return None,ev
    uses=inv.uses[owner.header].get(create.id,[])
    if len(uses)!=1:return fail('CLOSURE_MULTIPLE_OR_MISSING_USES')
    store,n=uses[0]
    if store.op not in ('StoreNewOwnPropertyInst','StorePropertyInst')or n!=0:return fail('NOT_OWN_PROPERTY_INITIALIZATION')
    ev['store']=fact(owner,store);key=literal(store.args[2]);receiver=untype(store.args[1])
    ev.update(property_key=key,receiver=receiver)
    if receiver=='globalObject':return fail('PUBLIC_GLOBAL_CALLSET_AND_RUNTIME_ORDER_UNPROVEN')
    if store.op!='StoreNewOwnPropertyInst' or key is None:return fail('OWN_DATA_DESCRIPTOR_NOT_PROVEN')
    alloc=owner.insts.get(receiver)
    if alloc is None or alloc.op!='AllocObjectInst':return fail('FRESH_OBJECT_IDENTITY_UNPROVEN')
                                                                              
                                                                     
    if any('This' in i.op or any(untype(a)=='%this' for a in i.args)for i in callee.insts.values()):return fail('CALLEE_THIS_USE_UNSUPPORTED')
    if any('Eval'in i.op for i in owner.insts.values()):return fail('OWNER_DYNAMIC_EVAL_UNSUPPORTED')
    block=alloc.block
    if block not in owner.live_blocks or any(owner.reachable(b,block)for b in owner.succ.get(block,[])):return fail('OBJECT_LIFETIME_IN_LOOP_OR_UNREACHABLE')
    def before(a,b):return a.block==b.block==block and owner.positions[a.id]<owner.positions[b.id]
    if not before(alloc,store)or not before(create,store):return fail('INITIALIZATION_ORDER_UNPROVEN')
    aliases={alloc.id};todo=[alloc.id];done=set();reads={};receivers=[];seen_bindings=set();nodes=0
    while todo:
        aid=todo.pop()
        if aid in done:continue
        done.add(aid)
        if len(done)>32:return fail('OBJECT_ALIAS_BUDGET')
        origin=owner.insts[aid]
        for user,index in inv.uses[owner.header].get(aid,[]):
            nodes+=1
            if nodes>256:return fail('OBJECT_USE_BUDGET')
            if not before(origin,user):return fail('OBJECT_USE_ORDER_UNPROVEN')
            if user is store and index==1:continue
            if user.op=='ThrowIfEmptyInst'and index==0 and len(user.args)==1:
                                                                              
                                                                         
                aliases.add(user.id);todo.append(user.id)
                ev['edges'].append(dict(kind='INITIALIZED_OBJECT_TDZ_GUARD',instruction=fact(owner,user)))
                continue
            if user.op=='StoreFrameInst'and index==0:
                binding=slot(user.args[1])
                if binding not in owner.local_slots or binding in seen_bindings:return fail('OBJECT_BINDING_NOT_UNIQUE_LOCAL')
                seen_bindings.add(binding)
                for writer,other in inv.stores[binding]:
                    if writer is owner and other is user:continue
                    if writer is owner and untype(other.args[0])in('undefined','empty')and before(other,user):continue
                    return fail('OBJECT_BINDING_REASSIGNED_OR_CAPTURED')
                for reader,load in inv.loads[binding]:
                    if reader is not owner or not before(user,load):return fail('OBJECT_CAPTURE_OR_LOAD_ORDER_UNPROVEN')
                                                                              
                    from .engine import frame_owner
                    a=frame_owner(owner,binding,untype(user.args[2]),user)
                    b=frame_owner(owner,binding,untype(load.args[1]),load)
                    if a is None or a!=b:return fail('OBJECT_BINDING_ENVIRONMENT_UNPROVEN')
                    aliases.add(load.id);todo.append(load.id)
                    ev['edges'].append(dict(kind='EXACT_LOCAL_OBJECT_ALIAS',store=fact(owner,user),load=fact(owner,load)))
                continue
            if user.op=='LoadPropertyInst'and index==0 and literal(user.args[1])==key and before(store,user):
                reads[user.id]=user;continue
            if user.op=='CallInst'and index==2:receivers.append(user);continue
            return fail('OBJECT_ESCAPE_MUTATION_OR_UNKNOWN_USE')
    calls=[]
    for load in reads.values():
        lu=inv.uses[owner.header].get(load.id,[])
        if len(lu)!=1 or lu[0][0].op!='CallInst'or lu[0][1]!=0:return fail('PROPERTY_VALUE_ESCAPE_OR_INDIRECT_CALL')
        call=lu[0][0]
        if not before(load,call)or untype(call.args[1])!='undefined':return fail('PROPERTY_CALL_ORDER_OR_NEW_TARGET')
        if untype(call.args[2])not in aliases:return fail('CALL_RECEIVER_IDENTITY_UNPROVEN')
        calls.append(call)
        ev['edges'].append(dict(kind='OWN_DATA_STORE_LOAD_CALL',store=fact(owner,store),load=fact(owner,load),call=fact(owner,call)))
    if len(calls)!=1 or any(c not in calls for c in receivers):return fail('NOT_ONE_CLOSED_PROPERTY_CALL')
    ev.update(supported=True,obstacle=None,callset_complete=True,object_allocation=fact(owner,alloc),call=fact(owner,calls[0]),checked_uses=nodes,aliases=sorted(aliases))
    return calls[0],ev
