from .ir import header_body
"""Bounded lexical argument proofs over complete compile-only IR.

Exact scope-qualified slots, not spelling, join references. A complete IR scan
is only a use inventory: exports, aliases and callbacks keep the callset open.
"""
import re
from collections import defaultdict
from .ir import untype,literal
from .contexts import function_ref,fact

def slot(s):return untype(s).split('@',1)[0].rstrip(']')+']'
def params(fn):
    m=re.search(r'\(([^()]*)\)#\d+$',fn.header)
    return ['%'+x.strip() for x in m[1].split(',') if x.strip()] if m else []

def reaching(fn,load,binding):
    todo=[(load.block,fn.positions[load.id])];seen=set();out={}
    while todo:
        b,pos=todo.pop()
        if (b,pos) in seen:continue
        seen.add((b,pos))
        if len(seen)>1000:return [None]
        found=next((i for i in reversed(fn.blocks[b][:pos]) if i.op=='StoreFrameInst' and slot(i.args[1])==binding),None)
        if found:out[found.id]=found
        elif not fn.preds.get(b):out[None]=None
        else:todo.extend((p,len(fn.blocks[p])) for p in fn.preds[b])
    return list(out.values())

class Inventory:
    def __init__(self,fs):
        self.functions=fs;self.byheader={f.header:f for f in fs}
        refs=[function_ref(header_body(f.header)) for f in fs]
        if len(self.byheader)!=len(fs) or len(set(refs))!=len(refs):raise ValueError('Ambiguous IR function identity')
        self.creates=defaultdict(list);self.loads=defaultdict(list);self.stores=defaultdict(list);self.uses={}
        for f in fs:
            uses=defaultdict(list)
            for i in f.insts.values():
                for n,a in enumerate(i.args):uses[untype(a)].append((i,n))
                if i.op=='CreateFunctionInst':self.creates[function_ref(untype(i.args[0])[1:])].append((f,i))
                if i.op=='LoadFrameInst':self.loads[slot(i.args[0])].append((f,i))
                if i.op=='StoreFrameInst':self.stores[slot(i.args[1])].append((f,i))
            self.uses[f.header]=uses

class Proof:
    MAX_DEPTH=16;MAX_CALLS=8;MAX_NODES=256
    def __init__(self,sl,inventory):
        self.sl=sl;self.inv=inventory;self.nodes=0;self.active=set();self.contexts={};self.related={};self.allowed_calls=set()
        self.ev={'rule':'ARGUMENT_CONTEXT_PROOF','function':sl.fn.header,'supported':False,'proof_scope':'C',
                 'edges':[],'obstacles':[],'budgets':dict(depth=self.MAX_DEPTH,callsites_per_binding=self.MAX_CALLS,nodes=self.MAX_NODES),
                 'assumptions':['standard unmodified browser globals and Date built-ins',
                                'static closed lexical uses only; complete IR is not complete dynamic dispatch']}
    def obstacle(self,code,fn=None,i=None,**detail):
        e=dict(code=code,**detail)
        if fn:e['function']=fn.header
        if i:e.update(fact(fn,i))
        self.ev['obstacles'].append(e);return None
    def enter(self,key,depth):
        self.nodes+=1
        if depth>self.MAX_DEPTH:return self.obstacle('ARGUMENT_DEPTH_BUDGET')
        if self.nodes>self.MAX_NODES:return self.obstacle('ARGUMENT_NODE_BUDGET')
        if key in self.active:return self.obstacle('RECURSIVE_ARGUMENT_CONTEXT',key=str(key))
        self.active.add(key);return True
    def initialized_prefix(self,owner,create,binding):
        """Hoisted closure definitions before any observable/reentrant effect.

        Creation order of sibling function declarations is NOT call order.
        A pure entry prologue initializes the slot before any sibling can run.
        """
        if not binding or create.block!=next(iter(owner.blocks)):return False
        stores=[i for f,i in self.inv.stores[binding] if f.header==owner.header and untype(i.args[0])==create.id]
        if len(stores)!=1 or stores[0].block!=create.block:return False
        store=stores[0];prefix=owner.blocks[create.block][:owner.positions[store.id]+1]
        if len(prefix)>3000:return False
        for i in prefix:
            if i.op in ('CreateScopeInst','CreateFunctionInst'):continue
            if i.op=='StoreFrameInst' and slot(i.args[1]) in owner.local_slots:continue
            return False
        self.ev['edges'].append(dict(kind='NONREENTRANT_CLOSURE_INITIALIZATION',status='PROVEN_BEFORE_EXECUTABLE_BODY',**fact(owner,store),lexical_slot=binding,checked_prefix_instructions=len(prefix)))
        return True
    def calls(self,fn):
        if fn.header in self.contexts:return self.contexts[fn.header]
        sites=self.inv.creates[function_ref(header_body(fn.header))]
        if len(sites)!=1:return self.obstacle('MULTIPLE_OR_MISSING_CREATION_SITES',fn,creation_count=len(sites))
        owner,create=sites[0];self.related[owner.header]=owner
        todo=[(owner,create)];calls=[];closed=True;binding=None
                                                                               
                                                                               
        for user,n in self.inv.uses[owner.header].get(create.id,[]):
            if user.op=='StoreFrameInst' and n==0 and binding is None:
                binding=slot(user.args[1])
                if binding not in owner.local_slots:
                    closed=False;self.obstacle('OUTER_FUNCTION_BINDING_STORE',owner,user)
                for writer,store in self.inv.stores[binding]:
                    if writer.header==owner.header and store.id==user.id:continue
                    if writer.header==owner.header and untype(store.args[0])=='undefined' and store.block==create.block and owner.positions[store.id]<owner.positions[create.id]:continue
                    closed=False;self.obstacle('CALLEE_BINDING_REASSIGNED',writer,store,lexical_slot=binding)
                todo.extend(self.inv.loads[binding])
                self.ev['edges'].append(dict(kind='LEXICAL_BINDING',status='EXACT_STATIC_REFERENCE',**fact(owner,user),lexical_slot=binding,target=fn.header))
        for caller,value in todo:
            for user,n in self.inv.uses[caller.header].get(value.id,[]):
                if value is create and user.op=='StoreFrameInst' and n==0 and slot(user.args[1])==binding:continue
                if user.op=='CallInst' and n==0:
                                                                              
                                                               
                    if value.op=='LoadFrameInst' and caller.header==owner.header:
                        defs=reaching(caller,value,binding)
                        if not defs or any(x is None or untype(x.args[0])!=create.id for x in defs):
                            closed=False;self.obstacle('CALLEE_REACHING_DEFINITION_UNPROVEN',caller,value)
                    if value.op=='LoadFrameInst' and caller.header!=owner.header:
                                                                              
                                                                                
                        cs=self.inv.creates[function_ref(header_body(caller.header))]
                        ordered=(len(cs)==1 and cs[0][0].header==owner.header and cs[0][1].block==create.block and owner.positions[cs[0][1].id]>owner.positions[create.id])
                        if not ordered and not self.initialized_prefix(owner,create,binding):
                            closed=False;self.obstacle('CAPTURED_CALLEE_INITIALIZATION_ORDER_UNPROVEN',caller,value,target=fn.header)
                    calls.append((caller,user));self.related[caller.header]=caller
                    self.allowed_calls.add((caller.header,user.id))
                else:
                    closed=False;self.obstacle('FUNCTION_ESCAPE_OR_INDIRECT_USE',caller,user,operand_index=n,target=fn.header)
        if not calls:closed=False;self.obstacle('NO_CLOSED_DIRECT_CALL_CONTEXT',fn)
        if len(calls)>self.MAX_CALLS:
            closed=False;self.obstacle('ARGUMENT_CALLSITE_BUDGET',fn,callsite_count=len(calls));calls=calls[:self.MAX_CALLS]
        self.contexts[fn.header]=(calls,closed)
        return calls,closed
    def formal(self,fn,param,depth=0):
        key=(fn.header,param)
        if not self.enter(key,depth):return None
        try:
            self.related[fn.header]=fn
            ps=params(fn)
            if param not in ps:return self.obstacle('NOT_A_FORMAL_PARAMETER',fn,parameter=param)
            found=self.calls(fn)
            if found is None:return None
            calls,closed=found;values=[]
            for caller,call in calls:
                n=3+ps.index(param)
                if len(call.args)<=n:values.append(self.obstacle('MISSING_ACTUAL_ARGUMENT',caller,call));continue
                actual=call.args[n]
                edge=dict(kind='ACTUAL_TO_FORMAL',status='EXACT_STATIC_REFERENCE_NOT_CONTEXT_PROOF',**fact(caller,call),
                          actual=actual,callee=fn.header,formal=param,formal_index=ps.index(param))
                self.ev['edges'].append(edge)
                value=self.value(caller,actual,call,depth+1);edge['browser_identity']=value;values.append(value)
            return 'window' if closed and values and all(v=='window' for v in values) else None
        finally:self.active.remove(key)
    def value(self,fn,operand,at,depth):
        key=(fn.header,untype(operand),at.id)
        if not self.enter(key,depth):return None
        try:
            op=untype(operand)
            if op in params(fn):return self.formal(fn,op,depth+1)
            i=fn.insts.get(op)
            if not i:return self.obstacle('VALUE_ORIGIN_UNRESOLVED',fn,at,operand=op)
            if i.op=='LoadFrameInst':
                binding=slot(i.args[0]);stores=self.inv.stores[binding];captured_closed=True
                if slot(i.args[0]) in fn.local_slots:
                    defs=reaching(fn,i,binding)
                    if len(defs)!=1 or defs[0] is None:return self.obstacle('MULTIPLE_OR_MISSING_REACHING_STORES',fn,i,lexical_slot=binding)
                    writer,store=fn,defs[0]
                    if any(f.header!=fn.header for f,x in stores):return self.obstacle('CAPTURED_SLOT_EXTERNAL_WRITER',fn,i,lexical_slot=binding)
                else:
                    captured_context=self.calls(fn)
                    if captured_context is None or not captured_context[1]:
                        captured_closed=False;self.obstacle('CAPTURED_READER_CONTEXT_OPEN',fn,i,lexical_slot=binding)
                    noninit=[(f,s) for f,s in stores if untype(s.args[0])!='undefined']
                    if len(noninit)!=1:return self.obstacle('CAPTURED_SLOT_MUTABLE_OR_MISSING',fn,i,lexical_slot=binding,stores=[fact(f,s) for f,s in stores])
                    writer,store=noninit[0]
                    sites=self.inv.creates[function_ref(header_body(fn.header))]
                    if len(sites)!=1 or sites[0][0].header!=writer.header:return self.obstacle('CAPTURE_INITIALIZATION_CONTEXT_UNPROVEN',fn,i,lexical_slot=binding)
                    creation=sites[0][1]
                    if store.block!=creation.block or writer.positions[store.id]>=writer.positions[creation.id]:return self.obstacle('CAPTURE_INITIALIZATION_ORDER_UNPROVEN',fn,i,definition=fact(writer,store))
                    if any(s is not store and not (f.header==writer.header and untype(s.args[0])=='undefined' and s.block==store.block and writer.positions[s.id]<writer.positions[store.id]) for f,s in stores):return self.obstacle('CAPTURED_SLOT_REASSIGNED',fn,i)
                self.ev['edges'].append(dict(kind='REACHING_FRAME_DEFINITION',status='PROVEN_UNDER_RECORDED_CONTEXT',**fact(fn,i),lexical_slot=binding,definition=fact(writer,store)))
                self.related[writer.header]=writer
                origin=self.value(writer,store.args[0],store,depth+1)
                return origin if captured_closed else None
            from .engine import Slice
            s=Slice(fn,self.sl.source_fn,self.sl.source,self.sl.functions);v=s.operand(operand)
            if v.kind=='symbol' and v.data in ('window','self'):
                self.ev['edges'].append(dict(kind='BROWSER_GLOBAL',status='PROVEN_STANDARD_GLOBAL',**fact(fn,i),value=v.data));return 'window'
            if i.op=='LoadPropertyInst':
                self.ev['edges'].append(dict(kind='PROPERTY_RECEIVER_CANDIDATE',status='NOT_BROWSER_IDENTITY_PROOF',**fact(fn,i),receiver=i.args[0],property=literal(i.args[1])))
                                                                               
                                                                             
                self.value(fn,i.args[0],i,depth+1)
            return self.obstacle('VALUE_ORIGIN_UNRESOLVED',fn,i,operand=operand,value_kind=v.kind,value=v.data)
        finally:self.active.remove(key)
    def effects(self):
        from .engine import Slice,val
        for fn in self.related.values():
            s=Slice(fn,self.sl.source_fn,self.sl.source,self.sl.functions)
            if fn.header==self.sl.fn.header:s.bindings[self.ev['parameter']]=val('symbol','window')
            for i in fn.insts.values():
                if i.block not in fn.live_blocks:continue
                if i.op in ('StorePropertyInst','StoreNewOwnPropertyInst'):
                    if literal(i.args[2])!='cookie' or fn.header!=self.sl.fn.header or s.operand(i.args[1])!=val('symbol','document'):return self.obstacle('RELATED_PROPERTY_WRITE_OR_EXPORT',fn,i)
                if i.op in ('StoreGetterSetterInst','DeletePropertyInst','ThrowInst','GetPNamesInst','GetNextPNameInst'):return self.obstacle('RELATED_DYNAMIC_EFFECT_UNSUPPORTED',fn,i)
                if i.op=='LoadPropertyInst':
                    receiver=s.operand(i.args[0]);name=literal(i.args[1])
                    safe=(receiver.kind in ('date','timestamp','date_number','literal','string','number') or
                          (receiver.kind=='symbol' and ((receiver.data in ('window','self') and name=='document') or (receiver.data=='document' and name=='cookie'))))
                    if not safe:return self.obstacle('RELATED_UNKNOWN_GETTER_EFFECT',fn,i)
                if i.op=='CallInst' and (fn.header,i.id) not in self.allowed_calls:
                    v=s.eval(i.id)
                    if v.kind=='unknown' or v.incomplete:return self.obstacle('RELATED_UNKNOWN_CALL_EFFECT',fn,i)
        return True
    def run(self,param):
        self.ev['parameter']=param
        value=self.formal(self.inv.byheader[self.sl.fn.header],param)
        if value=='window' and self.effects():
            self.ev.update(supported=True,proof_scope='A',obstacle=None)
        else:self.ev['obstacle']=self.ev['obstacles'][0]['code'] if self.ev['obstacles'] else 'ACTUAL_CONTEXTS_NOT_ALL_BROWSER_GLOBAL'
        self.ev['visited_nodes']=self.nodes
        return self.ev

def bind(sl,param,inventory):
    from .engine import val
    proof=Proof(sl,inventory);ev=proof.run(param)
    sl.evidence[('context:'+param,'ARGUMENT_CONTEXT_PROOF')]=ev
    return val('symbol','window') if ev['supported'] else None
