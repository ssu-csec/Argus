"""Bounded backward slicing with reaching definitions; abstain on opaque flows.

No site names, route IDs or manual labels are inputs to the rules. Source tags
refer to an exact instruction in an exact function, not all Date instructions.
"""
from dataclasses import dataclass
from functools import cached_property
import hashlib
from itertools import product
import re
from . import VERSION
from .ir import untype, literal

@dataclass(frozen=True,eq=False)
class Value:
    kind: str
    data: str = ''
    args: tuple = ()
    tagged: bool = False
    uncertain: bool = False
    status: str = ''

    @cached_property
    def dep(self):return self.tagged or any(a.dep for a in self.args)
    @cached_property
    def incomplete(self):return self.uncertain or any(a.incomplete for a in self.args)
    @cached_property
    def token(self):
        return hashlib.sha256(repr((self.kind,self.data,tuple(a.token for a in self.args),self.tagged,self.uncertain,self.status)).encode()).hexdigest()
    def __hash__(self):return hash(self.token)
    def __eq__(self,other):return isinstance(other,Value) and self.token==other.token

def val(kind,data='',args=(),tagged=False,uncertain=False,status=''):
    return Value(kind,str(data),tuple(args),tagged,uncertain,status)

def choice(items):
    unique=tuple(dict.fromkeys(items))
    if len(unique)==1:return unique[0]
    return val('choice',args=unique) if unique else val('unknown','no reaching definition',uncertain=True)

def uncertain_dependency(v):
    return (v.uncertain and v.dep) or any(uncertain_dependency(a) for a in v.args)

class Slice:
    def __init__(self,fn,source_fn,source,functions=()):
        self.fn,self.source_fn,self.source=fn,source_fn,source
        self.functions=functions
        self.bindings={}
        self.memo={};self.active=set();self.evidence={};self.limit=0
        self.exceptions=[]
        self.date_states={};self.date_state_cache={}
        self.standard_returns={};self.standard_uses={}

    def record(self,i,rule):
        self.evidence[(i.id,rule)]={'function':self.fn.name,'block':i.block,'value_id':i.id,'location':i.loc,'instruction':i.text,'rule':rule}

    def operand(self,a):
        a=untype(a)
        if a in self.bindings:return self.bindings[a]
        if a in self.fn.insts:return self.eval(a)
        l=literal(a)
        if l is not None:return val('string',l)
        if a in ('undefined','null','true','false'):return val('literal',a)
        if re.fullmatch(r'-?\d+(\.\d+)?',a):return val('number',a)
        if a=='globalObject':return val('global','globalObject')
        return val('param',a)

    def key(self,a):
        v=self.operand(a)
        if v.kind in ('global','param','date','object','symbol','instance'):return (v.kind,v.data)
        if v.kind=='property':return ('property',v.data,tuple(x.token for x in v.args))
        return None

    def reaching(self,i,predicate,seen=None):
        """Walk backwards on CFG, stopping at the first matching store per path."""
        todo=[(i.block,self.fn.positions[i.id])];visited=set();result=[]
        while todo:
            block,pos=todo.pop();marker=(block,pos)
            if block not in self.fn.live_blocks or marker in visited:continue
            visited.add(marker)
            if len(visited)>1000:return val('unknown','CFG budget',uncertain=True)
            found=False
            for s in reversed(self.fn.blocks.get(block,[])[:pos]):
                if predicate(s):
                    self.record(s,'REACHING_STORE')
                    self.evidence[(i.id,'MEMORY_EDGE:'+s.id)]={'rule':'REACHING_MEMORY_EDGE','function':self.fn.name,'load_id':i.id,'store_id':s.id,'load_block':i.block,'store_block':s.block,'load_instruction':i.text,'store_instruction':s.text}
                    result.append(self.operand(s.args[0]));found=True;break
            if found:continue
            preds=self.fn.preds.get(block,[])
            if not preds:result.append(val('unknown','unresolved memory origin',uncertain=True))
            todo.extend((p,len(self.fn.blocks.get(p,[]))) for p in preds)
        return choice(result)

    def eval(self,id):
        if id in self.memo:return self.memo[id]
        if id in self.active or len(self.active)>90:return val('unknown','recursive value',uncertain=True)
        self.limit+=1
        if self.limit>12000:return val('unknown','slice budget',uncertain=True)
        self.active.add(id);i=self.fn.insts[id];self.record(i,'DEF_USE')
        try:v=self.transfer(i)
        except (IndexError,ValueError,RecursionError) as exc:v=val('unknown','unsupported operand '+str(exc),uncertain=True)
        self.active.remove(id);self.memo[id]=v
        return v

    def transfer(self,i):
        a=i.args;op=i.op
        if op=='LoadFrameInst':
            slot=untype(a[0]);env=untype(a[1])
            self.record(i,'LEXICAL_SLOT_REACHING_DEFINITION')
            owner=frame_owner(self.fn,slot,env,i)
            def matches(store):
                if store.op!='StoreFrameInst' or untype(store.args[1])!=slot:return False
                store_env=untype(store.args[2])
                if store_env==env:return True
                if owner is None or frame_owner(self.fn,slot,store_env,store)!=owner:return False
                self.record(i,'EXPLICIT_LEXICAL_PARENT_FRAME_OWNER')
                return True
            return self.reaching(i,matches)
        if op=='LoadStackInst':
            return self.reaching(i,lambda s:s.op=='StoreStackInst' and untype(s.args[1])==untype(a[0]))
        if op in ('AsNumberInst','AsNumericInst','ToNumberInst','ToNumericInst'):
            value=self.operand(a[0])
            if value.kind=='date':
                                                                        
                                                           
                self.record(i,'EXPLICIT_DATE_NUMERIC_CONVERSION')
                state=self.date_state(value,i)
                return val('timestamp','valueOf',(state,),status=state.status)
            return value
        if op in ('MovInst','ToStringInst'):return self.operand(a[0])
        if op=='PhiInst':return choice([self.operand(a[k]) for k in range(0,len(a),2) if untype(a[k+1]) in self.fn.live_blocks])
        if op in ('CreateScopeInst','CreateInnerScopeInst','AllocObjectInst','AllocArrayInst','AllocStackInst','CreateFunctionInst'):
            return val('object',self.fn.header+':'+i.id)
        if op in ('LoadPropertyInst','TryLoadGlobalPropertyInst','LoadGlobalObjectInst'):
            obj=self.operand(a[0]);prop=literal(a[1])
            if prop is None:return val('unknown','dynamic property',args=(obj,),uncertain=True)
            if prop=='cookie' and obj.kind=='symbol' and obj.data=='document':
                return val('cookie_read',i.id)
            key=self.key(a[0])
            if key:
                stores=[s for s in self.fn.insts.values() if s.op=='StorePropertyInst' and literal(s.args[2])==prop and self.key(s.args[1])==key]
                if stores:
                    self.record(i,'OBJECT_IDENTITY_REACHING_PROPERTY')
                    reached=self.reaching(i,lambda s:s in stores)
                    if reached.kind!='param':return reached
            sample=self.fn is self.source_fn and i.id==self.source.id
            if obj.kind=='global':return val('symbol',prop,tagged=sample)
            if prop=='document' and obj.kind=='symbol' and obj.data in ('window','self'):
                self.record(i,'BROWSER_GLOBAL_DOCUMENT_IDENTITY')
                return val('symbol','document',tagged=sample)
            return val('property',prop,(obj,),tagged=sample)
        if op=='ConstructInst':
            callee=self.operand(a[0]);sample=self.fn is self.source_fn and i.id==self.source.id
            if callee.kind=='symbol' and callee.data=='Date':
                return val('date',self.fn.header+':'+i.id,args=tuple(self.operand(x) for x in a[3:]),tagged=sample)
            from .contexts import local_instance
            instance=local_instance(self,i,callee)
            if instance is not None:return instance
            return val('unknown','unresolved constructor',args=tuple(self.operand(x) for x in a[3:]),tagged=sample,uncertain=True)
        if op=='BinaryOperatorInst':
            operator=literal(a[0]);x,y=self.operand(a[1]),self.operand(a[2])
            if operator=='+':
                if x.kind=='string' and y.kind=='string':return val('string',x.data+y.data)
                if x.kind=='string' or y.kind=='string' or x.kind=='concat' or y.kind=='concat':return val('concat',args=(x,y))
            return val('binary',operator,(x,y))
        if op=='UnaryOperatorInst':return val('unary',literal(a[0]),(self.operand(a[1]),))
        if op=='CallInst':return self.call(i)
        if op in ('StoreFrameInst','StorePropertyInst','StoreStackInst','ReturnInst'):return self.operand(a[0])
        return val('unknown','unsupported '+op,args=tuple(self.operand(x) for x in a if untype(x) in self.fn.insts),uncertain=True)

    def date_state(self,recv,before,include_setter=False):
        """Only model same-object setters in the same block before the read.

        Cross-block mutations are explicitly unresolved, not silently ignored.
        """
                                                                          
                                                                
        mutations=[]
        for j in self.fn.insts.values():
            if j.op!='CallInst' or len(j.args)<3:continue
            if j.id==before.id and not include_setter:continue
            if j.block==before.block and self.fn.positions[j.id]>self.fn.positions[before.id]:continue
            if j.block!=before.block and not self.fn.reachable(j.block,before.block):continue
            ci=self.fn.insts.get(untype(j.args[0]))
            if not ci or ci.op!='LoadPropertyInst' or literal(ci.args[1]) not in ('setTime','setDate','setUTCDate','setFullYear','setHours','setMinutes','setSeconds'):continue
            target=self.operand(j.args[2])
            if target.kind=='date' and target.data==recv.data:mutations.append(literal(ci.args[1]))
        if 'setTime' in mutations:
            from .date_states import analyze
            return analyze(self,recv,before,include_setter)
        status='TIMESTAMP_EXPRESSION';dependencies=recv
        for j in self.fn.insts.values():
            if j.op!='CallInst' or j.id==before.id or len(j.args)<3:continue
            if j.block==before.block and self.fn.positions[j.id]>=self.fn.positions[before.id]:continue
            if j.block!=before.block and not self.fn.reachable(j.block,before.block):continue
            ci=self.fn.insts.get(untype(j.args[0]))
            if not ci or ci.op!='LoadPropertyInst':continue
            method=literal(ci.args[1])
            if method not in ('setTime','setDate','setUTCDate','setFullYear','setHours','setMinutes','setSeconds'):continue
            target=self.operand(j.args[2])
            if target.kind!='date' or target.data!=recv.data:continue
            self.record(j,'DATE_MUTATION')
            if j.block!=before.block and not dominates(self.fn,j.block,before.block):return val('date_expression',args=(recv,),uncertain=True,status='UNKNOWN')
            arg=self.operand(j.args[3]) if len(j.args)>3 else val('unknown',uncertain=True)
            if method=='setTime':
                if arg.kind=='binary' and arg.data=='+' and any(x.kind=='date' for x in arg.args):status='INVALID_DATE'
                elif arg.kind=='concat':status='UNKNOWN'
                dependencies=arg
            else:
                                                                           
                                                                            
                dependencies=val('date_component_update',method,(dependencies,arg))
                if arg.incomplete:status='UNKNOWN'
        return val('date_expression',args=(dependencies,),status=status,uncertain=status=='UNKNOWN')

    def call(self,i):
        a=i.args;callee=self.operand(a[0]);recv=self.operand(a[2]) if len(a)>2 else val('unknown')
        args=tuple(self.operand(x) for x in a[3:])
                                                                            
                                                                             
        from .standard_returns import normal_return
        normal_return(self,i)
        sample=self.fn is self.source_fn and i.id==self.source.id
        if callee.kind=='property':
            method=callee.data
            if method=='concat' and recv.kind in ('string','concat'):
                x=recv
                for y in args:x=val('concat',args=(x,y))
                return x
            if recv.kind=='date':
                if method in ('toUTCString','toGMTString','toISOString','toString','getTime','valueOf','getDate','getUTCDate','getFullYear','getMinutes','getSeconds'):
                    state=self.date_state(recv,i)
                    return val('timestamp',method,(state,),status=state.status)
                if method in ('setTime','setDate','setUTCDate','setHours','setFullYear','setMinutes','setSeconds'):
                    if method=='setTime':
                        state=self.date_state(recv,i,include_setter=True)
                        return val('date_number',method,(state,),status=state.status)
                    return val('date_number',method,args,tagged=recv.dep)
            if method in ('toUTCString','toGMTString','toISOString') and recv.kind=='date_number':
                self.exceptions.append(i.id);self.record(i,'NUMBER_DATE_METHOD_TYPEERROR')
                return val('error','TYPEERROR_BEFORE_SINK',(recv,),status='TYPEERROR_BEFORE_SINK')
            if method in ('toUTCString','toGMTString','toISOString') and recv.kind=='choice':
                identities={x.data for x in recv.args if x.kind=='date'}
                if len(identities)>1:
                    self.record(i,'DATE_MULTIPLE_ALLOCATION_RECEIVER')
                    return val('unknown','multiple Date allocations at read',(recv,),uncertain=True)
                choices=[]
                for x in recv.args:
                    if x.kind=='date_number':
                        self.record(i,'NUMBER_DATE_METHOD_TYPEERROR')
                        choices.append(val('error','TYPEERROR_BEFORE_SINK',(x,),status='TYPEERROR_BEFORE_SINK'))
                    elif x.kind=='date':choices.append(val('timestamp',method,(self.date_state(x,i),),status='TIMESTAMP_EXPRESSION'))
                    else:choices.append(val('unknown','opaque receiver',(x,),uncertain=True))
                return choice(choices)
            if method=='now' and recv.kind=='symbol' and recv.data in ('Date','performance'):
                return val('timestamp',recv.data+'.now',tagged=sample or callee.dep,status='TIMESTAMP_EXPRESSION')
            if method in ('indexOf','includes','split','join','slice','substring','substr','charAt','replace','toLowerCase'):
                return val('operation',method,(recv,)+args,uncertain=method in ('replace','slice','substring','substr','charAt','split','join') and (recv.dep or any(x.dep for x in args)))
        if callee.kind=='symbol' and callee.data in ('encodeURIComponent','encodeURI','escape','String','Number','parseInt','parseFloat'):
            return val('encoded' if callee.data in ('encodeURIComponent','escape') else 'operation',callee.data,args)
        from .helpers import summarize
        from .contexts import method
        resolved=method(self,i,callee,recv,args)
        if resolved is not None:return resolved
        summary=summarize(self,i,callee,args)
        if summary is not None:return summary
        return val('unknown','opaque helper',args=(callee,recv)+args,tagged=sample,uncertain=True)

def expand(v,limit=32):
    if v.kind=='choice':
                                                                              
                                                                                
                                                                               
        if not v.dep and len(v.args)>1:return [[val('param','branch-varying text')]]
        result=[]
        for x in v.args:result+=expand(x,limit)
        if len(result)>limit:raise ValueError('EXPRESSION_ALTERNATIVE_BUDGET')
        return result
    if v.kind=='concat':
        result=[]
        for a,b in product(expand(v.args[0],limit),expand(v.args[1],limit)):
            result.append(a+b)
            if len(result)>limit:raise ValueError('EXPRESSION_ALTERNATIVE_BUDGET')
        return result
    return [[v]]

def field_roles(v,details=False):
    """Literal separators reset field state; opaque tokens can contain delimiters.

    No semantic decision uses reconstructed destination_url or path_nodes.
    """
    roles=set();statuses=set();unknown=False;observations=[];boundaries=[];attribute_events=[];literal_controls=[]
    for branch,parts in enumerate(expand(v)):
        mode='NAME';attr='';before_equals=True;pair_known=False
        for ordinal,x in enumerate(parts):
            if x.kind=='string':
                if details and re.search(r'[\x00-\x08\x0a-\x1f\x7f]',x.data):
                    literal_controls.append(dict(alternative=branch,token_index=ordinal,value=x.data))
                for c in x.data:
                    if c==';':mode='ATTRIBUTE_NAME';attr='';before_equals=True
                    elif c=='=' and mode=='NAME':mode='VALUE';pair_known=True
                    elif c=='=' and mode=='ATTRIBUTE_NAME':
                        attribute=attr.strip().lower()
                        if details:attribute_events.append(dict(alternative=branch,token_index=ordinal,name=attribute))
                        mode=({'expires':'EXPIRES','max-age':'MAX_AGE','ttl':'TTL'}.get(attribute,'OTHER_ATTRIBUTE') if details else 'EXPIRES' if attribute in ('expires','max-age','ttl') else 'OTHER_ATTRIBUTE')
                        before_equals=False
                    elif mode=='ATTRIBUTE_NAME':attr+=c
                continue
            if x.dep:
                field=mode if mode in ('NAME','VALUE','EXPIRES','OTHER_ATTRIBUTE','MAX_AGE','TTL') else 'UNKNOWN'
                                                                            
                                                                            
                if x.kind=='binary' and x.data=='+':
                                                                           
                                                                            
                    from .helpers import kind
                    if not all(kind(a) in ('number','boolean') for a in x.args):field='UNKNOWN'
                if details and x.kind in ('operation','helper_string'):
                                                                            
                                                                         
                    if x.data not in ('Number','parseInt','parseFloat'):field='UNKNOWN'
                roles.add(field)
                if details:
                    observations.append(dict(alternative=branch,token_index=ordinal,field=field,value_kind=x.kind,value=x.data,token=x.token,dependency_resolved=not uncertain_dependency(x),initial_pair_known=pair_known))
                def status(y):
                    if not y.dep:return
                    if y.kind=='property' and y.data in ('toUTCString','toGMTString','toISOString'):
                        statuses.add('FUNCTION_REFERENCE');return
                    if y.status:statuses.add(y.status);return
                    for z in y.args:status(z)
                status(x)
                unknown |= uncertain_dependency(x)
                                                                             
                                                                              
            safe=x.kind in ('number','timestamp','date_number','date','encoded') or (x.kind=='binary' and x.data in ('*','-','/','%'))
            if details and x.kind=='binary' and x.data=='+':
                from .helpers import kind
                safe=all(kind(a) in ('number','boolean') for a in x.args)
            if details and not safe:boundaries.append(dict(alternative=branch,token_index=ordinal,kind=x.kind,value=x.data,source_bearing=x.dep,mode_before=mode))
            if not safe:mode='UNKNOWN';attr=''
    if details:return dict(fields=sorted(roles),serialization_states=sorted(statuses),opaque_dependency=unknown,observations=observations,opaque_boundaries=boundaries,
                           attribute_events=attribute_events,literal_control_characters=literal_controls,
                           boundary_contract='SEMICOLON_RESETS_ATTRIBUTE_REGION_V6')
    return roles,statuses,unknown

def endpoint(functions,r,side):
    loc=r[side+'_location'];name=r[side+'_function']
    kinds=('ConstructInst',) if side=='source' and r['source_name']=='Date' else ('CallInst','LoadPropertyInst') if side=='source' else ('StorePropertyInst',)
    hits=[(f,i) for f in functions for i in f.insts.values() if f.name==name and i.loc==(loc['line'],loc['column']) and i.op in kinds]
    if side=='source' and r['source_name'] in ('Date.now','performance.now'):
        loads=[x for x in hits if x[1].op=='LoadPropertyInst' and literal(x[1].args[1])=='now']
        if loads:return loads
    return hits

def walk_values(v):
    yield v
    for a in v.args:yield from walk_values(a)

def cookie_name(v):
    alternatives=expand(v)
    names=[]
    for parts in alternatives:
        result=[];done=False
        for x in parts:
            if x.kind=='string':
                text=x.data
                if ';' in text.split('=')[0]:return None
                if '=' in text:
                    text=text.split('=',1)[0];done=True
                if text:result.append(('text',text))
            elif x.kind in ('timestamp','number','encoded'):
                result.append(('value',x.token))
            else:return None
            if done:break
        if not done:return None
                                                                       
        normalized=[]
        for k,s in result:
            if k=='text' and normalized and normalized[-1][0]=='text':normalized[-1]=('text',normalized[-1][1]+s)
            else:normalized.append((k,s))
        names.append(tuple(normalized))
    return names[0] if names and all(x==names[0] for x in names) else None

def usage_proof(sl,sink,value):
    """Require correlated write/read-comparison/delete, or an explicit API contract."""
    fn=sl.fn;name=cookie_name(value);proof=[]
    reads=[];writes=[];deletes=[];tracking=[]
    for i in fn.insts.values():
        if i.block not in fn.live_blocks:continue
        if i.op=='StorePropertyInst' and literal(i.args[2])=='cookie':
            x=sl.operand(i.args[0])
            if name and cookie_name(x)==name:
                writes.append(i)
                constants=''.join(a.data for parts in expand(x) for a in parts if a.kind=='string')
                if re.search(r';\s*(?:max-age\s*=\s*(?:0|-\d+)|expires\s*=[^;]*(?:1969|1970))',constants,re.I):deletes.append(i)
        if i.op!='CallInst':continue
        callee=sl.operand(i.args[0]);args=[sl.operand(a) for a in i.args[3:]]
        recv=sl.operand(i.args[2]) if len(i.args)>2 else val('unknown')
        if callee.kind=='property' and callee.data in ('indexOf','includes') and recv.kind=='cookie_read' and args:
                                                                              
            needle=args[0]
            if name and cookie_name(needle)==name:
                compared=callee.data=='includes' or any(j.op=='BinaryOperatorInst' and any(untype(a)==i.id for a in j.args[1:]) and literal(j.args[0]) in ('>=','>','===','!==','==','!=') for j in fn.insts.values())
                if compared:reads.append(i)
                                                                               
        if callee.kind=='property' and callee.data in ('identify','alias') and recv==val('symbol','analytics') and args and args[0].dep and not uncertain_dependency(args[0]) and (fn.reachable(sink.block,i.block) or fn.reachable(i.block,sink.block)):
            if any(a.dep and a in tuple(walk_values(value)) for a in walk_values(args[0])):
                tracking.append(i)
    if tracking:
        for i in tracking:sl.record(i,'EXPLICIT_ANALYTICS_IDENTIFIER_ARGUMENT')
        return 'TRACKING_RELATED'
    if reads and deletes and len(writes)>=2:
                                                                             
                                                                             
        for read in reads:
            for delete in deletes:
                for write in writes:
                    if write.id==delete.id:continue
                    ordered=lambda a,b:fn.reachable(a.block,b.block) and (a.block!=b.block or fn.positions[a.id]<fn.positions[b.id])
                    if ordered(write,read) and ordered(read,delete) and sink.id in (write.id,delete.id):
                        for x in (write,read,delete):sl.record(x,'MATCHED_PROBE_WRITE_READ_COMPARE_CLEANUP')
                        return 'BENIGN_FUNCTIONAL'
    return None

def reassigned_source_slots(sl,sink_value):
    """Identify concrete old-source-store -> clean-load bridges rejected by RD.

    This describes IR memory evidence, not a reconstruction of an undocumented
    historical trace. A separately recovered intent flow must not validate it.
    """
    if sl.fn is not sl.source_fn:return []
    original=[i for i in sl.fn.insts.values() if i.op=='StoreFrameInst' and untype(i.args[0])==sl.source.id]
    loads=[sl.fn.insts[e['value_id']] for e in list(sl.evidence.values()) if e.get('rule')=='LEXICAL_SLOT_REACHING_DEFINITION']
    bridges=[]
    for store in original:
        for load in loads:
            if untype(load.args[0])!=untype(store.args[1]) or untype(load.args[1])!=untype(store.args[2]):continue
            if not sl.fn.reachable(store.block,load.block):continue
            v=sl.eval(load.id)
            if v.dep or v.incomplete:continue
            edges=[e for e in list(sl.evidence.values()) if e.get('rule')=='REACHING_MEMORY_EDGE' and e['load_id']==load.id]
            if edges and all(e['store_id']!=store.id for e in edges):
                bridges.append({'rule':'REASSIGNED_SOURCE_SLOT','function':sl.fn.name,'source_store':store.text,'load':load.text,'reaching_stores':[e['store_instruction'] for e in edges],'source_store_location':store.loc,'load_location':load.loc,'interpretation':'Old sampled-source taint must not pass through this overwritten load.'})
    return bridges

def dominates(fn,a,b):
    if a==b:return True
    entries=[k for k in fn.blocks if not fn.preds.get(k)]
    todo=entries[:];seen=set()
    while todo:
        k=todo.pop()
        if k==a or k in seen:continue
        if k==b:return False
        seen.add(k);todo.extend(fn.succ.get(k,[]))
    return True

def ordered_reachable(fn,a,b):
    return fn.reachable(a.block,b.block) and (a.block!=b.block or fn.positions[a.id]<fn.positions[b.id])

def unresolved_effects(sl,sink):
    """A call with no known summary may alter a captured/global source value.

    Even an unused call result must prevent claims of clean overwrite/BE when
    it can execute between the sampled source and sink in this invocation.
    """
    if sl.fn is not sl.source_fn:return []
    problems=[]
    for i in sl.fn.insts.values():
        if i.op!='CallInst' or not ordered_reachable(sl.fn,sl.source,i) or not ordered_reachable(sl.fn,i,sink):continue
        v=sl.eval(i.id)
        if v.kind=='unknown' or (v.kind=='choice' and any(a.kind=='unknown' and a.dep for a in v.args)):
            problems.append({'rule':'UNRESOLVED_CALL_EFFECT','instruction':i.text,'function':sl.fn.name,'block':i.block,'location':i.loc})
    return problems

def _classify(functions,r):
    result={'classifier_version':VERSION,'semantic_label':'UNCLEAR','purpose_basis':'INSUFFICIENT_EVIDENCE','cookie_field':'UNKNOWN','connection_status':'UNVERIFIED','serialization_status':'UNKNOWN','evidence':[],'reason':'','roles':[],
            'assumptions':['standard Date built-ins; no prototype monkey-patching','standard browser window/self/document and hostname accessor, no global replacement outside modeled stores','same invocation; bounded explicit data-dependency model, not full JS satisfiability','static local reaching definitions; no browser execution proof','TIMESTAMP_EXPRESSION does not prove finite date value or browser cookie acceptance']}
    sources,sinks=endpoint(functions,r,'source'),endpoint(functions,r,'sink')
    if len(sources)!=1 or len(sinks)!=1:
        result['reason']='ENDPOINT_NOT_UNIQUE_OR_MISSING';return result
    sf,source=sources[0];tf,sink=sinks[0]
    result['source_ir']={'function':sf.header,'instruction':source.text,'block':source.block,'location':source.loc}
    result['sink_ir']={'function':tf.header,'instruction':sink.text,'block':sink.block,'location':sink.loc}
    if sf is tf:
        before=source.block==sink.block and tf.positions[source.id]>tf.positions[sink.id]
        cycle=any(tf.reachable(t,source.block) for t in tf.succ.get(source.block,[]))
        if (before and not cycle) or not tf.reachable(source.block,sink.block):
            result.update(semantic_label=None,purpose_basis='NOT_APPLICABLE_NO_MATCHED_FLOW',connection_status='DISPROVED',reason='SOURCE_AFTER_SINK_OR_DISJOINT_CFG')
            result['evidence']=[{'rule':'CFG_ORDER','source_block':source.block,'sink_block':sink.block,'successors':tf.succ}]
            return result
    sl=Slice(tf,sf,source,functions)
    receiver=sl.operand(sink.args[1])
    if receiver.kind=='property' and receiver.data=='document' and len(receiver.args)==1 and receiver.args[0].kind=='param' and receiver.args[0].data!='%this':
        from .contexts import bind_document_parameter
        parameter=receiver.args[0].data
        binding=bind_document_parameter(sl,parameter)
        if binding is not None:
            sl.bindings[parameter]=binding;sl.memo.clear()
        else:
            result['reason']='ARGUMENT_CONTEXT_UNPROVEN';result['evidence']=list(sl.evidence.values())
            proof=next((e for e in result['evidence'] if e['rule']=='ARGUMENT_CONTEXT_PROOF' and 'proof_scope' in e),None)
            if proof:
                obstacle=proof['obstacle']
                result['reason']=obstacle if obstacle.startswith('ARGUMENT_') else 'ARGUMENT_'+obstacle
            return result
    if literal(sink.args[2])!='cookie' or sl.operand(sink.args[1])!=val('symbol','document'):
        result['reason']='DOCUMENT_COOKIE_IDENTITY_UNRESOLVED';result['evidence']=list(sl.evidence.values());return result
    value=sl.operand(sink.args[0])
    result['date_states']=list(sl.date_states.values())
    from .date_states import policy_block
    date_block=policy_block(result['date_states'])
    bridges=reassigned_source_slots(sl,value)
    result['rejected_memory_bridges']=bridges
    if bridges:
        result['reported_path_status']='REASSIGNED_SOURCE_SLOT_BRIDGE_REJECTED'
    result['evidence']=list(sl.evidence.values())
    if date_block:
        result['reason']=date_block
                                                                             
        if any(x.kind=='error' and x.status=='TYPEERROR_BEFORE_SINK' for x in walk_values(value)):
            result['serialization_status']='TYPEERROR_BEFORE_SINK'
        return result
    if sf is not tf:
                                                                           
                                                                                  
        has_global_store=any(e['rule']=='REACHING_STORE' and 'globalObject' in e['instruction'] for e in result['evidence'])
                                                                                
                                                                
        closed_value=not any(x.kind in ('param','property','symbol','unknown') for x in walk_values(value))
        if has_global_store and not value.dep and not value.incomplete and closed_value:
            result.update(semantic_label=None,purpose_basis='NOT_APPLICABLE_NO_MATCHED_FLOW',connection_status='DISPROVED',reason='SINK_LOCAL_GLOBAL_OVERWRITE_EXCLUDES_OTHER_FUNCTION_SOURCE')
        else:result['reason']='INTERPROCEDURAL_DEPENDENCY_UNSUPPORTED'
        return result
    effects=unresolved_effects(sl,sink)
    result['evidence']=list(sl.evidence.values())
    if effects:
        open_receiver=False
        for e in effects:
            i=tf.insts[e['instruction'].split(' = ')[0]]
            recv=sl.operand(i.args[2])
            if recv.kind=='param' and recv.data=='%this' and getattr(functions,'creation_index',None) is not None:
                sl.record(i,'OPEN_RECEIVER_CONTEXT')
                sl.evidence[(i.id,'OPEN_RECEIVER_CONTEXT')].update(obstacle='No exact allocation/own-property/prototype/this chain; method name does not prove dispatch')
                open_receiver=True
        result.update(reason='METHOD_RECEIVER_CONTEXT_UNPROVEN' if open_receiver else 'UNRESOLVED_CALL_EFFECTS_BETWEEN_ENDPOINTS',evidence=list(sl.evidence.values())+effects)
        return result
    if not value.dep:
        if value.incomplete:
            result['reason']='OPAQUE_VALUE_OR_CYCLIC_MEMORY';return result
        for i in tf.insts.values():
            if i.op=='CondBranchInst' and tf.reachable(source.block,i.block) and tf.reachable(i.block,sink.block) and sl.operand(i.args[0]).dep:
                result.update(reason='CONTROL_DEPENDENCE_UNSUPPORTED',evidence=list(sl.evidence.values()))
                return result
                                                                          
                                                                      
        for i in tf.insts.values():
            if i.op=='CallInst' and tf.reachable(source.block,i.block) and tf.reachable(i.block,sink.block):
                x=sl.eval(i.id)
                if x.kind=='error' and x.dep:
                    result['serialization_status']='TYPEERROR_BEFORE_SINK'
                    result['evidence']=list(sl.evidence.values())
        result.update(semantic_label=None,purpose_basis='NOT_APPLICABLE_NO_MATCHED_FLOW',connection_status='DISPROVED',reason='REACHING_VALUE_EXCLUDES_SAMPLED_SOURCE')
        return result
    roles,statuses,opaque=field_roles(value)
    result['roles']=sorted(roles)
    result['cookie_field']=next(iter(roles)) if len(roles)==1 else 'MULTIPLE' if roles else 'UNKNOWN'
    result['connection_status']='SUPPORTED' if not uncertain_dependency(value) else 'UNVERIFIED'
    status=next((s for s in ('TYPEERROR_BEFORE_SINK','FUNCTION_REFERENCE','INVALID_DATE','UNKNOWN') if s in statuses),'TIMESTAMP_EXPRESSION' if 'TIMESTAMP_EXPRESSION' in statuses else 'UNKNOWN')
    result['serialization_status']=status
    result['serialization_alternatives']=sorted(statuses)
    if len(statuses-{'UNKNOWN'})>1:
        result.update(serialization_status='MIXED_OR_CONDITIONAL',reason='MIXED_DELIVERY_STATES',connection_status='UNVERIFIED')
        return result
    if status=='FUNCTION_REFERENCE':result['connection_status']='OBJECT_REFERENCE_ONLY'
    if status=='TYPEERROR_BEFORE_SINK':
        result['connection_status']='BLOCKED_BY_EXCEPTION'
        result.setdefault('reported_path_status','NOT_A_VALID_TIMESTAMP_DELIVERY_TRACE')
        result['evidence'].append({'rule':'EXCEPTION_VS_REASSIGNED_FRAME','note':'Expiration intent is reconstructed from operands independently of historical path_nodes; rejected memory bridges do not constitute timestamp delivery.'})
    if opaque or uncertain_dependency(value) or not roles or 'UNKNOWN' in roles:
        result['reason']='OPAQUE_DEPENDENCY_OR_COOKIE_BOUNDARY';return result
    if roles=={'EXPIRES'}:
        result.update(semantic_label='BENIGN_EXPIRATION',purpose_basis='EXPIRATION_INTENT_ONLY' if status in ('TYPEERROR_BEFORE_SINK','FUNCTION_REFERENCE','INVALID_DATE') else 'STATIC_FLOW_SUPPORTED',reason='SAMPLED_DEPENDENCY_ONLY_IN_EXPIRATION_METADATA')
        return result
    if roles & {'NAME','VALUE'}:
        proof=usage_proof(sl,sink,value)
        result['evidence']=list(sl.evidence.values())
        if proof:
            result.update(semantic_label=proof,purpose_basis='STATIC_FLOW_SUPPORTED',reason='EXPLICIT_IDENTIFIER_API_DATAFLOW' if proof=='TRACKING_RELATED' else 'MATCHED_WRITE_READ_COMPARE_DELETE_PROBE')
            return result
    result['reason']='NAME_VALUE_PURPOSE_NOT_PROVEN' if roles & {'NAME','VALUE'} else 'OTHER_ATTRIBUTE_PURPOSE_NOT_PROVEN'
    return result

def classify(functions,r):
    try:
        result=_classify(functions,r)
    except (ValueError,RecursionError) as exc:
        result={'classifier_version':VERSION,'semantic_label':'UNCLEAR','purpose_basis':'INSUFFICIENT_EVIDENCE','cookie_field':'UNKNOWN','roles':[],'connection_status':'UNVERIFIED','serialization_status':'UNKNOWN','reason':'ANALYSIS_LIMIT: '+str(exc),'evidence':[]}
    if result['semantic_label'] is None and result['serialization_status']=='UNKNOWN':
        result['serialization_status']='NOT_APPLICABLE_NO_MATCHED_FLOW'
    if result['serialization_status']=='INVALID_DATE':result['connection_status']='OBJECT_FLOW_WITH_INVALID_DATE'
    result['cookie_field_basis']='RECONSTRUCTED_INTENT_ONLY' if result['purpose_basis']=='EXPIRATION_INTENT_ONLY' else 'RECONSTRUCTED_VALUE_DEPENDENCY' if result['roles'] else 'UNRESOLVED_OR_NOT_APPLICABLE'
    code=result['reason'];result['reason_code']=code
    descriptions={
        'DATE_STATE_PROOF_INCOMPLETE':'Date 초기 시간값의 경로별 의존성·타입·효과 또는 유한 CFG 지원 조건을 입증하지 못했습니다. date_states를 확인하세요.',
        'DATE_INITIAL_TIME_DEPENDENCY_MIXED':'경로별 초기 시간값의 의존성이 서로 다릅니다. 한 경로의 긍정을 전체에 적용하지 않습니다.',
        'DATE_INITIAL_TIME_DEPENDENCY_ABSENT_POLICY_UNRESOLVED':'현재 시간값에서 초기 sampled 시간값의 의존성이 제거됐습니다. 객체·제어 영향까지 부정하는 기존 연결 부정 정책은 적용하지 않습니다.',
        'SAMPLED_DEPENDENCY_ONLY_IN_EXPIRATION_METADATA':'지정된 source의 복원된 의존성이 만료 속성에만 기여합니다. 정상 전달 여부는 purpose_basis와 serialization_status를 함께 확인해야 합니다.',
        'MATCHED_WRITE_READ_COMPARE_DELETE_PROBE':'같은 cookie 이름을 사용한 쓰기·읽기 비교·정리 동작이 IR 값 및 CFG로 연결됩니다.',
        'EXPLICIT_IDENTIFIER_API_DATAFLOW':'지정된 값이 cookie 이름/값과 지원하는 analytics 식별 API의 식별자 인자에 함께 전달됩니다.',
        'SOURCE_AFTER_SINK_OR_DISJOINT_CFG':'동일 호출 내 source가 sink보다 뒤에 있거나 두 블록 사이에 실행 경로가 없습니다.',
        'REACHING_VALUE_EXCLUDES_SAMPLED_SOURCE':'현재 sink에 도달하는 정의를 복원했지만 지정된 source의 데이터 의존성이 없습니다.',
        'SINK_LOCAL_GLOBAL_OVERWRITE_EXCLUDES_OTHER_FUNCTION_SOURCE':'sink 함수 내부의 공유 속성 재대입이 다른 함수의 이전 source 값을 대체합니다.',
        'UNRESOLVED_CALL_EFFECTS_BETWEEN_ENDPOINTS':'source와 sink 사이 호출의 반환값 또는 메모리 부작용을 모델링하지 못해 판정을 보류합니다.',
        'INTERPROCEDURAL_DEPENDENCY_UNSUPPORTED':'함수 간 전달 또는 helper 부작용을 충분히 검증하지 못했습니다.',
        'DOCUMENT_COOKIE_IDENTITY_UNRESOLVED':'sink 객체가 document임을 현재 범위에서 복원하지 못했습니다.',
        'ARGUMENT_CONTEXT_UNPROVEN':'정확한 parameter에 도달하는 모든 호출 context의 브라우저 객체 identity를 증명하지 못했습니다.',
        'METHOD_RECEIVER_CONTEXT_UNPROVEN':'this의 실제 객체와 own/prototype 메서드의 호출 연결 및 부작용을 증명하지 못했습니다.',
        'OPAQUE_DEPENDENCY_OR_COOKIE_BOUNDARY':'불투명한 의존성이나 동적 구분자 때문에 Date의 cookie field를 확정하지 못했습니다.',
        'OPAQUE_VALUE_OR_CYCLIC_MEMORY':'helper 또는 순환 메모리 정의의 값을 복원하지 못했습니다.',
        'NAME_VALUE_PURPOSE_NOT_PROVEN':'이름/값 기여는 확인했지만 기능 시험 또는 tracking 목적의 근거가 부족합니다.',
        'OTHER_ATTRIBUTE_PURPOSE_NOT_PROVEN':'만료 이외 속성의 기여에 적용할 목적 근거가 부족합니다.',
        'ENDPOINT_NOT_UNIQUE_OR_MISSING':'함수·API 유형·위치 기준 source/sink 대응이 없거나 유일하지 않습니다.',
        'CONTROL_DEPENDENCE_UNSUPPORTED':'데이터 값 대신 분기 조건을 통한 영향이 있어 현재 구현으로 연결 부재를 증명할 수 없습니다.',
        'MIXED_DELIVERY_STATES':'같은 source의 정상 표현과 오류 표현이 분기별로 달라 전달 상태를 하나로 확정하지 못했습니다.',
    }
    result['reason']=descriptions.get(code,'분석 한도에 도달해 전체 역할을 검증하지 못했습니다: '+code)
    if code.startswith('ARGUMENT_') and code not in descriptions:
        result['reason']='브라우저 document 인자 증명을 보류합니다. 정확한 미해결 연결은 evidence의 obstacles/edges 참조: '+code
    return result


def frame_owner(fn,slot,env,at):
    """Resolve only explicit, acyclic, function-owned lexical environments.

    Exact scope-qualified slots are mandatory. No captured/phi/global/name
    inference, and no merging of environments recreated in a CFG loop.
    """
    declarations=[scope for scope,slots in fn.scope_slots.items() if slots is not None and slot in slots]
    if len(declarations)!=1:return None
    declared=declarations[0];seen=set()
    for _ in range(32):
        i=fn.insts.get(env)
        if i is None or i.id in seen or i.block not in fn.live_blocks:return None
        seen.add(i.id)
        if i.op not in ('CreateScopeInst','CreateInnerScopeInst') or not i.args:return None
        if i.block==at.block:
            if fn.positions[i.id]>=fn.positions[at.id]:return None
        elif not dominates(fn,i.block,at.block):return None
        if any(fn.reachable(b,i.block) for b in fn.succ.get(i.block,[])):return None
        scope=untype(i.args[0]).removeprefix('%')
        if scope not in fn.scope_slots or fn.scope_slots[scope] is None:return None
        if scope==declared:return i.id
        if i.op!='CreateInnerScopeInst' or len(i.args)!=2:return None
        env=untype(i.args[1]);at=i
    return None
