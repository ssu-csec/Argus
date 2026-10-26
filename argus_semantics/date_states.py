"""Bounded path-local Date time state, NOT allocation-taint propagation.

Reuse Slice for expression and reaching-definition semantics. Each path has a
separate memo, so a read never borrows a setter from another predecessor.
No domain, route, function-name policy or JavaScript execution.
"""
from .engine import Slice, val, choice, walk_values
from .ir import untype, literal

MAX_PATHS=64
MAX_DEPTH=64
MAX_INSTRUCTIONS=2048
SETTERS={'setTime','setDate','setUTCDate','setFullYear','setHours','setMinutes','setSeconds'}
READS={'getTime','valueOf','toUTCString','toGMTString','toISOString','toString',
       'getDate','getUTCDate','getFullYear','getMinutes','getSeconds'}

class Stop(ValueError):pass

def dependency(v):
    return 'UNKNOWN' if v.incomplete else 'PRESENT' if v.dep else 'ABSENT'

def expression(v,depth=0):
    if depth>=8:return dict(kind=v.kind,token=v.token,truncated=True)
    return dict(kind=v.kind,value=v.data,sampled=v.tagged,unknown=v.uncertain,
                args=[expression(a,depth+1) for a in v.args])

def paths_to(fn,before):
    entry=next(iter(fn.blocks))
    relevant={b for b in fn.live_blocks if fn.reachable(b,before.block)}
    if sum(len(fn.blocks[b]) for b in relevant)>MAX_INSTRUCTIONS:raise Stop('DATE_CFG_INSTRUCTION_BUDGET')
    paths=[]
    def visit(b,path):
        if b in path:raise Stop('DATE_CFG_LOOP_OR_BACKEDGE')
        if len(path)>=MAX_DEPTH:raise Stop('DATE_CFG_DEPTH_BUDGET')
        path=path+[b]
        if b==before.block:
                                                                  
            if any(fn.reachable(t,b) for t in fn.succ.get(b,[])):raise Stop('DATE_CFG_LOOP_OR_BACKEDGE')
            paths.append(path)
            if len(paths)>MAX_PATHS:raise Stop('DATE_CFG_PATH_BUDGET')
            return
        for t in fn.succ.get(b,[]):
            if t in relevant:visit(t,path)
    visit(entry,[])
    if not paths:raise Stop('DATE_READ_UNREACHABLE')
    return paths

class PathSlice(Slice):
    def __init__(self,parent,path):
        super().__init__(parent.fn,parent.source_fn,parent.source,parent.functions)
        self.bindings=dict(parent.bindings)
        self.path=path
        self.linear=[i for b in path for i in self.fn.blocks[b]]
        self.index={i.id:n for n,i in enumerate(self.linear)}
        self.truth={};self.number_tokens=set();self.conditions=[]
        self.states={};self.state_active=set()
        self.completed_numbers={};self.completed_used=set();self.completed_edges=[]
        self.number_bindings={}

    def reaching(self,i,predicate,seen=None):
        if i.id not in self.index:return val('unknown','off-path definition',uncertain=True)
        for j in reversed(self.linear[:self.index[i.id]]):
            if predicate(j):
                self.record(j,'DATE_PATH_REACHING_STORE')
                value=self.operand(j.args[0])
                if value.kind=='completed_number':
                                                                             
                    if i.op not in ('LoadFrameInst','LoadStackInst'):
                        return val('unknown','completed numeric heap transport unsupported',uncertain=True)
                    if i.op=='LoadFrameInst':
                        slot=untype(i.args[0])
                        if slot not in self.fn.local_slots:
                            return val('unknown','completed numeric nonlocal slot',uncertain=True)
                        canonical=lambda s:s.split('@')[0].rstrip(']')+']'
                        if any(f is not self.fn and any(k.op in ('LoadFrameInst','StoreFrameInst') and canonical(untype(k.args[0] if k.op=='LoadFrameInst' else k.args[1]))==canonical(slot) for k in f.insts.values()) for f in self.functions):
                            return val('unknown','completed numeric captured slot',uncertain=True)
                                                                            
                                                                            
                    for k in self.linear[self.index[j.id]+1:self.index[i.id]]:
                        if k.op!='CallInst':continue
                        c=self.operand(k.args[0]);r=self.operand(k.args[2]) if len(k.args)>2 else val('unknown')
                        if not (c.kind=='property' and c.data in READS|SETTERS and r.kind=='date'):
                            return val('unknown','completed numeric intervening call',uncertain=True)
                    edge=dict(load=i.id,store=j.id,load_instruction=i.text,store_instruction=j.text,scope=self.fn.header,result=value.data)
                    if edge not in self.completed_edges:self.completed_edges.append(edge)
                return value
        return val('unknown','path memory origin',uncertain=True)

    def transfer(self,i):
        if i.id not in self.index:return val('unknown','off-path value',uncertain=True)
        if i.op=='PhiInst':
            pos=self.path.index(i.block)
            pred=self.path[pos-1] if pos else None
            xs=[self.operand(i.args[k]) for k in range(0,len(i.args),2) if untype(i.args[k+1])==pred]
            return choice(xs)
        if i.op=='BinaryOperatorInst' and literal(i.args[0])=='*':
                                                                               
                                                                            
                                                                         
            source_pos=self.index.get(self.source.id,-1)
            before_source=self.fn is self.source_fn and self.source.op=='ConstructInst' and self.index[i.id]<source_pos
            bigint_prefix=any(': bigint' in a for k in self.linear[:source_pos] for a in k.args)
            if before_source and not bigint_prefix and any(a.endswith(' : number') and not untype(a).startswith('%') for a in i.args[1:]):
                xs=[self.operand(a) for a in i.args[1:]]
                                                                               
                                                                       
                if all(x.kind in ('param','number','string','literal','completed_number') for x in xs):
                    key=self.fn.header+':'+i.id
                    self.completed_numbers[key]=dict(rule='COMPLETED_NUMBER_MULTIPLY_BEFORE_ALLOCATION',scope=self.fn.header,
                        instruction=i.id,instruction_text=i.text,location=i.loc,block=i.block,
                        sampled_allocation=self.fn.header+':'+self.source.id,path=list(self.path),
                        normal_result_type='Number',condition='multiplication completed normally on this enumerated path before allocation',
                        operands=[expression(x) for x in xs],operand_primitive='NOT_PROVEN',
                        prior_conversion_effects='NOT_PROVEN_PURE',prior_conversion_exceptions='MAY_THROW_BEFORE_ALLOCATION',
                        finite='NOT_PROVEN',date_range='NOT_PROVEN',execution_safe='NOT_PROVEN')
                    return val('completed_number',key)
        return super().transfer(i)

    def assume(self,i,target):
        v=self.operand(i.args[0]);truth=target==untype(i.args[1])
        if v.token in self.truth and self.truth[v.token]!=truth:return False
        if v.kind=='literal' and v.data in ('true','false','undefined','null'):
            if (v.data=='true')!=truth:return False
        if v.kind=='number' and (float(v.data)!=0)!=truth:return False
        self.truth[v.token]=truth
        self.conditions.append(dict(instruction=i.id,expression=expression(v),taken=truth,target=target))
        if v.kind=='binary' and v.data in ('==','===','!=','!=='):
            equal=truth if v.data in ('==','===') else not truth
            if equal:
                for x,y in (v.args,v.args[::-1]):
                    if x.kind=='string' and x.data=='number' and y.kind=='unary' and y.data=='typeof' and y.args[0].kind=='param':
                                                                             
                                                                                 
                        self.number_tokens.add(y.args[0].token)
        return True

    def number(self,v,allocation=None):
        if v.incomplete:return False
        if v.kind=='param':
            if v.data not in self.number_bindings:
                from .number_bindings import prove
                self.number_bindings[v.data]=prove(self,v.data)
            proof=self.number_bindings[v.data]
            if proof and proof['supported']:return True
        if v.kind=='completed_number':
            proof=self.completed_numbers.get(v.data)
            if proof and allocation is not None and self.index[proof['instruction']]<self.index[allocation.id]:
                self.completed_used.add(v.data);return True
            return False
        if v.token in self.number_tokens:return True
        if v.kind in ('number','helper_number','date_number'):return True
        if v.kind=='timestamp':return v.data in ('getTime','valueOf','getDate','getUTCDate','getFullYear','getMinutes','getSeconds','Date.now','performance.now')
        if v.kind=='literal':return v.data in ('true','false','null')
        if v.kind=='binary' and v.data in ('+','-','*','/','%'):
            return all(self.number(x,allocation) for x in v.args)
        if v.kind=='unary' and v.data in ('-','+'):return self.number(v.args[0],allocation)
        return False

    def call(self,i):
        callee=self.operand(i.args[0]);recv=self.operand(i.args[2]) if len(i.args)>2 else val('unknown')
        if callee.kind=='property' and recv.kind=='date' and callee.data in SETTERS:
            state=self.state(recv,i,include=True)[0]
            return val('date_number',callee.data,(state,),status=state.status)
        return super().call(i)

    def date_state(self,recv,before,include_setter=False):
        return self.state(recv,before,include_setter)[0]

    def state(self,recv,before,include=False):
        key=(recv.data,before.id,include)
        if key in self.states:return self.states[key]
        if key in self.state_active:raise Stop('DATE_STATE_RECURSION')
        self.state_active.add(key)
        try:result=self._state(recv,before,include)
        finally:self.state_active.remove(key)
        self.states[key]=result
        return result

    def _state(self,recv,before,include):
        prefix=self.fn.header+':'
        allocation=self.fn.insts.get(recv.data[len(prefix):]) if recv.data.startswith(prefix) else None
        end=self.index.get(before.id,-1)+int(include)
        if not allocation or allocation.op!='ConstructInst' or allocation.id not in self.index or self.index[allocation.id]>=end:
            raise Stop('DATE_ALLOCATION_NOT_BEFORE_READ_ON_PATH')
                                                                        
        current=val('initial_time',recv.data,recv.args,tagged=recv.tagged)
        validity='VALID' if not recv.args else 'MAYBE_INVALID'
        if len(recv.args)==1 and recv.args[0].kind=='number':
            validity='VALID' if abs(float(recv.args[0].data))<=8.64e15 else 'INVALID'
        setters=[];effects=[];status='TIMESTAMP_EXPRESSION'
        start=self.index[allocation.id]+1
        for j in self.linear[start:end]:
            if j.op=='StoreFrameInst' and self.operand(j.args[0]).kind=='date' and self.operand(j.args[0]).data==recv.data:
                if untype(j.args[1]) not in self.fn.local_slots:raise Stop('DATE_ESCAPES_NONLOCAL_FRAME')
            if j.op in ('StorePropertyInst','StoreNewOwnPropertyInst','StoreOwnPropertyInst'):
                x=self.operand(j.args[0]);target=self.operand(j.args[1])
                if any(v.kind=='date' and v.data==recv.data for v in walk_values(x)) or (target.kind=='date' and target.data==recv.data):
                    raise Stop('DATE_HEAP_ESCAPE_OR_PROPERTY_MUTATION')
            if j.op in ('CreateFunctionInst','CreateClosureInst'):raise Stop('DATE_OPEN_CAPTURE_AFTER_ALLOCATION')
            if j.op!='CallInst':continue
            callee=self.operand(j.args[0]);target=self.operand(j.args[2]) if len(j.args)>2 else val('unknown')
            method=callee.data if callee.kind=='property' else None
            if target.kind=='date' and target.data==recv.data and method in SETTERS:
                if method!='setTime':raise Stop('DATE_BRANCH_COMPONENT_SETTER_UNSUPPORTED')
                arg=self.operand(j.args[3]) if len(j.args)>3 else val('unknown','missing setTime argument',uncertain=True)
                old=dependency(current)
                if not self.number(arg,allocation):
                                                                                  
                    current=val('unknown','setTime argument/coercion unresolved',(arg,),uncertain=True)
                    effects.append(dict(instruction=j.id,reason='DATE_ARGUMENT_COERCION_OR_RETURN_UNKNOWN'))
                    status='UNKNOWN';validity='UNKNOWN'
                else:
                    current=arg
                    validity=('VALID' if abs(float(arg.data))<=8.64e15 else 'INVALID') if arg.kind=='number' else 'MAYBE_INVALID'
                    status='INVALID_DATE' if validity=='INVALID' else 'TIMESTAMP_EXPRESSION'
                setters.append(dict(instruction=j.id,method=method,before_dependency=old,after_dependency=dependency(current),
                                    argument=expression(arg),validity=validity,strong_update=True))
            elif target.kind=='date' and method in READS:
                if method=='toISOString':
                    previous=self.eval(j.id)
                    if previous.incomplete or previous.status in ('UNKNOWN','INVALID_DATE'):
                        effects.append(dict(instruction=j.id,reason='DATE_PRIOR_READ_MAY_THROW'))
                        current=val('unknown','earlier ISO conversion may throw',(current,),uncertain=True)
                        status='UNKNOWN';validity='UNKNOWN'
                continue
            else:
                if any(v.kind=='date' and v.data==recv.data for a in j.args[3:] for v in walk_values(self.operand(a))):
                    raise Stop('DATE_ESCAPES_CALL_ARGUMENT')
                x=self.eval(j.id)
                from .standard_returns import concat_effect
                                                                           
                                                                            
                                                                               
                opaque_concat=(method=='concat' and target.kind in ('string','concat') and
                    any(self.operand(a).kind in ('object','instance','param','property','unknown') for a in j.args[3:]))
                if (x.incomplete or opaque_concat) and not concat_effect(self,j):
                    effects.append(dict(instruction=j.id,reason='DATE_UNKNOWN_INTERVAL_CALL_EFFECT'))
                    current=val('unknown','interval call effect',(current,),uncertain=True);status='UNKNOWN';validity='UNKNOWN'
        if effects and status!='UNKNOWN':
            current=val('unknown','unresolved earlier effect',(current,),uncertain=True);status='UNKNOWN'
                                                                              
                                                                              
        slots={untype(j.args[1]) for j in self.linear[start:end] if j.op=='StoreFrameInst' and
               self.operand(j.args[0]).kind=='date' and self.operand(j.args[0]).data==recv.data}
        canonical=lambda slot:slot.split('@')[0].rstrip(']')+']'
        slots={canonical(s) for s in slots}
        for f in self.functions:
            if f is self.fn:continue
            for j in f.insts.values():
                if j.op in ('LoadFrameInst','StoreFrameInst'):
                    slot=untype(j.args[0] if j.op=='LoadFrameInst' else j.args[1])
                    if canonical(slot) in slots:raise Stop('DATE_CAPTURED_LOCAL_ALIAS')
        read_callee=self.operand(before.args[0]) if before.op=='CallInst' else None
        read_method=read_callee.data if read_callee else 'valueOf'
        if read_method=='toISOString' and validity!='VALID':serialization='POSSIBLE_RANGEERROR'
        elif read_method in ('toUTCString','toGMTString','toString'):
            serialization='INVALID_DATE_STRING' if validity=='INVALID' else 'TIMESTAMP_OR_INVALID_DATE_STRING' if validity=='MAYBE_INVALID' else status
        else:serialization='NAN' if validity=='INVALID' else 'NUMBER_OR_NAN' if validity in ('MAYBE_INVALID','UNKNOWN') else 'NUMBER'
        if serialization=='POSSIBLE_RANGEERROR':
            current=val('unknown','toISOString validity not proven',(current,),uncertain=True);status='UNKNOWN'
        info=dict(allocation=recv.data,initial_time_dependency=dependency(current),time_expression=expression(current),validity=validity,
                  setter_sequence=setters,effects=effects,serialization=serialization,
                  exceptions=['POSSIBLE_RANGEERROR'] if serialization=='POSSIBLE_RANGEERROR' else ['UNVERIFIED_EFFECT_OR_COERCION'] if effects else [],
                  control_dependency='NOT_MODELED')
        if self.completed_used:
            info['completed_numeric_results']=list(self.completed_numbers.values())
            info['completed_numeric_reaching_edges']=list(self.completed_edges)
        bindings=[p for p in self.number_bindings.values() if p is not None]
        if bindings:info['number_bindings']=bindings
        if self.standard_returns:info['standard_normal_returns']=list(self.standard_returns.values())
        if self.standard_uses:info['standard_primitive_uses']=list(self.standard_uses.values())
        return val('date_expression',args=(current,),status=status,uncertain=status=='UNKNOWN'),info

def analyze(parent,recv,before,include_setter=False):
    key=(recv.data,before.id,include_setter)
    if key in parent.date_state_cache:return parent.date_state_cache[key]
    record=dict(rule='DATE_PATH_STATE',function=parent.fn.header,allocation=recv.data,read=before.id,
                is_sampled_allocation=(parent.fn is parent.source_fn and recv.data==parent.fn.header+':'+parent.source.id),
                read_instruction=before.text,read_location=before.loc,include_setter=include_setter,
                mode='BOUNDED_PATH_SET_TIME',budgets=dict(paths=MAX_PATHS,depth=MAX_DEPTH,instructions=MAX_INSTRUCTIONS),paths=[],blockers=[])
    values=[]
    try:
        for path in paths_to(parent.fn,before):
            sl=PathSlice(parent,path);possible=True
            for b,target in zip(path,path[1:]):
                last=parent.fn.blocks[b][-1]
                if last.op=='CondBranchInst' and not sl.assume(last,target):possible=False;break
                if last.op not in ('CondBranchInst','BranchInst'):raise Stop('DATE_UNSUPPORTED_CFG_TERMINATOR')
            if not possible:continue
            value,info=sl.state(recv,before,include_setter)
            info.update(blocks=path,conditions=sl.conditions)
            record['paths'].append(info);values.append(value)
        if not values:raise Stop('DATE_NO_SUPPORTED_READ_PATH')
        deps={p['initial_time_dependency'] for p in record['paths']}
        record['initial_time_dependency']=next(iter(deps)) if len(deps)==1 else 'MIXED'
        record['validity_states']=sorted({p['validity'] for p in record['paths']})
        blocked=record['initial_time_dependency'] in ('MIXED','UNKNOWN') or ('INVALID' in record['validity_states'] and len(record['validity_states'])>1)
        result=val('date_expression',args=(choice(values),),uncertain=blocked,
                   status='UNKNOWN' if blocked else 'INVALID_DATE' if record['validity_states']==['INVALID'] else 'TIMESTAMP_EXPRESSION')
    except Stop as exc:
        record['blockers'].append(str(exc));record['initial_time_dependency']='UNKNOWN'
        result=val('date_expression',args=(recv,),uncertain=True,status='UNKNOWN')
    parent.date_states[key]=record
    parent.evidence[(before.id,'DATE_PATH_STATE:'+recv.data+':'+str(include_setter))]=record
    parent.date_state_cache[key]=result
    return result

def policy_block(states):
    """Time-value absence is NOT a proof excluding object/control influence."""
    deps={s['initial_time_dependency'] for s in states if s.get('is_sampled_allocation')}
    if 'UNKNOWN' in deps:return 'DATE_STATE_PROOF_INCOMPLETE'
    if 'MIXED' in deps:return 'DATE_INITIAL_TIME_DEPENDENCY_MIXED'
    if 'ABSENT' in deps:return 'DATE_INITIAL_TIME_DEPENDENCY_ABSENT_POLICY_UNRESOLVED'
    return None
