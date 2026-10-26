"""Conditional read insertion observations; never consumed by purpose policy.

Reuse Slice and field_roles in isolated instances. An exact read result is a
hole under a normal-result/insertion condition, NOT restored timestamp taint.
No type, heap, callback, IIFE or exception-CFG proof is added here.
"""
from .engine import Slice, val, endpoint, field_roles, expand, walk_values, ordered_reachable
from .contexts import fact
from .date_states import READS, dependency
from .ir import literal

MAX_READS = 16
CONDITIONS = [
    'this exact read completes normally and its result reaches this sampled RHS alternative',
    'standard unmodified Date and string built-ins within existing Slice models',
    'insertion position only; not initial timestamp delivery, execution, exclusivity or benign purpose',
]

def unavailable(reason, status='NOT_ANALYZED'):
    return dict(status=status, reason=reason, observations=[], limitations=[],
                contract='CONDITIONAL_EXACT_READ_INSERTION_V1', conditions=CONDITIONS)

def execution_summary(final, local):
    """Canonical findings with multiple references, not independent counts."""
    found={}
    def add(code,scope,instruction,ref,category):
        key=(code,scope,str(instruction))
        if key not in found:found[key]=dict(code=code,scope=scope,instruction=instruction,category=category,references=[])
        if ref not in found[key]['references']:found[key]['references'].append(ref)
    for origin,obj in [('date_states',final),('local_role.date_states',local)]:
        for k,s in enumerate(obj.get('date_states',[])):
            ref=f'{origin}/{k}';scope=s['function']
            for code in s['blockers']:add(code,scope,None,ref+'/blockers','ANALYSIS_LIMIT_OR_UNSUPPORTED')
            for j,p in enumerate(s['paths']):
                for e in p.get('standard_normal_returns',[]):
                    if e.get('supported'):
                        add('STANDARD_STRINGIFY_MAY_THROW',e['scope'],e['instruction'],f'{ref}/paths/{j}/standard_normal_returns','POSSIBLE_EXCEPTION')
                        add('STANDARD_STRINGIFY_PRIOR_EFFECTS_NOT_DISCHARGED',e['scope'],e['instruction'],f'{ref}/paths/{j}/standard_normal_returns','UNRESOLVED_EFFECT_OR_CONVERSION')
                        if e.get('completion_obstacle'):add(e['completion_obstacle'],e['scope'],e['instruction'],f'{ref}/paths/{j}/standard_normal_returns','POSSIBLE_EXCEPTION')
                for e in p['effects']:
                    code=e['reason'];code='UNKNOWN_CALL_EFFECT' if code=='DATE_UNKNOWN_INTERVAL_CALL_EFFECT' else code
                    add(code,scope,e['instruction'],f'{ref}/paths/{j}/effects','UNRESOLVED_EFFECT_OR_CONVERSION')
                for code in p['exceptions']:
                                                                              
                    if code=='UNVERIFIED_EFFECT_OR_COERCION':continue
                    add(code,scope,s['read'],f'{ref}/paths/{j}/exceptions','POSSIBLE_EXCEPTION')
    for k,e in enumerate(local.get('evidence',[])):
        if e['rule']=='LOCAL_PREWRITE_EXCEPTIONS':
            for x in e['exceptions']:
                add('DATE_METHOD_TYPEERROR',x['function'],x.get('instruction'),f'local_role.evidence/{k}',
                    'MODELED_BLOCKING_EXCEPTION' if x['dominates_write'] and x['definite_value_error'] else 'POSSIBLE_EXCEPTION')
                                                                           
                                                                            
    for origin,obj in [('evidence',final),('local_role.evidence',local)]:
        for k,e in enumerate(obj.get('evidence',[])):
            if e.get('rule')=='STANDARD_NORMAL_RETURN' and e.get('supported'):
                add('STANDARD_STRINGIFY_MAY_THROW',e['scope'],e['instruction'],f'{origin}/{k}','POSSIBLE_EXCEPTION')
                add('STANDARD_STRINGIFY_PRIOR_EFFECTS_NOT_DISCHARGED',e['scope'],e['instruction'],f'{origin}/{k}','UNRESOLVED_EFFECT_OR_CONVERSION')
                if e.get('completion_obstacle'):add(e['completion_obstacle'],e['scope'],e['instruction'],f'{origin}/{k}','POSSIBLE_EXCEPTION')
    for k,e in enumerate(local.get('blockers',[])):
        if e['code']=='UNRESOLVED_RHS_INTERVAL_CALL_EFFECT':
            inst=e.get('instruction','');add('UNKNOWN_CALL_EFFECT',local.get('write',{}).get('function',''),inst.split(' = ')[0],f'local_role.blockers/{k}','UNRESOLVED_EFFECT_OR_CONVERSION')
    findings=list(found.values())
    for k,e in enumerate(findings):e['id']=f'execution:{k}'
    return dict(status='UNCERTAINTY_RECORDED' if findings else 'NO_ADDITIONAL_RECORDED_FINDING',
        findings=findings,legacy_prewrite_status=local.get('prewrite_status','UNVERIFIED'),
        legacy_prewrite_scope='modeled interval calls and Date-method TypeError checks; NO_MODELED_BLOCKER is not conversion or execution safety',
        unchecked=['full JS feasibility','unmodeled coercion/getter/alias effects','all exception paths','browser parser and storage','other uses of this script'],
        execution_success='NOT_PROVEN',browser_storage='NOT_TESTED')

class ReadHoleSlice(Slice):
    def __init__(self,parent,read,method):
        super().__init__(parent.fn,parent.source_fn,parent.source,parent.functions)
        self.read=read
                                                                               
        self.marker=val('timestamp',method,(val('read_hole',parent.fn.header+':'+read.id),),tagged=True)
    def transfer(self,i):
        if i.id==self.read.id:return self.marker
        return super().transfer(i)

def direct_hole(v,token):
    if v.token==token:return True
                                                                               
                                                              
    if v.kind in ('timestamp','date','date_expression','date_number','error','property','unknown'):return False
    return any(direct_hole(x,token) for x in v.args)

def analyze(functions,route,final,local,identity):
    out=unavailable('SOURCE_NOT_DATE_ALLOCATION')
    if route['source_name']!='Date':return out
    sources=endpoint(functions,route,'source');sinks=endpoint(functions,route,'sink')
    if len(sources)!=1 or len(sinks)!=1:return unavailable('ENDPOINT_NOT_UNIQUE','READ_NOT_LINKED')
    sf,source=sources[0];tf,sink=sinks[0]
    if sf is not tf:return unavailable('INTERPROCEDURAL_READ_NOT_SUPPORTED','ANALYSIS_LIMIT')
    if literal(sink.args[2])!='cookie':return unavailable('NOT_COOKIE_WRITE')
    if not ordered_reachable(tf,source,sink):return unavailable('NO_ORDERED_SOURCE_TO_SINK','READ_NOT_LINKED')
    sl=Slice(tf,sf,source,functions);value=sl.operand(sink.args[0])
    allocation=tf.header+':'+source.id; candidates=[]
    for id in list(sl.memo):
        i=tf.insts[id]
        if i.op!='CallInst' or len(i.args)<3:continue
        callee=sl.operand(i.args[0]);recv=sl.operand(i.args[2])
        if callee.kind!='property' or callee.data not in READS:continue
        if recv.kind!='date' or recv.data!=allocation:continue
        if not ordered_reachable(tf,source,i) or not ordered_reachable(tf,i,sink):continue
        candidates.append((i,callee.data,recv))
    out=unavailable('NO_EXACT_SAMPLED_ALLOCATION_READ','READ_NOT_LINKED')
    out.update(source=fact(sf,source),allocation=allocation,sink=fact(tf,sink),rhs_operand=sink.args[0],
               sink_identity_reference='sink_identity',sink_identity_status=identity.get('status','UNVERIFIED'))
    if len(candidates)>MAX_READS:return {**out,'status':'ANALYSIS_LIMIT','reason':'CONDITIONAL_READ_BUDGET'}
    if any(x.kind=='unknown' and ('budget' in x.data or 'recursive' in x.data) for x in walk_values(value)):
        return {**out,'status':'ANALYSIS_LIMIT','reason':'LEGACY_SLICE_LIMIT'}
    for i,method,recv in sorted(candidates,key=lambda x:int(x[0].id[1:])):
        hole=ReadHoleSlice(sl,i,method);rhs=hole.operand(sink.args[0])
        details=field_roles(rhs,details=True);parts=expand(rhs)
        positions=[]
        for o in details['observations']:
            node=parts[o['alternative']][o['token_index']]
            if direct_hole(node,hole.marker.token):
                                                                           
                positions.append({k:v for k,v in o.items() if k not in ('dependency_resolved','token')})
        if not positions:continue
        state=sl.date_state(recv,i)
        refs=[s for s in sl.date_states.values() if s['allocation']==allocation and s['read']==i.id and not s['include_setter']]
        dep=refs[0]['initial_time_dependency'] if refs else dependency(state)
        fields=sorted({p['field'] for p in positions if p['field']!='UNKNOWN'})
        obs=dict(status='POSITION_OBSERVED' if fields else 'BOUNDARY_UNRESOLVED',allocation=allocation,
            allocation_relation='EXACT_SAMPLED_ALLOCATION',read=fact(tf,i),read_method=method,sink=fact(tf,sink),rhs_operand=sink.args[0],
            conditional_fields=fields,positions=positions,conditions=CONDITIONS,
            boundary_evidence=dict(contract=details['boundary_contract'],attribute_events=details['attribute_events'],opaque_boundaries=details['opaque_boundaries'],
                rhs_slice=[e for e in hole.evidence.values() if e.get('rule') in ('DEF_USE','REACHING_MEMORY_EDGE','REACHING_STORE')]),
            initial_time_dependency=dep,initial_dependency_evidence=refs or [dict(mode='LEGACY_DATE_STATE',dependency=dep,serialization=state.status)],
            execution_reference='execution_uncertainty',unresolved=['execution and insertion are conditional','not an expiration-only or storage proof'])
        out['observations'].append(obs)
        if any(p['field']=='UNKNOWN' for p in positions):obs['unresolved'].append('one or more RHS alternatives have unresolved boundaries')
    if out['observations']:
        out['status']='POSITION_OBSERVED' if any(x['conditional_fields'] for x in out['observations']) else 'BOUNDARY_UNRESOLVED'
        out['reason']='CONDITIONAL_ONLY_NOT_TIMESTAMP_DELIVERY'
    return out
