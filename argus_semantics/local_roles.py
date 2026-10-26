"""Read-only auxiliary roles in a candidate cookie RHS, not purpose decisions.

Reuse the existing Slice/field_roles/effect models. Never bind an unresolved
receiver to document just to analyze its RHS, and never modify final outputs.
"""
from .engine import (Slice,endpoint,field_roles,unresolved_effects,uncertain_dependency,
                     val,reassigned_source_slots,walk_values,ordered_reachable,dominates)
from .contexts import fact
from .ir import literal

ASSUMPTIONS=[
    'exact sampled instruction in exact function scope; explicit RHS data only',
    'standard unmodified Date/string/encoding built-ins within existing models',
    'bounded static alternatives; no claim of feasible execution, browser storage or network delivery',
    'PARTIAL fields are reconstructed operand positions, not complete dependency/noninterference proofs',
    'expiration-only covers contributions to this sampled RHS, not every use in the script',
    'literal semicolon resets attribute region even without a proven initial pair; parser acceptance is separate',
    'opaque primitive/coercion output may reject storage; NO_MODELED_BLOCKER is not proof of successful conversion',
]

def unavailable(code,detail=''):
    return dict(status='UNVERIFIED',fields=[],expiration_only=None,basis='UNRESOLVED',
                dependency='UNVERIFIED',serialization_states=[],prewrite_status='UNVERIFIED',blockers=[dict(code=code,detail=detail)],
                assumptions=ASSUMPTIONS,evidence=[])

def analyze(functions,route,final_result=None):
    result=unavailable('ENDPOINT_NOT_UNIQUE_OR_MISSING')
    identity=dict(status='UNVERIFIED',reason='ENDPOINT_NOT_UNIQUE_OR_MISSING',evidence=[])
    sources=endpoint(functions,route,'source');sinks=endpoint(functions,route,'sink')
    if len(sources)!=1 or len(sinks)!=1:return result,identity
    sf,source=sources[0];tf,sink=sinks[0]
    sl=Slice(tf,sf,source,functions)
    receiver=sl.operand(sink.args[1])
    identity.update(reason='RECEIVER_NOT_PROVEN_BROWSER_DOCUMENT',receiver_kind=receiver.kind,receiver_value=receiver.data,
                    evidence=[fact(tf,sink)],assumptions=['standard browser global bindings; static reference, not execution proof'])
    if receiver==val('symbol','document'):
        identity.update(status='SUPPORTED_BROWSER_DOCUMENT',reason='STATIC_BROWSER_REFERENCE')
    else:
                                                                             
        for e in (final_result or {}).get('evidence',[]):
            if e['rule']=='ARGUMENT_CONTEXT_PROOF':
                identity['evidence'].append(e)
                if e.get('supported') and e.get('function')==tf.header:
                    check=Slice(tf,sf,source,functions);check.bindings[e['parameter']]=val('symbol','window')
                    if check.operand(sink.args[1])==val('symbol','document'):
                        identity.update(status='SUPPORTED_BROWSER_DOCUMENT',reason='REUSED_CLOSED_ARGUMENT_PROOF')
    if literal(sink.args[2])!='cookie':return unavailable('NOT_A_COOKIE_PROPERTY_WRITE'),identity
    result.update(blockers=[],source=fact(sf,source),write=fact(tf,sink),rhs_operand=sink.args[0])
    def block(code,**detail):result['blockers'].append(dict(code=code,**detail))
    if sf is not tf:
        block('INTERPROCEDURAL_RHS_NOT_MODELED');return result,identity
    if not ordered_reachable(tf,source,sink):
        result['dependency']='NO_SAME_INVOCATION_FLOW';result['prewrite_status']='NO_SAME_INVOCATION_FLOW';block('SOURCE_AFTER_WRITE_OR_DISJOINT_CFG');return result,identity
    try:
        value=sl.operand(sink.args[0])
        result['date_states']=list(sl.date_states.values())
        from .date_states import policy_block
        date_block=policy_block(result['date_states'])
        if date_block:block(date_block)
        details=field_roles(value,details=True)
        effects=unresolved_effects(sl,sink)
        for e in effects:block('UNRESOLVED_RHS_INTERVAL_CALL_EFFECT',**e)
        exceptions=[]
        for i in tf.insts.values():
            if i.op=='CallInst' and ordered_reachable(tf,source,i) and ordered_reachable(tf,i,sink):
                x=sl.eval(i.id)
                if any(v.status=='TYPEERROR_BEFORE_SINK' for v in walk_values(x)):
                    exceptions.append(dict(fact(tf,i),dominates_write=dominates(tf,i.block,sink.block),definite_value_error=x.kind=='error'))
        result['prewrite_status']='MODELED_TYPEERROR_BEFORE_WRITE' if any(e['dominates_write'] and e['definite_value_error'] for e in exceptions) else 'POSSIBLE_TYPEERROR_BEFORE_WRITE' if exceptions else 'UNVERIFIED' if effects else 'NO_MODELED_BLOCKER'
                                                                           
                                                                               
        if value.incomplete and not value.dep:block('OPAQUE_RHS_CANNOT_PROVE_ABSENCE')
        if uncertain_dependency(value):block('UNRESOLVED_SOURCE_DEPENDENCY')
        if 'UNKNOWN' in details['fields']:block('COOKIE_BOUNDARY_UNRESOLVED')
        result['fields']=sorted({o['field'] for o in details['observations'] if o['field']!='UNKNOWN' and o['dependency_resolved']})
        result['serialization_states']=details['serialization_states'] or (['UNKNOWN'] if value.dep else [])
        result['dependency']='PRESENT' if value.dep and not uncertain_dependency(value) and not effects else 'ABSENT' if not value.dep and not value.incomplete and not effects else 'UNVERIFIED'
        if date_block:result['dependency']='UNVERIFIED'
        result['status']='PROVEN' if not result['blockers'] else 'PARTIAL' if result['fields'] else 'UNVERIFIED'
        result['expiration_only']=(bool(result['fields']) and set(result['fields'])<=set(('EXPIRES','MAX_AGE','TTL'))) if result['status']=='PROVEN' else None
        result['basis']='EXPRESSION_INTENT_ONLY' if exceptions or set(result['serialization_states']) & {'TYPEERROR_BEFORE_SINK','FUNCTION_REFERENCE','INVALID_DATE'} else 'STATIC_RHS_STRUCTURE'
                                                                            
                                                                             
                                                                              
        result['cookie_interpretation']=dict(
            scope='CONDITIONAL_STRUCTURE_NOT_RUNTIME_PARSER',
            attribute_role_rule='SEMICOLON_RESETS_ATTRIBUTE_REGION_V6',
            initial_pair_required_for_attribute_role=False,
            known_literal_controls=bool(details['literal_control_characters']),
            recognized_expiration_fields=sorted(set(result['fields']) & {'EXPIRES','MAX_AGE'}),
            nonstandard_ttl_metadata='TTL' in result['fields'],
            attribute_events=details['attribute_events'],
            parser_acceptance='NOT_EVALUATED',effective_expiration='UNVERIFIED',
            browser_storage='NOT_TESTED',
            caveats=['duplicate Expires and Max-Age precedence do not change insertion role',
                     'invalid date/method reference is intent only, not valid expiry',
                     'NAME is the initial lexical region; a missing first = can yield nameless VALUE in a permissive parser',
                     'unknown prefix/suffix can contain CTL, policy attributes, duplicates or throw during coercion'])
        result['evidence']=[dict(rule='LOCAL_RHS_FIELD_SCAN',function=tf.header,**details),
                            dict(rule='LOCAL_PREWRITE_EXCEPTIONS',exceptions=exceptions),
                            dict(rule='LOCAL_REASSIGNED_MEMORY_BRIDGES',bridges=reassigned_source_slots(sl,value))]+list(sl.evidence.values())+effects
    except (ValueError,RecursionError) as exc:
        result.update(status='UNVERIFIED',fields=[],expiration_only=None,basis='UNRESOLVED')
        block('LOCAL_ROLE_ANALYSIS_LIMIT',detail=str(exc))
    return result,identity
