from .ir import header_body
"""Conditional primitive-Number proof for one nonescaping direct local closure.

Not a browser identity proof, numeric coercion proof, or execution/effect proof.
Only hash-verified complete inventories opt in. No site/route/name policies.
"""
import hashlib,re
from .ir import parse,untype,literal
from .arguments import Inventory,params,slot,reaching
from .contexts import function_ref,target,fact

def verified_inventory(full,meta,base):
    if (meta.get('status')!='OK' or meta.get('complete_ir') is not True or
        any(meta.get(k)!=base.get(k) for k in ('engine_sha256','reconstructed_sha256')) or
        meta.get('base_ir_sha256')!=base.get('ir_sha256') or
        hashlib.sha256(full).hexdigest()!=meta.get('ir_sha256')):
        raise ValueError('Number inventory provenance/hash/completeness mismatch')
    text=full.decode();fs=parse(text,complete=True)
    if not fs or getattr(fs,'coverage_errors',[]) or len(fs)!=sum(l.startswith('function_end') for l in text.splitlines()):
        raise ValueError('Number inventory malformed function coverage')
    inv=Inventory(fs)
    inv.number_provenance={k:meta[k] for k in ('engine_sha256','reconstructed_sha256','base_ir_sha256','ir_sha256','complete_ir')}
    return inv

def prove(sl,param):
    inv=getattr(sl.functions,'argument_inventory',None)
    if inv is None or not getattr(inv,'number_provenance',None) or not inv.functions.complete:return None
    if param not in params(sl.fn):return None
    ev=dict(rule='NUMBER_ACTUAL_FORMAL_PROOF',callee=sl.fn.header,formal=param,supported=False,
            scope='CONDITIONAL_CLOSED_DIRECT_CALL',hashes=inv.number_provenance,
            assumptions=['faithful complete IR for the fingerprinted input',
                         'ordinary lexical semantics; no debugger, caller/arguments reflection, dynamic code or instrumentation accessing hidden closures/frames'],
            execution_success='NOT_PROVEN',prior_effects='NOT_PROVEN_PURE',finite='NOT_PROVEN',date_range='NOT_PROVEN',
            budgets=dict(callsites=1,actual_nodes=64,actual_depth=8,phi_incoming=16),actual_definitions=[])
    def fail(reason):ev['obstacle']=reason;return ev
    fn=inv.byheader.get(sl.fn.header)
    if fn is None or len([f for f in inv.functions if f.header==fn.header])!=1:return fail('CALLEE_NOT_UNIQUE')
    if [(i.id,i.text,i.loc) for i in fn.insts.values()]!=[(i.id,i.text,i.loc) for i in sl.fn.insts.values()]:return fail('CALLEE_BODY_MISMATCH')
    if any(i.op in ('CreateArgumentsInst','DirectEvalInst') or 'Eval' in i.op for i in fn.insts.values()):return fail('ARGUMENTS_OR_EVAL_UNSUPPORTED')
                                                                             
    entries=[i for i in fn.insts.values() if i.op=='StoreFrameInst' and untype(i.args[0])==param]
    if len(entries)!=1:return fail('FORMAL_ENTRY_NOT_UNIQUE')
    entry=entries[0];binding=slot(entry.args[1])
    if entry.block!=next(iter(fn.blocks)) or binding not in fn.local_slots:return fail('FORMAL_NOT_LOCAL_ENTRY')
    stores=inv.stores[binding];loads=inv.loads[binding]
    if len(stores)!=1 or stores[0][0] is not fn or stores[0][1] is not entry:return fail('FORMAL_REASSIGNED_OR_CAPTURED_WRITER')
    edges=[]
    for reader,load in loads:
        if reader is not fn:return fail('FORMAL_CAPTURE_UNSUPPORTED')
        defs=reaching(fn,load,binding)
        if len(defs)!=1 or defs[0] is not entry:return fail('FORMAL_REACHING_DEFINITION_UNPROVEN')
        edges.append(dict(load=fact(fn,load),store=fact(fn,entry)))
    sites=inv.creates[function_ref(header_body(fn.header))]
    if len(sites)!=1:return fail('CREATION_NOT_UNIQUE')
    owner,create=sites[0]
    if target(inv.functions,create) is not fn:return fail('CREATION_TARGET_MISMATCH')
    uses=inv.uses[owner.header].get(create.id,[])
    ev.update(creation=fact(owner,create),closure_uses=[dict(**fact(owner,i),operand_index=n) for i,n in uses])
    closure_status='ONE_DIRECT_CALLEE_USE_NO_ALIAS_OR_ESCAPE'
    if len(uses)==1 and uses[0][0].op=='CallInst' and uses[0][1]==0:
        call=uses[0][0]
    else:
        from .property_calls import resolve
        call,property_proof=resolve(inv,owner,create,fn)
        ev['property_call_proof']=property_proof
        if call is None:return fail('PROPERTY_CALL_BINDING_UNPROVEN')
        closure_status='ONE_CLOSED_FRESH_OBJECT_OWN_DATA_PROPERTY_CALL'
        ev['scope']='CONDITIONAL_CLOSED_OWN_DATA_PROPERTY_CALL'
    if untype(call.args[1])!='undefined':return fail('NEW_TARGET_UNSUPPORTED')
    from .engine import dominates
    def precedes(i,at):
        return (owner.positions[i.id]<owner.positions[at.id]) if i.block==at.block else dominates(owner,i.block,at.block)
    if not precedes(create,call):return fail('CREATION_ORDER_UNPROVEN')
    index=params(fn).index(param);operand_index=3+index
    if operand_index>=len(call.args):return fail('MISSING_ACTUAL')
    nodes=0;active=set()
    def number_literal(a):
        return a.endswith(' : number') and re.fullmatch(r'-?(?:(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|Infinity|NaN)',untype(a)) is not None
    def numeric(a,at,depth=0):
        nonlocal nodes
        nodes+=1
        if nodes>64 or depth>8:return False
        if number_literal(a):
            ev['actual_definitions'].append(dict(kind='NUMBER_LITERAL',operand=a));return True
        i=owner.insts.get(untype(a))
        if i is None or i.id in active or not precedes(i,at):return False
        active.add(i.id)
        try:
            if i.op=='UnaryOperatorInst' and literal(i.args[0])=='-' and number_literal(i.args[1]):
                ev['actual_definitions'].append(dict(kind='NUMBER_LITERAL_UNARY_MINUS',**fact(owner,i)));return True
            if i.op=='PhiInst':
                incoming=[untype(x) for x in i.args[1::2]];preds=owner.preds.get(i.block,[])
                if len(i.args)%2 or not incoming or len(incoming)>16 or len(set(incoming))!=len(incoming) or set(incoming)!=set(preds):return False
                ev['actual_definitions'].append(dict(kind='NUMBER_PHI',**fact(owner,i),incoming=[dict(operand=i.args[n],predecessor=i.args[n+1]) for n in range(0,len(i.args),2)]))
                return all(numeric(i.args[n],owner.blocks[untype(i.args[n+1])][-1],depth+1) for n in range(0,len(i.args),2))
            return False
        finally:active.remove(i.id)
    actual=call.args[operand_index]
    ev.update(caller=owner.header,callsite=fact(owner,call),actual_operand_index=operand_index,
              formal_index=index,actual=actual,entry_store=fact(fn,entry),reaching_edges=edges,
              closure_use_status=closure_status)
    if not numeric(actual,call):return fail('ACTUAL_NOT_PROVEN_PRIMITIVE_NUMBER')
    ev.update(supported=True,normal_argument_type='Number',obstacle=None,visited_nodes=nodes)
    return ev
