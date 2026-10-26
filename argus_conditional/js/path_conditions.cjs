'use strict';
function attachPathConditions(ast,result,sourceText) {
  const parent=new WeakMap(),nodes=new Map();
  function visit(n,p){if(!n||typeof n.type!=='string')return;parent.set(n,p);nodes.set(n.start,n);for(const[k,v]of Object.entries(n)){if(['loc','extra','comments','tokens','errors'].includes(k))continue;if(Array.isArray(v)){for(const c of v)visit(c,n);}else if(v&&typeof v.type==='string')visit(v,n);}}
  visit(ast,null);
  const desc=n=>({sourceHash:result.sourceHash,start:n.start,end:n.end,loc:n.loc&&{start:n.loc.start,end:n.loc.end},text:sourceText.slice(n.start,n.end).slice(0,500)});
  function predicates(at){const out=[];let child=nodes.get(at.start);if(!child)return out;for(let p=parent.get(child);p;child=p,p=parent.get(p)){
    if((p.type==='IfStatement'||p.type==='ConditionalExpression')&&(child===p.consequent||child===p.alternate))out.push({kind:'LEXICAL_BRANCH',predicate:desc(p.test),required:child===p.consequent?'TRUTHY':'FALSY',valueObserved:false});
    if(p.type==='LogicalExpression'&&child===p.right)out.push({kind:'LEXICAL_SHORT_CIRCUIT',predicate:desc(p.left),required:p.operator==='&&'?'TRUTHY':p.operator==='||'?'FALSY':'NULLISH',valueObserved:false});
    if(['WhileStatement','ForStatement'].includes(p.type)&&child===p.body&&p.test)out.push({kind:'LOOP_BODY_ENTRY',predicate:desc(p.test),required:'TRUTHY_FOR_ITERATION',iterationObserved:false});
    if(['FunctionExpression','FunctionDeclaration','ArrowFunctionExpression','ObjectMethod','ClassMethod','ClassPrivateMethod'].includes(p.type))out.push({kind:'ENCLOSING_FUNCTION_INVOCATION',function:desc(p),observed:false});
  }return out;}
  for(const f of result.cookie.flows)f.controlObligations={source:predicates(f.source.range),sink:predicates(f.sink.range),calls:f.path.filter(p=>p.call).map(p=>({call:p.call,predicates:predicates(p.call)})),allRequiredEffectsStillUnproved:true};
  for(const r of result.callbacks.records)for(const c of r.callers)c.controlObligations=predicates(c.range);
}
module.exports={attachPathConditions};
