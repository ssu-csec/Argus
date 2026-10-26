'use strict';
                                                                                             
function analyzeSiteContext(ast, {sourceId, sourceHash, sourceText = ''}) {
  const parent = new WeakMap(), nodes = [], scopes = new WeakMap();
  const functionType=n=>n&&(/Function/.test(n.type)||['ObjectMethod','ClassMethod','ClassPrivateMethod'].includes(n.type));
  function visit(n, p, scope) {
    if (!n || typeof n.type !== 'string') return;
    if (n.type === 'Program' || functionType(n) || n.type === 'BlockStatement' || n.type==='CatchClause') scope = {parent: scope, names: new Set(), functionBoundary:n.type==='Program'||functionType(n)};
    if (p) parent.set(n, p); scopes.set(n, scope); nodes.push(n);
    if (functionType(n)) for (const a of n.params || []) addNames(a, scope.names);
    if (n.type === 'VariableDeclarator') {let target=scope;if(p?.kind==='var')while(target.parent&&!target.functionBoundary)target=target.parent;addNames(n.id,target.names);}
    if(n.type==='CatchClause')addNames(n.param,scope.names);
    if(n.type==='FunctionDeclaration'&&n.id)(scope.parent||scope).names.add(n.id.name);
    if(n.type==='ClassDeclaration'&&n.id)scope.names.add(n.id.name);
    for (const [k, v] of Object.entries(n)) {
      if (['loc','start','end','extra','comments','tokens','errors'].includes(k)) continue;
      if (Array.isArray(v)) for (const x of v) visit(x, n, scope);
      else if (v && typeof v.type === 'string') visit(v, n, scope);
    }
  }
  function addNames(n,s) {if (!n) return;if(n.type==='Identifier')s.add(n.name);else if(n.type==='AssignmentPattern')addNames(n.left,s);else if(n.type==='RestElement')addNames(n.argument,s);else if(n.type==='ObjectPattern')for(const p of n.properties)addNames(p.value||p.argument,s);else if(n.type==='ArrayPattern')for(const p of n.elements)addNames(p,s);}
  visit(ast, null, null);
  function bound(n, name) {for(let s=scopes.get(n);s;s=s.parent)if(s.names.has(name))return true;return false;}
  function member(n) {if(!n)return null;if(n.type==='Identifier')return [n.name];if(n.type!=='MemberExpression' || n.optional)return null;const p=n.computed?(n.property.type==='StringLiteral'?n.property.value:null):n.property.name;const b=member(n.object);return p!=null&&b?[...b,p]:null;}
  function pbjsCall(n) {const p=member(n.callee);if(!p)return null;if(p[0]==='window'&&!bound(n,'window')&&p[1]==='pbjs')return p.slice(2);if(p[0]==='pbjs'&&!bound(n,'pbjs'))return p.slice(1);return null;}
  const desc = n => ({sourceId, sourceHash, type:n.type, range:[n.start,n.end], loc:n.loc && {start:n.loc.start,end:n.loc.end}, text:sourceText.slice(n.start,n.end).slice(0,400)});
  const isFn = functionType;
  function ancestors(n) {const a=[];for(let p=parent.get(n);p;p=parent.get(p))a.push(p);return a;}
  function predicates(n) {
    const out=[];let child=n;
    for(let p=parent.get(n);p;child=p,p=parent.get(p)) {
      if(p.type==='IfStatement' && (child===p.consequent||child===p.alternate))out.push({kind:'BRANCH',test:desc(p.test),truthy:child===p.consequent});
      if(p.type==='ConditionalExpression' && (child===p.consequent||child===p.alternate))out.push({kind:'BRANCH',test:desc(p.test),truthy:child===p.consequent});
      if(p.type==='LogicalExpression' && child===p.right)out.push({kind:'SHORT_CIRCUIT',test:desc(p.left),required:p.operator==='&&'?'TRUTHY':p.operator==='||'?'FALSY':'NULLISH'});
      if(isFn(p))out.push({kind:'ENCLOSING_FUNCTION_MUST_BE_INVOKED',function:desc(p),observed:false});
    }
    return out;
  }
  const queues=[], apiCalls=[], eventRegistrations=[];
  for(const n of nodes)if(n.type==='CallExpression') {
    const p=pbjsCall(n);
    if(p&&p.length===2&&['que','cmd'].includes(p[0])&&p[1]==='push'&&isFn(n.arguments[0]))queues.push({call:desc(n),queue:p[0],callback:desc(n.arguments[0]),predicates:predicates(n),status:'REGISTRATION_ONLY',required:'Same pbjs object/realm; callable queue push; later callback dispatch with preceding effects completing normally'});
    if(p&&p.length===1)apiCalls.push({api:p[0],call:desc(n),predicates:predicates(n),queueCallback:queues.find(q=>q.callback.range[0]<=n.start&&n.end<=q.callback.range[1])?.callback||null,status:'CONDITIONAL_CALL_CANDIDATE',invocationObserved:false});
    const leaf=n.callee?.type==='MemberExpression'?(n.callee.computed?n.callee.property?.type==='StringLiteral'?n.callee.property.value:null:n.callee.property?.name):null;
    if(leaf==='on'&&n.arguments[0]?.type==='StringLiteral'&&isFn(n.arguments[1]))eventRegistrations.push({event:n.arguments[0].value,call:desc(n),callback:desc(n.arguments[1]),status:'STRUCTURAL_EVENT_REGISTRATION_CANDIDATE',unresolved:'Receiver/event-library semantics and actual event occurrence are not established'});
  }
  return {schemaVersion:1,sourceId,sourceHash,status:'STATIC_SITE_CONTEXT',queueRegistrations:queues,apiCallCandidates:apiCalls,eventRegistrations,runtimeObserved:false,completeCallGraph:false};
}
module.exports={analyzeSiteContext};
