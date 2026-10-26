'use strict';
const traverse=require('./deps.cjs').requireBabel('@babel/traverse').default;
                                                                                   
function analyzeCallbackLinks(ast,bundle,cookie,{sourceId,sourceHash}) {
  const paths=[], byStart=new Map();traverse(ast,{enter(p){paths.push(p);byStart.set(p.node.start,p);}});
  const span=n=>({start:n.start,end:n.end,loc:n.loc&&{start:n.loc.start,end:n.loc.end}});
  const unseq=p=>p?.isSequenceExpression()?p.get('expressions').at(-1):p;
  const prop=n=>n?.type==='MemberExpression'?(n.computed?n.property.type==='StringLiteral'?n.property.value:null:n.property.name):null;
  const imports=new Map(bundle.imports.filter(x=>x.targets.length===1&&x.targetIdentity==='UNIQUE_IN_STORED_REGISTRIES_UNDER_FRESH_CONTEXT').map(x=>[x.range.start,x]));
  function lexical(p,seen=new Set(),depth=0) {
    p=unseq(p);if(!p||depth>18||seen.has(p.node))return null;seen=new Set(seen).add(p.node);
    if(p.isIdentifier()) {const b=p.scope.getBinding(p.node.name);if(!b||!b.constant)return null;
      if(b.path.isVariableDeclarator()&&b.path.get('init').isIdentifier())return lexical(b.path.get('init'),seen,depth+1);
      return {binding:b,path:b.path};}
    if(p.isMemberExpression()) {const key=prop(p.node),ob=p.get('object');if(key===null||!ob.isIdentifier())return null;
      const b=ob.scope.getBinding(ob.node.name);if(!b||!b.constant||!b.path.isVariableDeclarator())return null;
      const init=b.path.get('init'),imp=imports.get(init.node?.start);if(!imp)return null;
      const matches=bundle.exports.filter(e=>e.moduleKey===imp.targets[0]).flatMap(e=>e.items.map(i=>({e,i}))).filter(x=>String(x.i.name)===key);
      if(matches.length!==1)return null;let q=byStart.get(matches[0].i.expressionRange?.start);if(!q)return null;
      if(matches[0].i.form==='GETTER_CANDIDATE') {if(!q.isFunction())return null;if(q.get('body').isBlockStatement()){const rs=q.get('body.body').filter(x=>x.isReturnStatement());if(rs.length!==1)return null;q=rs[0].get('argument');}else q=q.get('body');}
      const r=lexical(q,seen,depth+1);return r?{...r,exportContract:'STRUCTURAL_EXPORT_HELPER_ABI_AND_UNIQUE_FRESH_REGISTRY_REQUIRED',importSite:imp.range}:null;}
    return null;
  }
  function returnedFunction(f) {
    if(!f?.isFunction())return null;
    const rs=[];f.traverse({Function(p){p.skip();},ReturnStatement(p){rs.push(p.get('argument'));}});
    if(rs.length!==1)return null;const r=rs[0];if(r.isFunction())return r;
    const b=lexical(r);return b?.path.isVariableDeclarator()&&b.path.get('init').isFunction()?b.path.get('init'):null;
  }
  const records=[];
  for(const p of paths)if(p.isFunction()&&p.parentPath?.isCallExpression()) {
    const registration=p.parentPath,index=registration.get('arguments').findIndex(x=>x.node===p.node);if(index<0)continue;
    const helper=lexical(registration.get('callee'));let helperFn=helper?.path;
    if(helperFn?.isVariableDeclarator())helperFn=helperFn.get('init');if(!helperFn?.isFunction())continue;
    const param=helperFn.get('params')[index];if(!param?.isIdentifier())continue;
    const paramBinding=param.scope.getBinding(param.node.name),wrapper=returnedFunction(helperFn);if(!wrapper||wrapper.isArrowFunctionExpression()||!paramBinding?.constant)continue;
    const dispatch=[];wrapper.traverse({Function(q){q.skip();},CallExpression(q){const c=q.get('callee'),a=q.get('arguments');if(c.isMemberExpression()&&prop(c.node)==='apply'&&c.get('object').isIdentifier()&&c.scope.getBinding(c.node.object.name)===paramBinding&&a.length===2&&a[0].isThisExpression()&&a[1].isIdentifier({name:'arguments'})&&!a[1].scope.getBinding('arguments'))dispatch.push(q);}});
    if(!dispatch.length)continue;
    let owner=registration.parentPath;
    if(owner.isReturnStatement()) {const iife=owner.getFunctionParent(),call=iife?.parentPath;if(!call?.isCallExpression()||call.get('callee').node!==iife.node)continue;owner=call.parentPath;}
    if(!owner.isVariableDeclarator()||!owner.get('id').isIdentifier())continue;
    const b=owner.scope.getBinding(owner.node.id.name);if(!b||!b.constant)continue;
    const callers=[];
    for(const q of paths)if(q.isCallExpression()) {const r=lexical(q.get('callee'));if(r?.binding===b)callers.push({range:span(q.node),arguments:q.get('arguments').map(a=>({range:span(a.node),state:a.isIdentifier({name:'undefined'})&&!a.scope.getBinding('undefined')?'UNDEFINED':a.isUnaryExpression({operator:'void'})&&a.get('argument').isNumericLiteral({value:0})?'UNDEFINED':a.isSpreadElement()?'SPREAD_UNRESOLVED':'PROVIDED_VALUE_UNRESOLVED'})),enclosingFunction:q.getFunctionParent()?span(q.getFunctionParent().node):null,exportContract:r.exportContract||null,status:'EXACT_LEXICAL_CALLSITE_CANDIDATE_INVOCATION_UNPROVEN'});}
    records.push({callback:span(p.node),registration:span(registration.node),helper:span(helperFn.node),returnedWrapper:span(wrapper.node),wrapperDispatches:dispatch.map(q=>span(q.node)),argumentsForwardedUnchanged:true,binding:{name:b.identifier.name,declaration:span(owner.node)},callers,conditions:['Helper/export ABI behaves as structurally described and no intervening mutation changes bindings.','The returned wrapper is invoked at a recorded caller; caller execution is unproved.','The branch guarding callback.apply(this, arguments) permits it (for memoizers, a cache miss is required).'],executionObserved:false});
  }
  return {sourceId,sourceHash,status:'CONDITIONAL_CALLBACK_RELATIONS',records,completeCallGraph:false,crossScriptExecutionLink:'UNRESOLVED_REALM_ORDER_QUEUE_AND_API_DISPATCH'};
}
module.exports={analyzeCallbackLinks};
