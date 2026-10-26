'use strict';

                                                                             
                                                                               
                                                            
function analyzeBundle(ast, options = {}) {
  const root = ast && ast.type === 'File' ? ast.program : ast;
  if (!root || root.type !== 'Program') throw new TypeError('Babel Program/File AST required');
  const nodes = [], scopes = [], parents = new WeakMap(), scopeAt = new WeakMap();
  const owners = new WeakMap(), bindingNodes = new WeakMap(), functions = [];
  const isFn = n => !!n && /^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod|ClassMethod|ClassPrivateMethod)$/.test(n.type);
  const childNodes = n => Object.keys(n).flatMap(k => {
    if (k === 'loc' || k === 'tokens' || k === 'comments' || k === 'extra' || k === 'parent') return [];
    const v = n[k];
    return Array.isArray(v) ? v.filter(x => x && typeof x.type === 'string') : v && typeof v.type === 'string' ? [v] : [];
  });
  const range = n => n ? {start:n.start ?? null, end:n.end ?? null, loc:n.loc ? {start:n.loc.start, end:n.loc.end} : null} : null;
  const nodeId = n => n ? `${n.type}@${n.start ?? nodes.indexOf(n)}` : null;
  function newScope(parent, kind, node) { const s={id:scopes.length,parent,kind,node,bindings:new Map()}; scopes.push(s); return s; }
  function declare(pattern, scope, declaration, init = null) {
    if (!pattern) return;
    if (pattern.type === 'Identifier') {
      let b=scope.bindings.get(pattern.name);
      if (!b) {b={id:`S${scope.id}:${pattern.name}`, name:pattern.name, scope, declarations:[], initializers:[]};scope.bindings.set(pattern.name,b);}
      b.declarations.push(declaration); if (init) b.initializers.push(init); bindingNodes.set(pattern,b); return;
    }
    if (pattern.type === 'AssignmentPattern') return declare(pattern.left,scope,declaration,pattern.right);
    if (pattern.type === 'RestElement') return declare(pattern.argument,scope,declaration);
    if (pattern.type === 'ObjectPattern') for (const p of pattern.properties) declare(p.value || p.argument,scope,declaration);
    if (pattern.type === 'ArrayPattern') for (const p of pattern.elements) declare(p,scope,declaration);
  }
  function visit(n, parent, scope, fn) {
    if (!n || typeof n.type !== 'string') return;
    nodes.push(n); if(parent)parents.set(n,parent);
    if(n.type==='Program')scope=newScope(null,'function',n);
    if(n.type==='FunctionDeclaration'&&n.id)declare(n.id,scope,n,n);
    if(isFn(n)) {
      scope=newScope(scope,'function',n);fn=n;functions.push(n);
      if(n.type==='FunctionExpression'&&n.id)declare(n.id,scope,n,n);
      for(const p of n.params)declare(p,scope,n);
    } else if(n.type==='BlockStatement'&&!(isFn(parent)&&parent.body===n)) scope=newScope(scope,'block',n);
    else if(n.type==='CatchClause') {scope=newScope(scope,'block',n);declare(n.param,scope,n);}
    scopeAt.set(n,scope);owners.set(n,fn || root);
    if(n.type==='VariableDeclaration') {
      let target=scope;if(n.kind==='var')while(target.parent&&target.kind!=='function')target=target.parent;
      for(const d of n.declarations)declare(d.id,target,d,d.init);
    }
    for(const c of childNodes(n))visit(c,n,scope,fn);
  }
  visit(root,null,null,null);
  const nodesByOwner=new Map();
  for(const n of nodes) {const o=owners.get(n);if(!nodesByOwner.has(o))nodesByOwner.set(o,[]);nodesByOwner.get(o).push(n);}
  function binding(n) {
    if(!n||n.type!=='Identifier')return null;
    if(bindingNodes.has(n))return bindingNodes.get(n);
    for(let s=scopeAt.get(n);s;s=s.parent)if(s.bindings.has(n.name))return s.bindings.get(n.name);
    return null;
  }
  const same = (a,b) => !!a&&!!b&&a.type==='Identifier'&&b.type==='Identifier'&&binding(a)&&binding(a)===binding(b);
  const prop = n => n && (n.type==='MemberExpression'||n.type==='OptionalMemberExpression'||n.type==='ObjectProperty'||n.type==='ObjectMethod') ? (!n.computed&&n.property?.type==='Identifier' ? n.property.name : !n.computed&&n.key?.type==='Identifier' ? n.key.name : literal(n.property || n.key)) : null;
  function literal(n) {
    if(!n)return null;
    if(n.type==='StringLiteral'||n.type==='NumericLiteral'||n.type==='BooleanLiteral')return n.value;
    if(n.type==='NullLiteral')return null;
    if(n.type==='Literal'&&['string','number','boolean'].includes(typeof n.value))return n.value;
    return null;
  }
  const member = n => n && n.type==='MemberExpression';
  const staticMemberPath = n => n?.type==='Identifier'||(member(n)&&prop(n)!==null&&staticMemberPath(n.object));
  const call = n => n && n.type==='CallExpression';
  const childrenOf = (n, descendFunctions=true) => {
    const out=[];function walk(x){out.push(x);for(const c of childNodes(x))if(descendFunctions||!isFn(c))walk(c);}walk(n);return out;
  };
  const local = fn => nodesByOwner.get(fn)||[];
  function sig(n) {
    if(!n)return '?';
    if(n.type==='Identifier')return binding(n)?.id || `ambient:${n.name}`;
    if(member(n))return `${sig(n.object)}[${n.computed&&literal(n.property)===null?sig(n.property):JSON.stringify(prop(n))}]`;
    return `${n.type}:${JSON.stringify(literal(n))}`;
  }
  function ancestor(n, pred) {for(let p=parents.get(n);p;p=parents.get(p))if(pred(p))return p;return null;}
  function inNode(n,p) {for(let v=n;v;v=parents.get(v))if(v===p)return true;return false;}
  const fnBinding = fn => fn.id ? binding(fn.id) : parents.get(fn)?.type==='VariableDeclarator' ? binding(parents.get(fn).id) : null;
  const expressionOfBinding = b => b&&b.initializers.length===1?b.initializers[0]:null;
  const propertyValue = (obj,name) => obj?.type==='ObjectExpression' ? obj.properties.find(p=>p.type==='ObjectProperty'&&String(prop(p))===name)?.value : null;
  const objectEmpty = n => n?.type==='ObjectExpression'&&n.properties.length===0;
  const indexSame = (n,id) => member(n)&&n.computed&&same(n.property,id);
  const undefinedExpr = n => n?.type==='UnaryExpression'&&n.operator==='void'&&literal(n.argument)===0;
  const assignments=nodes.filter(n=>n.type==='AssignmentExpression');
  const updates=nodes.filter(n=>n.type==='UpdateExpression');
  function constant(n) {
    const direct=literal(n);if(direct!==null)return {value:direct,kind:'LITERAL'};
    if(n?.type==='AssignmentExpression'&&n.operator==='=')return constant(n.right);
    const b=binding(n);if(!b)return null;
                                                                              
                                                                            
    if(b.declarations.some(isFn)||updates.some(u=>same(u.argument,n))||assignments.some(a=>same(a.left,n)&&a.operator!=='='))return null;
    const sources=[...b.initializers.map(x=>({value:x,at:x})),...assignments.filter(a=>same(a.left,n)).map(a=>({value:a.right,at:a}))];
    if(sources.length!==1)return null;
    const s=sources[0],v=literal(s.value);if(v===null||(s.at.start??Infinity)>=(n.start??-Infinity))return null;
    if(owners.get(s.at)!==owners.get(n)||ancestor(s.at,p=>owners.get(p)===owners.get(s.at)&&/^(IfStatement|ConditionalExpression|ForStatement|WhileStatement|DoWhileStatement|TryStatement|SwitchStatement)$/.test(p.type)))return null;
    if(local(owners.get(n)).some(x=>call(x)&&(x.start??-1)>(s.at.end??Infinity)&&(x.end??Infinity)<(n.start??-1)))return null;
    return {value:v,kind:'SINGLE_STRAIGHTLINE_LITERAL_BINDING',binding:b.id,evidence:range(s.at)};
  }
  const context={schemaVersion:1,sourceId:options.sourceId??null,sourceHash:options.sourceHash??null,status:'CONDITIONAL_AST_CONTEXT',guards:[],loaders:[],chunks:[],modules:[],imports:[],exports:[],entryCandidates:[],unresolvedEdges:[],assumptions:[
    'AST supplied by caller; this module does not parse or execute source.',
    'All execution statements are conditional on normal preceding completion; registration is not invocation or factory completion.',
    'Fresh queue is an explicit hypothetical state; existing ambient state, getters, proxies, realm identity and mutations remain UNKNOWN.',
    'Literal edges are structural candidates, not a complete call graph, runtime observation or private PROVED result.'
  ]};
  const unresolved=(kind,n,detail)=>context.unresolvedEdges.push({kind,range:range(n),detail});
  for(const n of nodes)if(n.type==='IfStatement'&&n.test?.type==='LogicalExpression'&&n.test.operator==='&&') {
    const a=n.test.left,b=n.test.right;
    if(member(a)&&member(b)&&member(b.object)&&staticMemberPath(a)&&prop(b)!==null&&sig(a)===sig(b.object)) {
      context.guards.push({guardKey:nodeId(n),range:range(n),testRange:range(n.test),base:sig(a),statusProperty:prop(b),baseReads:[range(a),range(b.object)],basePropertyReadCountMax:2,shortCircuit:true,conditionThrowCaughtByThen:false,thenRange:range(n.consequent),elseRange:range(n.alternate),scenarios:[
        {when:'first base read falsy',outcome:'ELSE_ENTRY_CONDITIONAL_MUST',secondRead:false},
        {when:'stable truthy base with falsy status property',outcome:'ELSE_ENTRY_CONDITIONAL_MUST'},
        {when:'stable truthy base with truthy status property',outcome:'THEN_ENTRY_CONDITIONAL_MUST_ELSE_NOT_REACHED'},
        {when:'unstable getter/proxy or throw',outcome:'UNKNOWN_OR_ABRUPT',effectsMustBePreserved:true}
      ],node:n});
    }
  }
                                                                                
  const loaderInternals=[];
  for(const fn of functions) {
    if(fn.params.length!==1||fn.params[0].type!=='Identifier')continue;
    const id=fn.params[0],fb=fnBinding(fn);if(!fb)continue;
    for(const c of local(fn).filter(call)) {
      if(!member(c.callee)||prop(c.callee)!=='call'||!indexSame(c.callee.object,id)||c.arguments.length!==4)continue;
      const registry=c.callee.object.object,receiver=c.arguments[0],record=c.arguments[1];
      if(!binding(registry)||!member(receiver)||prop(receiver)!=='exports'||!same(receiver.object,record)||sig(c.arguments[2])!==sig(receiver)||binding(c.arguments[3])!==fb)continue;
      const recordInit=expressionOfBinding(binding(record));
      if(recordInit?.type!=='AssignmentExpression'||recordInit.operator!=='='||!indexSame(recordInit.left,id)||!objectEmpty(propertyValue(recordInit.right,'exports')))continue;
      const cache=recordInit.left.object,cacheBinding=binding(cache),registryBinding=binding(registry);
      if(!cacheBinding||!objectEmpty(expressionOfBinding(cacheBinding))||expressionOfBinding(registryBinding)?.type!=='ObjectExpression')continue;
      const hitChecks=local(fn).filter(x=>x.type==='IfStatement'&&x.test?.type==='BinaryExpression'&&['!==','!='].includes(x.test.operator));
      const hit=hitChecks.find(x=>{
        const other=undefinedExpr(x.test.left)?x.test.right:undefinedExpr(x.test.right)?x.test.left:null;
        const init=expressionOfBinding(binding(other));
        if(!indexSame(init,id)||binding(init.object)!==cacheBinding)return false;
        const rs=x.consequent.type==='ReturnStatement'?[x.consequent]:childrenOf(x.consequent,false).filter(y=>y.type==='ReturnStatement');
        return rs.length===1&&member(rs[0].argument)&&prop(rs[0].argument)==='exports'&&same(rs[0].argument.object,other);
      });
      if(!hit||(hit.end??Infinity)>=(recordInit.start??-Infinity)||(recordInit.end??Infinity)>=(c.start??-Infinity))continue;
      const fact={loaderKey:fb.id,functionRange:range(fn),registryBinding:registryBinding.id,cacheBinding:cacheBinding.id,callRange:range(c),cacheAllocationRange:range(recordInit),cacheHitRange:range(hit),cacheBeforeFactory:true,cacheDoesNotProveCompletion:true,factoryArguments:['module.exports','module','module.exports','same loader'],recognition:'STRUCTURAL_CANDIDATE_NOT_EFFECT_PROOF',queueKey:null,scheduler:null};
      context.loaders.push(fact);loaderInternals.push({fact,fn,fb,registryBinding,cacheBinding});break;
    }
  }
  function queueExpression(n) {
    if(n?.type==='AssignmentExpression'&&n.operator==='='&&member(n.left)&&staticMemberPath(n.left)&&n.right?.type==='LogicalExpression'&&n.right.operator==='||'&&sig(n.left)===sig(n.right.left)&&n.right.right?.type==='ArrayExpression'&&n.right.right.elements.length===0)
      return {key:sig(n.left),range:range(n),propertyReads:1,propertyWrites:1,fallbackFreshArray:true};
    if(member(n)&&staticMemberPath(n))return {key:sig(n),range:range(n),propertyReads:1,propertyWrites:0,fallbackFreshArray:false};
    return null;
  }
  const moduleInternals=[];
  function addRegistry(registry,origin,chunk,loaderKey=null) {
    if(registry?.type!=='ObjectExpression')return;
    for(const p of registry.properties) {
      const id=prop(p),f=p.type==='ObjectMethod'?p:p.type==='ObjectProperty'?p.value:null;
      if((typeof id!=='number'&&typeof id!=='string')||!isFn(f)||(p.type==='ObjectMethod'&&p.kind!=='method')) {unresolved('NONLITERAL_OR_NONFUNCTION_REGISTRY_SLOT',p,'No factory identity inferred; accessor values require property-read effects.');continue;}
      const item={moduleKey:`${nodeId(registry)}:${String(id)}`,moduleId:id,factoryRange:range(f),registryRange:range(registry),origin,chunkKey:chunk?.chunkKey??null,chunkIds:chunk?.chunkIds??[],loaderKey,execution:'REGISTERED_FACTORY_ONLY',completion:'UNPROVEN'};
      context.modules.push(item);moduleInternals.push({item,fn:f});
    }
  }
  for(const loader of loaderInternals)addRegistry(expressionOfBinding(loader.registryBinding),'BOOTSTRAP_REGISTRY',null,loader.fb.id);
  const chunkInternals=[];
  for(const c of nodes.filter(call)) {
    if(!member(c.callee)||prop(c.callee)!=='push'||c.arguments.length!==1)continue;
    const queue=queueExpression(c.callee.object),tuple=c.arguments[0];
    if(!queue||tuple?.type!=='ArrayExpression'||tuple.elements.length<2||tuple.elements[0]?.type!=='ArrayExpression'||tuple.elements[1]?.type!=='ObjectExpression')continue;
    const ids=tuple.elements[0].elements.map(literal);if(ids.some(x=>typeof x!=='number'&&typeof x!=='string')){unresolved('DYNAMIC_CHUNK_ID',c,'Chunk IDs not inferred.');continue;}
    const runtime=tuple.elements[2];
    const fact={chunkKey:nodeId(c),queueKey:queue.key,queueEvaluation:queue,chunkIds:ids,range:range(c),registryRange:range(tuple.elements[1]),runtimeRange:isFn(runtime)?range(runtime):null,registrationDoesNotProveFactoryExecution:true,existingQueueState:'UNKNOWN',freshQueueState:'ASSUMED_ONLY',loaderKey:null};
    context.chunks.push(fact);chunkInternals.push({fact,runtime:isFn(runtime)?runtime:null,registry:tuple.elements[1]});addRegistry(tuple.elements[1],'CHUNK_PUSH',fact);
    if(runtime&&!isFn(runtime))unresolved('NONFUNCTION_CHUNK_RUNTIME',runtime,'Runtime callback identity unresolved.');
  }
                                                                              
  for(const loader of loaderInternals) {
    const registryAliases=assignments.filter(a=>member(a.left)&&binding(a.left.object)===loader.fb&&binding(a.right)===loader.registryBinding).map(a=>prop(a.left));
    const handlers=functions.filter(fn=>local(fn).some(n=>n.type==='AssignmentExpression'&&member(n.left)&&member(n.left.object)&&binding(n.left.object.object)===loader.fb&&registryAliases.includes(prop(n.left.object))));
    for(const handler of handlers) {
      const hb=fnBinding(handler);if(!hb)continue;
      const installs=assignments.filter(a=>member(a.left)&&prop(a.left)==='push'&&call(a.right)&&member(a.right.callee)&&prop(a.right.callee)==='bind'&&binding(a.right.callee.object)===hb);
      for(const install of installs) {
        const qb=binding(install.left.object),qi=expressionOfBinding(qb),queue=queueExpression(qi);if(!queue)continue;
        const replay=nodes.find(n=>call(n)&&member(n.callee)&&prop(n.callee)==='forEach'&&binding(n.callee.object)===qb&&n.arguments.some(a=>call(a)&&member(a.callee)&&prop(a.callee)==='bind'&&binding(a.callee.object)===hb));
        if(!replay)continue;
        if(loader.fact.queueKey&&loader.fact.queueKey!==queue.key){unresolved('AMBIGUOUS_LOADER_QUEUE',install,'Multiple queue identities; no unconditional linkage.');continue;}
        loader.fact.queueKey=queue.key;loader.fact.queueBootstrap={initialization:queue,replayRange:range(replay),pushInstallRange:range(install),handlerRange:range(handler),priorPushState:'UNKNOWN',handlerEffects:'NOT_FULLY_PROVED'};
      }
    }
    const sched=assignments.filter(a=>member(a.left)&&binding(a.left.object)===loader.fb&&isFn(a.right)&&a.right.params.length>=3).find(a=>local(a.right).some(n=>n.type==='ArrayExpression'&&n.elements.some(x=>same(x,a.right.params[1]))&&n.elements.some(x=>same(x,a.right.params[2]))));
    if(sched) {
      const predicates=assignments.filter(a=>member(a.left)&&member(a.left.object)&&binding(a.left.object.object)===loader.fb&&prop(a.left.object)===prop(sched.left)&&isFn(a.right)).map(a=>{
        const body=a.right.body,zeroSide=body?.type==='BinaryExpression'&&body.operator==='==='?(literal(body.left)===0?body.right:literal(body.right)===0?body.left:null):null;
        const ready=zeroSide&&a.right.params.length===1&&indexSame(zeroSide,a.right.params[0])?binding(zeroSide.object):null;
        const initial=expressionOfBinding(ready),slots=initial?.type==='ObjectExpression'?initial.properties.filter(p=>p.type==='ObjectProperty'&&prop(p)!==null).map(p=>({chunkId:prop(p),value:literal(p.value),range:range(p)})):null;
        return {property:prop(a.left),range:range(a),bodyRange:range(body),readyMapBinding:ready?.id??null,readyValue:ready?0:null,initialSlots:slots,semantics:ready?'LITERAL_ZERO_READINESS_SHAPE_WITH_EFFECTS_UNPROVED':'READINESS_PREDICATE_UNPROVED'};
      });
      loader.fact.scheduler={property:prop(sched.left),range:range(sched),dependencyArgument:1,callbackArgument:2,predicates,registrationVsDrain:'Candidate registration call has a dependency array; drain calls require separate effect/order proof.'};
    }
  }
  for(const chunk of chunkInternals) {
    const matches=loaderInternals.filter(l=>l.fact.queueKey===chunk.fact.queueKey);
    if(matches.length===1) {chunk.fact.loaderKey=matches[0].fb.id;for(const m of context.modules)if(m.chunkKey===chunk.fact.chunkKey)m.loaderKey=matches[0].fb.id;}
    else unresolved('CHUNK_LOADER_UNRESOLVED',null,{chunkKey:chunk.fact.chunkKey,matches:matches.length,reason:'Same name alone does not prove registry identity.'});
  }
  function exportItems(c, module, requireBinding) {
    if(!member(c.callee)||binding(c.callee.object)!==requireBinding||c.arguments.length<2||module.fn.params.length<2||!same(c.arguments[0],module.fn.params[1]))return;
    const definition=c.arguments[1],items=[];
    if(definition.type==='ObjectExpression')for(const p of definition.properties)if(p.type==='ObjectProperty'&&prop(p)!==null)items.push({name:prop(p),form:'GETTER_CANDIDATE',expressionRange:range(p.value)});
    if(definition.type==='ArrayExpression')for(let i=0;i<definition.elements.length;) {
      const name=literal(definition.elements[i++]),tag=definition.elements[i++];if(name===null||!tag)break;
      if(literal(tag)===0){items.push({name,form:'DATA_CANDIDATE',expressionRange:range(definition.elements[i++])});}
      else items.push({name,form:'GETTER_CANDIDATE',expressionRange:range(tag)});
    }
    if(items.length)context.exports.push({moduleKey:module.item.moduleKey,helperProperty:prop(c.callee),range:range(c),items,status:'STRUCTURAL_EXPORT_HELPER_CANDIDATE_ABI_NOT_PROVED',readingExportMayInvokeGetter:true});
  }
  for(const module of moduleInternals) {
    const rp=module.fn.params[2],rb=binding(rp);
    for(const a of childrenOf(module.fn).filter(n=>n.type==='AssignmentExpression'&&n.operator==='='&&member(n.left))) {
      const target=a.left.object,name=prop(a.left);
      const direct=same(target,module.fn.params[1]);
      const viaModule=member(target)&&prop(target)==='exports'&&same(target.object,module.fn.params[0]);
      const replacement=name==='exports'&&same(target,module.fn.params[0]);
      if((direct||viaModule||replacement)&&name!==null)context.exports.push({moduleKey:module.item.moduleKey,range:range(a),items:[{name:replacement?'*module.exports*':name,form:replacement?'MODULE_EXPORTS_REPLACEMENT_CANDIDATE':'DIRECT_PROPERTY_WRITE_CANDIDATE',expressionRange:range(a.right)}],status:'STRUCTURAL_EXPORT_WRITE_NOT_DESCRIPTOR_OR_EFFECT_PROOF',nestedCallback:owners.get(a)!==module.fn});
    }
    if(!rb)continue;
    for(const c of childrenOf(module.fn).filter(call)) {
      exportItems(c,module,rb);
      if(binding(c.callee)!==rb)continue;
      const resolved=c.arguments.length===1?constant(c.arguments[0]):null;
      const targets=resolved&&module.item.loaderKey?context.modules.filter(m=>m.loaderKey===module.item.loaderKey&&String(m.moduleId)===String(resolved.value)):[];
      context.imports.push({from:module.item.moduleKey,requestedModuleId:resolved?.value??null,argumentResolution:resolved,status:resolved?'LITERAL_REQUIRE_CANDIDATE':'DYNAMIC_REQUIRE_UNRESOLVED',range:range(c),nestedCallback:owners.get(c)!==module.fn,targets:targets.map(t=>t.moduleKey),targetIdentity:targets.length===1?'UNIQUE_IN_STORED_REGISTRIES_UNDER_FRESH_CONTEXT':'UNKNOWN_OR_MULTIPLE',requiresFactoryExecution:true,normalCompletion:'UNPROVEN'});
    }
  }
                                                                        
  const entryScopes=loaderInternals.map(l=>({root:owners.get(parents.get(l.fn))||root,binding:l.fb,loader:l.fact,runtime:false}));
  for(const c of chunkInternals)if(c.runtime&&c.fact.loaderKey&&c.runtime.params[0]) {
    const l=context.loaders.find(x=>x.loaderKey===c.fact.loaderKey),rb=binding(c.runtime.params[0]);
    if(rb)entryScopes.push({root:c.runtime,binding:rb,loader:l,runtime:true,chunk:c.fact});
    else unresolved('RUNTIME_LOADER_PARAMETER_UNRESOLVED',c.runtime,'No unbound call is interpreted as require.');
  }
  const seenEntry=new Set(),moduleFunctions=new Set(moduleInternals.map(m=>m.fn));
  for(const scope of entryScopes)for(const c of childrenOf(scope.root).filter(call)) {
    if(binding(c.callee)!==scope.binding||ancestor(c,p=>moduleFunctions.has(p)))continue;
    const k=`${scope.loader.loaderKey}:${nodeId(c)}`;if(seenEntry.has(k))continue;seenEntry.add(k);
    const arg=c.arguments.length===1?constant(c.arguments[0]):null;
    const enclosingFn=owners.get(c),schedulerCall=ancestor(enclosingFn,p=>call(p)&&member(p.callee)&&binding(p.callee.object)===scope.binding&&prop(p.callee)===scope.loader.scheduler?.property);
    const dependencyArray=schedulerCall?.arguments[1];
    context.entryCandidates.push({entryKey:k,loaderKey:scope.loader.loaderKey,moduleId:arg?.value??null,argumentResolution:arg,range:range(c),callbackRange:isFn(enclosingFn)?range(enclosingFn):null,schedulerRegistrationRange:range(schedulerCall),dependencies:dependencyArray?.type==='ArrayExpression'?dependencyArray.elements.map(literal):null,chunkKey:scope.chunk?.chunkKey??null,status:arg?'EXACT_CALL_CANDIDATE_UNDER_ASSUMPTIONS':'DYNAMIC_ENTRY_UNRESOLVED',freshQueue:'ASSUMED_NO_EFFECT_OR_COMPLETION_PROOF',existingQueue:'UNKNOWN',executionObserved:false,completionProved:false});
  }
  for(const loader of context.loaders) {
    loader.guardKeys=context.guards.filter(g=>inNode(loaderInternals.find(l=>l.fact===loader).fn,g.node.alternate)).map(g=>g.guardKey);
    if(!loader.queueKey)unresolved('QUEUE_BOOTSTRAP_NOT_RECOGNIZED',null,{loaderKey:loader.loaderKey});
    if(!loader.scheduler)unresolved('SCHEDULER_NOT_RECOGNIZED',null,{loaderKey:loader.loaderKey});
  }
  for(const g of context.guards)delete g.node;
  context.guard=context.guards.length===1?context.guards[0]:null;
  context.entry=context.entryCandidates.length===1?context.entryCandidates[0]:null;
  context.chunkPredicates=context.loaders.flatMap(l=>(l.scheduler?.predicates||[]).map(p=>({loaderKey:l.loaderKey,...p})));
  context.statistics={astNodes:nodes.length,lexicalScopes:scopes.length,guards:context.guards.length,loaders:context.loaders.length,chunks:context.chunks.length,modules:context.modules.length,imports:context.imports.length,exports:context.exports.length,entries:context.entryCandidates.length};
  return context;
}

module.exports = {analyzeBundle};
