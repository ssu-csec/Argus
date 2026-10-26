'use strict';
const crypto=require('node:crypto');
                                                                                   
function traceContext(result) {
  const c=result.bundle, contains=(a,b)=>a&&b&&a.start<=b.start&&b.end<=a.end;
  const guards=c.guards.filter(g=>g.statusProperty==='libLoaded'&&g.base==='ambient:window["pbjs"]');
  function pathTo(module) {
    if(!module?.loaderKey)return null;
    for(const entry of c.entryCandidates.filter(x=>x.loaderKey===module.loaderKey&&x.moduleId!==null)) {
      const roots=c.modules.filter(m=>m.loaderKey===entry.loaderKey&&String(m.moduleId)===String(entry.moduleId));if(roots.length!==1)continue;
      const todo=[{key:roots[0].moduleKey,edges:[]}],seen=new Set();
      while(todo.length){const p=todo.shift();if(p.key===module.moduleKey)return {entry,edges:p.edges};if(seen.has(p.key))continue;seen.add(p.key);
        for(const e of c.imports.filter(x=>x.from===p.key&&!x.nestedCallback&&x.targets.length===1))todo.push({key:e.targets[0],edges:[...p.edges,e]});}
    }
    return null;
  }
  const flows=result.cookie.flows.map(f=> {
    const module=c.modules.find(m=>contains(m.factoryRange,f.source.range)),entryPath=pathTo(module);
    const enclosingGuards=guards.filter(g=>contains(g.elseRange,f.source.range)&&contains(g.elseRange,f.sink.range));
    const wrapper=result.callbacks.records.find(r=>contains(r.callback,f.source.range));
    const defaults=f.conditions.filter(x=>x.code==='PARAMETER_DEFAULT_USED'&&wrapper&&contains(wrapper.callback,x.range));
    const compatibleCallers=(wrapper?.callers||[]).filter(call=>!call.arguments.some(a=>a.state==='SPREAD_UNRESOLVED')&&defaults.every(d=>!call.arguments[d.detail.parameterIndex]||call.arguments[d.detail.parameterIndex].state==='UNDEFINED'));
    const unresolvedCallers=(wrapper?.callers||[]).filter(call=>!compatibleCallers.includes(call));
    const callbackLinked=compatibleCallers.length>0;
    const status=module&&!entryPath?'DORMANT_LOCAL_DATAFLOW':(wrapper||module&&f.source.enclosingFunction)&&!callbackLinked?'CONDITIONAL_LOCAL_DATAFLOW_UNLINKED_CALLBACK':'CONDITIONAL_MAY_FLOW';
    const assumptions=[...f.conditions,
      {kind:'NORMAL_COMPLETION_NO_RELEVANT_MUTATION',detail:'All preceding required operations and exact callee/receiver bindings retain the stated semantics.'},
      ...enclosingGuards.map(g=>({kind:'PBJS_ELSE_PREDICATE',guardKey:g.guardKey,detail:'first window.pbjs read falsy OR first read truthy and separate second pbjs/libLoaded read normally yields falsy'})),
      ...(entryPath?[{kind:'FRESH_KNOWN_LOADER_CONTEXT',detail:'Pristine matched loader ABI, compatible fresh chunk state, known factories/dependencies and preceding normal completion; historical state not observed.'}]:[]),
      ...(wrapper?[{kind:'WRAPPER_CALLER_AND_CACHE_BRANCH',detail:'One recorded lexical caller invokes the returned wrapper and its callback-dispatch branch is taken; invocation and cache state remain unobserved.'}]:[])];
    const variant=crypto.createHash('sha256').update(JSON.stringify(f.conditions)).digest('hex').slice(0,16);
    return {...f,id:f.id+':variant:'+variant,semanticPathKey:f.id,status,localStatus:f.status,context:{module:module||null,entryPath,guardKeys:enclosingGuards.map(g=>g.guardKey),callbackWrapper:wrapper||null,compatibleCallers,unresolvedCallers,defaultCompatibility:'Only omitted/lexically undefined arguments join a default receiver; other supplied values remain separate.',callbackInvocationLinked:callbackLinked,executionObserved:false,fullProgramReachabilityProved:false},assumptions,quantitativeCountEligible:false};
  });
  const scenarios=guards.map(g=>({guardKey:g.guardKey,interpretation:'Explicit hypothetical condition, not evaluation of historical browser state',
    loaded:{predicate:'first read truthy, second read/libLoaded normal and truthy',else:'NOT_REACHED',eligibleElseFlowIds:[]},
    initialize:{predicate:'first read normal/falsy OR second status normal/falsy after truthy first read',else:'CALL_ATTEMPT_IF_PREFIX_COMPLETES',eligibleElseFlowIds:flows.filter(f=>f.context.guardKeys.includes(g.guardKey)).map(f=>f.id),allOtherAssumptionsStillRequired:true},
    effects:{predicate:'getter/proxy/throw or binding identity unresolved',state:'UNKNOWN_OR_ABRUPT',assumedPure:false}}));
  const grouped=new Map();for(const f of flows){const k=JSON.stringify([f.source.id,f.sink.id,f.field]);if(!grouped.has(k))grouped.set(k,{source:f.source,sink:f.sink,field:f.field,pathIds:[],statuses:[]});const g=grouped.get(k);g.pathIds.push(f.id);if(!g.statuses.includes(f.status))g.statuses.push(f.status);}
  return {schema:'pbjs-conditional-trace-v1',status:'CONDITIONAL_STATIC_TRACE',flows,uniqueSourceSinkFieldObservations:[...grouped.values()],scenarios,
    invariants:{nativeProofUnchanged:true,runtimeExecutionObserved:false,unconditionalPrivateRecoveryCount:0,unconditionalReachedFlowCount:0,prevalenceCountEligible:false},
    unresolved:result.cookie.unresolvedConditions,siteToPublicApiDispatch:'UNRESOLVED; site API call candidates are separate until realm, installation and dispatch are established'};
}
module.exports={traceContext};
