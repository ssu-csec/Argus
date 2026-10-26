'use strict';
const crypto=require('node:crypto');
const {requireBabel,dependencyVersion,loadedDependencyPins}=require('./deps.cjs');
const parser=requireBabel('@babel/parser');
const {analyzeBundle}=require('./bundle_context.cjs');
const {analyzeCookieFlows}=require('./cookie_flow.cjs');
const {analyzeSiteContext}=require('./site_context.cjs');
const {analyzeCallbackLinks}=require('./callback_links.cjs');
const {traceContext}=require('./trace_context.cjs');
const {attachPathConditions}=require('./path_conditions.cjs');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const LIMITS={inputBytes:4*1024*1024,outputBytes:32*1024*1024,astNodes:250000,flowRecords:4096};
function analyzeSource(bytes,sourceId) {
  if(bytes.length>LIMITS.inputBytes)throw Error('INPUT_SIZE_LIMIT');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),sourceHash=hash(bytes);
  if(!Buffer.from(text,'utf8').equals(bytes))throw Error('INPUT_ENCODING_ROUNDTRIP');
  const ast=parser.parse(text,{sourceType:'unambiguous',sourceFilename:sourceId,errorRecovery:false});
  const todo=[ast];let count=0;
  while(todo.length){const n=todo.pop();if(++count>LIMITS.astNodes)throw Error('AST_NODE_LIMIT');for(const [k,v]of Object.entries(n)){if(['loc','extra','comments','tokens','errors'].includes(k))continue;if(Array.isArray(v)){for(const c of v)if(c&&typeof c.type==='string')todo.push(c);}else if(v&&typeof v.type==='string')todo.push(v);}}
  const options={sourceId,sourceHash,sourceText:text};
  const bundle=analyzeBundle(ast,options),cookie=analyzeCookieFlows(ast,options),site=analyzeSiteContext(ast,options);
  const callbacks=analyzeCallbackLinks(ast,bundle,cookie,options);
  const result={schemaVersion:1,status:'CONDITIONAL_STATIC_ANALYSIS',sourceId,sourceHash,bytes:bytes.length,astNodes:count,parser:{package:'@babel/parser',version:dependencyVersion('@babel/parser'),sourceType:ast.program.sourceType},bundle,cookie,site,callbacks,
    semantics:{runtimeObserved:false,sourceJavaScriptExecutions:0,nativeProofUpdated:false,unconditionalReachedPairs:0,prevalenceCountEligible:false,readiness:'CANDIDATE_STATIC_PASS',limitations:['Conditional local dataflow is distinct from observed execution and from the existing native exact PROVED contract.','Chunk, module and callback registration is not an execution fact.','Unsupported receiver identity and control effects are retained as unresolved boundaries.']}};
  attachPathConditions(ast,result,text);result.trace=traceContext(result);
  result.flowRecordCounts={cookiePaths:result.cookie.flows.length,tracePaths:result.trace.flows.length,uniqueObservations:result.trace.uniqueSourceSinkFieldObservations.length};
  result.flowRecordCounts.total=Object.values(result.flowRecordCounts).reduce((a,b)=>a+b,0);
  if(result.flowRecordCounts.total>LIMITS.flowRecords)throw Object.assign(Error('FLOW_RECORD_LIMIT'),{code:'FLOW_RECORD_LIMIT',flowRecordCounts:result.flowRecordCounts});
  return result;
}
module.exports={analyzeSource,loadedDependencyPins,LIMITS,hash};
