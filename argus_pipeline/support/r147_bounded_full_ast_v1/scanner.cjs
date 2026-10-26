'use strict';
                                                                                               
const fs=require('fs'),crypto=require('crypto');
const deps=require('../r136_module_dependency_recovery_v1/deps.cjs');
const parser=deps.load('@babel/parser'),keys=deps.load('@babel/types').VISITOR_KEYS;
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
function inspectAST(ast){
 let nodes=0,signalCount=0,maxDepth=0;const signals=[];
 function frame(node){
  if(!node||typeof node.type!=='string'||!Object.prototype.hasOwnProperty.call(keys,node.type))throw Error('UNKNOWN_AST_NODE:'+String(node?.type));
  nodes++;
  if(/^Import|^Export/.test(node.type)||node.type==='MetaProperty'&&node.meta?.name==='import'||node.type==='CallExpression'&&node.callee?.type==='Import'){
   signalCount++;if(signals.length<20)signals.push({type:node.type,line:node.loc?.start.line});
  }
  return {node,fields:keys[node.type],keyIndex:0,arrayIndex:0};
 }
 const stack=[frame(ast)];
                                                                          
 while(stack.length){
  maxDepth=Math.max(maxDepth,stack.length);const f=stack[stack.length-1];
  if(f.keyIndex>=f.fields.length){stack.pop();continue;}
  const child=f.node[f.fields[f.keyIndex]];
  if(Array.isArray(child)){
   if(f.arrayIndex>=child.length){f.keyIndex++;f.arrayIndex=0;continue;}
   const n=child[f.arrayIndex++];if(n!==null&&n!==undefined)stack.push(frame(n));
  }else{f.keyIndex++;f.arrayIndex=0;if(child!==null&&child!==undefined)stack.push(frame(child));}
 }
 return {nodes,signals,signal_count:signalCount,max_traversal_depth:maxDepth,full_ast_scanned:true,status:signalCount?'HELD_MODULE_CONTEXT':'SCRIPT_STATIC_ADMITTED',reason:signalCount?'MODULE_SYNTAX_FOUND':null};
}
function inspectSource(body,expected){
 if(digest(body)!==expected)throw Error('INPUT_HASH_MISMATCH');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(body);
 const ast=parser.parse(text,{sourceType:'unambiguous',allowReturnOutsideFunction:false,createImportExpressions:true,errorRecovery:false});
 return inspectAST(ast);
}
module.exports={inspectAST,inspectSource};
if(require.main===module){
 const [source,expected,output]=process.argv.slice(2);const started=performance.now();let result;
 try{result=inspectSource(fs.readFileSync(source),expected);if(digest(fs.readFileSync(source))!==expected)throw Error('INPUT_CHANGED_DURING_SCAN');}
 catch(e){result={status:'HELD_PARSE_OR_RESOURCE',reason:String(e.message),full_ast_scanned:false};}
 const record={...result,input_sha256:expected,source_bytes:fs.statSync(source).size,seconds:(performance.now()-started)/1000,peak_rss_kib:process.resourceUsage().maxRSS,dependencies:deps.pins,source_js_evaluations:0};
 fs.writeFileSync(output,JSON.stringify(record,null,2),{flag:'wx'});
}
