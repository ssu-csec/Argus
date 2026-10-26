                                                                               
                                                                          
                                                                                 
   
function createDynamicModuleRuntime(P) {
  var apply = Function.prototype.call.bind(Function.prototype.apply);
  var create = Object.create, define = Object.defineProperty;
  var own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
  var prevent = Object.preventExtensions, keys = Object.keys;
  var getDesc = Object.getOwnPropertyDescriptor, freeze = Object.freeze;
  var ProxyCtor = Proxy, TypeErrorCtor = TypeError, ReferenceErrorCtor = ReferenceError;
  var tag = Symbol.toStringTag;
  var min = Math.min;
  var slice = Function.prototype.call.bind(Array.prototype.slice);
  var sort = Function.prototype.call.bind(Array.prototype.sort);
  var push = Function.prototype.call.bind(Array.prototype.push);
  var pop = Function.prototype.call.bind(Array.prototype.pop);
  var next = Object.getPrototypeOf(Object.getPrototypeOf((function*(){})())).next;
  function graph(descriptors) {
    var records = create(null), stack = [], serial = 0;
    for (var i = 0; i < descriptors.length; ++i) {
      var d = descriptors[i];
      if (own(records,d.id)) throw new TypeErrorCtor('Duplicate module');
      records[d.id] = {d:d,state:0,getters:create(null),namespace:null,iterator:null,error:undefined,index:0,low:0};
    }
    function record(id) {
      if (!own(records,id)) throw new TypeErrorCtor('Missing stored module: '+id);
      return records[id];
    }
    function value(r,k) {
      if (!own(r.getters,k)) throw new ReferenceErrorCtor('Export not instantiated: '+k);
      return apply(r.getters[k],undefined,[]);
    }
    function namespace(r) {
      if (r.namespace) return r.namespace;
      var target=create(null), names=sort(slice(r.d.exports));
      for(var i=0;i<names.length;++i)define(target,names[i],{value:undefined,writable:true,enumerable:true,configurable:false});
      define(target,tag,{value:'Module',writable:false,enumerable:false,configurable:false});
      prevent(target);
      r.namespace=new ProxyCtor(target,{
        ownKeys:function(){var list=slice(names);push(list,tag);return list;},
        get:function(t,k){return typeof k==='string'&&own(t,k)?value(r,k):t[k];},
        getOwnPropertyDescriptor:function(t,k){
          if(typeof k==='string'&&own(t,k))return {value:value(r,k),writable:true,enumerable:true,configurable:false};
          return getDesc(t,k);
        },
        set:function(){return false;},
        deleteProperty:function(t,k){return !own(t,k);},
        defineProperty:function(t,k,d){
          var old=getDesc(t,k);if(!old)return false;
          if(typeof k!=='string')return (!own(d,'value')||d.value===old.value)&&!d.configurable&&!d.writable&&!d.enumerable&&!own(d,'get')&&!own(d,'set');
          if(d.configurable===true||d.enumerable===false||d.writable===false||own(d,'get')||own(d,'set'))return false;
          var v=value(r,k);return !own(d,'value')||(d.value===v&&(v!==0||1/d.value===1/v))||(d.value!==d.value&&v!==v);
        },
        setPrototypeOf:function(t,p){return p===null;}
      });
      return r.namespace;
    }
    function instantiate(r) {
      if(r.state===5)throw r.error;
      if(r.state!==0)return;
      r.state=1;
      var context=freeze({
        bind:function(k,getter){
          var found=false;for(var i=0;i<r.d.exports.length;++i)if(r.d.exports[i]===k)found=true;
          if(r.state!==1||!found||own(r.getters,k))throw new TypeErrorCtor('Invalid export binding');
          r.getters[k]=getter;
        },
        read:function(id,k){return value(record(id),k);},
        namespace:function(id){return namespace(record(id));},
        import:function(id){return dynamicImport(id);}
      });
      try {
        r.iterator=apply(r.d.factory,undefined,[context]);
        var first=apply(next,r.iterator,[]);
        if(first.done)throw new TypeErrorCtor('Missing instantiation suspension');
        if(keys(r.getters).length!==r.d.exports.length)throw new TypeErrorCtor('Missing export binding');
        for(var i=0;i<r.d.deps.length;++i)instantiate(record(r.d.deps[i]));
        r.state=2;
      }catch(e){r.state=5;r.error=e;throw e;}
    }
    function visit(r) {
      if(r.state===5)throw r.error;
      if(r.state===4||r.state===3)return;
      r.state=3;r.index=r.low=serial++;push(stack,r);
      for(var i=0;i<r.d.deps.length;++i){
        var dep=record(r.d.deps[i]);visit(dep);
        if(dep.state===3)r.low=min(r.low,dep.low);
      }
      var result=apply(next,r.iterator,[]);
      if(!result.done)throw new TypeErrorCtor('Unexpected module suspension');
      if(r.low===r.index){var item;do{item=pop(stack);item.state=4;}while(item!==r);}
    }
    function evaluate(id) {
      var r=record(id);instantiate(r);
      try{visit(r);}catch(e){
                                                                               
        while(stack.length){var item=pop(stack);item.state=5;item.error=e;}
        throw e;
      }
      return namespace(r);
    }
    function dynamicImport(id) {
                                                                                 
      return P.then(P.resolve(undefined),function(){return evaluate(id);});
    }
    return freeze({start:evaluate,import:dynamicImport,namespace:function(id){return namespace(record(id));}});
  }
  return graph;
}
internalBytecodeResult.dynamicModuleGraph=createDynamicModuleRuntime(internalBytecodeResult.promiseOperations);
