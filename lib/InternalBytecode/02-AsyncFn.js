/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

function initAsyncFn() {
  var P = internalBytecodeResult.promiseOperations;
  var apply = Function.prototype.call.bind(Function.prototype.apply);
  var getPrototypeOf = Object.getPrototypeOf;
  var generatorPrototype = getPrototypeOf(getPrototypeOf((function* () {})()));
  var next = generatorPrototype.next;
  var throwInto = generatorPrototype.throw;

                                             
                                                                       
                          
                                                                                
                                       
                                                            
  function spawn(genF, self, args) {
    return P.create(function (resolve, reject) {
      var gen = apply(genF, self, args);
      function step(nextF) {
        var outcome;
        try {
          outcome = nextF();
        } catch (e) {
                                                      
          reject(e);
          return;
        }
        if (outcome.done) {
                                                       
          resolve(outcome.value);
          return;
        }
                                                                       
        var awaited;
        try {
          awaited = P.resolve(outcome.value);
        } catch (e) {
          step(function () { return apply(throwInto, gen, [e]); });
          return;
        }
        P.then(awaited,
          function (v) {
            step(function () {
              return apply(next, gen, [v]);
            });
          },
          function (e) {
            step(function () {
              return apply(throwInto, gen, [e]);
            });
          }
        );
      }
      step(function () {
        return apply(next, gen, [undefined]);
      });
    });
  }

                              
  internalBytecodeResult.spawnAsync = spawn;
}

                                                      
if (HermesInternal?.hasPromise?.()) {
  initAsyncFn();
} else {
                                                               
                                                       
  internalBytecodeResult.spawnAsync = function (){
    throw Error("async function cannot be used with Promise disabled. spawnAsync not registered.");
  };
}

                                                                            
                                                                               
function initAsyncIteration() {
  var P = internalBytecodeResult.promiseOperations;
  var apply = Function.prototype.call.bind(Function.prototype.apply);
  var TypeErrorCtor = TypeError;
  var iteratorSymbol = Symbol.iterator;
  var asyncIteratorSymbol = Symbol.asyncIterator;
  function object(value) {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function'))
      throw new TypeErrorCtor('iterator result is not an object');
    return value;
  }
  function method(value, key) {
    var m = value[key];
    if (m === undefined || m === null) return undefined;
    if (typeof m !== 'function') throw new TypeErrorCtor('iterator method is not callable');
    return m;
  }
  function get(value) {
    var m = method(value, asyncIteratorSymbol);
    var sync = m === undefined;
    if (sync) m = method(value, iteratorSymbol);
    if (m === undefined) throw new TypeErrorCtor('value is not iterable');
    var iterator = object(apply(m, value, []));
                                                                              
    return {iterator: iterator, next: iterator.next, sync: sync};
  }
  function fromSync(result) {
    object(result);
    var done = !!result.done;
    var value = result.value;
    return P.then(P.resolve(value), function (v) {
      return {value: v, done: done};
    }, undefined);
  }
  function next(record) {
    var result = apply(record.next, record.iterator, []);
    return record.sync ? fromSync(result) : result;
  }
  function close(record, isThrow) {
                                                                               
                                                                               
                                                                                
    try {
      var m = method(record.iterator, 'return');
      if (m === undefined) return undefined;
      var result = apply(m, record.iterator, []);
      if (record.sync) result = fromSync(result);
      return P.then(P.resolve(result), function (r) {
        if (!isThrow) object(r);
      }, function (e) {
        if (!isThrow) throw e;
      });
    } catch (e) {
      if (!isThrow) throw e;
    }
  }
  internalBytecodeResult.asyncIterator = get;
  internalBytecodeResult.asyncIteratorNext = next;
  internalBytecodeResult.asyncIteratorClose = close;
}
if (HermesInternal?.hasPromise?.()) {
  initAsyncIteration();
} else {
  internalBytecodeResult.asyncIterator = internalBytecodeResult.spawnAsync;
  internalBytecodeResult.asyncIteratorNext = internalBytecodeResult.spawnAsync;
  internalBytecodeResult.asyncIteratorClose = internalBytecodeResult.spawnAsync;
}
