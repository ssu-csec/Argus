function createAsyncGeneratorRuntime(P, prototype) {
  var apply = Function.prototype.call.bind(Function.prototype.apply);
  var getPrototypeOf = Object.getPrototypeOf;
  var create = Object.create;
  var defineProperty = Object.defineProperty;
  var TypeErrorCtor = TypeError;
  var WeakMapCtor = WeakMap;
  var wmGet = WeakMapCtor.prototype.get;
  var wmSet = WeakMapCtor.prototype.set;
  var records = new WeakMapCtor();
  var awaitTokens = new WeakMapCtor();
  var delegateTokens = new WeakMapCtor();
  var asyncIteratorSymbol = Symbol.asyncIterator;
  var iteratorSymbol = Symbol.iterator;
  var genProto = getPrototypeOf(getPrototypeOf((function* () {})()));
  var genNext = genProto.next;
  var genThrow = genProto.throw;
  var genReturn = genProto.return;

  function awaitValue(value) {
    var token = create(null);
    apply(wmSet, awaitTokens, [token, {value: value}]);
    return token;
  }

                                                                          
                                                                              
  function delegateValue(value) {
    var token = create(null);
    apply(wmSet, delegateTokens, [token, {value: value}]);
    return token;
  }
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
  function beginDelegate(record, value) {
    try {
      var m = method(value, asyncIteratorSymbol), sync = m === undefined;
      if (sync) m = method(value, iteratorSymbol);
      if (m === undefined) throw new TypeErrorCtor('value is not iterable');
      var iterator = object(apply(m, value, []));
      record.delegate = {iterator: iterator, next: iterator.next, sync: sync};
    } catch (e) { resume(record, 'throw', e); return; }
    delegateResume(record, 'next', undefined);
  }
  function delegateResume(record, kind, value) {
    var d = record.delegate;
    function fail(e) { record.delegate = null; resume(record, 'throw', e); }
    function finish(result) {
      try {
        object(result);
        var done = !!result.done, v = result.value;
        if (done) {
          record.delegate = null;
          resume(record, kind === 'return' ? 'return' : 'next', v);
        } else {
                                                                        
                                                                       
          complete(record, true, v, false);
        }
      } catch (e) { fail(e); }
    }
    function receive(result) {
      if (!d.sync) { awaitThen(result, finish, fail); return; }
      try {
        object(result); var done = !!result.done, v = result.value;
                                                                             
                                                                              
        awaitThen(v, function (v) {
          awaitThen({value:v,done:done}, finish, fail);
        }, fail);
      } catch (e) { fail(e); }
    }
    try {
      var m = kind === 'next' ? d.next : method(d.iterator, kind);
      if (m === undefined && kind === 'return') {
        record.delegate = null; resume(record, 'return', value); return;
      }
      if (m === undefined && kind === 'throw') {
        var close = method(d.iterator, 'return');
        if (close === undefined) { fail(new TypeErrorCtor('delegate has no throw')); return; }
        var closeResult = apply(close, d.iterator, []);
        if (d.sync) {
                                                                             
                                                                   
          object(closeResult);
          awaitThen(undefined, function () { fail(new TypeErrorCtor('delegate has no throw')); }, fail);
          return;
        }
        awaitThen(closeResult, function (r) {
          try { object(r); fail(new TypeErrorCtor('delegate has no throw')); }
          catch (e) { fail(e); }
        }, fail);
        return;
      }
      receive(apply(m, d.iterator, [value]));
    } catch (e) { fail(e); }
  }

  function complete(record, fulfilled, value, done) {
    var request = record.head;
    record.head = request.next;
    if (!record.head) record.tail = null;
    record.state = done ? 'done' : 'yield';
    if (done) record.generator = null;
    if (fulfilled) request.resolve({value: value, done: done});
    else request.reject(value);
    drain(record);
  }

  function awaitThen(value, fulfilled, rejected) {
    var promise;
    try { promise = P.resolve(value); }
    catch (error) { rejected(error); return; }
    P.then(promise, fulfilled, rejected);
  }

  function resume(record, kind, value) {
    if (record.delegate) { delegateResume(record, kind, value); return; }
    var result;
    try {
      var method = kind === 'next' ? genNext : kind === 'throw' ? genThrow : genReturn;
      result = apply(method, record.generator, [value]);
    } catch (error) {
      complete(record, false, error, true);
      return;
    }
    if (result.done) {
                                                                          
                                                                            
      complete(record, true, result.value, true);
      return;
    }
    var token = apply(wmGet, awaitTokens, [result.value]);
    if (token) {
      awaitThen(token.value,
        function (value) { resume(record, 'next', value); },
        function (error) { resume(record, 'throw', error); });
      return;
    }
    var delegated = apply(wmGet, delegateTokens, [result.value]);
    if (delegated) { beginDelegate(record, delegated.value); return; }
                                                                           
    complete(record, true, result.value, false);
  }

  function drain(record) {
    if (record.draining) return;
    record.draining = true;
    while (record.head && record.state !== 'executing' && record.state !== 'awaiting-return') {
      var request = record.head;
      if (record.state === 'done' || (record.state === 'start' && request.kind !== 'next')) {
        if (request.kind === 'return') {
          record.state = 'awaiting-return';
          awaitThen(request.value,
            function (value) { complete(record, true, value, true); },
            function (error) { complete(record, false, error, true); });
        } else {
          complete(record, request.kind !== 'throw', request.kind === 'throw' ? request.value : undefined, true);
        }
      } else {
        record.state = 'executing';
        if (request.kind === 'return') {
                                                                         
                                                                             
          awaitThen(request.value,
            function (value) { resume(record, 'return', value); },
            function (error) { resume(record, 'throw', error); });
        } else resume(record, request.kind, request.value);
      }
    }
    record.draining = false;
  }

  function enqueue(receiver, kind, value) {
    return P.create(function (resolve, reject) {
      var record = apply(wmGet, records, [receiver]);
      if (!record) { reject(new TypeErrorCtor('incompatible AsyncGenerator receiver')); return; }
      var request = {kind: kind, value: value, resolve: resolve, reject: reject, next: null};
      if (record.tail) record.tail.next = request;
      else record.head = request;
      record.tail = request;
      drain(record);
    });
  }
  function next(value) { return enqueue(this, 'next', value); }
  function returnMethod(value) { return enqueue(this, 'return', value); }
  function throwMethod(value) { return enqueue(this, 'throw', value); }
  defineProperty(returnMethod, 'name', {value: 'return', configurable: true});
  defineProperty(throwMethod, 'name', {value: 'throw', configurable: true});

  function wrap(generator, instancePrototype) {
    var result = create(instancePrototype === undefined ? getPrototypeOf(generator) : instancePrototype);
    apply(wmSet, records, [result, {generator: generator, state: 'start', head: null, tail: null, draining: false}]);
    return result;
  }
  function start(generator) { return apply(genNext, generator, []); }
  return {start: start, wrap: wrap, awaitValue: awaitValue, delegateValue: delegateValue, next: next, returnMethod: returnMethod, throwMethod: throwMethod};
}

var asyncGeneratorRuntime = createAsyncGeneratorRuntime(internalBytecodeResult.promiseOperations);
internalBytecodeResult.asyncGeneratorWrap = asyncGeneratorRuntime.wrap;
internalBytecodeResult.asyncGeneratorStart = asyncGeneratorRuntime.start;
internalBytecodeResult.asyncGeneratorAwait = asyncGeneratorRuntime.awaitValue;
internalBytecodeResult.asyncGeneratorDelegate = asyncGeneratorRuntime.delegateValue;
internalBytecodeResult.asyncGeneratorNext = asyncGeneratorRuntime.next;
internalBytecodeResult.asyncGeneratorReturn = asyncGeneratorRuntime.returnMethod;
internalBytecodeResult.asyncGeneratorThrow = asyncGeneratorRuntime.throwMethod;
