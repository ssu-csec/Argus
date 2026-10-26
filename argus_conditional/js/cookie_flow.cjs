'use strict';

                                                                                  
                                                                           
                                                                        
function analyzeCookieFlows(ast, options = {}) {
  const sourceId = String(options.sourceId || 'unknown-source');
  const sourceHash = String(options.sourceHash || 'unknown-hash');
  const LIMIT = { nodes: 400000, depth: 48, variants: 32, segments: 256, factory: 20 };
  const nodeScope = new WeakMap(), nodeFunction = new WeakMap(), parents = new WeakMap();
  const functionInfo = new WeakMap(), nodeIds = new WeakMap(), scopes = [], bindings = [], nodes = [], functions = [];
  const unresolved = [], sourceNodes = new WeakMap(), sources = [], assignments = [], calls = [];
  let nodeCounter = 0, stopped = false;
  const fnTypes = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'ClassPrivateMethod']);
  const isFn = n => n && fnTypes.has(n.type);
  const children = n => Object.entries(n).flatMap(([k, v]) => {
    if (['loc', 'extra', 'tokens', 'comments', 'leadingComments', 'trailingComments', 'innerComments'].includes(k)) return [];
    if (Array.isArray(v)) return v.filter(x => x && typeof x.type === 'string').map(x => [k, x]);
    return v && typeof v.type === 'string' ? [[k, v]] : [];
  });
  function span(n) {
    if (!n) return null;
    return { start: Number.isInteger(n.start) ? n.start : null, end: Number.isInteger(n.end) ? n.end : null,
      loc: n.loc ? { start: { line: n.loc.start.line, column: n.loc.start.column }, end: { line: n.loc.end.line, column: n.loc.end.column } } : null };
  }
  function id(n) {
    if (!nodeIds.has(n)) nodeIds.set(n, `${sourceId}:${sourceHash}:${n.start ?? 'n'}:${n.end ?? ++nodeCounter}:${n.type}`);
    return nodeIds.get(n);
  }
  function scope(parent, kind, fn) { const s = { id: `S${scopes.length}`, parent, kind, fn, bindings: new Map() }; scopes.push(s); return s; }
  function varScope(s) { while (s.parent && !['program', 'functionBody'].includes(s.kind)) s = s.parent; return s; }
  function bind(name, s, definition) {
    let b = s.bindings.get(name);
    if (!b) { b = { id: `B${bindings.length}`, name, scope: s, definitions: [], writes: [], propertyWrites: [] }; bindings.push(b); s.bindings.set(name, b); }
    b.definitions.push(definition); return b;
  }
  function bindPattern(p, s, def, path = []) {
    if (!p) return;
    if (p.type === 'Identifier') bind(p.name, s, { ...def, path });
    else if (p.type === 'AssignmentPattern') bindPattern(p.left, s, { ...def, defaultValue: p.right }, path);
    else if (p.type === 'RestElement') bindPattern(p.argument, s, { ...def, unsupportedPattern: true }, path);
    else if (p.type === 'ObjectPattern') for (const q of p.properties) {
      if (q.type === 'ObjectProperty' && !q.computed) bindPattern(q.value, s, def, path.concat(q.key.name ?? q.key.value));
      else if (q.type === 'RestElement') bindPattern(q.argument, s, { ...def, unsupportedPattern: true }, path);
    }
    else if (p.type === 'ArrayPattern') p.elements.forEach((q, i) => bindPattern(q, s, def, path.concat(i)));
  }
  function visit(n, s, fn, parent = null, key = '') {
    if (!n || stopped) return;
    if (nodes.length >= LIMIT.nodes) { stopped = true; return; }
    nodes.push(n); id(n); nodeScope.set(n, s); nodeFunction.set(n, fn); if (parent) parents.set(n, { node: parent, key });
    if (isFn(n)) {
      if (n.type === 'FunctionDeclaration' && n.id) bind(n.id.name, s, { kind: 'function', node: n });
      const f = { id: id(n), node: n, parent: fn, context: parent ? { parentType: parent.type, key } : null };
      functions.push(f); functionInfo.set(n, f);
      const ps = scope(s, 'parameters', f);
      if (n.type === 'FunctionExpression' && n.id) bind(n.id.name, ps, { kind: 'function', node: n });
      n.params.forEach((p, index) => bindPattern(p, ps, { kind: 'parameter', function: f, parameterIndex: index, node: p }));
      for (const p of n.params) visit(p, ps, f, n, 'params');
      if (n.computed && n.key) visit(n.key, s, fn, n, 'key');
      const bs = scope(ps, 'functionBody', f);
      if (n.body.type === 'BlockStatement') {
        nodeScope.set(n.body, bs); nodeFunction.set(n.body, f); parents.set(n.body, { node: n, key: 'body' });
        for (const st of n.body.body) visit(st, bs, f, n.body, 'body');
      } else visit(n.body, bs, f, n, 'body');
      return;
    }
    if (n.type === 'BlockStatement') {
      const bs = scope(s, 'block', fn); nodeScope.set(n, bs);
      for (const st of n.body) visit(st, bs, fn, n, 'body'); return;
    }
    if (n.type === 'CatchClause') {
      const cs = scope(s, 'catch', fn); if (n.param) bindPattern(n.param, cs, { kind: 'catch', node: n.param });
      if (n.param) visit(n.param, cs, fn, n, 'param'); visit(n.body, cs, fn, n, 'body'); return;
    }
    if (n.type === 'ClassDeclaration' && n.id) bind(n.id.name, s, { kind: 'class', node: n });
    if (n.type === 'VariableDeclaration') for (const d of n.declarations) bindPattern(d.id, n.kind === 'var' ? varScope(s) : s, { kind: 'variable', node: d, init: d.init });
    if (n.type === 'AssignmentExpression' || n.type === 'UpdateExpression') assignments.push(n);
    if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') calls.push(n);
    for (const [k, c] of children(n)) visit(c, s, fn, n, k);
  }
  const program = ast.type === 'File' ? ast.program : ast;
  visit(program, scope(null, 'program', null), null);
  function lookup(n) {
    if (!n || n.type !== 'Identifier') return null;
    for (let s = nodeScope.get(n); s; s = s.parent) if (s.bindings.has(n.name)) return s.bindings.get(n.name);
    return null;
  }
  function global(n, name) { return n && n.type === 'Identifier' && n.name === name && !lookup(n); }
  function keyName(n) {
    if (!n) return null;
    if (!n.computed && n.property?.type === 'Identifier') return n.property.name;
    if (n.property?.type === 'StringLiteral' || n.property?.type === 'NumericLiteral') return String(n.property.value);
    return null;
  }
  for (const n of assignments) {
    const left = n.left || n.argument;
    if (left?.type === 'Identifier') { const b = lookup(left); if (b) b.writes.push(n); }
    if (left?.type === 'MemberExpression' && left.object.type === 'Identifier') { const b = lookup(left.object); if (b) b.propertyWrites.push(n); }
  }
  function fnSummary(f) { return f ? { id: f.id, range: span(f.node), type: f.node.type, name: f.node.id?.name || f.node.key?.name || null, syntacticContext: f.context, invocation: 'UNPROVEN' } : null; }
  function functionChain(n) { const a = []; for (let f = nodeFunction.get(n); f; f = f.parent) a.push(fnSummary(f)); return a; }
  function condition(code, n, detail) { return { code, range: span(n), ...(detail ? { detail } : {}) }; }
  const uniq = a => [...new Map(a.map(x => [JSON.stringify(x), x])).values()];
  function dateKind(n) {
    if (n.type === 'NewExpression' && global(n.callee, 'Date')) return 'NEW_DATE';
    if (n.type === 'CallExpression' && global(n.callee, 'Date')) return 'DATE_CALL';
    if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && global(n.callee.object, 'Date') && keyName(n.callee) === 'now') return 'DATE_NOW';
    return null;
  }
  for (const n of nodes) {
    const kind = dateKind(n); if (!kind) continue;
    const s = { id: id(n), sourceId, sourceHash, kind, range: span(n), enclosingFunction: fnSummary(nodeFunction.get(n)), enclosingFunctions: functionChain(n) };
    sourceNodes.set(n, s); sources.push(s);
  }
  const pureDateMethods = new Set(['toUTCString', 'toISOString', 'getTime', 'valueOf', 'toString']);
  function dateObjectBinding(b, seen = new Set()) {
    if (!b || seen.has(b) || b.definitions.length !== 1 || b.writes.length) return null;
    const d = b.definitions[0]; if (d.kind !== 'variable' || !d.init || d.path.length) return null;
    if (d.init.type === 'NewExpression' && global(d.init.callee, 'Date')) return b;
    if (d.init.type === 'Identifier') return dateObjectBinding(lookup(d.init), new Set(seen).add(b));
    return null;
  }
  const dateMutationOrEscape = new Map();
  function markDateBoundary(b, node, why) {
    const root = dateObjectBinding(b); if (!root) return;
    if (!dateMutationOrEscape.has(root.id)) dateMutationOrEscape.set(root.id, []);
    dateMutationOrEscape.get(root.id).push(condition(why, node, root.id));
  }
  for (const b of bindings) for (const write of b.propertyWrites) markDateBoundary(b, write, 'DATE_OBJECT_PROPERTY_MUTATION');
  for (const n of nodes) {
    if (n.type !== 'Identifier') continue;
    const b = lookup(n), root = dateObjectBinding(b); if (!root) continue;
    const p = parents.get(n); if (!p) continue;
    if ((p.node.type === 'MemberExpression' || p.node.type === 'OptionalMemberExpression') && p.key === 'object') {
      const use = parents.get(p.node);
      if (use?.node.type === 'CallExpression' && use.key === 'callee' && pureDateMethods.has(keyName(p.node))) continue;
      markDateBoundary(b, p.node, 'DATE_OBJECT_UNKNOWN_MEMBER_OR_MUTATOR');
    } else if ((p.node.type === 'CallExpression' || p.node.type === 'NewExpression') && p.key === 'arguments') {
      if (['String', 'Number'].some(k => global(p.node.callee, k))) continue;
      markDateBoundary(b, p.node, 'DATE_OBJECT_ESCAPE_TO_CALL');
    } else if (['ReturnStatement', 'ObjectProperty', 'ArrayExpression', 'AssignmentExpression', 'SpreadElement'].includes(p.node.type)) {
      markDateBoundary(b, p.node, 'DATE_OBJECT_ESCAPE_OR_ALIAS_WRITE');
    }
  }
  const literal = value => [{ segments: [{ text: String(value) }], conditions: [] }];
  const atom = (deps, conditions = [], safe = false) => [{ segments: [{ deps: uniq(deps), delimiterSafe: safe }], conditions }];
  const unknown = (n, why) => atom([{ kind: 'unknown', nodeId: id(n) }], [condition(why, n)]);
  function depsOf(values) { return uniq(values.flatMap(v => v.segments.flatMap(s => s.deps || []))); }
  function merge(a, b) {
    if (a.length * b.length > LIMIT.variants) return null;
    const out = [];
    for (const x of a) for (const y of b) {
      if (x.segments.length + y.segments.length > LIMIT.segments) return null;
      out.push({ segments: x.segments.concat(y.segments), conditions: uniq(x.conditions.concat(y.conditions)) });
    }
    return out;
  }
  function encodeURISegments(values, origin) {
    try {
      return values.map(v => ({ conditions: v.conditions, segments: v.segments.map(s => {
        if (Object.hasOwn(s, 'text')) return { text: encodeURI(s.text) };
                                                                               
                                                                                
                                                                              
        return { ...s, encoding: s.encoding === 'encodeURIComponent' ? s.encoding : 'encodeURI' };
      }) }));
    } catch (_) { return unknown(origin, 'UNRESOLVED_URI_ENCODING_COMPLETION'); }
  }
  const valueCache = new WeakMap();
  function value(n, trail = new Set(), depth = 0) {
    if (!n) return literal('undefined');
    if (depth > LIMIT.depth) return unknown(n, 'VALUE_DEPTH_LIMIT');
    if (valueCache.has(n)) return valueCache.get(n);
    if (trail.has(n)) return unknown(n, 'CYCLIC_VALUE_BINDING');
    const t = new Set(trail).add(n); const next = x => value(x, t, depth + 1);
    let out;
    const src = sourceNodes.get(n);
    if (src) out = atom([{ kind: 'date', sourceId: src.id }], [], true);
    else if (['StringLiteral', 'NumericLiteral', 'BooleanLiteral'].includes(n.type)) out = literal(n.value);
    else if (n.type === 'NullLiteral') out = literal('null');
    else if (n.type === 'Identifier') {
      const b = lookup(n);
      if (!b) out = unknown(n, 'UNRESOLVED_GLOBAL_VALUE');
      else if (b.definitions.length !== 1 || b.writes.length) out = unknown(n, 'AMBIGUOUS_OR_REASSIGNED_BINDING');
      else if (dateMutationOrEscape.has(dateObjectBinding(b)?.id)) out = unknown(n, 'DATE_OBJECT_MUTATION_OR_ESCAPE_UNRESOLVED');
      else {
        const d = b.definitions[0];
        if (d.kind === 'parameter') out = atom([{ kind: 'parameter', bindingId: b.id, functionId: d.function.id, parameterIndex: d.parameterIndex, propertyPath: d.path }]);
        else if (d.init && d.path.length === 0 && (!Number.isInteger(d.node.end) || !Number.isInteger(n.start) || d.node.end <= n.start || nodeFunction.get(d.node) !== nodeFunction.get(n))) out = next(d.init);
        else out = unknown(n, 'UNSUPPORTED_BINDING_VALUE');
      }
    } else if (n.type === 'TemplateLiteral') {
      out = literal(n.quasis[0].value.cooked ?? n.quasis[0].value.raw);
      for (let i = 0; i < n.expressions.length; i++) {
        out = merge(out, next(n.expressions[i])); if (!out) break;
        out = merge(out, literal(n.quasis[i + 1].value.cooked ?? n.quasis[i + 1].value.raw));
      }
      if (!out) out = unknown(n, 'STRING_VARIANT_LIMIT');
    } else if (n.type === 'BinaryExpression' && n.operator === '+') {
      const a = next(n.left), b = next(n.right);
                                                                                
                                                                                      
      out = merge(a, b) || unknown(n, 'STRING_VARIANT_LIMIT');
    } else if (n.type === 'ConditionalExpression') {
      out = [...next(n.consequent).map(v => ({ ...v, conditions: v.conditions.concat(condition('CONDITION_TRUTHY', n.test)) })),
        ...next(n.alternate).map(v => ({ ...v, conditions: v.conditions.concat(condition('CONDITION_FALSY', n.test)) }))];
      if (out.length > LIMIT.variants) out = unknown(n, 'STRING_VARIANT_LIMIT');
    } else if (n.type === 'LogicalExpression') {
                                                                                                 
      out = [...next(n.left).map(v => ({ ...v, conditions: v.conditions.concat(condition('LOGICAL_LEFT_SELECTED', n, n.operator)) })),
        ...next(n.right).map(v => ({ ...v, conditions: v.conditions.concat(condition('LOGICAL_RIGHT_SELECTED', n, n.operator)) }))];
    } else if (n.type === 'CallExpression' && ['encodeURIComponent', 'encodeURI', 'String', 'Number'].some(k => global(n.callee, k)) && n.arguments.length === 1 && n.arguments[0].type !== 'SpreadElement') {
      const a = next(n.arguments[0]);
      if (n.callee.name === 'String') out = a;
      else if (n.callee.name === 'encodeURI') out = encodeURISegments(a, n);
      else if (n.callee.name === 'encodeURIComponent') {
        out = atom(depsOf(a), uniq(a.flatMap(v => v.conditions)), true);
        out[0].segments[0].encoding = 'encodeURIComponent';
      } else {
                                                                                
                                                                            
        out = unknown(n, 'NUMBER_COERCION_VALUE_UNRESOLVED');
      }
    } else if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && ['toUTCString', 'toISOString', 'getTime', 'valueOf', 'toString'].includes(keyName(n.callee)) && n.arguments.length === 0) {
      const a = next(n.callee.object), deps = depsOf(a);
      if (deps.length && deps.every(d => d.kind === 'date')) out = atom(deps, uniq(a.flatMap(v => v.conditions)), true);
      else out = unknown(n, 'UNRESOLVED_DATE_METHOD_RECEIVER');
    } else if (n.type === 'ParenthesizedExpression' || n.type === 'TSAsExpression') out = next(n.expression);
    else if (n.type === 'SequenceExpression') out = next(n.expressions[n.expressions.length - 1]).map(v => ({ ...v, conditions: v.conditions.concat(condition('PRIOR_SEQUENCE_EFFECTS_UNPROVEN', n)) }));
    else out = unknown(n, 'UNSUPPORTED_VALUE_EXPRESSION');
    valueCache.set(n, out); return out;
  }
  function docReceiver(n) {
    return global(n, 'document') || (n?.type === 'MemberExpression' && keyName(n) === 'document' && ['window', 'self', 'globalThis'].some(k => global(n.object, k)));
  }
  const sinks = assignments.filter(n => n.type === 'AssignmentExpression' && n.operator === '=' && n.left.type === 'MemberExpression' && keyName(n.left) === 'cookie' && docReceiver(n.left.object));
  function fieldOccurrences(variant, sink) {
    let state = 'NAME', attr = '', pending = [], uncertain = [];
    const out = [];
    for (const seg of variant.segments) {
      if (Object.hasOwn(seg, 'text')) {
        for (const ch of seg.text) {
          if (ch === ';') { state = 'ATTRIBUTE_KEY'; attr = ''; }
          else if (ch === '=') {
            if (state === 'NAME') state = 'VALUE';
            else if (state === 'ATTRIBUTE_KEY') { const a = attr.trim().toLowerCase(); state = a === 'expires' ? 'EXPIRES' : a === 'max-age' ? 'MAX_AGE' : ['domain', 'path', 'samesite'].includes(a) ? a.toUpperCase() : 'OTHER_ATTRIBUTE'; }
          } else if (state === 'ATTRIBUTE_KEY') attr += ch;
        }
      } else {
        for (const dep of seg.deps) out.push({ dep, field: state, conditions: uniq(variant.conditions.concat(uncertain)), sink, variant });
        if (!seg.delimiterSafe) {
          pending = seg.deps.filter(d => d.kind === 'parameter');
          if (pending.length) uncertain = uncertain.concat(pending.map(d => condition('NO_EARLIER_COOKIE_DELIMITER_IN_ARGUMENT', sink, d.bindingId)));
          else if (seg.deps.some(d => d.kind === 'unknown')) uncertain.push(condition('EARLIER_COOKIE_FIELD_STRUCTURE_UNRESOLVED', sink));
        }
      }
    }
    return out;
  }
  const summaries = new Map(), direct = [];
  for (const sink of sinks) for (const v of value(sink.right)) for (const occ of fieldOccurrences(v, sink)) {
    if (!['NAME', 'VALUE', 'EXPIRES', 'MAX_AGE', 'PATH', 'DOMAIN', 'SAMESITE', 'OTHER_ATTRIBUTE'].includes(occ.field)) continue;
    if (occ.dep.kind === 'date') direct.push(occ);
    else if (occ.dep.kind === 'parameter' && occ.dep.propertyPath.length === 0) {
      if (!summaries.has(occ.dep.functionId)) summaries.set(occ.dep.functionId, []);
      summaries.get(occ.dep.functionId).push(occ);
    }
  }
  function functionValue(n) {
    if (isFn(n)) return functionInfo.get(n);
    if (n?.type !== 'Identifier') return null;
    const b = lookup(n); if (!b || b.writes.length || b.definitions.length !== 1) return null;
    const d = b.definitions[0];
    return d.kind === 'function' ? functionInfo.get(d.node) : isFn(d.init) ? functionInfo.get(d.init) : null;
  }
  function returns(f) {
    if (f.node.body.type !== 'BlockStatement') return [f.node.body];
                                                                              
                                                                          
    const all = [];
    function scan(n) { if (isFn(n)) return; if (n.type === 'ReturnStatement') all.push(n); for (const [, c] of children(n)) scan(c); }
    scan(f.node.body);
    if (all.length !== 1 || !f.node.body.body.includes(all[0])) return [];
    return all[0].argument ? [all[0].argument] : [];
  }
  function objectValue(n, env = new Map(), chain = [], conditions = [], seen = new Set(), depth = 0) {
    if (!n || depth > LIMIT.factory || seen.has(n)) return null;
    const seen2 = new Set(seen).add(n), step = (x, e = env, c = chain, q = conditions) => objectValue(x, e, c, q, seen2, depth + 1);
    if (n.type === 'ObjectExpression') return { object: n, env, chain: chain.concat({ kind: 'RETURNED_OBJECT_IDENTITY', range: span(n) }), conditions };
    if (n.type === 'Identifier') {
      const b = lookup(n); if (!b || b.writes.length || b.propertyWrites.length || b.definitions.length !== 1) return null;
      const d = b.definitions[0];
      if (env.has(b.id)) { const x = env.get(b.id); return step(x.node, x.env, chain.concat({ kind: 'ACTUAL_TO_FACTORY_FORMAL', bindingId: b.id, range: span(n) }), conditions); }
      if (d.kind === 'parameter' && d.defaultValue && d.path.length === 0) return step(d.defaultValue, env,
        chain.concat({ kind: 'PARAMETER_DEFAULT', bindingId: b.id, parameterIndex: d.parameterIndex, range: span(d.node) }),
        conditions.concat(condition('PARAMETER_DEFAULT_USED', d.node, { bindingId: b.id, parameterIndex: d.parameterIndex, requires: 'actual value is undefined / argument omitted' })));
      if (d.kind === 'variable' && d.init && d.path.length === 0) return step(d.init, env, chain.concat({ kind: 'LEXICAL_OBJECT_BINDING', bindingId: b.id, range: span(d.node) }), conditions);
      return null;
    }
    if (n.type === 'CallExpression' && n.arguments.every(x => x.type !== 'SpreadElement')) {
      const f = functionValue(n.callee); if (!f) return null;
      const rs = returns(f); if (rs.length !== 1) return null;
      const local = new Map(env);
      for (const b of bindings) {
        if (b.definitions.length !== 1) continue;
        const d = b.definitions[0];
        if (d.kind === 'parameter' && d.function === f && d.path.length === 0 && n.arguments[d.parameterIndex]) local.set(b.id, { node: n.arguments[d.parameterIndex], env });
      }
      return step(rs[0], local, chain.concat({ kind: 'DIRECT_FACTORY_CALL_AND_RETURN', call: span(n), function: fnSummary(f) }),
        conditions.concat(condition('FACTORY_NORMAL_COMPLETION_REQUIRED', n, f.id)));
    }
    return null;
  }
  function ownKey(p) {
    if (!p.computed && p.key?.type === 'Identifier') return p.key.name;
    if (p.key?.type === 'StringLiteral' || p.key?.type === 'NumericLiteral') return String(p.key.value);
    return null;
  }
  function definitelyOtherKey(p, wanted) {
    const k = ownKey(p); if (k !== null) return k !== wanted;
    if (p.computed && p.key?.type === 'TemplateLiteral') {
      const q = p.key.quasis, prefix = q[0].value.cooked ?? q[0].value.raw, suffix = q[q.length - 1].value.cooked ?? q[q.length - 1].value.raw;
      return (prefix && !wanted.startsWith(prefix)) || (suffix && !wanted.endsWith(suffix));
    }
    return false;
  }
  function selectOwnMethod(obj, wanted, seen = new Set()) {
    if (seen.has(obj.object)) return null; const next = new Set(seen).add(obj.object);
    let selected = null, uncertain = false;
    for (const p of obj.object.properties) {
      if (p.type === 'SpreadElement') {
        const spread = objectValue(p.argument, obj.env); if (!spread) { uncertain = true; continue; }
                                                                               
        if (!spread.object.properties.every(q => q.type !== 'SpreadElement' && definitelyOtherKey(q, wanted))) uncertain = true;
      } else if (ownKey(p) === wanted) {
        if (p.type === 'ObjectMethod' && p.kind !== 'get' && p.kind !== 'set') selected = functionInfo.get(p);
        else if (p.type === 'ObjectProperty') selected = functionValue(p.value);
        else selected = null;
        uncertain = !selected;
      } else if (!definitelyOtherKey(p, wanted)) uncertain = true;
    }
    return selected && !uncertain ? selected : null;
  }
  const flows = [];
  function fieldSupported(occ) {
    return !occ.conditions.some(c => ['NO_EARLIER_COOKIE_DELIMITER_IN_ARGUMENT', 'EARLIER_COOKIE_FIELD_STRUCTURE_UNRESOLVED'].includes(c.code));
  }
  function flow(source, occ, path, conditions, call = null, receiver = null) {
    flows.push({ id: `${source.id}->${id(occ.sink)}:${occ.field}:${call ? id(call) : 'direct'}`, status: 'LOCAL_DATAFLOW_SUPPORTED',
      runtimeReached: false, cookieStored: 'UNOBSERVED', source, sink: { id: id(occ.sink), sourceId, sourceHash, range: span(occ.sink), enclosingFunction: fnSummary(nodeFunction.get(occ.sink)), enclosingFunctions: functionChain(occ.sink) },
      field: occ.field, path, receiver, conditions: uniq(conditions.concat(condition('SOURCE_AND_SINK_EXECUTION_UNPROVEN', occ.sink),
        ...(nodeFunction.get(occ.sink) ? [condition('ENCLOSING_CALLBACK_INVOCATION_UNPROVEN', occ.sink, functionChain(occ.sink))] : []))) });
  }
  for (const occ of direct) {
    const src = sources.find(s => s.id === occ.dep.sourceId);
    if (!fieldSupported(occ)) { unresolved.push({ status: 'UNKNOWN_FIELD', sourceId: src.id, sink: span(occ.sink), conditions: occ.conditions, promotedToFlow: false }); continue; }
    flow(src, occ, [{ kind: 'LEXICAL_VALUE_TO_COOKIE_FIELD', sourceRange: src.range, sinkRange: span(occ.sink) }], occ.conditions);
  }
  const methodNames = new Set(functions.filter(f => summaries.has(f.id) && (f.node.type === 'ObjectMethod' || parents.get(f.node)?.node.type === 'ObjectProperty')).map(f => ownKey(f.node.type === 'ObjectMethod' ? f.node : parents.get(f.node).node)).filter(x => x !== null));
  for (const call of calls) {
    let f = null, receiver = null, extra = [];
    if (call.callee.type === 'Identifier') f = functionValue(call.callee);
    else if (call.callee.type === 'MemberExpression') {
      const key = keyName(call.callee); if (!methodNames.has(key)) continue;
      const obj = objectValue(call.callee.object);
      if (obj) { f = selectOwnMethod(obj, key); receiver = { objectRange: span(obj.object), chain: obj.chain, identity: 'LEXICAL_DEFAULT_FACTORY_RETURN_OBJECT', conditions: obj.conditions }; extra = obj.conditions; }
      if (!f || !summaries.has(f.id)) {
        const dateActuals = call.arguments.filter(a => a.type !== 'SpreadElement').flatMap(a => depsOf(value(a)).filter(d => d.kind === 'date'));
        if (dateActuals.length) unresolved.push({ status: 'UNRESOLVED_RECEIVER', call: span(call), property: key, dateSourceIds: uniq(dateActuals).map(d => d.sourceId), reason: obj ? 'RETURN_OBJECT_METHOD_NOT_PROVEN' : 'NO_EXACT_RECEIVER_BINDING_CHAIN', promotedToFlow: false });
        continue;
      }
    }
    if (!f || !summaries.has(f.id)) continue;
    const uniqueVariants = [...new Map(summaries.get(f.id).map(o => [id(o.sink) + JSON.stringify(o.variant), o])).values()];
    for (const summary of uniqueVariants) {
      let instantiated = [{ segments: [], conditions: summary.variant.conditions }];
      const links = [];
      for (const seg of summary.variant.segments) {
        const owned = (seg.deps || []).filter(d => d.kind === 'parameter' && d.functionId === f.id);
        let replacement = [{ segments: [seg], conditions: [] }];
        if (owned.length) {
          if (owned.length !== 1 || seg.deps.length !== 1 || owned[0].propertyPath.length) { instantiated = null; break; }
          const dep = owned[0], arg = call.arguments[dep.parameterIndex];
          if (arg?.type === 'SpreadElement') { instantiated = null; break; }
          const actual = arg ? value(arg) : literal('undefined');
          links.push({ kind: 'ACTUAL_ARGUMENT_TO_FORMAL', call: span(call), actual: span(arg), parameterIndex: dep.parameterIndex, bindingId: dep.bindingId, function: fnSummary(f) });
          if (seg.encoding === 'encodeURIComponent') {
            replacement = atom(depsOf(actual), uniq(actual.flatMap(v => v.conditions)), true);
            replacement[0].segments[0].encoding = 'encodeURIComponent';
          } else if (seg.encoding === 'encodeURI') replacement = encodeURISegments(actual, arg || call);
          else replacement = actual;
        }
        instantiated = merge(instantiated, replacement); if (!instantiated) break;
      }
      if (!instantiated) { unresolved.push({ status: 'UNKNOWN_FIELD', call: span(call), sink: span(summary.sink), reason: 'ACTUAL_SUBSTITUTION_UNSUPPORTED_OR_LIMIT', promotedToFlow: false }); continue; }
                                                                                    
                                                                                           
      for (const actualVariant of instantiated) for (const occ of fieldOccurrences(actualVariant, summary.sink)) {
        if (occ.dep.kind !== 'date') continue;
        const src = sources.find(s => s.id === occ.dep.sourceId);
        if (!fieldSupported(occ) || !['NAME', 'VALUE', 'EXPIRES', 'MAX_AGE', 'DOMAIN', 'PATH', 'SAMESITE', 'OTHER_ATTRIBUTE'].includes(occ.field)) {
          unresolved.push({ status: 'UNKNOWN_FIELD', sourceId: src.id, call: span(call), sink: span(occ.sink), conditions: occ.conditions, promotedToFlow: false }); continue;
        }
        flow(src, occ, [{ kind: 'EXACT_DATE_SOURCE', range: src.range }, ...links, { kind: 'ACTUAL_STRING_REPARSED_COOKIE_FIELD', field: occ.field, sink: span(occ.sink) }],
          extra.concat(occ.conditions, condition('CALLSITE_EXECUTION_UNPROVEN', call), condition('INTERPROCEDURAL_EFFECTS_AND_METHOD_INVOCATION_REQUIRED', call, f.id)), call, receiver);
      }
    }
  }
  if (stopped) unresolved.push({ status: 'AST_NODE_LIMIT', limit: LIMIT.nodes, promotedToFlow: false });
  return { schema: 'lexical-cookie-flow-v1', sourceId, sourceHash, analysisKind: 'STATIC_LOCAL_DATAFLOW_CANDIDATES',
    sources, flows: [...new Map(flows.map(f => [f.id + JSON.stringify(f.conditions), f])).values()], unresolvedConditions: unresolved,
    dateObjectBoundaries: [...dateMutationOrEscape.entries()].map(([bindingId, reasons]) => ({ bindingId, reasons: uniq(reasons) })),
    assertedRuntimeReachedPairs: 0, statistics: { nodes: nodes.length, scopes: scopes.length, bindings: bindings.length, functions: functions.length, cookieAssignments: sinks.length },
    limits: LIMIT, assumptions: ['Unshadowed Date/document and approved conversion intrinsics have their standard meanings.', 'LOCAL_DATAFLOW_SUPPORTED never asserts actual callback invocation, browser state, cookie persistence or a native proof.', 'Alternative receiver arguments are not resolved by a default-object path; PARAMETER_DEFAULT_USED is an explicit predicate.', 'Only structurally resolved direct lexical functions/return objects are joined; identical method spelling alone cannot establish a callee.'] };
}

module.exports = { analyzeCookieFlows };
