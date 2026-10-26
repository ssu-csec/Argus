'use strict';
                                                                                   
                                                    
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const BYTE_LIMITS = Object.freeze({ inputBytes: 4 * 1024 * 1024, outputBytes: 32 * 1024 * 1024, flowRecords: 4096 });
const CODE_FILES = ['analyze.cjs', 'bundle_context.cjs', 'callback_links.cjs', 'cookie_flow.cjs', 'path_conditions.cjs', 'site_context.cjs', 'trace_context.cjs', 'deps.cjs', 'worker.cjs'];
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function failure(code, detail) { return Object.assign(new Error(code), { code, ...(detail || {}) }); }
function codePins() {
  return Object.fromEntries(CODE_FILES.map(name => { const file = path.join(__dirname, name); return [file, hash(fs.readFileSync(file))]; }));
}
function samePins(before, after, code) {
  for (const [file, digest] of Object.entries(before)) if (after[file] !== digest) throw failure(code, { changedFile: file });
}
function boundedRead(file) {
                                                                                
  const pre = fs.statSync(file);
  if (!pre.isFile()) throw failure('INPUT_NOT_REGULAR_FILE');
  if (pre.size > BYTE_LIMITS.inputBytes) throw failure('INPUT_SIZE_LIMIT', { inputBytes: pre.size });
  const fd = fs.openSync(file, 'r');
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile()) throw failure('INPUT_NOT_REGULAR_FILE');
    if (opened.size > BYTE_LIMITS.inputBytes) throw failure('INPUT_SIZE_LIMIT', { inputBytes: opened.size });
    if (pre.dev !== opened.dev || pre.ino !== opened.ino) throw failure('INPUT_IDENTITY_CHANGED_DURING_OPEN');
    const buffer = Buffer.allocUnsafe(BYTE_LIMITS.inputBytes + 1); let used = 0;
    while (used < buffer.length) {
      const got = fs.readSync(fd, buffer, used, buffer.length - used, null);
      if (got === 0) break; used += got;
    }
    if (used > BYTE_LIMITS.inputBytes) throw failure('INPUT_SIZE_LIMIT', { inputBytesAtLeast: used });
    const after = fs.fstatSync(fd);
    if (opened.size !== used || after.size !== used || opened.mtimeMs !== after.mtimeMs || opened.ctimeMs !== after.ctimeMs) throw failure('INPUT_CHANGED_DURING_READ');
    return { bytes: Buffer.from(buffer.subarray(0, used)), identity: { dev: after.dev, ino: after.ino, size: after.size } };
  } finally { fs.closeSync(fd); }
}
function writeNewOutput(file, bytes) {
  const fd = fs.openSync(file, 'wx');
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); }
  catch (error) { try { fs.closeSync(fd); } catch (_) {} try { fs.unlinkSync(file); } catch (_) {} throw error; }
  fs.closeSync(fd);
}
function run() {
  const args = process.argv.slice(2);
  if (args.length !== 3 || !/^[a-fA-F0-9]{64}$/.test(args[2])) throw failure('USAGE_INPUT_OUTPUT_EXPECTED_SHA256');
  const [givenInput, givenOutput, expected] = args, expectedHash = expected.toLowerCase();
  const input = fs.realpathSync(path.resolve(givenInput)), output = path.resolve(givenOutput);
  if (input === output) throw failure('OUTPUT_EQUALS_INPUT');
  if (fs.existsSync(output)) throw failure('OUTPUT_ALREADY_EXISTS');
  const pinsBefore = codePins(), first = boundedRead(input), firstHash = hash(first.bytes);
  if (firstHash !== expectedHash) throw failure('INPUT_SHA256_MISMATCH', { expectedHash, observedHash: firstHash });
                                                                          
  const { analyzeSource, LIMITS } = require('./analyze.cjs');
  const deps = require('./deps.cjs'), depPinsBefore = deps.loadedDependencyPins();
  if (LIMITS.inputBytes !== BYTE_LIMITS.inputBytes || LIMITS.outputBytes !== BYTE_LIMITS.outputBytes || LIMITS.flowRecords !== BYTE_LIMITS.flowRecords) throw failure('WORKER_ANALYZER_LIMIT_MISMATCH');
  const started = new Date().toISOString();
  const result = analyzeSource(first.bytes, input);
  const observedCounts = { cookiePaths: result.cookie.flows.length, tracePaths: result.trace.flows.length, uniqueObservations: result.trace.uniqueSourceSinkFieldObservations.length };
  observedCounts.total = Object.values(observedCounts).reduce((a, b) => a + b, 0);
  if (observedCounts.total > BYTE_LIMITS.flowRecords) throw failure('FLOW_RECORD_LIMIT', { flowRecordCounts: observedCounts });
  const last = boundedRead(input), lastHash = hash(last.bytes);
  if (lastHash !== expectedHash || first.identity.dev !== last.identity.dev || first.identity.ino !== last.identity.ino) throw failure('INPUT_CHANGED_AFTER_ANALYSIS');
  const pinsAfter = codePins(), depPinsAfter = deps.loadedDependencyPins();
  samePins(pinsBefore, pinsAfter, 'ANALYZER_CODE_CHANGED');
  samePins(depPinsBefore, depPinsAfter, 'ANALYZER_DEPENDENCY_CHANGED');
  result.worker = { schema: 'argus-conditional-worker-v1', started, ended: new Date().toISOString(), input: { requestedPath: givenInput, actualPath: input, expectedSha256: expectedHash, beforeSha256: firstHash, afterSha256: lastHash, bytes: first.bytes.length, regularFileVerified: true, identityStable: true },
    limits: { ...LIMITS, flowRecordCountDefinition: 'sum(cookie.flows, trace.flows, uniqueSourceSinkFieldObservations); no silent truncation', parentOwnsTimeoutAndChildMemory: true },
    flowRecordCounts: observedCounts, codePins: pinsAfter, dependencies: deps.dependencyInfo(), dependencyPins: depPinsAfter,
    sourceJavaScriptExecutions: 0, nativeCalls: 0, runtimeObserved: false, outputMode: 'CREATE_NEW_ONLY' };
  const bytes = Buffer.from(JSON.stringify(result) + '\n', 'utf8');
  if (bytes.length > BYTE_LIMITS.outputBytes) throw failure('OUTPUT_SIZE_LIMIT', { outputBytes: bytes.length });
  writeNewOutput(output, bytes);
  process.stdout.write(JSON.stringify({ status: 'COMPLETE_CONDITIONAL_ANALYSIS', sourceId: input, sourceHash: expectedHash, output, outputBytes: bytes.length, outputSha256: hash(bytes), flowRecordCounts: observedCounts, nativeCalls: 0, sourceJavaScriptExecutions: 0 }) + '\n');
}
try { run(); }
catch (error) {
  process.stdout.write(JSON.stringify({ status: 'CONDITIONAL_INPUT_ERROR', code: error.code || (error.name === 'SyntaxError' ? 'INPUT_PARSE_ERROR' : 'ANALYSIS_ERROR'),
    message: String(error.message || error).slice(0, 2048), input: process.argv[2] || null, output: process.argv[3] || null,
    dependency: error.dependency || null, nativeCalls: 0, sourceJavaScriptExecutions: 0, outputIsValid: false }) + '\n');
  process.exitCode = 2;
}
