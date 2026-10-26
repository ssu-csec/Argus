'use strict';

                                                                              
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TextDecoder } = require('util');
const { createRequire } = require('module');

const VERSION = '2.0.0';
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const now = () => new Date().toISOString();
const message = error => String(error && error.message || error);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const DEFAULTS = Object.freeze({
  concurrency: 1, navigationMs: 30000, scrollMs: 45000, settleMs: 2000,
  drainMs: 15000, taskMs: 240000, scroll: true, stealth: true,
  transform: 'preserve', limit: null, dependencyRoot: __dirname,
});

function writeJson(file, data, io = fs) {
  const tmp = file + '.' + crypto.randomBytes(6).toString('hex') + '.tmp';
  io.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { flag: 'wx' });
  io.renameSync(tmp, file);
}

function parseArgs(args) {
  const options = { ...DEFAULTS };
  const numeric = { '--concurrency': 'concurrency', '--navigation-ms': 'navigationMs',
    '--scroll-ms': 'scrollMs', '--settle-ms': 'settleMs', '--drain-ms': 'drainMs',
    '--task-ms': 'taskMs', '--limit': 'limit' };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--no-scroll') options.scroll = false;
    else if (arg === '--no-stealth') options.stealth = false;
    else if (arg === '--check-input') options.checkInput = true;
    else if (numeric[arg] || ['--out', '--transform', '--dependency-root'].includes(arg)) {
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error('Missing value: ' + arg);
      if (numeric[arg]) {
        const number = Number(value);
        if (!Number.isSafeInteger(number) || number < (arg === '--settle-ms' ? 0 : 1)) {
          throw new Error('Invalid positive integer: ' + arg);
        }
        options[numeric[arg]] = number;
      } else options[{ '--out': 'out', '--transform': 'transform', '--dependency-root': 'dependencyRoot' }[arg]] = value;
    } else if (arg.startsWith('-') || options.listFile) throw new Error('Unknown argument: ' + arg);
    else options.listFile = arg;
  }
  if (!options.help && !options.listFile) throw new Error('A URL list file is required. Use --help.');
  if (!['preserve', 'babel'].includes(options.transform)) throw new Error('Transform must be preserve or babel.');
  options.dependencyRoot = path.resolve(options.dependencyRoot);
  return options;
}

function readTargets(bytes, limit) {
  const targets = [];
  for (const [index, raw] of bytes.toString('utf8').replace(/^\uFEFF/, '').split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
                                                                                         
    const fields = line.split(',');
    const input = fields.length > 1 ? fields[1].trim() : line;
    const target = { visit_id: String(targets.length + 1).padStart(6, '0'), input, input_line: index + 1 };
    try {
      const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : 'https://' + input);
      if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) throw new Error('Unsupported URL');
      target.url = url.href;
      target.hostname = url.hostname;
    } catch (error) { target.input_error = message(error); }
    targets.push(target);
    if (limit && targets.length >= limit) break;
  }
  if (!targets.length) throw new Error('The input contains no targets.');
  return targets;
}

function createRunDirectory(requested) {
  const root = path.resolve(requested || path.join(__dirname, 'runs',
    now().replace(/[:.]/g, '-') + '-' + crypto.randomBytes(4).toString('hex')));
  fs.mkdirSync(path.dirname(root), { recursive: true });
                                                                            
  fs.mkdirSync(root);
  fs.mkdirSync(path.join(root, 'visits'));
  return root;
}

function isScript(url, type, contentType) {
  let extension = false;
  try { extension = /\.(?:js|mjs|cjs)$/i.test(new URL(url).pathname); } catch (_) {                             }
  return type === 'script' || /(?:javascript|ecmascript)/i.test(contentType) || extension;
}

function decodeBody(bytes, contentType) {
  const match = /charset\s*=\s*["']?([^;\s"']+)/i.exec(contentType || '');
                                                                                   
                                                                               
                                                                                     
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const code = decoder.decode(bytes);
  return { code, declared_charset: match ? match[1] : null,
    decoder_encoding: decoder.encoding, basis: 'PUPPETEER_API_UTF8_REPRESENTATION', fatal: true,
    browser_may_have_reencoded: true, http_original_bytes_preserved: false,
    replacement_character_present: code.includes('\uFFFD') };
}

function makeTransformer(options, requireFrom) {
  if (options.transform === 'preserve') return code => ({ code, status: 'NOT_REQUESTED', policy: 'preserve' });
  const babel = requireFrom('@babel/core');
  const preset = requireFrom('@babel/preset-env');
  return code => {
    if (code.length >= 250000) return { code, status: 'SKIPPED_SIZE_LIMIT', policy: 'babel' };
    try {
      const transformed = babel.transformSync(code, {
        presets: [[preset, { targets: { ie: '11' }, modules: 'commonjs', useBuiltIns: false }]],
        sourceType: 'unambiguous', babelrc: false, configFile: false,
        filename: 'collected.js', comments: true, compact: false, sourceMaps: true,
      });
      if (!transformed || typeof transformed.code !== 'string') throw new Error('No Babel output');
      return { code: transformed.code, map: transformed.map, policy: 'babel', status: 'APPLIED' };
    } catch (error) {
      return { code, policy: 'babel', status: 'FAILED_FALLBACK_TO_DECODED', error: message(error) };
    }
  };
}

class Visit {
  constructor(root, target, options, transform, io = fs) {
    this.io = io; this.target = target; this.options = options; this.transform = transform;
    const slug = (target.hostname || 'invalid').replace(/[^a-z0-9.-]/gi, '_');
    this.dir = path.join(root, 'visits', target.visit_id + '-' + slug);
    io.mkdirSync(this.dir); io.mkdirSync(path.join(this.dir, 'raw')); io.mkdirSync(path.join(this.dir, 'scripts'));
    this.record = { ...target, started_at: now(), status: 'RUNNING', requests: [], artifacts: [], errors: [],
      observation_scope: 'HTTP responses observed during this visit; not script execution or cookie storage',
      inline_scripts: 'NOT_COLLECTED', runtime_events: 'NOT_COLLECTED',
      decoded_source_positions: 'NEW_INPUT_VERSION; do not reuse historical route coordinates' };
    this.requests = new WeakMap(); this.pending = new Set(); this.saved = [];
    this.accepting = true; this.closed = false; this.finishing = null; this.detach = () => {};
    writeJson(path.join(this.dir, 'visit.json'), this.record, io);
  }

  error(stage, error) {
    if (!this.closed) this.record.errors.push({ stage, message: message(error), at: now() });
  }

  request(req) {
    let record = this.requests.get(req);
    if (!record) {
      record = { request_id: 'r' + String(this.record.requests.length + 1).padStart(6, '0'),
        url: req.url(), resource_type: req.resourceType(), observed_at: now(), outcome: 'PENDING' };
      this.requests.set(req, record); this.record.requests.push(record);
    }
    return record;
  }

  track(work, stage) {
    const tracked = Promise.resolve().then(work).catch(error => this.error(stage, error));
    this.pending.add(tracked);
    tracked.then(() => this.pending.delete(tracked));
    return tracked;
  }

  attach(page) {
    const onRequest = req => {
      if (!this.accepting) { Promise.resolve().then(() => req.continue()).catch(() => {}); return; }
      const record = this.request(req);
      const blocked = ['image', 'media', 'font'].includes(record.resource_type);
      record.collector_action = blocked ? 'ABORT_RESOURCE_POLICY' : 'CONTINUE';
      this.track(() => blocked ? req.abort() : req.continue(), 'REQUEST_INTERCEPTION');
    };
    const onResponse = response => {
      if (!this.accepting) return;
      const req = response.request();
      const record = this.request(req);
      record.response_received_at = now(); record.http_status = response.status();
      record.outcome = 'RESPONSE_OBSERVED';
      const contentType = response.headers()['content-type'] || '';
      record.content_type = contentType;
      if (isScript(record.url, record.resource_type, contentType)) {
        record.script_body = 'PENDING';
        this.track(() => this.capture(response, record), 'RESPONSE_CAPTURE');
      }
    };
    const onFailed = req => {
      if (!this.accepting) return;
      const record = this.request(req);
      record.outcome = 'REQUEST_FAILED';
      record.failure = req.failure && req.failure();
      if (record.resource_type === 'script' && record.collector_action !== 'ABORT_RESOURCE_POLICY') {
        this.error('SCRIPT_REQUEST_FAILED', record.failure && record.failure.errorText || record.url);
      }
    };
    const onFinished = req => {
      if (!this.accepting) return;
      const record = this.request(req); record.outcome = 'REQUEST_FINISHED'; record.finished_at = now();
    };
    page.on('request', onRequest); page.on('response', onResponse);
    page.on('requestfailed', onFailed); page.on('requestfinished', onFinished);
    this.detach = () => {
      page.off('response', onResponse); page.off('requestfailed', onFailed); page.off('requestfinished', onFinished);
                                                                                     
                                                                                  
    };
  }

  async capture(response, request) {
    let bytes;
    try { bytes = await response.buffer(); }
    catch (error) {
      if (!this.closed) { request.script_body = 'BUFFER_FAILED'; this.error('BODY_READ', error); }
      return;
    }
    if (this.closed) return;                                                
    const rawFile = 'raw/' + request.request_id + '.response.bin';
    try {
      this.io.writeFileSync(path.join(this.dir, rawFile), bytes, { flag: 'wx' });
      request.raw_artifact = rawFile;
      this.record.artifacts.push({ file: rawFile, kind: 'RESPONSE_API_BYTES', bytes: bytes.length, sha256: sha256(bytes) });
      if (!bytes.length) { request.script_body = 'EMPTY_RESPONSE'; return; }
      if (request.http_status >= 400) { request.script_body = 'HTTP_ERROR'; this.error('SCRIPT_HTTP_ERROR', request.http_status); return; }
      const decoded = decodeBody(bytes, request.content_type);
      const { code, ...decodeMetadata } = decoded;
      request.decode = decodeMetadata;
      if (decodeMetadata.replacement_character_present) {
        this.error('ENCODING_REVIEW', 'U+FFFD is present in the API text; original intent/encoding is not established. Bytes are preserved.');
      }
      const decodedFile = 'raw/' + request.request_id + '.decoded.js';
      const decodedBytes = Buffer.from(code, 'utf8');
      this.io.writeFileSync(path.join(this.dir, decodedFile), decodedBytes, { flag: 'wx' });
      this.record.artifacts.push({ file: decodedFile, kind: 'DECODED_JS', bytes: decodedBytes.length, sha256: sha256(decodedBytes), parent: rawFile });
      if (!code.trim()) { request.script_body = 'EMPTY_DECODED_SCRIPT'; return; }
      const output = this.transform(code);
      request.transform = { policy: output.policy, status: output.status, error: output.error };
      if (output.status.startsWith('FAILED')) this.error('TRANSFORM', output.error);
      const scriptFile = 'scripts/' + request.request_id + '.js';
      const scriptBytes = Buffer.from(output.code, 'utf8');
      this.io.writeFileSync(path.join(this.dir, scriptFile), scriptBytes, { flag: 'wx' });
      this.record.artifacts.push({ file: scriptFile, kind: 'ANALYSIS_JS', bytes: scriptBytes.length, sha256: sha256(scriptBytes), parent: decodedFile });
      if (output.map) {
        const mapFile = scriptFile + '.map.json';
        writeJson(path.join(this.dir, mapFile), output.map, this.io);
        const mapBytes = this.io.readFileSync(path.join(this.dir, mapFile));
        this.record.artifacts.push({ file: mapFile, kind: 'TRANSFORM_SOURCE_MAP', bytes: mapBytes.length, sha256: sha256(mapBytes), parent: decodedFile });
      }
      request.script_body = 'SAVED'; request.analysis_artifact = scriptFile;
      this.saved.push({ request_id: request.request_id, url: request.url, file: scriptFile, sha256: sha256(scriptBytes) });
    } catch (error) { request.script_body = 'PROCESSING_FAILED'; this.error('DECODE_OR_SAVE', error); }
  }

  finalize(reason) {
    if (reason && !this.closed) this.taskFailure = reason;
    if (!this.finishing) this.finishing = this.finish(reason);
    return this.finishing;
  }

  async finish(reason) {
    this.accepting = false; this.detach();
    if (reason) this.error('TASK', reason);
    for (const req of this.record.requests) {
      if (isScript(req.url, req.resource_type, req.content_type || '') &&
          req.collector_action !== 'ABORT_RESOURCE_POLICY' && !req.script_body && req.outcome === 'PENDING') {
        req.script_body = 'NO_RESPONSE_AT_OBSERVATION_CUTOFF';
        this.error('SCRIPT_RESPONSE_NOT_OBSERVED', req.request_id);
      }
    }
    let timer;
    const complete = await Promise.race([
      Promise.all([...this.pending]).then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), this.options.drainMs); }),
    ]);
    clearTimeout(timer);
    this.record.drain_complete = complete;
    this.record.pending_at_cutoff = this.pending.size;
    if (!complete) {
      this.error('DRAIN_TIMEOUT', 'Some handlers did not finish before the cutoff.');
      for (const req of this.record.requests) if (req.script_body === 'PENDING') req.script_body = 'DRAIN_TIMEOUT';
    }
    this.closed = true;
    const segments = []; let offset = 0;
    const wholeHash = crypto.createHash('sha256');
                                                                                 
    const scripts = [...this.saved].sort((a, b) => a.request_id.localeCompare(b.request_id));
    const wholeFile = path.join(this.dir, 'wholepage.js');
    let fd;
    try {
      fd = this.io.openSync(wholeFile, 'wx');
      for (const script of scripts) {
        const bytes = this.io.readFileSync(path.join(this.dir, script.file));
        const safeUrl = JSON.stringify(script.url).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
        const header = Buffer.from('\n;\n// request: ' + script.request_id + ' source: ' + safeUrl + '\n');
        this.io.writeFileSync(fd, header); wholeHash.update(header); offset += header.length;
        segments.push({ ...script, start_byte: offset, end_byte_exclusive: offset + bytes.length });
        this.io.writeFileSync(fd, bytes); wholeHash.update(bytes); offset += bytes.length;
        this.io.writeFileSync(fd, Buffer.from('\n')); wholeHash.update('\n'); offset++;
      }
      this.record.wholepage = { file: 'wholepage.js', bytes: offset, sha256: wholeHash.digest('hex'), segments,
      order: 'REQUEST_OBSERVATION_ORDER_NOT_EXECUTION_ORDER',
      semantics: 'Concatenation artifact only; script/module/frame isolation is not modeled.' };
    } catch (error) {
      this.taskFailure = 'WHOLEPAGE_SAVE: ' + message(error);
      this.record.errors.push({ stage: 'WHOLEPAGE_SAVE', message: message(error), at: now() });
      this.record.wholepage = { file: 'wholepage.js', status: 'WRITE_FAILED', reason: message(error) };
    } finally { if (fd !== undefined) this.io.closeSync(fd); }
    this.record.saved_script_count = scripts.length;
    this.record.finished_at = now();
    this.record.status = this.taskFailure ? 'FAILED' : scripts.length === 0 ? 'NO_SCRIPTS' : this.record.errors.length ? 'PARTIAL' : 'SUCCESS';
    if (this.taskFailure) this.record.error = this.taskFailure;
    writeJson(path.join(this.dir, 'network_logs.json'), this.record.requests, this.io);
    writeJson(path.join(this.dir, 'visit.json'), this.record, this.io);
    return this.record;
  }
}

function summaryOf(targets, outcomes) {
  const counts = { SUCCESS: 0, PARTIAL: 0, NO_SCRIPTS: 0, FAILED: 0, NOT_STARTED: 0 };
  let scripts = 0;
  for (const target of targets) {
    const row = outcomes.get(target.visit_id);
    counts[row ? row.status : 'NOT_STARTED']++;
    scripts += row && row.saved_script_count || 0;
  }
  return { targets: targets.length, counts, saved_scripts: scripts,
    accounting_complete: Object.values(counts).reduce((a, b) => a + b, 0) === targets.length };
}

async function visitPage(page, visit) {
  let fatal;
  try {
    if (visit.target.input_error) throw new Error(visit.target.input_error);
    visit.record.browser_version = await page.browser().version();
    if (!visit.accepting) return visit.finalize();
    visit.attach(page);
    await page.setRequestInterception(true);
    try {
      await page.goto(visit.target.url, { waitUntil: 'domcontentloaded', timeout: visit.options.navigationMs });
    } catch (error) { visit.error('NAVIGATION', error); }
    if (visit.accepting && visit.options.scroll) {
      let timer;
      try {
        await Promise.race([
          page.evaluate(ms => new Promise(resolve => {
            const started = Date.now(); let height = 0;
            const interval = setInterval(() => {
              if (!document.body || Date.now() - started >= ms || height >= document.body.scrollHeight || height > 50000) {
                clearInterval(interval); resolve(); return;
              }
              window.scrollBy(0, 300); height += 300;
            }, 150);
          }), visit.options.scrollMs),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Scroll timeout')), visit.options.scrollMs + 1000); }),
        ]);
      } catch (error) { visit.error('SCROLL', error); }
      finally { clearTimeout(timer); }
    }
    if (visit.accepting) await delay(visit.options.settleMs);
    if (!visit.closed) visit.record.final_url_snapshot = { value: page.url(), observed_at: now() };
  } catch (error) { fatal = message(error); }
  return visit.finalize(fatal);
}

async function main(args) {
  const options = parseArgs(args);
  if (options.help) {
    console.log('Usage: node crawler.cjs URL_LIST [--out NEW_RUN_DIRECTORY] [--limit N]\n' +
      '  --check-input                Inspect the input only; no browser or output files\n' +
      '  --dependency-root DIR        Resolve installed packages from DIR\n' +
      '  --transform preserve|babel   Default preserve; no deobfuscation or guessed decoding\n' +
      '  --no-stealth --no-scroll     Explicit collection setting changes\n' +
      '  --concurrency N              Default 1; --navigation-ms, --scroll-ms, --settle-ms,\n' +
      '  --drain-ms, --task-ms         Explicit time budgets in milliseconds\n' +
      'Existing output directories are refused. New runs cannot repair old corpus metadata.');
    return 0;
  }
  const input = fs.readFileSync(path.resolve(options.listFile));
  const targets = readTargets(input, options.limit);
  if (options.checkInput) {
    console.log(JSON.stringify({ targets: targets.length, invalid_inputs: targets.filter(t => t.input_error),
      list_sha256: sha256(input), limit: options.limit, first: targets.slice(0, 5) }, null, 2));
    return targets.some(t => t.input_error) ? 2 : 0;
  }
  if (Number(process.versions.node.split('.')[0]) < 18) throw new Error('Use Node.js 18 or newer (20+ recommended).');
  const requireFrom = createRequire(path.join(options.dependencyRoot, 'package.json'));
  const { Cluster } = requireFrom('puppeteer-cluster');
  const puppeteer = requireFrom(options.stealth ? 'puppeteer-extra' : 'puppeteer');
  if (options.stealth) puppeteer.use(requireFrom('puppeteer-extra-plugin-stealth')());
  const transform = makeTransformer(options, requireFrom);
  const root = createRunDirectory(options.out);
  const browserOptions = { headless: true, protocolTimeout: options.taskMs,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-background-networking'] };
  const run = { schema_version: 1, collector_version: VERSION, run_id: path.basename(root),
    started_at: now(), status: 'RUNNING', node_version: process.version,
    collector_file: __filename, collector_sha256: sha256(fs.readFileSync(__filename)),
    input_file: path.resolve(options.listFile), input_sha256: sha256(input), settings: options,
    dependency_resolution: {}, output_directory: root,
    collection_policy: { browser_options: browserOptions, wait_until: 'domcontentloaded',
      blocked_resource_types: ['image', 'media', 'font'], retry_limit: 0,
      stealth_puppeteer_explicitly_passed: options.stealth },
    coverage: { sources: 'NETWORK_SCRIPT_RESPONSES', inline: 'NOT_COLLECTED', eval: 'NOT_COLLECTED',
      runtime: 'NOT_COLLECTED', wire_bytes: 'NOT_COLLECTED', provenance_complete: false } };
  for (const name of ['puppeteer-cluster', 'puppeteer', 'puppeteer-extra', 'puppeteer-extra-plugin-stealth', ...(options.transform === 'babel' ? ['@babel/core', '@babel/preset-env'] : [])]) {
    try {
      const packageFile = requireFrom.resolve(name + '/package.json');
      const bytes = fs.readFileSync(packageFile);
      run.dependency_resolution[name] = { file: packageFile, sha256: sha256(bytes), version: JSON.parse(bytes).version };
    } catch (error) { run.dependency_resolution[name] = { status: 'UNAVAILABLE', reason: message(error) }; }
  }
  writeJson(path.join(root, 'run.json'), run);
  const outcomes = new Map(), visits = new Map(), finalizers = new Set();
  const progress = summaryOf(targets, outcomes);
  let cluster, runError;
  function accept(target, record) {
    if (!outcomes.has(target.visit_id)) {
      const visit = visits.get(target.visit_id);
      outcomes.set(target.visit_id, { status: record.status, saved_script_count: record.saved_script_count || 0,
        error: record.error, persistence_error: record.persistence_error,
        visit_manifest: visit ? path.relative(root, path.join(visit.dir, 'visit.json')) : null });
      visits.delete(target.visit_id);                                                            
      progress.counts.NOT_STARTED--; progress.counts[record.status]++;
      progress.saved_scripts += record.saved_script_count || 0;
      writeJson(path.join(root, 'progress.json'), progress);
      console.log('[' + record.status + '] ' + target.visit_id + ' ' + target.input + ': ' + (record.saved_script_count || 0) + ' scripts');
    }
  }
  async function failed(target, error) {
    if (outcomes.has(target.visit_id)) return;
    try {
      const visit = visits.get(target.visit_id);
      const record = visit ? await visit.finalize(message(error)) : { ...target, status: 'FAILED', saved_script_count: 0, error: message(error) };
      accept(target, record);
    } catch (saveError) {
      accept(target, { ...target, status: 'FAILED', saved_script_count: 0,
        error: message(error), persistence_error: message(saveError) });
    }
  }
  try {
    cluster = await Cluster.launch({ concurrency: Cluster.CONCURRENCY_BROWSER,
      maxConcurrency: options.concurrency, retryLimit: 0, timeout: options.taskMs, monitor: false,
      puppeteer, puppeteerOptions: browserOptions });
    cluster.on('taskerror', (error, target, willRetry) => {
      if (willRetry) return;
      const task = failed(target, error).catch(saveError => { runError = message(saveError); });
      finalizers.add(task); task.then(() => finalizers.delete(task), () => finalizers.delete(task));
    });
    await cluster.task(async ({ page, data: target }) => {
      const visit = new Visit(root, target, options, transform);
      visits.set(target.visit_id, visit);
      accept(target, await visitPage(page, visit));
    });
    for (const target of targets) await cluster.queue(target);
    await cluster.idle();
    await Promise.all([...finalizers]);
  } catch (error) { runError = message(error); }
  finally {
    if (cluster) { try { await cluster.close(); } catch (error) { runError = runError || message(error); } }
    for (const target of targets) if (!outcomes.has(target.visit_id) && visits.has(target.visit_id)) await failed(target, runError || 'No terminal result');
    run.status = runError ? 'FAILED' : 'COMPLETED'; run.error = runError;
    run.finished_at = now(); run.summary = summaryOf(targets, outcomes);
    writeJson(path.join(root, 'outcomes.json'), targets.map(target => {
      const record = outcomes.get(target.visit_id);
      return { visit_id: target.visit_id, input: target.input, status: record ? record.status : 'NOT_STARTED',
        saved_script_count: record && record.saved_script_count || 0, error: record && record.error,
        persistence_error: record && record.persistence_error,
        visit_manifest: record && record.visit_manifest || null };
    }));
    writeJson(path.join(root, 'run.json'), run);
  }
  console.log(JSON.stringify({ output: root, ...run.summary, error: runError }, null, 2));
  return runError || run.summary.counts.NOT_STARTED || run.summary.counts.FAILED ? 1 :
    run.summary.counts.PARTIAL || run.summary.counts.NO_SCRIPTS ? 2 : 0;
}

module.exports = { VERSION, DEFAULTS, parseArgs, readTargets, createRunDirectory, isScript,
  decodeBody, makeTransformer, Visit, summaryOf, visitPage, main, sha256 };
if (require.main === module) main(process.argv.slice(2)).then(code => { process.exitCode = code; })
  .catch(error => { console.error('[FATAL] ' + message(error)); process.exitCode = 1; });
