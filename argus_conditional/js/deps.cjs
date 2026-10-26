'use strict';
                                                                                   
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ALLOWED = new Set(['@babel/parser', '@babel/traverse']);
const resolved = new Map();
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function ancestorDirectories(start) {
  const out = []; let dir = path.resolve(start);
  for (let i = 0; i < 16; i++) {
    out.push(dir); const parent = path.dirname(dir); if (parent === dir) break; dir = parent;
  }
  return out;
}
function packageMetadata(entry, expectedName) {
  for (const dir of ancestorDirectories(path.dirname(entry))) {
    const file = path.join(dir, 'package.json');
    if (!fs.existsSync(file)) continue;
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data.name === expectedName) return { packageJson: fs.realpathSync(file), version: data.version || null };
  }
  const error = new Error(`DEPENDENCY_METADATA_MISSING:${expectedName}`); error.code = 'DEPENDENCY_METADATA_MISSING'; throw error;
}
function resolveBabel(name) {
  if (!ALLOWED.has(name)) throw Object.assign(new Error(`UNAPPROVED_ANALYSIS_DEPENDENCY:${name}`), { code: 'UNAPPROVED_ANALYSIS_DEPENDENCY' });
  if (resolved.has(name)) return resolved.get(name);
  const configured = process.env.ARGUS_BABEL_ROOT;
  const roots = configured
    ? [path.resolve(configured), path.resolve(configured, 'node_modules'), path.resolve(configured, 'crawler', 'node_modules')]
    : [...new Set([...ancestorDirectories(process.cwd()), ...ancestorDirectories(__dirname)].map(dir => path.join(dir, 'crawler', 'node_modules')))];
  const attempts = []; let entry = null, strategy = null;
  for (const root of roots) {
    const candidate = path.join(root, name); attempts.push(candidate);
    try { entry = require.resolve(candidate); strategy = configured ? 'ARGUS_BABEL_ROOT' : 'REPOSITORY_CRAWLER_NODE_MODULES'; break; }
    catch (error) { if (error.code !== 'MODULE_NOT_FOUND' && error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error; }
  }
  if (!entry && !configured) {
    attempts.push(`normal-node-resolution:${name}`);
    try { entry = require.resolve(name, { paths: [process.cwd(), __dirname] }); strategy = 'NORMAL_NODE_RESOLUTION'; }
    catch (error) { if (error.code !== 'MODULE_NOT_FOUND' && error.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error; }
  }
  if (!entry) {
    const error = new Error(`BABEL_DEPENDENCY_MISSING:${name}; set ARGUS_BABEL_ROOT to the installed node_modules or repository root`);
    error.code = 'BABEL_DEPENDENCY_MISSING'; error.dependency = name; error.attemptedResolution = attempts; throw error;
  }
  entry = fs.realpathSync(entry);
  const info = { name, entry, strategy, ...packageMetadata(entry, name) };
  resolved.set(name, info); return info;
}
function requireBabel(name) { return require(resolveBabel(name).entry); }
function dependencyVersion(name) { return resolveBabel(name).version; }
function dependencyInfo() { return [...resolved.values()].map(info => ({ ...info })); }
function loadedDependencyPins() {
  const files = new Set(), seen = new Set();
  function scan(module) {
    if (!module || seen.has(module.id)) return; seen.add(module.id);
    if (module.filename && path.isAbsolute(module.filename)) files.add(module.filename);
    for (const child of module.children || []) scan(child);
  }
  for (const info of resolved.values()) { files.add(info.packageJson); scan(require.cache[info.entry]); }
  const pins = {};
  for (const file of [...files].sort()) pins[fs.realpathSync(file)] = hash(fs.readFileSync(file));
  return pins;
}
module.exports = { requireBabel, dependencyVersion, dependencyInfo, loadedDependencyPins };
