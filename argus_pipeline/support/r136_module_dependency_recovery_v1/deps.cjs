'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const roots = [process.env.ARGUS_BABEL_ROOT, path.resolve(process.cwd(), 'crawler/node_modules')].filter(Boolean);
const pins = {};
exports.load = function(name) {
  let resolved;
  for (const root of roots) {
    try { resolved = require.resolve(name, {paths: [root]}); break; } catch (_) {}
  }
  if (!resolved) { try { resolved = require.resolve(name); } catch (_) { throw new Error('MISSING_DEPENDENCY:' + name); } }
  pins[name] = {path: resolved, sha256: crypto.createHash('sha256').update(fs.readFileSync(resolved)).digest('hex')};
  return require(resolved);
};
exports.pins = pins;
