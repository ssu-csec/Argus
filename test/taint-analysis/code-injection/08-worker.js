/**
 * Test: Worker-based code injection
 * Expected: VULNERABILITY - hash to Worker script
 */

function test() {
  var script = window.location.hash.substring(1);
  var blob = new Blob([script], { type: 'application/javascript' });
  var worker = new Worker(URL.createObjectURL(blob));
  worker.postMessage('start');
}

test();