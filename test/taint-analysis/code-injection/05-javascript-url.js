/**
 * Test: Code injection via scriptlet
 * Expected: VULNERABILITY - URL hash to javascript: URL
 */

function test() {
  var code = window.location.hash.substring(1);
  window.location.href = 'javascript:' + code;
}

test();