/**
 * Test: Direct eval code injection
 * Expected: VULNERABILITY - URL hash to eval
 */

function test() {
  var code = window.location.hash.substring(1);
  eval(code);
}

test();
