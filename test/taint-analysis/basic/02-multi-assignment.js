/**
 * Test: Taint propagation through multiple assignments
 * Expected: VULNERABILITY - cookie flows to eval
 */

function test() {
  var a = document.cookie;
  var b = a;
  var c = b;
  eval(c);
}

test();
