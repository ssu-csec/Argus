/**
 * Test: Code injection via Function constructor
 * Expected: VULNERABILITY - URL search to Function
 */

function test() {
  var search = window.location.search;
  var fn = new Function('return ' + search);
  fn();
}

test();
