/**
 * Test: Open redirect via location.assign
 * Expected: VULNERABILITY - hash to location.assign
 */

function test() {
  var target = window.location.hash.substring(1);
  window.location.assign(target);
}

test();
