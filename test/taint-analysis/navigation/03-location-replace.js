/**
 * Test: Open redirect via location.replace
 * Expected: VULNERABILITY - referrer to location.replace
 */

function test() {
  var ref = document.referrer;
  window.location.replace(ref);
}

test();
