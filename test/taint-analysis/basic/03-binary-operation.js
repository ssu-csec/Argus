/**
 * Test: Taint propagation through binary operations
 * Expected: VULNERABILITY - userAgent flows to innerHTML
 */

function test() {
  var ua = navigator.userAgent;
  var msg = "User Agent: " + ua;
  document.body.innerHTML = msg;
}

test();
