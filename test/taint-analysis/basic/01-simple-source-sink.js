/**
 * Test: Simple source to sink flow
 * Expected: VULNERABILITY - userAgent flows to innerHTML
 */

function test() {
  var ua = navigator.userAgent;
  document.getElementById('output').innerHTML = ua;
}

test();
