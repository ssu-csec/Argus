/**
 * Test: Code injection via setInterval
 * Expected: VULNERABILITY - URL to setInterval
 */

function test() {
  var url = window.location.href;
  setInterval('alert("' + url + '")', 5000);
}

test();
