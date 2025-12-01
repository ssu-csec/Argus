/**
 * Test: XSS via document.write
 * Expected: VULNERABILITY - userAgent to document.write
 */

function test() {
  var ua = navigator.userAgent;
  document.write('<p>Your browser: ' + ua + '</p>');
}

test();
