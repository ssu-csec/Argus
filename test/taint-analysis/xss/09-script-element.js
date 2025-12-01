/**
 * Test: XSS via createElement with user content
 * Expected: VULNERABILITY - user input in script element
 */

function test() {
  var userCode = window.location.hash.substring(1);
  var script = document.createElement('script');
  script.text = userCode;
  document.head.appendChild(script);
}

test();