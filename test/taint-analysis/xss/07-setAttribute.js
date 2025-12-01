/**
 * Test: XSS via setAttribute
 * Expected: VULNERABILITY - URL hash to setAttribute
 */

function test() {
  var hash = window.location.hash.substring(1);
  var elem = document.createElement('div');
  elem.setAttribute('onclick', hash);
  document.body.appendChild(elem);
}

test();