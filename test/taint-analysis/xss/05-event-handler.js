/**
 * Test: XSS via event handler injection
 * Expected: VULNERABILITY - search query to innerHTML
 */

function test() {
  var query = window.location.search;
  var btn = '<button onclick="' + query + '">Click</button>';
  document.body.innerHTML = btn;
}

test();
