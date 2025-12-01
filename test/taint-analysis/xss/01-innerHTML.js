/**
 * Test: XSS via innerHTML
 * Expected: VULNERABILITY - URL parameter to innerHTML
 */

function test() {
  var params = new URLSearchParams(window.location.search);
  var name = params.get('name');
  document.getElementById('greeting').innerHTML = name;
}

test();
