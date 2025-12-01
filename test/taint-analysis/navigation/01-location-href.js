/**
 * Test: Open redirect via location.href
 * Expected: VULNERABILITY - URL param to location.href
 */

function test() {
  var params = new URLSearchParams(window.location.search);
  var redirect = params.get('redirect');
  window.location.href = redirect;
}

test();
