/**
 * Test: Open redirect via window.open
 * Expected: VULNERABILITY - URL to window.open
 */

function test() {
  var url = window.location.search;
  window.open(url, '_blank');
}

test();
