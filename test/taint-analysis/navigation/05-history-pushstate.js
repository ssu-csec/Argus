/**
 * Test: History manipulation redirect
 * Expected: VULNERABILITY - URL param to history.pushState
 */

function test() {
  var newUrl = new URLSearchParams(window.location.search).get('redirect');
  history.pushState(null, '', newUrl);
  window.location.reload();
}

test();