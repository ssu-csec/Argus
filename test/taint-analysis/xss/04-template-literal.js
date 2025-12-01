/**
 * Test: XSS via template literal
 * Expected: VULNERABILITY - hash to innerHTML
 */

function test() {
  var hash = window.location.hash;
  var html = `<div>${hash}</div>`;
  document.body.innerHTML = html;
}

test();
