/**
 * Test: XSS via textContent (should be safe)
 * Expected: NO VULNERABILITY - textContent is safe
 */

function test() {
  var userInput = window.location.search;
  document.getElementById('output').textContent = userInput;
}

test();