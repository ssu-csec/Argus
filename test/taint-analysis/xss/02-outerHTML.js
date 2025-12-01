/**
 * Test: XSS via outerHTML
 * Expected: VULNERABILITY - cookie to outerHTML
 */

function test() {
  var data = document.cookie;
  var elem = document.getElementById('content');
  elem.outerHTML = '<div>' + data + '</div>';
}

test();
