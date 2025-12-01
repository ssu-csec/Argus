/**
 * Test: Iframe src navigation
 * Expected: VULNERABILITY - URL hash to iframe src
 */

function test() {
  var target = window.location.hash.substring(1);
  var iframe = document.createElement('iframe');
  iframe.src = target;
  document.body.appendChild(iframe);
}

test();