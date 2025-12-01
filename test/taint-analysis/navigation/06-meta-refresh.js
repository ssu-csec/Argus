/**
 * Test: Meta refresh redirect
 * Expected: VULNERABILITY - referrer to meta refresh
 */

function test() {
  var target = document.referrer;
  var meta = document.createElement('meta');
  meta.setAttribute('http-equiv', 'refresh');
  meta.setAttribute('content', '0; url=' + target);
  document.head.appendChild(meta);
}

test();