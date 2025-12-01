/**
 * Test: Taint through ternary operator
 * Expected: VULNERABILITY - conditional source to innerHTML
 */

function test(flag) {
  var data = flag ? document.cookie : window.location.href;
  document.body.innerHTML = data;
}

test(true);
