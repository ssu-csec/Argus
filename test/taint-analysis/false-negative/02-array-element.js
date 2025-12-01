/**
 * Test: Taint through array element (may not be detected)
 * Expected: POTENTIAL FALSE NEGATIVE - array tracking limitation
 */

function test() {
  var arr = [];
  arr[0] = navigator.userAgent;
  document.body.innerHTML = arr[0];
}

test();
