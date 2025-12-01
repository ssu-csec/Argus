/**
 * Test: Function parameter propagation
 * Expected: VULNERABILITY - userAgent through function parameter to eval
 */

function leakData(sensitive) {
  eval('console.log("' + sensitive + '")');
}

function test() {
  var ua = navigator.userAgent;
  leakData(ua);
}

test();