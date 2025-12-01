/**
 * Test: Code injection via setTimeout
 * Expected: VULNERABILITY - cookie to setTimeout
 */

function test() {
  var data = document.cookie;
  setTimeout('console.log("' + data + '")', 1000);
}

test();
