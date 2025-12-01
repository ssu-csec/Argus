/**
 * Test: Tainted variable overwritten with constant
 * Expected: POTENTIAL FALSE POSITIVE - taint should be cleared
 */

function test() {
  var data = document.cookie;
  data = "safe constant";
  document.body.innerHTML = data;
}

test();
