/**
 * Test: Type conversion that might be safe
 * Expected: POTENTIAL FALSE POSITIVE - number conversion
 */

function test() {
  var width = screen.width;  // number
  var num = parseInt(width);
  document.body.innerHTML = num.toString();
}

test();
