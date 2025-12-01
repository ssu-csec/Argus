/**
 * Test: Taint propagation through closure
 * Expected: VULNERABILITY - cookie flows through closure to eval
 */

function test() {
  var secret = document.cookie;
  
  function inner() {
    eval(secret);
  }
  
  inner();
}

test();
