/**
 * Test: Taint through prototype chain (may not be detected)
 * Expected: POTENTIAL FALSE NEGATIVE - prototype pollution limitation
 */

function test() {
  var userInput = window.location.hash.substring(1);
  
  // Pollute prototype
  Object.prototype.tainted = userInput;
  
  var obj = {};
  document.body.innerHTML = obj.tainted;
}

test();