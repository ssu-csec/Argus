/**
 * Test: Multiple XSS vectors
 * Expected: VULNERABILITY - cookie to multiple sinks
 */

function test() {
  var data = document.cookie;
  
  // Multiple potential XSS vectors
  document.write(data);
  document.body.innerHTML = data;
  document.getElementById('test').outerHTML = '<div>' + data + '</div>';
}

test();