/**
 * Test: Taint through callback closure
 * Expected: VULNERABILITY - userAgent in callback to innerHTML
 */

function test() {
  var ua = navigator.userAgent;
  
  setTimeout(function() {
    document.body.innerHTML = ua;
  }, 100);
}

test();
