/**
 * Test: Taint through nested closures
 * Expected: VULNERABILITY - userAgent through 2 closures to innerHTML
 */

function test() {
  var ua = navigator.userAgent;
  
  function middle() {
    function inner() {
      document.body.innerHTML = ua;
    }
    inner();
  }
  
  middle();
}

test();
