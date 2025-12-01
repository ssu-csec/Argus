/**
 * Test: Event listener with closure
 * Expected: VULNERABILITY - cookie captured in event listener
 */

function test() {
  var secret = document.cookie;
  
  document.addEventListener('click', function(event) {
    eval('console.log("' + secret + '")');
  });
  
  // Simulate click
  document.click();
}

test();