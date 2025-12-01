/**
 * Test: Taint through while loop
 * Expected: VULNERABILITY - URL params accumulated to innerHTML
 */

function test() {
  var params = new URLSearchParams(window.location.search);
  var output = "";
  var i = 0;
  
  while (i < params.size) {
    output += params.get('param' + i);
    i++;
  }
  
  document.body.innerHTML = output;
}

test();
