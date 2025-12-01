/**
 * Test: DOM-based XSS with multiple steps
 * Expected: VULNERABILITY - location search to innerHTML via multiple steps
 */

function test() {
  var search = window.location.search;
  var params = new URLSearchParams(search);
  var message = params.get('msg');
  var output = '<div class="message">' + message + '</div>';
  
  document.getElementById('content').innerHTML = output;
}

test();