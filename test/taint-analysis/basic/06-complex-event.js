/**
 * Test: Complex event handler with multiple sources
 * Expected: VULNERABILITY - multiple sources to innerHTML
 */

function test() {
  var ua = navigator.userAgent;
  var lang = navigator.language;
  var info = "Browser: " + ua + ", Language: " + lang;
  
  document.addEventListener('click', function(event) {
    document.body.innerHTML = info + " Clicked at: " + event.clientX;
  });
}

test();