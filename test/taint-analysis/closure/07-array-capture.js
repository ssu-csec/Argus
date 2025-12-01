/**
 * Test: Closure with array capture
 * Expected: VULNERABILITY - userAgent array element in closure
 */

function test() {
  var sources = [navigator.userAgent, navigator.language];
  
  function processLater() {
    sources.forEach(function(source) {
      document.body.innerHTML += '<p>' + source + '</p>';
    });
  }
  
  setTimeout(processLater, 500);
}

test();