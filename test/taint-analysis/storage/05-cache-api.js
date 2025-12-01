/**
 * Test: Cache API storage
 * Expected: VULNERABILITY - cookie stored in Cache API
 */

function test() {
  var secret = document.cookie;
  
  caches.open('v1').then(function(cache) {
    cache.put('/data', new Response(secret));
  });
}

test();