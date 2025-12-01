/**
 * Test: Writing user data to cookie
 * Expected: VULNERABILITY - referrer to cookie
 */

function test() {
  var ref = document.referrer;
  document.cookie = 'tracker=' + ref;
}

test();
