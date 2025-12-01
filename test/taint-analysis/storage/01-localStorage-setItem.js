/**
 * Test: Sensitive data storage
 * Expected: VULNERABILITY - cookie to localStorage
 */

function test() {
  var cookie = document.cookie;
  localStorage.setItem('backup', cookie);
}

test();
