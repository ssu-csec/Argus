/**
 * Test: Sensitive data in session storage
 * Expected: VULNERABILITY - URL to sessionStorage
 */

function test() {
  var url = window.location.href;
  sessionStorage.setItem('lastVisit', url);
}

test();
