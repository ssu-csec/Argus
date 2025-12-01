/**
 * Test: Sanitized input (should be safe, but conservative analysis may flag)
 * Expected: POTENTIAL FALSE POSITIVE - sanitized cookie to innerHTML
 */

function sanitize(input) {
  return input.replace(/[<>]/g, '');
}

function test() {
  var cookie = document.cookie;
  var safe = sanitize(cookie);
  document.body.innerHTML = safe;
}

test();
