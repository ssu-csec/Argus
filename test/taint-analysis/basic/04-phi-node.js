/**
 * Test: Taint propagation through phi nodes (if-else)
 * Expected: VULNERABILITY - referrer flows to fetch
 */

function test(flag) {
  var data;
  if (flag) {
    data = document.referrer;
  } else {
    data = "safe";
  }
  fetch("https://example.com?q=" + data);
}

test(true);
